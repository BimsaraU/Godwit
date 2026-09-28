"""``godwit-replay`` -- the harness as a command.

    godwit-replay datasets
    godwit-replay verdict --dataset nyc-tlc --months 12
    godwit-replay diff --dataset golden-drift --challenger-seed 99
    godwit-replay baseline --dataset ieee-cis
    godwit-replay verify-baseline --dataset golden-classification

THERE IS NO CLOCK READ HERE EITHER
----------------------------------
``--as-of`` defaults to the last instant in the dataset's own history, not to now. A report
generated from the same data twice carries the same timestamp, which is what makes two runs
comparable. Pass ``--as-of`` explicitly when you want the report to say when a human ran it.

EXIT CODES
----------
``0`` the run passed. ``1`` the run failed -- a leak, future knowledge, or a baseline that did
not reproduce. ``2`` the dataset's raw files are not present. A failing run still prints its
report, because the failure is the evidence.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final, TextIO

from godwit_contracts.common import Instant
from godwit_contracts.errors import BudgetExceededError

from godwit_replay.baseline import build_baseline, load_baseline, save_baseline, verify_baseline
from godwit_replay.datasets import REGISTRY, dataset_root, missing_files, resolve
from godwit_replay.diff import diff_reports
from godwit_replay.diff import render_markdown as render_diff
from godwit_replay.driver import ReplayConfig
from godwit_replay.errors import (
    BaselineNotReproducibleError,
    DatasetNotAvailableError,
    ReplayError,
)
from godwit_replay.harness import METADATA_BUDGET, RunOptions, run_dataset
from godwit_replay.leak import forbidden_strings
from godwit_replay.split import MaskKind
from godwit_replay.verdict import KILL_SENTENCE, ReviewMark, render_markdown, render_review_template

__all__ = ["build_parser", "main"]

DEFAULT_CODE_VERSION: Final[str] = "godwit-replay/0.1.0"
DEFAULT_SEED: Final[int] = 20240117

_PLACEHOLDER_AS_OF: Final[Instant] = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)
"""Stands in until the dataset's own last instant is known.

The epoch, not ``now()``: a placeholder that looks like a real timestamp is worse than one
that obviously is not. Every command replaces it with the last instant in the data.
"""

_TRAINING_BUDGET_SECONDS: Final[float] = 1_000_000.0
"""Ceiling for the baseline's deterministic training-cost proxy. Generous on purpose: the
proxy exists to stop a runaway grid, not to tune anything."""

EXIT_OK: Final[int] = 0
EXIT_FAILED: Final[int] = 1
EXIT_UNAVAILABLE: Final[int] = 2


def _repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "tests" / "golden").is_dir():
            return parent
    return Path.cwd()


def _instant(text: str) -> Instant:
    moment = _dt.datetime.fromisoformat(text)
    if moment.tzinfo is None:
        raise argparse.ArgumentTypeError("--as-of must carry a timezone, e.g. 2024-01-01T00:00:00Z")
    return moment.astimezone(_dt.UTC)


def _add_common(target: argparse.ArgumentParser) -> None:
    target.add_argument("--dataset", required=True, choices=sorted(REGISTRY))
    target.add_argument("--months", type=int, default=None, help="Replay this many months")
    target.add_argument("--seed", type=int, default=DEFAULT_SEED)
    target.add_argument("--code-version", default=DEFAULT_CODE_VERSION)
    target.add_argument("--as-of", type=_instant, default=None)
    target.add_argument("--data-root", type=Path, default=None)
    target.add_argument("--workspace", type=Path, default=None)
    target.add_argument("--small-cell-threshold", type=int, default=20)


def build_parser() -> argparse.ArgumentParser:
    """The command-line surface. One parser, five subcommands, no hidden flags."""
    parser = argparse.ArgumentParser(
        prog="godwit-replay",
        description="Replay history, score what came out, and refuse to let a change ship "
        "that made things worse.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "datasets", help="List every dataset, its assumptions and whether it is available"
    )

    verdict = subparsers.add_parser(
        "verdict", help="The kill criterion: top 20 patterns plus a review template"
    )
    _add_common(verdict)
    verdict.add_argument("--top", type=int, default=20)
    verdict.add_argument(
        "--repeats", type=int, default=1, help="Extra runs for the stability check"
    )
    verdict.add_argument(
        "--out", type=Path, default=None, help="Write report.md and report.json here"
    )
    verdict.add_argument("--marks", type=Path, default=None, help="JSON: segment key -> mark")
    verdict.add_argument(
        "--reveal-values",
        action="store_true",
        help="THE LEAKY CONFIGURATION. Renders row values into the report. The egress audit "
        "catches it and the run fails. It exists to prove the audit works.",
    )

    difference = subparsers.add_parser("diff", help="Champion vs challenger over the same replay")
    _add_common(difference)
    difference.add_argument("--challenger-seed", type=int, default=None)
    difference.add_argument("--challenger-max-p-value", type=float, default=None)
    difference.add_argument("--out", type=Path, default=None)

    baseline = subparsers.add_parser(
        "baseline", help="Build and record the tuned expert baseline for one dataset"
    )
    _add_common(baseline)
    baseline.add_argument("--mask", choices=[item.value for item in MaskKind], default="temporal")
    baseline.add_argument("--baselines-dir", type=Path, default=None)

    verify = subparsers.add_parser(
        "verify-baseline", help="Rebuild a recorded baseline and refuse if the numbers moved"
    )
    _add_common(verify)
    verify.add_argument("--baselines-dir", type=Path, default=None)
    verify.add_argument("--tolerance", type=float, default=0.0)
    return parser


def _config(args: argparse.Namespace) -> ReplayConfig:
    return ReplayConfig(
        name=f"{args.dataset}:seed{args.seed}",
        seed=int(args.seed),
        code_version=str(args.code_version),
        small_cell_threshold=int(args.small_cell_threshold),
        reveal_values_in_output=bool(getattr(args, "reveal_values", False)),
        max_periods=None,
    )


def _workspace(args: argparse.Namespace, stack: list[tempfile.TemporaryDirectory[str]]) -> Path:
    if args.workspace is not None:
        chosen = Path(str(args.workspace))
        chosen.mkdir(parents=True, exist_ok=True)
        return chosen
    # ignore_cleanup_errors: on Windows an object-store handle can outlive the run by a
    # moment, and failing a verdict because a temporary file was still open would be absurd.
    handle = tempfile.TemporaryDirectory(prefix="godwit-replay-", ignore_cleanup_errors=True)
    stack.append(handle)
    return Path(handle.name)


def _golden_manifest(dataset: str) -> Mapping[str, object] | None:
    if dataset != "golden-drift":
        return None
    path = _repo_root() / "tests" / "golden" / "drift_table" / "manifest.json"
    if not path.is_file():
        return None
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise TypeError("the golden drift manifest is not a JSON object")
    return loaded


def _forbidden(dataset: str) -> frozenset[str]:
    """The string backstop's needles, which belong to one fixture and only to it.

    Empty for every dataset in the registry, on purpose. The needle list in
    ``pii_torture/expected_leaks.json`` contains the words ``unknown`` and ``general``,
    because in that fixture they are column values; searching an NYC-taxi report for them
    would fail the run on the phrase "segment population: unknown". The backstop is
    exercised where it means something -- see ``tests/test_leak.py`` -- and the typed arm
    is the control everywhere.
    """
    if dataset != "pii-torture":
        return frozenset()
    try:
        return forbidden_strings(_repo_root() / "tests" / "golden")
    except (OSError, KeyError, ValueError):
        return frozenset()


def _marks(path: Path | None) -> Mapping[str, ReviewMark] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(key): ReviewMark(str(value)) for key, value in payload.items()}


def _emit(out: TextIO, text: str) -> None:
    out.write(text + "\n")


def _cmd_datasets(_: argparse.Namespace, out: TextIO) -> int:
    lines: list[str] = ["# Datasets", ""]
    for spec in REGISTRY.values():
        absent = missing_files(spec)
        availability = "yes" if not absent else "NO -- " + ", ".join(p.name for p in absent)
        labels = (
            "none"
            if not spec.is_labelled
            else f"{spec.label_column}, label_time "
            + ("from the data" if spec.has_honest_label_time else "FABRICATED")
        )
        lines.extend(
            [
                f"## {spec.name} -- {spec.title}",
                "",
                f"- origin: {spec.origin}",
                f"- expects: {', '.join(spec.raw_files)} under {dataset_root(spec)}",
                f"- available: {availability}",
                f"- period: one commit per {spec.period.value}",
                f"- event time: {spec.event_time_column}",
                f"- labels: {labels}",
            ]
        )
        lines.extend(f"- **caveat**: {caveat}" for caveat in spec.caveats)
        if spec.note:
            lines.append(f"- note: {spec.note}")
        lines.append("")
    _emit(out, "\n".join(lines))
    return EXIT_OK


def _cmd_verdict(args: argparse.Namespace, out: TextIO) -> int:
    stack: list[tempfile.TemporaryDirectory[str]] = []
    try:
        result = run_dataset(
            str(args.dataset),
            workspace=_workspace(args, stack),
            config=_config(args),
            as_of=args.as_of if args.as_of is not None else _PLACEHOLDER_AS_OF,
            options=RunOptions(
                months=args.months,
                root=args.data_root,
                budget=METADATA_BUDGET,
                repeats=int(args.repeats),
                golden_manifest=_golden_manifest(str(args.dataset)),
                forbidden=_forbidden(str(args.dataset)),
                marks=_marks(args.marks),
            ),
        )
        report = result.report
        if args.as_of is None:
            report = report.model_copy(update={"generated_as_of": result.loaded.clock_instants[-1]})
        rendered = render_markdown(report)
        _emit(out, rendered)
        _emit(out, "")
        _emit(out, KILL_SENTENCE)
        if args.out is not None:
            destination = Path(str(args.out))
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "report.md").write_text(rendered, encoding="utf-8")
            (destination / "report.json").write_text(
                json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (destination / "review-template.md").write_text(
                render_review_template(report), encoding="utf-8"
            )
        return EXIT_OK if report.passed else EXIT_FAILED
    finally:
        for handle in stack:
            handle.cleanup()


def _cmd_diff(args: argparse.Namespace, out: TextIO) -> int:
    stack: list[tempfile.TemporaryDirectory[str]] = []
    try:
        workspace = _workspace(args, stack)
        champion_config = _config(args)
        challenger_config = champion_config.model_copy(
            update={
                "name": f"{args.dataset}:challenger",
                "seed": (
                    int(args.challenger_seed)
                    if args.challenger_seed is not None
                    else int(args.seed) + 1
                ),
                "detector": (
                    champion_config.detector.model_copy(
                        update={"max_p_value": float(args.challenger_max_p_value)}
                    )
                    if args.challenger_max_p_value is not None
                    else champion_config.detector
                ),
            }
        )
        as_of = args.as_of if args.as_of is not None else _PLACEHOLDER_AS_OF
        options = RunOptions(
            months=args.months,
            root=args.data_root,
            golden_manifest=_golden_manifest(str(args.dataset)),
            forbidden=_forbidden(str(args.dataset)),
            repeats=0,
        )
        champion = run_dataset(
            str(args.dataset),
            workspace=workspace,
            config=champion_config,
            as_of=as_of,
            options=options,
        )
        challenger = run_dataset(
            str(args.dataset),
            workspace=workspace,
            config=challenger_config,
            as_of=as_of,
            options=options,
        )
        comparison = diff_reports(champion.report, challenger.report)
        rendered = render_diff(comparison)
        _emit(out, rendered)
        if args.out is not None:
            destination = Path(str(args.out))
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "diff.md").write_text(rendered, encoding="utf-8")
            (destination / "diff.json").write_text(
                json.dumps(comparison.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        both_passed = champion.report.passed and challenger.report.passed
        return EXIT_OK if both_passed else EXIT_FAILED
    finally:
        for handle in stack:
            handle.cleanup()


def _cmd_baseline(args: argparse.Namespace, out: TextIO) -> int:
    spec = resolve(str(args.dataset))
    record = build_baseline(
        spec.name,
        seed=int(args.seed),
        as_of=args.as_of if args.as_of is not None else _PLACEHOLDER_AS_OF,
        code_version=str(args.code_version),
        budget=METADATA_BUDGET.model_copy(update={"train_seconds": _TRAINING_BUDGET_SECONDS}),
        root=args.data_root,
        mask=MaskKind(str(args.mask)),
    )
    path = save_baseline(record, directory=args.baselines_dir)
    lines = [
        f"# Expert baseline -- {spec.name}",
        "",
        record.comparison_note(),
        "",
        f"- chosen candidate: {dict(sorted(record.chosen.items()))}",
        f"- validation AUC: {record.validation_auc:.4f}",
        f"- held-out AUC: {record.metrics['auc']:.4f}",
        f"- held-out PR-AUC: {record.metrics['pr_auc']:.4f}",
        f"- features: {len(record.feature_names)} ({len(record.dropped_columns)} dropped)",
        *(f"- caveat: {caveat}" for caveat in record.caveats),
        "",
        f"recorded at {path}",
    ]
    _emit(out, "\n".join(lines))
    return EXIT_OK


def _cmd_verify_baseline(args: argparse.Namespace, out: TextIO) -> int:
    record = load_baseline(str(args.dataset), directory=args.baselines_dir)
    verify_baseline(
        record,
        code_version=str(args.code_version),
        budget=METADATA_BUDGET.model_copy(update={"train_seconds": _TRAINING_BUDGET_SECONDS}),
        root=args.data_root,
        tolerance=float(args.tolerance),
    )
    _emit(
        out,
        f"{record.dataset}: rebuilt to the recorded numbers exactly (AUC {record.auc:.4f}).",
    )
    return EXIT_OK


_COMMANDS: Final[Mapping[str, Callable[[argparse.Namespace, TextIO], int]]] = {
    "datasets": _cmd_datasets,
    "verdict": _cmd_verdict,
    "diff": _cmd_diff,
    "baseline": _cmd_baseline,
    "verify-baseline": _cmd_verify_baseline,
}


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """Run one command. Returns an exit code; never calls ``sys.exit`` itself."""
    stream = out if out is not None else sys.stdout
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handler = _COMMANDS[str(args.command)]
    try:
        return handler(args, stream)
    except DatasetNotAvailableError as exc:
        print(f"dataset unavailable: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except BaselineNotReproducibleError as exc:
        print(f"baseline not reproducible: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except BudgetExceededError as exc:
        print(f"refused on budget (a normal outcome, invariant 6): {exc}", file=sys.stderr)
        return EXIT_FAILED
    except ReplayError as exc:
        print(f"replay failed: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
