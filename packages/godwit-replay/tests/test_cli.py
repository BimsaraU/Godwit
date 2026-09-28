"""The command line: the kill criterion as a runnable command, and its exit codes."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from godwit_replay.cli import EXIT_FAILED, EXIT_OK, EXIT_UNAVAILABLE, build_parser, main
from godwit_replay.verdict import KILL_SENTENCE, KILL_THRESHOLD, ReviewMark


def _run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(argv, out=out)
    return code, out.getvalue()


def test_the_parser_offers_exactly_the_five_documented_commands() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
    for command in ("datasets", "verdict", "diff", "baseline", "verify-baseline"):
        namespace = parser.parse_args(
            [command] if command == "datasets" else [command, "--dataset", "golden-drift"]
        )
        assert namespace.command == command


def test_datasets_prints_every_fabricated_assumption() -> None:
    code, text = _run("datasets")
    assert code == EXIT_OK
    for name in ("ieee-cis", "paysim", "telco-churn", "nyc-tlc"):
        assert name in text
    assert "FABRICATED" in text
    assert "caveat" in text
    assert "kaggle.com" in text


def test_verdict_runs_end_to_end_on_metadata_detectors_alone(tmp_path: Path) -> None:
    """Acceptance: the verdict command works before Wave 2 exists.

    Nothing in this path touches a detector, a model or an LLM. It reads Iceberg manifests and
    runs A1's six metadata detectors, which is the whole system as of today.
    """
    code, text = _run(
        "verdict",
        "--dataset",
        "golden-drift",
        "--workspace",
        str(tmp_path / "ws"),
        "--out",
        str(tmp_path / "out"),
        "--repeats",
        "1",
    )
    assert code == EXIT_OK
    assert "# Replay verdict -- golden-drift" in text
    assert "metadata-only" in text
    assert KILL_SENTENCE in text
    assert "0 bytes of table data" in text
    assert "reproducible: yes" in text

    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["verdict"] == "passed"
    assert report["kill"]["required"] == KILL_THRESHOLD
    assert (tmp_path / "out" / "report.md").is_file()
    template = (tmp_path / "out" / "review-template.md").read_text(encoding="utf-8")
    assert "non-obvious-and-real" in template
    assert KILL_SENTENCE in template


def test_the_verdict_timestamp_comes_from_the_data_not_from_a_clock(tmp_path: Path) -> None:
    """Two runs of the same data produce the same report timestamp. No clock is read."""
    args = ("verdict", "--dataset", "golden-drift", "--repeats", "0", "--out")
    first = _run(*args, str(tmp_path / "a"))
    second = _run(*args, str(tmp_path / "b"))
    assert first[0] == second[0] == EXIT_OK
    left = json.loads((tmp_path / "a" / "report.json").read_text(encoding="utf-8"))
    right = json.loads((tmp_path / "b" / "report.json").read_text(encoding="utf-8"))
    assert left["generated_as_of"] == right["generated_as_of"]
    assert left["generated_as_of"].startswith("2024-")
    assert left["content_digest"] == right["content_digest"]


def test_marks_are_counted_against_the_threshold(tmp_path: Path) -> None:
    """Fewer than three non-obvious-and-real means NOT SUPPORTED, in the tool's own words."""
    unmarked = _run(
        "verdict", "--dataset", "golden-drift", "--repeats", "0", "--out", str(tmp_path / "u")
    )
    assert unmarked[0] == EXIT_OK
    report = json.loads((tmp_path / "u" / "report.json").read_text(encoding="utf-8"))
    keys = [row["segment_key"] for row in report["top"]]
    assert keys, "the fixture surfaces at least one pattern to mark"

    marks = tmp_path / "marks.json"
    marks.write_text(
        json.dumps(dict.fromkeys(keys, ReviewMark.NON_OBVIOUS_AND_REAL.value)), encoding="utf-8"
    )
    code, text = _run(
        "verdict",
        "--dataset",
        "golden-drift",
        "--repeats",
        "0",
        "--marks",
        str(marks),
    )
    assert code == EXIT_OK
    assert "NOT SUPPORTED" in text, (
        "one marked pattern is fewer than three, and the tool must say the thesis is not "
        "supported rather than soften it"
    )
    assert KILL_SENTENCE in text


def test_the_audit_can_fail_the_command_not_merely_annotate_it(tmp_path: Path) -> None:
    """An absurd small-cell threshold makes every reported statistic a finding.

    The point is the exit code. A harness whose audit produces a paragraph at the bottom of a
    report that still exits zero has not gated anything.
    """
    code, text = _run(
        "verdict",
        "--dataset",
        "golden-drift",
        "--workspace",
        str(tmp_path / "ws"),
        "--repeats",
        "0",
        "--small-cell-threshold",
        "1000000",
    )
    assert code == EXIT_FAILED
    assert "failed_leak" in text
    assert "THIS RUN FAILED" in text
    assert "small_cell" in text


def test_the_reveal_flag_is_plumbed_but_has_nothing_to_reveal_at_l_minus_one(
    tmp_path: Path,
) -> None:
    """A documented limit, asserted rather than assumed.

    ``--reveal-values`` is the deliberately leaky configuration and the audit catches it -- see
    ``test_golden.py::test_a_leaky_configuration_fails_the_run``, which drives the harness with
    candidates that carry values. Through the CLI today the only handler is A1's metadata
    detectors, and those emit segments whose operators are nullary: there is no predicate value
    in an L-1 candidate to reveal. So the flag changes the configuration digest and produces no
    finding, and this test pins that fact so nobody reads the passing exit code as proof that
    the audit is asleep.
    """
    code, text = _run(
        "verdict",
        "--dataset",
        "golden-drift",
        "--workspace",
        str(tmp_path / "ws"),
        "--reveal-values",
        "--repeats",
        "0",
        "--out",
        str(tmp_path / "out"),
    )
    assert code == EXIT_OK
    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["config"]["reveal_values_in_output"] is True
    assert report["leaks"] == []
    assert all(row["disclosed"] == [] for row in report["top"])
    assert "not_null" in text, "the L-1 segments really are nullary"


def test_diff_runs_two_arms_and_prints_the_comparison(tmp_path: Path) -> None:
    code, text = _run(
        "diff",
        "--dataset",
        "golden-drift",
        "--workspace",
        str(tmp_path / "ws"),
        "--challenger-max-p-value",
        "0.5",
        "--out",
        str(tmp_path / "out"),
    )
    assert code == EXIT_OK
    assert "# Champion vs challenger -- golden-drift" in text
    payload = json.loads((tmp_path / "out" / "diff.json").read_text(encoding="utf-8"))
    assert payload["champion"]["config_digest"] != payload["challenger"]["config_digest"]
    assert (tmp_path / "out" / "diff.md").is_file()


def test_an_absent_dataset_exits_with_the_unavailable_code() -> None:
    code, _ = _run("verdict", "--dataset", "ieee-cis", "--data-root", "this-does-not-exist")
    assert code == EXIT_UNAVAILABLE


def test_verify_baseline_confirms_the_recorded_numbers() -> None:
    """The recorded baseline in the package must rebuild exactly, or CI fails here."""
    code, text = _run("verify-baseline", "--dataset", "golden-classification")
    assert code == EXIT_OK
    assert "rebuilt to the recorded numbers exactly" in text


def test_verify_baseline_fails_when_there_is_nothing_recorded(tmp_path: Path) -> None:
    code, _ = _run("verify-baseline", "--dataset", "ieee-cis", "--baselines-dir", str(tmp_path))
    assert code == EXIT_FAILED


def test_as_of_must_carry_a_timezone() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["verdict", "--dataset", "golden-drift", "--as-of", "2024-01-01"])
