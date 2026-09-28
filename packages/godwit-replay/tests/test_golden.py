"""The acceptance criteria, against ``tests/golden``.

Four claims are made here and each one is a criterion from the brief:

1. Replay over the golden fixture is bit-identical across two runs.
2. A deliberately leaky configuration is caught and fails the run.
3. The verdict command runs end to end using only metadata detectors.
4. The metadata tier reads zero bytes of table data -- measured, not asserted in prose.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from _replay_support import GoldenCandidateHandler
from godwit_replay.datasets import LoadedDataset
from godwit_replay.driver import MetadataOnlyHandler, ReplayConfig, ReplayVerdict, replay
from godwit_replay.harness import HarnessResult, read_history
from godwit_replay.leak import LeakKind
from godwit_replay.verdict import KILL_SENTENCE, build_report, render_markdown


def test_replay_over_the_golden_fixture_is_bit_identical(
    golden_loaded: LoadedDataset, golden_history: tuple[Any, ...], config: ReplayConfig
) -> None:
    handler = MetadataOnlyHandler(code_version=config.code_version)

    def once() -> Any:
        return replay(
            dataset="golden-drift",
            history=golden_history,
            clock_instants=golden_loaded.clock_instants,
            period_keys=golden_loaded.period_keys,
            handler=handler,
            config=config,
            budget=_budget(),
        )

    first, second = once(), once()
    assert first.digest == second.digest
    assert first.content_digest == second.content_digest
    assert first.model_dump_json() == second.model_dump_json()
    assert first.verdict is ReplayVerdict.PASSED


def test_the_metadata_tier_reads_no_table_data(golden_loaded: LoadedDataset) -> None:
    _, meter = read_history(golden_loaded)
    assert meter.data_bytes == 0
    assert not meter.touched_table_data
    assert meter.metadata_bytes > 0


def test_a_leaky_configuration_fails_the_run(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Any, ...],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    """The deliberately leaky arm: reveal predicate values into the report.

    The candidates come from ``tests/golden/candidates.json`` because A1's metadata detectors
    deliberately emit nullary segments, which carry no value to leak. Proving the audit works
    needs an artifact that has something in it worth stopping.

    The typed arm must be the one that fires. If only the string backstop had caught it, the
    taint typing would be wrong somewhere, and the assertion below is what says so.
    """
    handler = GoldenCandidateHandler(candidates=golden_candidates)
    leaky = config.model_copy(update={"name": "leaky", "reveal_values_in_output": True})
    honest = config.model_copy(update={"name": "honest", "reveal_values_in_output": False})

    def once(arm: ReplayConfig) -> Any:
        run = replay(
            dataset="golden-drift",
            history=golden_history,
            clock_instants=golden_loaded.clock_instants,
            period_keys=golden_loaded.period_keys,
            handler=handler,
            config=arm,
            budget=_budget(),
        )
        return build_report(run, as_of=frozen_now)

    leaked = once(leaky)
    assert leaked.verdict is ReplayVerdict.FAILED_LEAK
    assert not leaked.passed
    kinds = {finding.kind for finding in leaked.leaks}
    assert LeakKind.DATA_VALUE_EGRESS in kinds, (
        "the typed arm must fire; a leak caught only by the string scan is a taint-typing bug"
    )
    assert "PT" in render_markdown(leaked), "the leaky arm really did render the value"

    clean = once(honest)
    assert clean.passed, [finding.line() for finding in clean.leaks]
    assert "PT" not in render_markdown(clean)


def test_the_report_never_renders_a_predicate_value(golden_run: HarnessResult) -> None:
    rendered = render_markdown(golden_run.report)
    assert golden_run.report.passed
    assert "<tainted" in rendered, "redacted labels are what a safe report shows instead"
    for row in golden_run.report.top:
        assert row.disclosed == ()


def test_the_report_always_prints_the_kill_sentence(golden_run: HarnessResult) -> None:
    rendered = render_markdown(golden_run.report)
    assert KILL_SENTENCE in rendered
    assert "UNREVIEWED" in rendered
    assert golden_run.report.kill.supported is None


def test_the_stability_check_is_recorded_not_merely_asserted(golden_run: HarnessResult) -> None:
    stability = golden_run.score.stability
    assert len(stability.strict_digests) == 2
    assert stability.strict_agree
    assert stability.content_agree
    assert golden_run.score.is_reproducible


def test_a_report_built_twice_is_identical(golden_run: HarnessResult, frozen_now: Any) -> None:
    left = build_report(golden_run.run, as_of=frozen_now, score=golden_run.score)
    right = build_report(golden_run.run, as_of=frozen_now, score=golden_run.score)
    assert left.model_dump_json() == right.model_dump_json()
    assert render_markdown(left) == render_markdown(right)


def _budget() -> Any:
    from godwit_replay.harness import METADATA_BUDGET

    return METADATA_BUDGET
