"""The driver's refusals: future knowledge, wall-clock reads and budget exhaustion.

Every test here is about the driver declining to produce a result. That is the point of the
package: a harness that cannot fail a run cannot certify one either.
"""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal
from typing import Any

import pytest
from _replay_support import (
    ClockReadingHandler,
    FutureDateHandler,
    FutureSnapshotHandler,
    GoldenCandidateHandler,
    LabelPeekingHandler,
)
from godwit_contracts.cost import CostBudget
from godwit_contracts.discovery import Candidate, CoverageScope, Label, LabelSet
from godwit_contracts.segment import Segment
from godwit_contracts.taint import Acquisition, data_value
from godwit_replay.datasets import LoadedDataset
from godwit_replay.driver import ReplayConfig, ReplayVerdict, replay
from godwit_replay.errors import FutureKnowledgeError, WallClockAccessError
from godwit_replay.harness import METADATA_BUDGET
from godwit_replay.verdict import assert_passed, build_report

TINY_BUDGET = CostBudget(
    bytes_scanned=1, wall_seconds=0.0, usd=Decimal("0"), llm_tokens=0, train_seconds=0.0
)


def _run(
    *,
    loaded: LoadedDataset,
    history: tuple[Any, ...],
    handler: Any,
    config: ReplayConfig,
    budget: CostBudget = METADATA_BUDGET,
    labels: LabelSet | None = None,
) -> Any:
    return replay(
        dataset="golden-drift",
        history=history,
        clock_instants=loaded.clock_instants,
        period_keys=loaded.period_keys,
        handler=handler,
        config=config,
        budget=budget,
        labels=labels,
    )


def test_a_candidate_naming_a_future_snapshot_fails_the_run(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    config: ReplayConfig,
) -> None:
    run = _run(
        loaded=golden_loaded,
        history=golden_history,
        handler=FutureSnapshotHandler(candidates=golden_candidates),
        config=config,
    )
    assert run.verdict is ReplayVerdict.FAILED_FUTURE
    assert run.refusal is not None
    assert "not visible" in run.refusal


def test_a_candidate_dated_after_the_step_fails_the_run(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    config: ReplayConfig,
) -> None:
    run = _run(
        loaded=golden_loaded,
        history=golden_history,
        handler=FutureDateHandler(candidates=golden_candidates),
        config=config,
    )
    assert run.verdict is ReplayVerdict.FAILED_FUTURE
    assert run.refusal is not None
    assert "after the step instant" in run.refusal


def test_assert_passed_raises_on_a_future_failure(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    run = _run(
        loaded=golden_loaded,
        history=golden_history,
        handler=FutureSnapshotHandler(candidates=golden_candidates),
        config=config,
    )
    report = build_report(run, as_of=frozen_now)
    with pytest.raises(FutureKnowledgeError):
        assert_passed(report)


def test_a_handler_that_reads_the_clock_is_stopped(
    golden_loaded: LoadedDataset, golden_history: tuple[Any, ...], config: ReplayConfig
) -> None:
    """The guard is active around ``observe``, so this raises out of the driver.

    It is not caught and turned into a verdict: a component reading a clock is a code defect,
    not a run outcome, and swallowing it would let the defect ship.
    """
    with pytest.raises(WallClockAccessError):
        _run(
            loaded=golden_loaded,
            history=golden_history,
            handler=ClockReadingHandler(),
            config=config,
        )


def test_the_guard_can_be_disabled_for_a_deliberate_comparison(
    golden_loaded: LoadedDataset, golden_history: tuple[Any, ...], config: ReplayConfig
) -> None:
    run = replay(
        dataset="golden-drift",
        history=golden_history,
        clock_instants=golden_loaded.clock_instants,
        period_keys=golden_loaded.period_keys,
        handler=ClockReadingHandler(),
        config=config,
        budget=METADATA_BUDGET,
        guard_wall_clock=False,
    )
    assert run.verdict is ReplayVerdict.PASSED


def test_running_out_of_budget_is_a_refusal_not_a_crash(
    golden_loaded: LoadedDataset, golden_history: tuple[Any, ...], config: ReplayConfig
) -> None:
    """Invariant 6: refusing to spend is a normal outcome.

    The golden history reports zero scanned bytes at L-1, so the budget is exhausted by an
    explicit wall-clock ceiling of zero rather than by bytes. The run comes back with a
    verdict and a reason, not an exception.
    """
    starved = CostBudget(
        bytes_scanned=0,
        wall_seconds=0.0,
        usd=Decimal("0"),
        llm_tokens=0,
        train_seconds=0.0,
    )
    history = tuple(item.model_copy(update={"scanned_bytes": 1}) for item in golden_history)
    run = _run(
        loaded=golden_loaded,
        history=history,
        handler=GoldenCandidateHandler(candidates=()),
        config=config,
        budget=starved,
    )
    assert run.verdict is ReplayVerdict.REFUSED_BUDGET
    assert run.refusal is not None
    assert "budget refused at step 0" in run.refusal
    assert run.steps == ()


def test_a_handler_only_ever_sees_labels_that_already_existed(
    golden_loaded: LoadedDataset, golden_history: tuple[Any, ...], config: ReplayConfig
) -> None:
    """The label set holds three labels revealed one period apart.

    At step N the handler must see exactly the labels whose ``label_time`` has passed. If it
    ever sees more, the harness is leaking the future into every number it reports.
    """
    instants = golden_loaded.clock_instants
    labels = LabelSet(
        coverage=CoverageScope(
            entity_type="order_id",
            population=Segment(),
            complete_from=instants[0],
            complete_to=instants[-1],
            is_exhaustive=True,
        ),
        labels=tuple(
            Label(
                entity_id=data_value(
                    f"ord_{index}", acquisition=Acquisition.SEGMENT_PREDICATE, column="order_id"
                ),
                value=data_value(
                    True, acquisition=Acquisition.SEGMENT_PREDICATE, column="is_fraud"
                ),
                event_time=instants[0],
                label_time=moment,
                source="test",
            )
            for index, moment in enumerate(instants)
        ),
    )
    counter = LabelPeekingHandler(seen=[])
    run = _run(
        loaded=golden_loaded,
        history=golden_history,
        handler=counter,
        config=config,
        labels=labels,
    )
    assert run.verdict is ReplayVerdict.PASSED
    assert counter.seen == [1, 2, 3]
    assert [int(step.visible_label_count) for step in run.steps] == [1, 2, 3]


def test_max_periods_shortens_the_run_and_changes_the_config_digest(
    golden_loaded: LoadedDataset, golden_history: tuple[Any, ...], config: ReplayConfig
) -> None:
    short = config.model_copy(update={"max_periods": 2})
    run = _run(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=()),
        config=short,
    )
    assert len(run.steps) == 2
    assert short.digest() != config.digest()


def test_replay_refuses_mismatched_history_and_clock(
    golden_history: tuple[Any, ...], config: ReplayConfig
) -> None:
    with pytest.raises(ValueError, match="same length"):
        replay(
            dataset="golden-drift",
            history=golden_history,
            clock_instants=(_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),),
            period_keys=("only-one",),
            handler=GoldenCandidateHandler(candidates=()),
            config=config,
            budget=METADATA_BUDGET,
        )


def test_first_surfaced_reports_the_earliest_step_per_segment(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    config: ReplayConfig,
) -> None:
    run = _run(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates, emit_from_step=1),
        config=config,
    )
    first = run.first_surfaced()
    assert set(first) == {str(candidate.segment.key) for candidate in golden_candidates}
    assert set(first.values()) == {golden_loaded.clock_instants[1]}
