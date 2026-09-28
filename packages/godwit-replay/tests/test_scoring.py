"""Discovery scoring, including the two numbers that are easy to fake.

Precision over an empty covered set and a novelty rate measured against nothing are the two
ways a discovery scoreboard flatters itself. Both are pinned here.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from typing import Any

from _replay_support import GoldenCandidateHandler
from godwit_contracts.discovery import Candidate
from godwit_contracts.segment import Segment
from godwit_replay.datasets import LoadedDataset
from godwit_replay.driver import ReplayConfig, replay
from godwit_replay.harness import METADATA_BUDGET, HarnessResult, empty_truth
from godwit_replay.scoring import (
    K_VALUES,
    SegmentTruth,
    TruthSet,
    naive_threshold_keys,
    score_discovery,
    truth_from_golden_manifest,
)


def test_truth_from_the_golden_manifest_carries_keys_not_values(
    golden_manifest: Mapping[str, Any],
) -> None:
    truth = truth_from_golden_manifest(golden_manifest)
    assert len(truth.segments) == 3
    assert len(truth.real_keys) == 2
    controls = [item for item in truth.segments if not item.is_real]
    assert len(controls) == 1
    assert "false-positive control" in controls[0].note
    rendered = truth.model_dump_json()
    assert "PT" not in rendered, "a truth set is hashes; it must be committable"
    assert "refund" not in rendered
    assert set(truth.columns_of_interest) == {"country", "status"}


def test_precision_is_computed_over_covered_items_and_says_how_many(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
) -> None:
    """Both golden candidates are real, so precision is 1.0 -- over exactly two items."""
    run = replay(
        dataset="golden-drift",
        history=golden_history,
        clock_instants=golden_loaded.clock_instants,
        period_keys=golden_loaded.period_keys,
        handler=GoldenCandidateHandler(candidates=golden_candidates),
        config=config,
        budget=METADATA_BUDGET,
    )
    truth = truth_from_golden_manifest(golden_manifest)
    score = score_discovery(run, truth=truth)
    assert score.surfaced_covered == 2
    for k in K_VALUES:
        assert score.precision_at_k[str(k)] == 1.0
        assert score.considered_at_k[str(k)] == 2, (
            "a precision@100 over two items must report two, not pretend to a hundred"
        )
    assert score.real_surfaced == 2
    assert score.real_total == 2
    assert score.false_positives_on_controls == ()


def test_surfacing_the_documented_control_is_recorded_as_a_false_positive(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
) -> None:
    """Mark one of the surfaced segments as not real and it must land in the control list."""
    run = replay(
        dataset="golden-drift",
        history=golden_history,
        clock_instants=golden_loaded.clock_instants,
        period_keys=golden_loaded.period_keys,
        handler=GoldenCandidateHandler(candidates=golden_candidates),
        config=config,
        budget=METADATA_BUDGET,
    )
    surfaced = str(golden_candidates[0].segment.key)
    truth = TruthSet(
        dataset="golden-drift",
        segments=(SegmentTruth(segment_key=surfaced, is_real=False, note="control"),),
    )
    score = score_discovery(run, truth=truth)
    assert score.false_positives_on_controls == (surfaced,)
    assert score.precision_at_k["10"] == 0.0
    assert score.real_surfaced == 0
    assert score.usd_per_confirmed is None
    assert score.bytes_per_confirmed is None


def test_precision_over_nothing_is_nan_not_zero_and_not_one(golden_run: HarnessResult) -> None:
    """The honest answer when nobody has said which segments are real."""
    score = score_discovery(golden_run.run, truth=empty_truth(golden_run.loaded.spec))
    for k in K_VALUES:
        assert score.considered_at_k[str(k)] == 0
        assert score.precision_at_k[str(k)] != score.precision_at_k[str(k)]  # NaN
    assert score.novelty_rate is None
    assert score.headline_time_to_detection_seconds is None


def test_time_to_detection_is_signed_and_negative_means_ahead(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
) -> None:
    run = replay(
        dataset="golden-drift",
        history=golden_history,
        clock_instants=golden_loaded.clock_instants,
        period_keys=golden_loaded.period_keys,
        handler=GoldenCandidateHandler(candidates=golden_candidates, emit_from_step=1),
        config=config,
        budget=METADATA_BUDGET,
    )
    truth = truth_from_golden_manifest(golden_manifest)
    surfaced_at = golden_loaded.clock_instants[1]
    caught_later = surfaced_at + _dt.timedelta(days=30)
    score = score_discovery(
        run,
        truth=truth,
        detection_reference=dict.fromkeys(truth.real_keys, caught_later),
    )
    assert score.headline_time_to_detection_seconds is not None
    assert score.headline_time_to_detection_seconds == -30 * 86400.0
    assert all(value < 0 for value in score.time_to_detection_seconds.values())


def test_novelty_is_measured_against_the_naive_rule_not_asserted(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
) -> None:
    run = replay(
        dataset="golden-drift",
        history=golden_history,
        clock_instants=golden_loaded.clock_instants,
        period_keys=golden_loaded.period_keys,
        handler=GoldenCandidateHandler(candidates=golden_candidates),
        config=config,
        budget=METADATA_BUDGET,
    )
    truth = truth_from_golden_manifest(golden_manifest)
    naive = naive_threshold_keys(golden_history)
    fully_novel = score_discovery(run, truth=truth, naive_keys=naive)
    assert fully_novel.novelty_rate == 1.0
    assert fully_novel.naive_surfaced_real == 0

    # Now pretend the naive rule had found one of them: novelty must fall to a half.
    already_known = frozenset({next(iter(sorted(truth.real_keys)))})
    partly = score_discovery(run, truth=truth, naive_keys=already_known)
    assert partly.novelty_rate == 0.5
    assert partly.naive_surfaced_real == 1


def test_the_naive_rule_fires_on_the_whole_table_when_the_row_count_moves(
    golden_history: tuple[Any, ...],
) -> None:
    """The golden table doubles at the second commit, so the naive rule fires. Correctly.

    Iceberg appends accumulate: snapshot 1 holds 12,000 rows against snapshot 0's 6,000, which
    is 0.69 in log units and over the threshold. What the rule flags is the *universe* segment
    -- "the table changed size" -- which is not any of the documented drift segments. That is
    the whole point of the comparison: a rule anyone could write in an afternoon notices the
    volume and says nothing about where the change lives.
    """
    flagged = naive_threshold_keys(golden_history)
    assert flagged != frozenset()
    assert flagged == {str(Segment().key)}


def test_the_naive_rule_stays_quiet_on_a_table_of_steady_size(
    golden_history: tuple[Any, ...],
) -> None:
    from godwit_contracts.taint import derived_statistic

    steady = tuple(
        item.model_copy(update={"row_count": derived_statistic(6000)}) for item in golden_history
    )
    assert naive_threshold_keys(steady) == frozenset()


def test_stability_reports_disagreement_rather_than_hiding_it(golden_run: HarnessResult) -> None:
    other = golden_run.run.model_copy(update={"digest": "rpl_something_else"})
    score = score_discovery(
        golden_run.run, truth=empty_truth(golden_run.loaded.spec), repeat_runs=(other,)
    )
    assert not score.stability.strict_agree
    assert score.stability.content_agree
    assert not score.is_reproducible
