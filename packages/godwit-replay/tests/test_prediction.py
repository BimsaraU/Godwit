"""Prediction scoring: intervals, slices, small-cell suppression and the 0.02 objective."""

from __future__ import annotations

import datetime as _dt

import numpy as np
from godwit_contracts.common import ArtifactId
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.taint import Acquisition, Sensitivity, data_value, schema_name
from godwit_replay.prediction import (
    AUC_OBJECTIVE_MARGIN,
    BaselineComparison,
    ScoringOptions,
    SegmentSlices,
    score_predictions,
    to_evaluation_report,
)

SEED = 7
OPTIONS = ScoringOptions(small_cell_threshold=20, k_values=(10, 50), resamples=120)


def _separable(count: int = 400) -> tuple[list[int], list[float]]:
    generator = np.random.default_rng(SEED)
    labels = (generator.random(count) < 0.3).astype(int)
    scores = np.clip(labels * 0.4 + generator.normal(0.3, 0.15, count), 0.0, 1.0)
    return labels.tolist(), scores.tolist()


def _months(count: int) -> list[_dt.datetime]:
    base = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
    return [base + _dt.timedelta(days=index % 90) for index in range(count)]


def test_every_metric_arrives_with_an_interval() -> None:
    labels, scores = _separable()
    score = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=scores,
        probabilities=scores,
        seed=SEED,
        options=OPTIONS,
    )
    assert set(score.metrics) == {
        "auc",
        "pr_auc",
        "precision_at_10",
        "precision_at_50",
        "recall_at_10",
        "recall_at_50",
    }
    for interval in score.metrics.values():
        assert interval.low <= interval.point <= interval.high
    assert 0.0 <= score.calibration_error <= 1.0
    assert 0.0 <= score.brier_score <= 1.0
    assert score.population == len(labels)
    assert score.positives == sum(labels)


def test_scoring_is_reproducible_from_its_seed() -> None:
    labels, scores = _separable()
    kwargs = {
        "dataset": "golden-classification",
        "model_label": "test",
        "labels": labels,
        "scores": scores,
        "seed": SEED,
        "options": OPTIONS,
    }
    left = score_predictions(**kwargs)  # type: ignore[arg-type]
    right = score_predictions(**kwargs)  # type: ignore[arg-type]
    assert left.model_dump_json() == right.model_dump_json()


def test_time_slices_carry_no_segment_and_suppress_small_buckets() -> None:
    """A month boundary is our bucket edge, not a row value, so it does not need a Segment."""
    labels, scores = _separable(120)
    score = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=scores,
        event_times=_months(120),
        seed=SEED,
        options=ScoringOptions(small_cell_threshold=200, k_values=(10,), resamples=50),
    )
    assert score.time_slices == ()
    assert score.suppressed_slices > 0

    generous = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=scores,
        event_times=_months(120),
        seed=SEED,
        options=ScoringOptions(small_cell_threshold=10, k_values=(10,), resamples=50),
    )
    assert generous.time_slices
    for item in generous.time_slices:
        assert item.population >= 10
        assert item.period_key.startswith("2024-")


def test_segment_slices_below_the_threshold_are_omitted_and_counted() -> None:
    labels, scores = _separable(200)
    tiny = np.zeros(200, dtype=bool)
    tiny[:3] = True
    large = np.ones(200, dtype=bool)
    segment = Segment(
        predicates=(
            Predicate(
                column=schema_name("country"),
                op=Operator.EQ,
                values=(data_value("PT", acquisition=Acquisition.SEGMENT_PREDICATE),),
            ),
        ),
        population=200,
    )
    score = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=scores,
        slices=SegmentSlices(masks={"tiny": tiny, "large": large}, segments={"large": segment}),
        seed=SEED,
        options=OPTIONS,
    )
    assert len(score.segment_slices) == 1
    assert score.suppressed_slices == 1
    only = score.segment_slices[0]
    assert only.population == 200
    assert only.value.sensitivity is Sensitivity.DERIVED_STATISTIC


def test_the_objective_is_within_two_auc_points_of_the_baseline() -> None:
    labels, scores = _separable()
    score = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=scores,
        seed=SEED,
        options=OPTIONS,
        baseline=BaselineComparison(
            metrics={"auc": 0.9}, note="a hand-built LightGBM, not a mature in-house system"
        ),
    )
    assert score.auc_gap is not None
    assert score.within_objective is (score.auc_gap >= -AUC_OBJECTIVE_MARGIN)
    assert "mature in-house system" in score.baseline_note


def test_without_a_baseline_the_objective_is_unanswerable_not_passed() -> None:
    labels, scores = _separable()
    score = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=scores,
        seed=SEED,
        options=OPTIONS,
    )
    assert score.auc_gap is None
    assert score.within_objective is None


def test_the_evaluation_report_carries_the_interval_bounds_beside_the_points() -> None:
    labels, scores = _separable()
    score = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=scores,
        probabilities=scores,
        event_times=_months(len(labels)),
        seed=SEED,
        options=ScoringOptions(small_cell_threshold=10, k_values=(10,), resamples=50),
        baseline=BaselineComparison(metrics={"auc": 0.9}, note="hand-built"),
    )
    report = to_evaluation_report(
        score,
        artifact_id=ArtifactId("art_test"),
        report_id="rep_test",
        as_of=_dt.datetime(2024, 6, 1, tzinfo=_dt.UTC),
    )
    assert report.primary_metric == "auc"
    assert report.metrics["auc"] == score.metrics["auc"].point
    assert report.metrics["auc_ci_low"] == score.metrics["auc"].low
    assert report.metrics["auc_ci_high"] == score.metrics["auc"].high
    assert report.baseline_metrics == {"auc": 0.9}
    assert report.baseline_note == "hand-built"
    assert report.calibration_error == score.calibration_error
    assert any(key.startswith("auc__2024-") for key in report.metrics)


def test_uncalibrated_scores_produce_no_calibration_claim() -> None:
    """Brier and ECE on raw scores would be numbers with no meaning, so they are NaN."""
    labels, _ = _separable(100)
    raw = [float(index) for index in range(100)]
    score = score_predictions(
        dataset="golden-classification",
        model_label="test",
        labels=labels,
        scores=raw,
        seed=SEED,
        options=ScoringOptions(k_values=(10,), resamples=40),
    )
    assert np.isnan(score.calibration_error)
    assert np.isnan(score.brier_score)
