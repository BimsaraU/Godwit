"""Prediction scoring: metrics with intervals, sliced by time and by segment.

**This module runs in the DATA PLANE.** It takes labels and scores, which are row-derived.
What it returns is aggregates, with two exceptions that are deliberate and typed:

* ``SliceMetric`` carries a ``Segment``, and a segment predicate is a row value. An
  ``EvaluationReport`` built by :func:`to_evaluation_report` therefore carries DATA_VALUE and
  **must pass godwit-guard before a human sees it.** It is a contract object for
  in-perimeter use, not a replay output artifact.
* :class:`TimeSlice` exists precisely so that replay's own reports do not have to carry a
  ``Segment`` for something that is not a row value. A calendar month boundary is our bucket
  edge, not a customer's value, and typing it DATA_VALUE to satisfy ``Predicate`` would put a
  false positive in every egress audit the harness runs on itself.

THE 0.02 AUC OBJECTIVE
----------------------
``auc_gap`` is the model's AUC minus the recorded expert baseline's. ``within_objective`` is
``auc_gap >= -0.02``. Both are computed against a baseline this package built itself, so A13
cannot grade its own work -- and the baseline's own record is what the comparison names.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable, Mapping, Sequence
from typing import Final

import numpy as np
from godwit_contracts.common import ArtifactId, GodwitModel, Instant, NonNegInt, Probability
from godwit_contracts.segment import Segment
from godwit_contracts.taint import Acquisition, derived_statistic
from godwit_contracts.training import EvaluationReport, SliceMetric
from numpy.typing import NDArray
from pydantic import Field

from godwit_replay.metrics import (
    DEFAULT_RESAMPLES,
    Interval,
    MetricFn,
    average_precision,
    bootstrap_ci,
    brier,
    expected_calibration_error,
    positive_rate,
    precision_at_k,
    recall_at_k,
    roc_auc,
)

__all__ = [
    "AUC_OBJECTIVE_MARGIN",
    "PREDICTION_K_VALUES",
    "BaselineComparison",
    "PredictionScore",
    "ScoringOptions",
    "SegmentSlices",
    "TimeSlice",
    "score_predictions",
    "to_evaluation_report",
]

AUC_OBJECTIVE_MARGIN: Final[float] = 0.02
"""How far below the expert baseline a model may land and still pass. From the brief."""

PREDICTION_K_VALUES: Final[tuple[int, ...]] = (50, 100, 500, 1000)
"""Review capacities for prediction. Larger than discovery's: a scoring queue is not a
human queue, and precision@50 on a million transactions is a different question."""


class TimeSlice(GodwitModel):
    """One metric over one time bucket. No segment, because a month is not a row value."""

    period_key: str
    metric: str
    value: float
    population: NonNegInt
    positive_rate: Probability | None = None


class ScoringOptions(GodwitModel):
    """The knobs, bundled so that adding one does not lengthen a call signature.

    Every field here changes a reported number, so the whole object is recorded on the score
    it produced rather than remembered by whoever ran it.
    """

    small_cell_threshold: NonNegInt = 20
    k_values: tuple[int, ...] = PREDICTION_K_VALUES
    resamples: int = Field(default=DEFAULT_RESAMPLES, ge=1)
    calibration_bins: int = Field(default=10, ge=2)


class SegmentSlices(GodwitModel):
    """Caller-supplied segment slices: the masks, and the segments they correspond to.

    Kept together because a mask without its segment is a metric nobody can attribute, and a
    segment without its mask is a claim with no measurement behind it.
    """

    model_config = GodwitModel.model_config | {"arbitrary_types_allowed": True}

    masks: Mapping[str, NDArray[np.bool_]] = Field(default_factory=dict)
    segments: Mapping[str, Segment] = Field(default_factory=dict)


class BaselineComparison(GodwitModel):
    """The expert baseline a score is measured against, and what that baseline actually was.

    ``note`` is not decoration. "Parity with a competent data scientist working for a week"
    and "parity with a mature in-house system" are different claims, and only the first is
    ours.
    """

    metrics: Mapping[str, float] = Field(default_factory=dict)
    note: str = ""


class PredictionScore(GodwitModel):
    """How a model did, with everything needed to distrust the number."""

    dataset: str
    model_label: str
    population: NonNegInt
    positives: NonNegInt
    positive_rate: Probability

    metrics: Mapping[str, Interval] = Field(
        description="Point estimate plus percentile bootstrap interval, per metric."
    )
    calibration_error: float = Field(description="Expected calibration error, equal-width bins.")
    brier_score: float

    time_slices: tuple[TimeSlice, ...] = ()
    segment_slices: tuple[SliceMetric, ...] = Field(
        default=(),
        description="Slices over caller-supplied segments. These carry DATA_VALUE in their "
        "predicates and must pass the gate before a human sees them.",
    )
    suppressed_slices: NonNegInt = Field(
        default=0,
        description="Slices dropped for being below the small-cell threshold. Reported as a "
        "count so a reader knows the table is incomplete, not that the model was even.",
    )

    baseline_metrics: Mapping[str, float] = Field(default_factory=dict)
    baseline_note: str = ""
    auc_gap: float | None = Field(
        default=None, description="This model's AUC minus the expert baseline's."
    )

    @property
    def within_objective(self) -> bool | None:
        """True when the model is within 0.02 AUC of the expert baseline."""
        if self.auc_gap is None:
            return None
        return self.auc_gap >= -AUC_OBJECTIVE_MARGIN

    @property
    def primary(self) -> float:
        """The AUC point estimate."""
        return self.metrics["auc"].point


def _at_k(
    metric: Callable[[NDArray[np.int_], NDArray[np.float64], int], float], k: int
) -> MetricFn:
    """Bind ``k`` into a top-k metric. A named closure, because a lambda in a loop is the
    classic late-binding bug and mypy cannot infer one anyway."""

    def _bound(labels: NDArray[np.int_], scores: NDArray[np.float64]) -> float:
        return metric(labels, scores, k)

    return _bound


def _period_keys(event_times: Sequence[Instant] | NDArray[np.datetime64]) -> NDArray[np.str_]:
    """Bucket instants into calendar months, as ``YYYY-MM`` strings.

    numpy has no timezone-aware datetime, so the offset is normalised to UTC and dropped
    explicitly rather than letting numpy warn and discard it silently. Every instant in Godwit
    is UTC by construction -- ``require_utc`` on the contract side -- so nothing is lost.
    """
    if isinstance(event_times, np.ndarray):
        stamps = event_times.astype("datetime64[M]")
    else:
        stamps = np.asarray(
            [moment.astimezone(_dt.UTC).replace(tzinfo=None) for moment in event_times],
            dtype="datetime64[M]",
        )
    return stamps.astype(str)


def score_predictions(
    *,
    dataset: str,
    model_label: str,
    labels: Sequence[int] | NDArray[np.int_],
    scores: Sequence[float] | NDArray[np.float64],
    probabilities: Sequence[float] | NDArray[np.float64] | None = None,
    event_times: Sequence[Instant] | NDArray[np.datetime64] | None = None,
    slices: SegmentSlices | None = None,
    seed: int,
    options: ScoringOptions | None = None,
    baseline: BaselineComparison | None = None,
) -> PredictionScore:
    """Score one model's output on a held-out half.

    ``scores`` may be uncalibrated; ``probabilities`` must be in [0, 1] and defaults to
    ``scores`` when they already are. Calibration and Brier are only meaningful on
    probabilities, so they are computed on that array and not on the ranking one.

    ``slices`` supplies segment masks and the segments they correspond to. Slices below
    ``options.small_cell_threshold`` are omitted and counted -- never reported with a wide
    interval, which is the mistake that re-identifies a twelve-person team.
    """
    settings = options if options is not None else ScoringOptions()
    comparison = baseline if baseline is not None else BaselineComparison()
    small_cell_threshold = int(settings.small_cell_threshold)
    k_values = settings.k_values
    resamples = settings.resamples
    y = np.asarray(labels, dtype=np.int64)
    s = np.asarray(scores, dtype=np.float64)
    p = s if probabilities is None else np.asarray(probabilities, dtype=np.float64)

    metrics: dict[str, Interval] = {
        "auc": bootstrap_ci(roc_auc, y, s, seed=seed, resamples=resamples),
        "pr_auc": bootstrap_ci(average_precision, y, s, seed=seed + 1, resamples=resamples),
    }
    for offset, k in enumerate(k_values):
        metrics[f"precision_at_{k}"] = bootstrap_ci(
            _at_k(precision_at_k, k), y, s, seed=seed + 2 + offset, resamples=resamples
        )
        metrics[f"recall_at_{k}"] = bootstrap_ci(
            _at_k(recall_at_k, k),
            y,
            s,
            seed=seed + 2 + offset + len(k_values),
            resamples=resamples,
        )

    time_slices: list[TimeSlice] = []
    suppressed = 0
    if event_times is not None:
        keys = _period_keys(event_times)
        for key in sorted(set(keys.tolist())):
            mask = keys == key
            count = int(mask.sum())
            if count < small_cell_threshold:
                suppressed += 1
                continue
            sliced_auc = roc_auc(y[mask], s[mask])
            time_slices.append(
                TimeSlice(
                    period_key=str(key),
                    metric="auc",
                    value=sliced_auc,
                    population=count,
                    positive_rate=float(y[mask].mean()),
                )
            )

    segment_slices: list[SliceMetric] = []
    if slices is not None:
        objects = slices.segments
        for label in sorted(slices.masks):
            mask = np.asarray(slices.masks[label], dtype=bool)
            count = int(mask.sum())
            if count < small_cell_threshold:
                suppressed += 1
                continue
            segment_slices.append(
                SliceMetric(
                    segment=objects.get(label, Segment(population=count)),
                    metric="auc",
                    value=derived_statistic(
                        roc_auc(y[mask], s[mask]),
                        acquisition=Acquisition.COMPUTED_STATISTIC,
                        population=count,
                    ),
                    population=count,
                )
            )

    baseline_metrics = dict(comparison.metrics)
    gap = None if "auc" not in baseline_metrics else metrics["auc"].point - baseline_metrics["auc"]

    return PredictionScore(
        dataset=dataset,
        model_label=model_label,
        population=int(y.size),
        positives=int(y.sum()),
        positive_rate=positive_rate(y),
        metrics=metrics,
        calibration_error=(
            expected_calibration_error(y, p, bins=settings.calibration_bins)
            if np.all((p >= 0.0) & (p <= 1.0))
            else float("nan")
        ),
        brier_score=(brier(y, p) if np.all((p >= 0.0) & (p <= 1.0)) else float("nan")),
        time_slices=tuple(time_slices),
        segment_slices=tuple(segment_slices),
        suppressed_slices=suppressed,
        baseline_metrics=baseline_metrics,
        baseline_note=comparison.note,
        auc_gap=gap,
    )


def to_evaluation_report(
    score: PredictionScore,
    *,
    artifact_id: ArtifactId,
    report_id: str,
    as_of: Instant,
) -> EvaluationReport:
    """Render a score into the contract type L7 and L8 consume.

    The contract has no field for a confidence interval, so the point estimates travel in
    ``metrics`` and the interval bounds travel beside them as ``<metric>_ci_low`` and
    ``<metric>_ci_high`` keys. That is a workaround, and it is filed as
    ``docs/change-requests/CR-A4-evaluation-report-has-no-intervals.md`` rather than fixed
    here: a point estimate with no interval is how a 0.93 that could be a 0.89 gets shipped.
    """
    flat: dict[str, float] = {}
    for name, interval in score.metrics.items():
        flat[name] = interval.point
        flat[f"{name}_ci_low"] = interval.low
        flat[f"{name}_ci_high"] = interval.high
    for item in score.time_slices:
        flat[f"{item.metric}__{item.period_key}"] = item.value
    return EvaluationReport(
        report_id=report_id,
        artifact_id=artifact_id,
        primary_metric="auc",
        metrics=flat,
        baseline_metrics=score.baseline_metrics,
        baseline_note=score.baseline_note,
        calibration_error=score.calibration_error,
        slices=score.segment_slices,
        evaluated_as_of=as_of,
        population=score.population,
        positive_rate=score.positive_rate,
    )
