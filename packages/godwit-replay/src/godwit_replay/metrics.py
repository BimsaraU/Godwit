"""The metrics, implemented here rather than imported.

Four reasons this is not a scikit-learn call:

1. **Tie handling is a correctness question, not a detail.** A model that assigns the same
   score to a fraud and a non-fraud should get 0.5 credit for that pair, not 1 and not 0.
   The Mann-Whitney form below uses average ranks, which is the only tie rule that keeps
   ``auc(y, s) + auc(y, -s) == 1``. A property test pins that identity.
2. **The harness grades other packages.** A scorer that shares a dependency with the thing
   it scores can share a bug with it.
3. **Determinism.** Every resample draws from an explicitly seeded generator. There is no
   global RNG anywhere in this module.
4. It is about two hundred lines of numpy, which is cheaper than a dependency.

Nothing here is tainted, because nothing here is a value: these functions take arrays of
labels and scores that already live in the data plane and return aggregates. Wrapping the
results is the caller's job -- see :mod:`godwit_replay.prediction`.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Final

import numpy as np
from godwit_contracts.common import GodwitModel, Probability
from numpy.typing import NDArray
from pydantic import Field

__all__ = [
    "DEFAULT_RESAMPLES",
    "Interval",
    "MetricFn",
    "average_precision",
    "bootstrap_ci",
    "brier",
    "expected_calibration_error",
    "positive_rate",
    "precision_at_k",
    "recall_at_k",
    "roc_auc",
]

DEFAULT_RESAMPLES: Final[int] = 1000
"""Bootstrap resamples. A thousand is enough for a two-decimal interval and cheap."""

_MIN_CALIBRATION_BINS: Final[int] = 2
"""One bin cannot show miscalibration: it is the overall positive rate with extra steps."""

type MetricFn = Callable[[NDArray[np.int_], NDArray[np.float64]], float]


class Interval(GodwitModel):
    """A point estimate with a bootstrap confidence interval.

    ``low`` and ``high`` are percentiles of the resampled statistic, not a normal
    approximation: AUC near 1.0 is badly skewed and a symmetric interval there is a
    fiction. ``resamples`` and ``seed`` are recorded so the interval can be rebuilt.
    """

    point: float
    low: float
    high: float
    level: Probability = 0.95
    resamples: int = Field(default=DEFAULT_RESAMPLES, ge=1)
    seed: int = 0

    @property
    def width(self) -> float:
        """How much the estimate could not pin down."""
        return self.high - self.low


def _as_arrays(
    labels: Sequence[int] | NDArray[np.int_], scores: Sequence[float] | NDArray[np.float64]
) -> tuple[NDArray[np.int_], NDArray[np.float64]]:
    y = np.asarray(labels, dtype=np.int64)
    s = np.asarray(scores, dtype=np.float64)
    if y.shape != s.shape:
        raise ValueError(f"labels and scores disagree in shape: {y.shape} vs {s.shape}")
    if y.ndim != 1:
        raise ValueError("labels and scores must be one-dimensional")
    if not np.all(np.isin(y, (0, 1))):
        raise ValueError("labels must be 0 or 1; this module scores binary problems only")
    if not np.all(np.isfinite(s)):
        raise ValueError("scores contain NaN or infinity")
    return y, s


def roc_auc(
    labels: Sequence[int] | NDArray[np.int_], scores: Sequence[float] | NDArray[np.float64]
) -> float:
    """Area under the ROC curve, by average-rank Mann-Whitney.

    Returns ``nan`` when one class is absent: an AUC over a single class is undefined and
    returning 0.5 there would silently turn "cannot say" into "no better than chance".
    """
    y, s = _as_arrays(labels, scores)
    positives = int(y.sum())
    negatives = int(y.size - positives)
    if positives == 0 or negatives == 0:
        return float("nan")
    order = np.argsort(s, kind="stable")
    ranks = np.empty(s.size, dtype=np.float64)
    sorted_scores = s[order]
    index = 0
    while index < s.size:
        stop = index
        while stop + 1 < s.size and sorted_scores[stop + 1] == sorted_scores[index]:
            stop += 1
        ranks[order[index : stop + 1]] = 0.5 * (index + stop) + 1.0
        index = stop + 1
    rank_sum = float(ranks[y == 1].sum())
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def average_precision(
    labels: Sequence[int] | NDArray[np.int_], scores: Sequence[float] | NDArray[np.float64]
) -> float:
    """PR-AUC as average precision: the step-wise sum, not a trapezoid.

    Trapezoidal interpolation of a precision-recall curve is optimistic, and on a 0.3%
    positive rate the optimism is larger than the differences we care about.
    """
    y, s = _as_arrays(labels, scores)
    positives = int(y.sum())
    if positives == 0:
        return float("nan")
    order = np.argsort(-s, kind="stable")
    hits = y[order]
    cumulative = np.cumsum(hits)
    precision = cumulative / np.arange(1, hits.size + 1, dtype=np.float64)
    return float((precision * hits).sum() / positives)


def precision_at_k(
    labels: Sequence[int] | NDArray[np.int_],
    scores: Sequence[float] | NDArray[np.float64],
    k: int,
) -> float:
    """Precision among the top ``k`` scores. Ties broken by original order, stably.

    ``k`` larger than the population is clamped and reported over what exists rather than
    padded with zeros: precision@100 on 50 rows is precision over 50 rows, and pretending
    otherwise halves the number.
    """
    if k <= 0:
        raise ValueError("k must be positive")
    y, s = _as_arrays(labels, scores)
    taken = min(k, y.size)
    if taken == 0:
        return float("nan")
    order = np.argsort(-s, kind="stable")[:taken]
    return float(y[order].sum() / taken)


def recall_at_k(
    labels: Sequence[int] | NDArray[np.int_],
    scores: Sequence[float] | NDArray[np.float64],
    k: int,
) -> float:
    """Share of all positives caught in the top ``k``."""
    if k <= 0:
        raise ValueError("k must be positive")
    y, s = _as_arrays(labels, scores)
    positives = int(y.sum())
    if positives == 0:
        return float("nan")
    order = np.argsort(-s, kind="stable")[: min(k, y.size)]
    return float(y[order].sum() / positives)


def brier(
    labels: Sequence[int] | NDArray[np.int_],
    probabilities: Sequence[float] | NDArray[np.float64],
) -> float:
    """Mean squared error of a probability forecast. Lower is better; 0.25 is a coin."""
    y, p = _as_arrays(labels, probabilities)
    if np.any((p < 0.0) | (p > 1.0)):
        raise ValueError("Brier score needs probabilities in [0, 1], not raw scores")
    return float(np.mean((p - y) ** 2))


def expected_calibration_error(
    labels: Sequence[int] | NDArray[np.int_],
    probabilities: Sequence[float] | NDArray[np.float64],
    *,
    bins: int = 10,
) -> float:
    """Population-weighted mean gap between predicted and observed frequency.

    Equal-width bins, stated rather than equal-mass, because equal-mass bins on a skewed
    score distribution hide miscalibration in the tail that is exactly where an alerting
    threshold sits. Empty bins contribute nothing.
    """
    if bins < _MIN_CALIBRATION_BINS:
        raise ValueError("calibration needs at least two bins")
    y, p = _as_arrays(labels, probabilities)
    if np.any((p < 0.0) | (p > 1.0)):
        raise ValueError("calibration error needs probabilities in [0, 1]")
    edges = np.linspace(0.0, 1.0, bins + 1)
    membership = np.clip(np.digitize(p, edges[1:-1], right=False), 0, bins - 1)
    total = 0.0
    for index in range(bins):
        mask = membership == index
        count = int(mask.sum())
        if count == 0:
            continue
        total += count * abs(float(p[mask].mean()) - float(y[mask].mean()))
    return total / y.size


def positive_rate(labels: Sequence[int] | NDArray[np.int_]) -> float:
    """Share of positives. On IEEE-CIS this is about 3.5%; on PaySim about 0.13%."""
    y = np.asarray(labels, dtype=np.int64)
    if y.size == 0:
        return float("nan")
    return float(y.mean())


def bootstrap_ci(
    metric: MetricFn,
    labels: Sequence[int] | NDArray[np.int_],
    scores: Sequence[float] | NDArray[np.float64],
    *,
    seed: int,
    resamples: int = DEFAULT_RESAMPLES,
    level: float = 0.95,
) -> Interval:
    """Percentile bootstrap interval for one metric.

    Resamples with replacement from an explicitly seeded generator, so the interval is a
    function of (data, metric, seed, resamples) and of nothing else. Resamples in which the
    metric is undefined -- one class absent -- are dropped and counted, which is honest: on
    a very rare positive class the interval is built from fewer draws than requested and
    saying so is better than substituting a number.
    """
    if not 0.0 < level < 1.0:
        raise ValueError("level must be strictly between 0 and 1")
    y, s = _as_arrays(labels, scores)
    point = metric(y, s)
    generator = np.random.default_rng(seed)
    drawn: list[float] = []
    for _ in range(resamples):
        picks = generator.integers(0, y.size, size=y.size)
        value = metric(y[picks], s[picks])
        if np.isfinite(value):
            drawn.append(float(value))
    if not drawn:
        return Interval(
            point=point,
            low=float("nan"),
            high=float("nan"),
            level=level,
            resamples=resamples,
            seed=seed,
        )
    tail = (1.0 - level) / 2.0
    low, high = np.quantile(np.asarray(drawn), [tail, 1.0 - tail])
    return Interval(
        point=point,
        low=float(low),
        high=float(high),
        level=level,
        resamples=len(drawn),
        seed=seed,
    )
