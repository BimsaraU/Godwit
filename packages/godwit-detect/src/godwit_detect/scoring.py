"""Unsupervised scoring: ECOD and COPOD over sketch feature vectors, and the matrix profile.

ECOD AND COPOD
--------------
Both score each row of a matrix -- here, one row per sketch, as the fixed-length vector
``godwit_sketch.extract_features`` produces -- by how deep in the tails of the other
rows it sits, one feature at a time: ``-log`` of the empirical left- and right-tail
probability, summed over features. They differ only in how the two tails are combined
(ECOD: the largest of the left-sum, right-sum and skewness-chosen sum; COPOD: per
feature, the larger of the skewness-chosen tail and the two-tail average). Both are
deterministic, parameter-free and ``O(n log n)`` per feature, and the per-feature terms
*are* the attribution, which the evidence panel needs anyway.

Isolation Forest is deliberately absent. It is not mergeable, not incremental, and its
randomness fights invariant 7.

Sketch-metadata slots (error bounds, value-bearing flags, retained-item counts) are not
scored: they describe the sketch, not the data. Missing slots (NaN) contribute nothing.

**p-value.** A conformal one: ``p_i = #{j : s_j >= s_i} / n``. The scores are a
symmetric function of all rows, so under exchangeability -- no row special -- ``p_i`` is
super-uniform and ``P(p_i <= alpha) <= alpha`` exactly, whatever the dependence between
features. The price is resolution: the smallest possible p is ``1/n``, and at
``alpha = 0.05`` about one row in twenty is emitted even when nothing is wrong. That is
the nominal false-positive rate, stated honestly; L5's FDR control is what turns it into
something a human should look at.

MATRIX PROFILE
--------------
For a univariate series -- one feature slot of one probe over time -- the z-normalised
distance from every length-``m`` subsequence to its nearest non-trivial neighbour. A
*discord* is a subsequence far from everything else in the series' own history; a
*motif* is a subsequence unusually close to an earlier one, a shape that recurred. By
default only subsequences overlapping the most recent ``m`` windows are reported: older
ones were someone else's news. Run it on a deseasonalised series (A12's residuals) --
on a raw weekly series the week itself is the motif, every time.

No p-value. Discords are chosen by maximising over overlapping subsequences, which
breaks exchangeability, and the standard nulls need surrogate series drawn at random --
which a pure detector cannot do. Effect sizes are ratios to the median nearest-neighbour
distance, and the emission thresholds are calibrated on white noise in the package
benchmarks, where the measured emission rate is recorded.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import ClassVar, Final

import numpy as np
import numpy.typing as npt
from godwit_contracts.common import GodwitModel, Instant, SnapshotId
from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.sketch import SketchEnvelope
from godwit_contracts.taint import derived_statistic
from godwit_sketch import FEATURE_LAYOUT, decode_envelope, extract_features, feature_index
from pydantic import Field

from godwit_detect.base import DetectorBase, Settings
from godwit_detect.evidence import (
    Attribution,
    DetectionResult,
    Direction,
    Finding,
    Measure,
    Refusal,
    RefusalReason,
    Window,
    measure,
)
from godwit_detect.series import ProbeContext, SketchSeries

__all__ = [
    "CopodScorer",
    "EcodScorer",
    "FeatureRow",
    "MatrixProfile",
    "MatrixProfileSettings",
    "ScoringSettings",
    "matrix_profile",
    "tail_scores",
]

type _Array = npt.NDArray[np.float64]

NOT_SCORED: Final[frozenset[str]] = frozenset(
    {
        "error_epsilon",
        "error_delta",
        "value_bearing",
        "merge_is_exact",
        "distinct_retained",
        "quantile_retained",
        "quantile_levels",
    }
)
"""Slots that describe the sketch rather than the data."""

SCORED_SLOTS: Final[tuple[str, ...]] = tuple(
    s.name for s in FEATURE_LAYOUT if s.name not in NOT_SCORED
)
_TOP_ATTRIBUTIONS: Final[int] = 3
_MIN_VALUES: Final[int] = 2
_PROFILE_FLOOR: Final[float] = 0.01


class FeatureRow(GodwitModel):
    """One sketch to score, with what it measured."""

    context: ProbeContext
    snapshot_id: SnapshotId
    at: Instant
    envelope: SketchEnvelope


class ScoringSettings(Settings):
    """Settings for :class:`EcodScorer` and :class:`CopodScorer`."""

    min_rows: int = Field(default=20, ge=2)


def _tails(matrix: _Array) -> tuple[_Array, _Array, _Array]:
    """``-log`` left and right tail probabilities per cell, and each column's skewness."""
    rows, cols = matrix.shape
    left = np.zeros((rows, cols))
    right = np.zeros((rows, cols))
    skew = np.zeros(cols)
    for j in range(cols):
        column = matrix[:, j]
        finite = np.isfinite(column)
        values = np.sort(column[finite])
        m = values.size
        if m < _MIN_VALUES or values[0] == values[-1]:
            continue
        x = column[finite]
        left[finite, j] = -np.log(np.searchsorted(values, x, side="right") / m)
        right[finite, j] = -np.log((m - np.searchsorted(values, x, side="left")) / m)
        centred = values - values.mean()
        sd = math.sqrt(float(np.mean(centred**2)))
        skew[j] = float(np.mean(centred**3)) / sd**3 if sd > 0 else 0.0
    return left, right, skew


def tail_scores(matrix: _Array, *, method: str) -> tuple[_Array, _Array, _Array]:
    """Scores, per-cell contributions and per-cell side (-1 left, +1 right, 0 both).

    ``method`` is ``"ecod"`` or ``"copod"``.
    """
    left, right, skew = _tails(matrix)
    by_skew = np.where(skew < 0, left, right)
    skew_side = np.where(skew < 0, -1.0, 1.0) * np.ones_like(left)
    if method == "ecod":
        sums = np.stack([left.sum(axis=1), right.sum(axis=1), by_skew.sum(axis=1)])
        choice = np.argmax(sums, axis=0)
        contributions = np.where(
            (choice == 0)[:, None], left, np.where((choice == 1)[:, None], right, by_skew)
        )
        side = np.where(
            (choice == 0)[:, None], -1.0, np.where((choice == 1)[:, None], 1.0, skew_side)
        )
        return sums.max(axis=0), contributions, side
    if method == "copod":
        average = (left + right) / 2.0
        contributions = np.maximum(by_skew, average)
        side = np.where(by_skew >= average, skew_side, 0.0)
        return contributions.sum(axis=1), contributions, side
    raise ValueError(f"unknown tail-scoring method {method!r}")


class _TailScorer(DetectorBase[ScoringSettings]):
    KIND: ClassVar[EvidenceKind] = EvidenceKind.DISTRIBUTION_SHIFT
    METHOD: ClassVar[str]

    @classmethod
    def default_settings(cls) -> ScoringSettings:
        """Alpha 0.05, 100 rows per sketch, twenty sketches."""
        return ScoringSettings()

    def run(self, rows: Sequence[FeatureRow]) -> DetectionResult:
        """Score every row against the others and emit the conformally significant ones."""
        kept: list[FeatureRow] = []
        refusals: list[Refusal] = []
        for row in rows:
            if decode_envelope(row.envelope).population < self.settings.min_support:
                refusals.append(
                    self._refusal(RefusalReason.THIN_SKETCH, (row.context.sketch_name,))
                )
            else:
                kept.append(row)
        if len(kept) < self.settings.min_rows:
            refusals.append(self._refusal(RefusalReason.TOO_FEW_PEERS, (), f"rows:{len(kept)}"))
            return self._result(refusals=refusals)
        indices = [feature_index(name) for name in SCORED_SLOTS]
        vectors = [extract_features(row.envelope) for row in kept]
        matrix = np.array([[vector[i] for i in indices] for vector in vectors], dtype=np.float64)
        scores, contributions, side = tail_scores(matrix, method=self.METHOD)
        n = len(kept)
        findings: list[Finding] = []
        for i, row in enumerate(kept):
            p_value = float(np.count_nonzero(scores >= scores[i])) / n
            if p_value > self.settings.alpha:
                continue
            findings.append(
                self._finding(row, float(scores[i]), p_value, contributions[i], side[i])
            )
        return self._result(findings, tests=n, refusals=refusals)

    def _finding(
        self, row: FeatureRow, score: float, p_value: float, contributions: _Array, side: _Array
    ) -> Finding:
        order = sorted(
            range(len(SCORED_SLOTS)), key=lambda j: (-float(contributions[j]), SCORED_SLOTS[j])
        )
        top = [j for j in order[:_TOP_ATTRIBUTIONS] if contributions[j] > 0]
        lead = side[top[0]] if top else 0.0
        direction = Direction.UP if lead > 0 else Direction.DOWN if lead < 0 else Direction.CHANGED
        context = row.context
        return Finding(
            detector=self.NAME,
            detector_version=self.VERSION,
            settings_digest=self.settings.digest(),
            method=self.METHOD,
            kind=self.KIND,
            probe_key=context.probe_key,
            source_id=context.source_id,
            sketch_names=(context.sketch_name,),
            segment=context.segment,
            columns=context.columns,
            window=Window(snapshot_id=row.snapshot_id, at=row.at, baseline_policy="cross_section"),
            direction=direction,
            statistic=measure("tail_score", score, "nats"),
            effect=measure("tail_improbability", score, "nats"),
            p_value=derived_statistic(p_value),
            p_value_note="conformal rank p-value over the rows scored together; valid under "
            "exchangeability, smallest possible value 1/rows",
            population=decode_envelope(row.envelope).population,
            shape=tuple(
                measure(f"tail_{SCORED_SLOTS[j]}", float(contributions[j]), "nats") for j in top
            ),
            attribution=tuple(
                Attribution(
                    feature=SCORED_SLOTS[j], contribution=derived_statistic(float(contributions[j]))
                )
                for j in top
            ),
            score=score,
        )


class EcodScorer(_TailScorer):
    """Empirical-CDF outlier detection (Li et al., 2022) over sketch feature vectors."""

    NAME: ClassVar[str] = "ecod"
    VERSION: ClassVar[str] = "1.0.0"
    SUMMARY: ClassVar[str] = "ECOD tail scores over feature vectors, conformal p-values"
    METHOD: ClassVar[str] = "ecod"


class CopodScorer(_TailScorer):
    """Copula-based outlier detection (Li et al., 2020) over sketch feature vectors."""

    NAME: ClassVar[str] = "copod"
    VERSION: ClassVar[str] = "1.0.0"
    SUMMARY: ClassVar[str] = "COPOD tail scores over feature vectors, conformal p-values"
    METHOD: ClassVar[str] = "copod"


def matrix_profile(values: Sequence[float], window: int) -> _Array:
    """Nearest-neighbour z-normalised distance of every subsequence. NaN where undefined.

    Subsequences containing a non-finite value have no profile. Flat subsequences are
    z-normalised to zero, so two flat stretches are identical and a flat stretch is at
    ``sqrt(2 * window)`` from anything that moves. The trivial-match exclusion zone is
    ``ceil(window / 4)`` either side, as in the SCRIMP/STOMP literature.
    """
    x = np.asarray(values, dtype=np.float64)
    count = x.size - window + 1
    if count < _MIN_VALUES:
        return np.full(max(count, 0), np.nan)
    subsequences = np.lib.stride_tricks.sliding_window_view(x, window)
    valid = np.all(np.isfinite(subsequences), axis=1)
    safe = np.where(valid[:, None], subsequences, 0.0)
    mean = safe.mean(axis=1, keepdims=True)
    sd = safe.std(axis=1, keepdims=True)
    flat = sd[:, 0] <= 1e-12 * np.maximum(1.0, np.abs(mean[:, 0]))
    z = np.where(flat[:, None], 0.0, (safe - mean) / np.where(sd > 0, sd, 1.0))
    correlation = (z @ z.T) / window
    distance = np.sqrt(np.maximum(0.0, 2.0 * window * (1.0 - correlation)))
    distance[np.outer(flat, flat)] = 0.0
    zone = math.ceil(window / 4)
    index = np.arange(count)
    distance[np.abs(index[:, None] - index[None, :]) < zone] = np.inf
    distance[~valid, :] = np.inf
    distance[:, ~valid] = np.inf
    profile = distance.min(axis=1)
    profile[~valid | ~np.isfinite(profile)] = np.nan
    return np.asarray(profile, dtype=np.float64)


class MatrixProfileSettings(Settings):
    """Settings for :class:`MatrixProfile`."""

    feature: str = "population"
    """Which ``godwit_sketch.FEATURE_LAYOUT`` slot to profile."""
    window: int = Field(default=8, ge=3)
    discord_ratio: float = Field(default=1.5, gt=1.0)
    """Emit a discord at this many times the median nearest-neighbour distance."""
    motif_ratio: float = Field(default=0.35, gt=0.0, lt=1.0)
    """Emit a motif at or below this fraction of the median nearest-neighbour distance."""
    recent_only: bool = True


class MatrixProfile(DetectorBase[MatrixProfileSettings]):
    """Discords and motifs in one feature slot of a sketch series."""

    NAME: ClassVar[str] = "matrix_profile"
    VERSION: ClassVar[str] = "1.0.0"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.RATE_CHANGE
    SUMMARY: ClassVar[str] = "Matrix-profile discords and motifs over a univariate feature series"

    @classmethod
    def default_settings(cls) -> MatrixProfileSettings:
        """Window 8, population slot, recent discords only."""
        return MatrixProfileSettings()

    def run(self, series: SketchSeries) -> DetectionResult:
        """Profile the series; report a recent discord and the strongest motif."""
        m = self.settings.window
        name = (series.context.sketch_name,)
        slot = feature_index(self.settings.feature)
        values = [
            extract_features(p.envelope)[slot] if p.envelope is not None else math.nan
            for p in series.points
        ]
        if sum(1 for v in values if math.isfinite(v)) < 4 * m:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_BASELINE, name)])
        profile = matrix_profile(values, m)
        finite = profile[np.isfinite(profile)]
        # A perfectly periodic series has a median neighbour distance of zero, which
        # would make every ratio infinite. Floor it at 1% of the largest possible
        # z-normalised distance, sqrt(2m).
        scale = max(
            float(np.median(finite)) if finite.size else 0.0, _PROFILE_FLOOR * math.sqrt(2 * m)
        )
        findings: list[Finding] = []
        count = profile.size
        start = count - m if self.settings.recent_only else 0
        candidates = [i for i in range(max(start, 0), count) if math.isfinite(profile[i])]
        if candidates:
            discord = max(candidates, key=lambda i: (float(profile[i]), -i))
            ratio = float(profile[discord]) / scale
            if ratio >= self.settings.discord_ratio:
                findings.append(
                    self._finding(series, values, discord, ratio, method="discord", count=count)
                )
            moving = [i for i in candidates if max(values[i : i + m]) > min(values[i : i + m])]
            if moving:
                motif = min(moving, key=lambda i: (float(profile[i]), i))
                ratio = float(profile[motif]) / scale
                if ratio <= self.settings.motif_ratio:
                    findings.append(
                        self._finding(series, values, motif, ratio, method="motif", count=count)
                    )
        return self._result(findings, tests=2)

    def _finding(
        self,
        series: SketchSeries,
        values: Sequence[float],
        start: int,
        ratio: float,
        *,
        method: str,
        count: int,
    ) -> Finding:
        m = self.settings.window
        context = series.context
        finite = [v for v in values if math.isfinite(v)]
        stretch = [v for v in values[start : start + m] if math.isfinite(v)]
        lifted = (sum(stretch) / len(stretch)) - (sum(finite) / len(finite)) if stretch else 0.0
        if method == "motif":
            direction = Direction.APPEARED
            score = 1.0 / max(ratio, 1e-9)
        else:
            direction = Direction.UP if lifted > 0 else Direction.DOWN
            score = ratio
        shape: tuple[Measure, ...] = (
            measure("offset_from_latest", count - 1 - start, "windows"),
            measure("subsequence_length", m, "windows"),
        )
        current = series.current
        return Finding(
            detector=self.NAME,
            detector_version=self.VERSION,
            settings_digest=self.settings.digest(),
            method=method,
            kind=self.KIND,
            probe_key=context.probe_key,
            source_id=context.source_id,
            sketch_names=(context.sketch_name,),
            segment=context.segment,
            columns=context.columns,
            window=Window(
                snapshot_id=current.snapshot_id,
                at=current.at,
                baseline_policy=f"history(points={len(series.points)})",
                baseline_snapshot_ids=(),
                baseline_from=series.points[0].at,
                baseline_to=current.at,
            ),
            direction=direction,
            statistic=measure("profile_ratio", ratio, "ratio"),
            effect=measure("distance_to_median_neighbour", ratio, "ratio"),
            p_value=None,
            p_value_note="no valid null without random surrogate series; emission threshold "
            "calibrated on white noise, measured rate in the package docs",
            shape=shape,
            attribution=(
                Attribution(feature=self.settings.feature, contribution=derived_statistic(ratio)),
            ),
            score=score,
        )
