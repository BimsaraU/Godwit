"""Segment divergence: one column behaving differently in one segment than in its peers.

The highest-yield family in practice, because it is where a fraud pattern hides from a
table-level statistic: refunds from one country change shape while the country mix and
the overall amount distribution barely move.

HOW A SEGMENT IS TESTED
-----------------------
The caller supplies a *panel*: the same column measured over comparable segments (every
value of ``country``, every ``country x status`` cell) at one snapshot. Each segment is
compared with the merged sketch of all the *other* segments -- leave-one-out, so a
divergent segment cannot dilute its own reference.

=====================  =========================================  ======================
Sketch                 Statistic                                  Effect size
=====================  =========================================  ======================
Moments                Welch z on the mean                        Cohen's d (pooled sd)
NullRate               two-proportion z                           null-rate difference
Category histogram,    G test of homogeneity                      JS divergence, bits
Count-Min
KLL                    G test over shared bins                    JS divergence, bits
=====================  =========================================  ======================

HETEROGENEITY IS THE WHOLE PROBLEM
----------------------------------
With enough rows every segment differs significantly from every other: Germany and
France really do have different basket sizes. A test that asks only "is this segment
distinguishable from the rest" fires on all of them. So every segment's chi-square is
divided by a dispersion factor: the *median* chi-square over every *pair* of segments,
scaled to its null median (:func:`godwit_detect.stats.dispersion_factor`). A segment is
then divergent only when it is an outlier *relative to how much segments ordinarily
differ* -- the quasi-likelihood answer. Pairs rather than leave-one-out comparisons,
because one outlier sits in every leave-one-out reference but in only ``2/K`` of the
pairs, so the median never sees it once there are five or more segments. Pairwise
differences carry twice the between-segment variance a leave-one-out comparison does,
so the correction errs conservative. It needs ``min_peers`` segments.

The same outlier also contaminates every *other* segment's leave-one-out reference: with
``c3`` far above the rest, every other segment looks low against a reference that
contains it, and at a few thousand rows looks significantly low. So references are
trimmed sequentially, in the manner of a generalised ESD test: the single most
significant segment is removed from every reference, all comparisons are redone, and
this repeats until the most significant remaining segment is not significant -- or until
removing another would leave fewer than ``min_peers``. The final pass is reported.

EMERGING, NOT MERELY DIFFERENT
------------------------------
Given a baseline panel as well, the question becomes whether the divergence is new.
For means and null rates it is a difference-in-differences z test: the segment's gap to
its peers now, minus its gap then, over their combined standard error (each inflated by
its panel's dispersion). For distributions there is no clean interaction test on
sketches, so the current divergence is tested and the finding is emitted only if the
same segment was *not* divergent in the baseline (or did not exist in it). The p-value
reported is then the current one, and ``p_value_note`` says so.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Final, Self

from godwit_contracts.common import GodwitModel, Instant, SnapshotId
from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.segment import Segment
from godwit_contracts.sketch import SketchEnvelope
from godwit_contracts.taint import Tainted, derived_statistic
from godwit_sketch import (
    BaseSketch,
    CategoryHistogram,
    CountMinHeavy,
    GodwitSketchError,
    KllQuantile,
    Moments,
    NullRate,
    decode_envelope,
)
from pydantic import Field, model_validator

from godwit_detect.base import DetectorBase, Settings, merge_all, same_keying
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
from godwit_detect.histograms import (
    OTHER,
    category_counts,
    compare,
    effective_n,
    kll_counts,
    kll_epsilon,
    numeric_edges,
)
from godwit_detect.series import ProbeContext
from godwit_detect.stats import chi2_sf, dispersion_factor, two_sided_normal_p

__all__ = [
    "PanelSnapshot",
    "SegmentDivergence",
    "SegmentDivergenceSettings",
    "SegmentSlice",
]

_TOP_ATTRIBUTIONS: Final[int] = 3


class SegmentSlice(GodwitModel):
    """One segment's sketch of the column under test."""

    context: ProbeContext
    envelope: SketchEnvelope


class PanelSnapshot(GodwitModel):
    """Comparable segments of one column at one snapshot."""

    snapshot_id: SnapshotId
    at: Instant
    slices: tuple[SegmentSlice, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _distinct_segments(self) -> Self:
        keys = [item.context.segment.key for item in self.slices]
        if len(set(keys)) != len(keys):
            raise ValueError("a panel holds each segment once")
        return self


class SegmentDivergenceSettings(Settings):
    """Settings for :class:`SegmentDivergence`."""

    min_support: int = Field(default=30, ge=1)
    min_peers: int = Field(default=4, ge=3)
    bins: int = Field(default=10, ge=2)


@dataclass(slots=True)
class _Stat:
    """One segment's comparison with its peers."""

    chi2: float
    df: int
    method: str
    effect: Measure
    direction: Direction
    difference: float | None = None
    """Mean or rate difference, for the difference-in-differences test."""
    standard_error: float | None = None
    shape: list[Measure] = field(default_factory=list)
    attribution: list[Attribution] = field(default_factory=list)
    population: int = 0
    rest_population: int = 0


def _moments_stat(own: Moments, rest: Moments) -> _Stat:
    n1, n0 = own.population, rest.population
    v1, v0 = own.variance(), rest.variance()
    difference = own.mean() - rest.mean()
    se = math.sqrt(max(v1 / n1 + v0 / n0, 1e-300))
    pooled = math.sqrt(max(((n1 - 1) * v1 + (n0 - 1) * v0) / max(n1 + n0 - 2, 1), 1e-300))
    z = difference / se
    return _Stat(
        chi2=z * z,
        df=1,
        method="welch",
        effect=measure("cohens_d", difference / pooled, "sd"),
        direction=Direction.UP if difference > 0 else Direction.DOWN,
        difference=difference,
        standard_error=se,
        shape=[measure("mean_difference", difference, "column_units")]
        + ([measure("sd_ratio", math.sqrt(v1 / v0), "ratio")] if v0 > 0 else []),
    )


def _null_stat(own: NullRate, rest: NullRate) -> _Stat:
    n1, n0 = own.population, rest.population
    r1, r0 = own.rate(), rest.rate()
    pooled = (own.nulls() + rest.nulls()) / (n1 + n0)
    se = math.sqrt(max(pooled * (1 - pooled) * (1 / n1 + 1 / n0), 1e-18))
    z = (r1 - r0) / se
    return _Stat(
        chi2=z * z,
        df=1,
        method="two_proportion",
        effect=measure("null_rate_difference", r1 - r0, "share"),
        direction=Direction.UP if r1 > r0 else Direction.DOWN,
        difference=r1 - r0,
        standard_error=se,
        shape=[measure("null_rate", r1, "share"), measure("null_rate_peers", r0, "share")],
    )


def _categorical_stat(
    own: CategoryHistogram | CountMinHeavy, rest: CategoryHistogram | CountMinHeavy
) -> _Stat:
    now, ref = category_counts(own), category_counts(rest)
    keys = [*sorted((set(now.counts) | set(ref.counts)) - {OTHER}), OTHER]
    comparison = compare(
        [now.counts.get(k, 0.0) for k in keys],
        [ref.counts.get(k, 0.0) for k in keys],
        n_current=effective_n(now.total, now.epsilon),
        n_reference=effective_n(ref.total, ref.epsilon),
        ordered=False,
    )
    ranked = sorted(range(len(keys)), key=lambda i: (-comparison.contributions[i], keys[i]))
    attribution = [
        Attribution(
            feature=f"category:{i}",
            contribution=derived_statistic(comparison.contributions[i]),
            identity=now.identities.get(keys[i]) or ref.identities.get(keys[i]),
        )
        for i in ranked[:_TOP_ATTRIBUTIONS]
        if comparison.contributions[i] > 0
    ]
    return _Stat(
        chi2=comparison.g_statistic,
        df=comparison.df,
        method="g_test",
        effect=measure("js_divergence", comparison.js_bits, "bits"),
        direction=Direction.CHANGED,
        shape=[measure("bins_tested", comparison.df + 1, "bins")],
        attribution=attribution,
    )


def _quantile_stat(own: KllQuantile, rest: KllQuantile, edges: Sequence[float]) -> _Stat:
    comparison = compare(
        kll_counts(own, edges),
        kll_counts(rest, edges),
        n_current=effective_n(own.population, kll_epsilon(own)),
        n_reference=effective_n(rest.population, kll_epsilon(rest)),
        ordered=True,
    )
    shift = 0.0
    cum_p = cum_q = 0.0
    for p, q in zip(comparison.current_shares[:-1], comparison.reference_shares[:-1], strict=True):
        cum_p += p
        cum_q += q
        shift += cum_q - cum_p
    shift /= max(len(edges), 1)
    ranked = sorted(range(len(edges) + 1), key=lambda i: (-comparison.contributions[i], i))
    return _Stat(
        chi2=comparison.g_statistic,
        df=comparison.df,
        method="g_test",
        effect=measure("js_divergence", comparison.js_bits, "bits"),
        direction=Direction.UP if shift > 0 else Direction.DOWN,
        shape=[
            measure("cdf_shift", shift, "share"),
            measure("bins_tested", comparison.df + 1, "bins"),
        ],
        attribution=[
            Attribution(
                feature=f"bin:{i}", contribution=derived_statistic(comparison.contributions[i])
            )
            for i in ranked[:_TOP_ATTRIBUTIONS]
            if comparison.contributions[i] > 0
        ],
    )


@dataclass(frozen=True, slots=True)
class _PanelStats:
    stats: dict[str, _Stat]
    """By segment key."""
    slices: dict[str, SegmentSlice]
    phi: float
    refusals: tuple[Refusal, ...]


class SegmentDivergence(DetectorBase[SegmentDivergenceSettings]):
    """Each segment against its peers, calibrated by how much peers ordinarily differ."""

    NAME: ClassVar[str] = "segment_divergence"
    VERSION: ClassVar[str] = "1.0.0"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.SEGMENT_DIVERGENCE
    SUMMARY: ClassVar[str] = (
        "Leave-one-out segment comparison with a robust heterogeneity correction"
    )
    CODECS: ClassVar[frozenset[str]] = frozenset(
        {
            Moments.CODEC,
            NullRate.CODEC,
            CategoryHistogram.CODEC,
            CountMinHeavy.CODEC,
            KllQuantile.CODEC,
        }
    )

    @classmethod
    def default_settings(cls) -> SegmentDivergenceSettings:
        """Alpha 0.05, 30 rows per segment, four peers."""
        return SegmentDivergenceSettings()

    def run(
        self, current: PanelSnapshot, *, baseline: PanelSnapshot | None = None
    ) -> DetectionResult:
        """Test every segment in ``current``; with ``baseline``, only emerging divergence."""
        now = self._panel_stats(current)
        if isinstance(now, Refusal):
            return self._result(refusals=[now])
        then = self._panel_stats(baseline) if baseline is not None else None
        window = Window(
            snapshot_id=current.snapshot_id,
            at=current.at,
            baseline_policy="peers" if baseline is None else f"peers;fixed({baseline.snapshot_id})",
            baseline_snapshot_ids=(baseline.snapshot_id,) if baseline is not None else (),
            baseline_from=baseline.at if baseline is not None else None,
            baseline_to=baseline.at if baseline is not None else None,
        )
        findings: list[Finding] = []
        for key in sorted(now.stats):
            stat = now.stats[key]
            earlier = then.stats.get(key) if isinstance(then, _PanelStats) else None
            finding = self._assess(
                stat, now, earlier, then if isinstance(then, _PanelStats) else None, key, window
            )
            if finding is not None:
                findings.append(finding)
        refusals = list(now.refusals)
        if isinstance(then, Refusal):
            refusals.append(then)
        return self._result(findings, tests=len(now.stats), refusals=refusals)

    def _panel_stats(self, panel: PanelSnapshot) -> _PanelStats | Refusal:
        sketches: dict[str, BaseSketch] = {}
        slices: dict[str, SegmentSlice] = {}
        refusals: list[Refusal] = []
        first = panel.slices[0].envelope
        for item in panel.slices:
            name = (item.context.sketch_name,)
            if item.envelope.codec not in self.CODECS:
                return self._refusal(RefusalReason.UNSUPPORTED_SKETCH, name)
            if item.envelope.codec != first.codec or not same_keying(item.envelope, first):
                return self._refusal(RefusalReason.INCOMPARABLE, name)
            sketch = decode_envelope(item.envelope)
            if sketch.population < self.settings.min_support:
                refusals.append(
                    self._refusal(
                        RefusalReason.THIN_SKETCH, name, f"segment:{item.context.segment.key}"
                    )
                )
                continue
            sketches[str(item.context.segment.key)] = sketch
            slices[str(item.context.segment.key)] = item
        if len(sketches) < self.settings.min_peers:
            return self._refusal(RefusalReason.TOO_FEW_PEERS, (), f"peers:{len(sketches)}")
        edges: tuple[float, ...] = ()
        ordered_keys = sorted(sketches)
        everything = merge_all([sketches[k] for k in ordered_keys])
        if isinstance(everything, KllQuantile):
            edges = numeric_edges(everything, first.params.get("cdf_grid"), self.settings.bins)
        try:
            phi = self._pairwise_dispersion(sketches, ordered_keys, edges)
            stats = self._trimmed(sketches, ordered_keys, edges, phi)
        except GodwitSketchError:
            return self._refusal(RefusalReason.INCOMPARABLE)
        return _PanelStats(stats=stats, slices=slices, phi=phi, refusals=tuple(refusals))

    def _trimmed(
        self,
        sketches: dict[str, BaseSketch],
        keys: Sequence[str],
        edges: Sequence[float],
        phi: float,
    ) -> dict[str, _Stat]:
        """Leave-one-out comparisons, with the worst outlier removed from every reference
        until none remains (or removing another would leave too few peers)."""
        excluded: frozenset[str] = frozenset()
        stats = self._compare_all(sketches, keys, edges, excluded=excluded)
        while len(keys) - len(excluded) > self.settings.min_peers:
            remaining = [
                (chi2_sf(stat.chi2 / phi, stat.df), key)
                for key, stat in stats.items()
                if key not in excluded
            ]
            if not remaining:
                break
            p_value, worst = min(remaining)
            if p_value > self.settings.alpha:
                break
            excluded = excluded | {worst}
            stats = self._compare_all(sketches, keys, edges, excluded=excluded)
        return stats

    def _pairwise_dispersion(
        self, sketches: dict[str, BaseSketch], keys: Sequence[str], edges: Sequence[float]
    ) -> float:
        """Dispersion from every pair of segments. One outlier touches only ``2/K`` of the
        pairs, so the median never sees it once there are five or more segments."""
        pairs: list[tuple[float, float]] = []
        for index, first in enumerate(keys):
            for second in keys[index + 1 :]:
                stat = self._stat(sketches[first], sketches[second], edges)
                if stat is not None and stat.df > 0:
                    pairs.append((stat.chi2, float(stat.df)))
        return dispersion_factor(pairs)

    def _compare_all(
        self,
        sketches: dict[str, BaseSketch],
        keys: Sequence[str],
        edges: Sequence[float],
        *,
        excluded: frozenset[str],
    ) -> dict[str, _Stat]:
        """Each segment against the merge of the others, leaving ``excluded`` out of every
        reference. Raises ``GodwitSketchError`` on sketches that cannot merge."""
        stats: dict[str, _Stat] = {}
        for key in keys:
            rest = merge_all([sketches[k] for k in keys if k != key and k not in excluded])
            stat = self._stat(sketches[key], rest, edges)
            if stat is None or stat.df == 0:
                continue
            stat.population = sketches[key].population
            stat.rest_population = rest.population
            stats[key] = stat
        return stats

    @staticmethod
    def _stat(own: BaseSketch, rest: BaseSketch, edges: Sequence[float]) -> _Stat | None:
        if isinstance(own, Moments) and isinstance(rest, Moments):
            return _moments_stat(own, rest)
        if isinstance(own, NullRate) and isinstance(rest, NullRate):
            return _null_stat(own, rest)
        if isinstance(own, CategoryHistogram | CountMinHeavy) and isinstance(
            rest, CategoryHistogram | CountMinHeavy
        ):
            return _categorical_stat(own, rest)
        if isinstance(own, KllQuantile) and isinstance(rest, KllQuantile) and edges:
            return _quantile_stat(own, rest, edges)
        return None

    def _assess(
        self,
        stat: _Stat,
        now: _PanelStats,
        earlier: _Stat | None,
        then: _PanelStats | None,
        key: str,
        window: Window,
    ) -> Finding | None:
        p_now = chi2_sf(stat.chi2 / now.phi, stat.df)
        shape = [*stat.shape, measure("dispersion", now.phi, "ratio")]
        baseline_measure: Measure | None = None
        if then is None:
            p_value, method = p_now, stat.method
            note = f"{stat.method} against the other segments, divided by panel dispersion"
        elif earlier is None:
            p_value, method = p_now, f"{stat.method}_new_segment"
            note = "segment absent from the baseline panel; current divergence tested"
        elif (
            stat.difference is not None
            and stat.standard_error is not None
            and earlier.difference is not None
            and earlier.standard_error is not None
        ):
            se = math.sqrt(stat.standard_error**2 * now.phi + earlier.standard_error**2 * then.phi)
            z = (stat.difference - earlier.difference) / se
            p_value, method = two_sided_normal_p(z), f"{stat.method}_emerging"
            note = "difference-in-differences z against the baseline panel"
            baseline_measure = measure("difference", earlier.difference, "column_units")
            shape.append(measure("emerging_z", z, "z"))
        else:
            p_then = chi2_sf(earlier.chi2 / then.phi, earlier.df)
            if p_then <= self.settings.alpha:
                return None
            p_value, method = p_now, f"{stat.method}_emerging"
            note = "current divergence; emitted only because the baseline panel showed none"
            baseline_measure = earlier.effect
        if p_value > self.settings.alpha:
            return None
        item = now.slices[key]
        identities: tuple[Tainted[str], ...] = tuple(
            a.identity for a in stat.attribution if a.identity is not None
        )
        segment: Segment = item.context.segment
        return Finding(
            detector=self.NAME,
            detector_version=self.VERSION,
            settings_digest=self.settings.digest(),
            method=method,
            kind=self.KIND,
            probe_key=item.context.probe_key,
            source_id=item.context.source_id,
            sketch_names=(item.context.sketch_name,),
            segment=segment,
            columns=item.context.columns,
            window=window,
            direction=stat.direction,
            statistic=measure("chi_square", stat.chi2 / now.phi, "chi2"),
            baseline=baseline_measure,
            effect=stat.effect,
            p_value=derived_statistic(p_value),
            p_value_note=note,
            population=stat.population,
            baseline_population=stat.rest_population,
            shape=tuple(shape),
            attribution=tuple(stat.attribution),
            identities=identities,
            score=-math.log10(max(p_value, 1e-300)),
        )
