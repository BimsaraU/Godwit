"""Distributional drift: PSI, Wasserstein and Jensen-Shannon over a sketch series.

Each compares the current window with the merged reference windows chosen by a
baseline policy (see :mod:`godwit_detect.series`), bins as described in
:mod:`godwit_detect.histograms`, and divides its test statistic by the dispersion the
reference windows show among themselves (:func:`godwit_detect.stats.dispersion_factor`).

=================  ===========================  =====================================
Detector           Reads                        Effect size / p-value
=================  ===========================  =====================================
``psi_drift``      KLL, category histogram,     PSI; ``PSI / (1/n + 1/m) ~ chi2(B-1)``
                   Count-Min                    (Yurdakul 2018)
``wasserstein``    KLL                          W1 in the column's own units; the KS
                                                statistic on the bin edges, Kolmogorov
``js_drift``       category histogram,          JS divergence in bits; the G test of
                   Count-Min                    homogeneity, ``G = 2(n+m) JS_w ~ chi2``
=================  ===========================  =====================================
"""

from __future__ import annotations

import abc
import math
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import ClassVar, Final

from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.taint import Tainted, derived_statistic
from godwit_sketch import CategoryHistogram, CountMinHeavy, KllQuantile
from pydantic import Field

from godwit_detect.base import Claim, SeriesDetector, Settings, decoded, merge_all
from godwit_detect.evidence import (
    Attribution,
    DetectionResult,
    Direction,
    Measure,
    RefusalReason,
    Window,
    measure,
)
from godwit_detect.histograms import (
    OTHER,
    Comparison,
    category_counts,
    compare,
    effective_n,
    kll_counts,
    kll_epsilon,
    numeric_edges,
)
from godwit_detect.series import SeriesPoint, SketchSeries
from godwit_detect.stats import chi2_sf, dispersion_factor, kolmogorov_sf

__all__ = [
    "DriftSettings",
    "JensenShannonDrift",
    "PsiDrift",
    "WassersteinDrift",
]

KLL_CODEC: Final[str] = KllQuantile.CODEC
CATEGORICAL_CODECS: Final[frozenset[str]] = frozenset(
    {CategoryHistogram.CODEC, CountMinHeavy.CODEC}
)
_TOP_ATTRIBUTIONS: Final[int] = 3


class DriftSettings(Settings):
    """Settings for the three drift detectors."""

    bins: int = Field(default=10, ge=2)
    """Equal-mass bins when the probe supplied no ``cdf_grid``."""


@dataclass(frozen=True, slots=True)
class _Binned:
    """Current and reference over shared bins, ready to compare."""

    labels: tuple[str, ...]
    identities: tuple[Tainted[str] | None, ...]
    current: tuple[float, ...]
    reference: tuple[float, ...]
    per_point: tuple[tuple[float, ...], ...]
    n_current: float
    n_reference: float
    n_points: tuple[float, ...]
    population: int
    reference_population: int
    ordered: bool
    edges: tuple[float, ...]


def _bin(series: SketchSeries, reference: Sequence[SeriesPoint], bins: int) -> _Binned | None:
    """Bin current, pooled reference and each reference window. None if nothing to bin."""
    current = decoded(series.current)
    windows = [decoded(point) for point in reference]
    pooled = merge_all(windows)
    if isinstance(current, KllQuantile) and isinstance(pooled, KllQuantile):
        grid = series.current.envelope.params.get("cdf_grid") if series.current.envelope else None
        edges = numeric_edges(pooled, grid, bins)
        if not edges:
            return None
        per_point = [kll_counts(w, edges) for w in windows if isinstance(w, KllQuantile)]
        n_points = [
            effective_n(w.population, kll_epsilon(w)) for w in windows if isinstance(w, KllQuantile)
        ]
        return _Binned(
            labels=tuple(f"bin:{i}" for i in range(len(edges) + 1)),
            identities=tuple(None for _ in range(len(edges) + 1)),
            current=kll_counts(current, edges),
            reference=kll_counts(pooled, edges),
            per_point=tuple(per_point),
            n_current=effective_n(current.population, kll_epsilon(current)),
            n_reference=effective_n(pooled.population, kll_epsilon(pooled)),
            n_points=tuple(n_points),
            population=current.population,
            reference_population=pooled.population,
            ordered=True,
            edges=edges,
        )
    if isinstance(current, CategoryHistogram | CountMinHeavy) and isinstance(
        pooled, CategoryHistogram | CountMinHeavy
    ):
        now, ref = category_counts(current), category_counts(pooled)
        points = [
            category_counts(w) for w in windows if isinstance(w, CategoryHistogram | CountMinHeavy)
        ]
        keys = [*sorted((set(now.counts) | set(ref.counts)) - {OTHER}), OTHER]
        return _Binned(
            labels=tuple(f"category:{i}" for i in range(len(keys))),
            identities=tuple(now.identities.get(k) or ref.identities.get(k) for k in keys),
            current=tuple(now.counts.get(k, 0.0) for k in keys),
            reference=tuple(ref.counts.get(k, 0.0) for k in keys),
            per_point=tuple(tuple(pt.counts.get(k, 0.0) for k in keys) for pt in points),
            n_current=effective_n(now.total, now.epsilon),
            n_reference=effective_n(ref.total, ref.epsilon),
            n_points=tuple(effective_n(pt.total, pt.epsilon) for pt in points),
            population=current.population,
            reference_population=pooled.population,
            ordered=False,
            edges=(),
        )
    return None


def _dispersion(binned: _Binned) -> float:
    """How much the reference windows disagree with each other, beyond sampling noise."""
    pairs: list[tuple[float, float]] = []
    count = len(binned.per_point)
    for j in range(count):
        rest = [
            sum(binned.per_point[i][b] for i in range(count) if i != j)
            for b in range(len(binned.labels))
        ]
        n_rest = sum(binned.n_points[i] for i in range(count) if i != j)
        comparison = compare(
            binned.per_point[j],
            rest,
            n_current=binned.n_points[j],
            n_reference=n_rest,
            ordered=binned.ordered,
        )
        if comparison.df > 0:
            pairs.append((comparison.g_statistic, float(comparison.df)))
    return dispersion_factor(pairs)


def _cdf_shift(comparison: Comparison) -> float:
    """Mean of (reference CDF - current CDF) over bin edges. Positive: current moved up."""
    shift = 0.0
    cum_p = cum_q = 0.0
    edges = len(comparison.current_shares) - 1
    for i in range(edges):
        cum_p += comparison.current_shares[i]
        cum_q += comparison.reference_shares[i]
        shift += cum_q - cum_p
    return shift / edges if edges else 0.0


def _direction(binned: _Binned, comparison: Comparison) -> Direction:
    if not binned.ordered:
        return Direction.CHANGED
    return Direction.UP if _cdf_shift(comparison) > 0 else Direction.DOWN


def _attribution(binned: _Binned, comparison: Comparison) -> tuple[Attribution, ...]:
    ranked = sorted(
        range(len(binned.labels)), key=lambda i: (-comparison.contributions[i], binned.labels[i])
    )[:_TOP_ATTRIBUTIONS]
    return tuple(
        Attribution(
            feature=binned.labels[i],
            contribution=derived_statistic(comparison.contributions[i]),
            identity=binned.identities[i],
        )
        for i in ranked
        if comparison.contributions[i] > 0
    )


def _shape(binned: _Binned, comparison: Comparison, phi: float) -> tuple[Measure, ...]:
    largest = max(
        (
            abs(p - q)
            for p, q in zip(comparison.current_shares, comparison.reference_shares, strict=True)
        ),
        default=0.0,
    )
    shape = [
        measure("js_divergence", comparison.js_bits, "bits"),
        measure("largest_share_change", largest, "share"),
        measure("bins_tested", comparison.df + 1, "bins"),
        measure("dispersion", phi, "ratio"),
        measure("effective_rows", binned.n_current, "rows"),
    ]
    if binned.ordered:
        shape.append(measure("cdf_shift", _cdf_shift(comparison), "share"))
    return tuple(shape)


class _BinnedDrift(SeriesDetector[DriftSettings]):
    """The common path: bin, check support, estimate dispersion, compare."""

    KIND: ClassVar[EvidenceKind] = EvidenceKind.DISTRIBUTION_SHIFT

    @classmethod
    def default_settings(cls) -> DriftSettings:
        """Deciles, alpha 0.05, 100 rows minimum."""
        return DriftSettings()

    def _detect(
        self, series: SketchSeries, reference: Sequence[SeriesPoint], window: Window
    ) -> DetectionResult:
        name = (series.context.sketch_name,)
        binned = _bin(series, reference, self.settings.bins)
        if binned is None:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_SKETCH, name)])
        if binned.population < self.settings.min_support:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_SKETCH, name)])
        if binned.reference_population < self.settings.min_support:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_BASELINE, name)])
        phi = _dispersion(binned)
        comparison = compare(
            binned.current,
            binned.reference,
            n_current=binned.n_current,
            n_reference=binned.n_reference,
            ordered=binned.ordered,
        )
        if comparison.df == 0:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_SKETCH, name)])
        claim = self._test(binned, comparison, phi)
        claim = replace(
            claim,
            population=binned.population,
            baseline_population=binned.reference_population,
        )
        finding = self._emit(series.context, window, claim)
        emitted = [finding] if finding is not None else []
        return self._result(emitted, tests=1)

    @abc.abstractmethod
    def _test(self, binned: _Binned, comparison: Comparison, phi: float) -> Claim:
        """Turn one comparison into a claim; the base class applies the threshold."""


class PsiDrift(_BinnedDrift):
    """Population Stability Index over a KLL or categorical series."""

    NAME: ClassVar[str] = "psi_drift"
    VERSION: ClassVar[str] = "1.0.0"
    SUMMARY: ClassVar[str] = (
        "PSI between the current window and the baseline, chi-square calibrated"
    )
    CODECS: ClassVar[frozenset[str]] = CATEGORICAL_CODECS | {KLL_CODEC}

    def _test(self, binned: _Binned, comparison: Comparison, phi: float) -> Claim:
        chi = comparison.psi_chi / phi
        p_value = chi2_sf(chi, comparison.df)
        return Claim(
            method="psi",
            statistic=measure("psi_chi_square", chi, "chi2"),
            effect=measure("psi", comparison.psi, "psi"),
            p_value=p_value,
            direction=_direction(binned, comparison),
            shape=_shape(binned, comparison, phi),
            attribution=_attribution(binned, comparison),
            note="PSI/(1/n_eff + 1/m_eff) ~ chi2(bins-1) asymptotically, over reference dispersion",
        )


class JensenShannonDrift(_BinnedDrift):
    """Jensen-Shannon divergence between category mixes."""

    NAME: ClassVar[str] = "js_drift"
    VERSION: ClassVar[str] = "1.0.0"
    SUMMARY: ClassVar[str] = "Jensen-Shannon divergence of a categorical mix, G-test calibrated"
    CODECS: ClassVar[frozenset[str]] = CATEGORICAL_CODECS

    def _test(self, binned: _Binned, comparison: Comparison, phi: float) -> Claim:
        chi = comparison.g_statistic / phi
        p_value = chi2_sf(chi, comparison.df)
        return Claim(
            method="jensen_shannon",
            statistic=measure("g_statistic", chi, "chi2"),
            effect=measure("js_divergence", comparison.js_bits, "bits"),
            p_value=p_value,
            direction=Direction.CHANGED,
            shape=_shape(binned, comparison, phi),
            attribution=_attribution(binned, comparison),
            note="G test of homogeneity, 2(n+m)*weighted JS ~ chi2(bins-1), over dispersion",
        )


class WassersteinDrift(_BinnedDrift):
    """Earth mover's distance between the current and reference CDFs, in column units."""

    NAME: ClassVar[str] = "wasserstein_drift"
    VERSION: ClassVar[str] = "1.0.0"
    SUMMARY: ClassVar[str] = "W1 between CDF exports; KS statistic on the bin edges for the p-value"
    CODECS: ClassVar[frozenset[str]] = frozenset({KLL_CODEC})

    @classmethod
    def default_settings(cls) -> DriftSettings:
        """Twenty equal-mass edges: W1 is an integral and wants a finer grid than PSI."""
        return DriftSettings(bins=20)

    def _test(self, binned: _Binned, comparison: Comparison, phi: float) -> Claim:
        edges = binned.edges
        current_cdf = _cumulative(comparison.current_shares)
        reference_cdf = _cumulative(comparison.reference_shares)
        gaps = [r - c for c, r in zip(current_cdf, reference_cdf, strict=True)]
        ks = max(abs(gap) for gap in gaps)
        widths = [edges[i + 1] - edges[i] for i in range(len(edges) - 1)]
        w1 = sum(abs(gaps[i]) * widths[i] for i in range(len(widths)))
        signed = sum(gaps[i] * widths[i] for i in range(len(widths)))
        n = binned.n_current * binned.n_reference / (binned.n_current + binned.n_reference) / phi
        p_value = kolmogorov_sf(ks * math.sqrt(n))
        shape = (
            *_shape(binned, comparison, phi),
            measure("ks_statistic", ks, "share"),
            measure("signed_shift", signed, "column_units"),
        )
        return Claim(
            method="wasserstein",
            statistic=measure("ks_statistic", ks, "share"),
            effect=measure("wasserstein_1", w1, "column_units"),
            p_value=p_value,
            direction=Direction.UP if signed > 0 else Direction.DOWN,
            shape=shape,
            attribution=_attribution(binned, comparison),
            note="two-sample KS evaluated at the bin edges only, so conservative; W1 covers "
            "the span of the edges and ignores mass beyond them",
        )


def _cumulative(shares: Sequence[float]) -> list[float]:
    """CDF at each interior edge: len(shares) - 1 values."""
    out: list[float] = []
    running = 0.0
    for share in shares[:-1]:
        running += share
        out.append(running)
    return out
