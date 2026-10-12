"""Turning sketches into aligned histograms, and comparing two of them.

Shared by the drift detectors and segment divergence, so both bin, collapse and test
the same way.

BINNING STRATEGY (numeric columns, from a KLL sketch)
-----------------------------------------------------
1. **The probe's grid, when it supplied one.** ``cdf_grid`` in the envelope parameters
   is a fixed list of cut points chosen before any data was read. Preferred, because the
   cut points are not data.
2. **Otherwise, equal-mass bins from the reference.** ``bins`` cut points at the
   reference's ``1/bins, 2/bins, ...`` quantiles (deciles by default -- the textbook PSI
   binning), with duplicate cut points dropped so that a discrete column does not
   produce empty bins. These cut points *are* row values -- a quantile is some row's
   number -- so they live only inside :func:`numeric_edges` and its caller, are used to
   evaluate the two CDFs, and never reach a finding. No finding here ever names a cut
   point; a bin is ``bin:3``.

Categorical columns bin by category, aligned across the two sides by key (see
:func:`godwit_detect.base.item_key`). Mass the sketch does not itemise -- the tail below
a Count-Min sketch's retained candidates -- is one extra "other" bin.

SPARSE BINS
-----------
The chi-square approximation behind every p-value here fails when expected counts are
small. Before testing, bins whose expected count on either side is below
``MIN_EXPECTED`` (5, Cochran's rule) are merged: adjacent bins for an ordered axis,
into the "other" bin for categories. Effect sizes are computed on the unmerged bins,
because merging would hide exactly the small categories whose growth is the story.

SKETCH ERROR
------------
A KLL estimate of a bin's mass carries error on top of sampling error. Measured in the
package benchmarks, its standard deviation is ``KLL_BIN_NOISE * epsilon`` -- about a
fifth of the sketch's declared rank bound -- and flat in both ``n`` and ``k``
(``docs/packages/godwit-detect.md`` has the table). Treated as extra variance on a bin of
typical mass ``p = 1/bins``, it caps the sample size a test may claim at

    n_eff = 1 / (1/n + (KLL_BIN_NOISE * epsilon)**2 / (p * (1 - p)))

Without it a PSI test on ``k=200`` sketches of 2,000 rows rejects at twice its nominal
rate; with it, at the nominal rate. For large ``n`` the correction dominates and the
tests become conservative, which is the honest direction to be wrong in: a million rows
through a ``k=200`` sketch do not carry a million rows' worth of shape. Exact histograms
have ``epsilon = 0`` and ``n_eff = n``. A degraded (Count-Min) histogram uses the same
formula with its own epsilon, which is conservative for it.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from godwit_contracts.taint import Tainted
from godwit_sketch import CategoryHistogram, CountMinHeavy, HistogramRegime, KllQuantile

from godwit_detect.base import item_key
from godwit_detect.stats import chi2_sf

__all__ = [
    "KLL_BIN_NOISE",
    "MIN_EXPECTED",
    "OTHER",
    "CategoryCounts",
    "Comparison",
    "category_counts",
    "compare",
    "effective_n",
    "kll_counts",
    "kll_epsilon",
    "numeric_edges",
]

MIN_EXPECTED: Final[float] = 5.0
KLL_BIN_NOISE: Final[float] = 0.2
"""Measured standard deviation of a KLL bin-mass estimate, in units of its epsilon."""
TYPICAL_BIN_SHARE: Final[float] = 0.1
OTHER: Final[str] = "\x00other"
"""Key for un-itemised mass. The NUL prefix cannot occur in a canonical sketch key."""
_SMOOTHING: Final[float] = 0.5
_MIN_BINS: Final[int] = 2


def effective_n(n: float, epsilon: float) -> float:
    """The sample size a test may claim, given a sketch's normalised error."""
    if n <= 0:
        return 0.0
    noise = (KLL_BIN_NOISE * epsilon) ** 2 / (TYPICAL_BIN_SHARE * (1.0 - TYPICAL_BIN_SHARE))
    return 1.0 / (1.0 / n + noise)


def kll_epsilon(sketch: KllQuantile) -> float:
    """Rank error of a KLL sketch: zero until its first compaction, the bound after."""
    if sketch.num_levels() <= 1:
        return 0.0
    return float(sketch.error_bound().epsilon or 0.0)


def numeric_edges(reference: KllQuantile, grid: object, bins: int) -> tuple[float, ...]:
    """Cut points: the probe's ``cdf_grid`` if it gave one, else equal-mass bins.

    See the module docstring. The equal-mass cut points are row values; they must not
    leave the caller.
    """
    if isinstance(grid, str) and grid.strip():
        try:
            points = sorted({float(piece) for piece in grid.split(",")})
        except ValueError:
            points = []
        if points:
            return tuple(points)
    if reference.population == 0:
        return ()
    cuts = {reference.quantile(i / bins).reveal() for i in range(1, bins)}
    return tuple(sorted(cut for cut in cuts if math.isfinite(cut)))


def kll_counts(sketch: KllQuantile, edges: Sequence[float]) -> tuple[float, ...]:
    """Estimated rows in each of the ``len(edges) + 1`` bins the edges induce."""
    if sketch.population == 0:
        return tuple(0.0 for _ in range(len(edges) + 1))
    return tuple(share * sketch.population for share in sketch.pmf(edges))


@dataclass(frozen=True, slots=True)
class CategoryCounts:
    """Per-key counts from a categorical sketch, plus its un-itemised remainder."""

    counts: dict[str, float]
    identities: dict[str, Tainted[str]]
    total: float
    epsilon: float


def category_counts(sketch: CategoryHistogram | CountMinHeavy) -> CategoryCounts:
    """Counts by key. An exact histogram is exact; anything else leaves an OTHER bin."""
    if isinstance(sketch, CategoryHistogram):
        pairs = sketch.categories()
        exact = sketch.regime is HistogramRegime.EXACT
        epsilon = 0.0 if exact else float(sketch.error_bound().epsilon or 0.0)
    else:
        pairs = sketch.heavy_hitters()
        epsilon = float(sketch.error_bound().epsilon or 0.0)
    counts: dict[str, float] = {}
    identities: dict[str, Tainted[str]] = {}
    for label, count in pairs:
        key = item_key(label)
        counts[key] = float(count)
        identities[key] = label
    itemised = sum(counts.values())
    remainder = sketch.population - itemised
    if remainder > 0:
        counts[OTHER] = float(remainder)
    total = max(float(sketch.population), itemised)
    return CategoryCounts(counts=counts, identities=identities, total=total, epsilon=epsilon)


@dataclass(frozen=True, slots=True)
class Comparison:
    """Two histograms over the same bins, compared every way a detector needs."""

    g_statistic: float
    """Likelihood-ratio homogeneity statistic on the collapsed bins."""
    df: int
    """Collapsed bins minus one. Zero means there was nothing left to test."""
    psi_chi: float
    """PSI scaled to its chi-square null: PSI / (1/n_a + 1/n_b)."""
    psi: float
    js_bits: float
    """Unweighted Jensen-Shannon divergence in bits, on the unmerged bins. In [0, 1]."""
    contributions: tuple[float, ...]
    """Each unmerged bin's share of ``js_bits``, in bin order."""
    current_shares: tuple[float, ...]
    reference_shares: tuple[float, ...]

    @property
    def g_p_value(self) -> float:
        """P-value of the G test; 1.0 when nothing could be tested."""
        return chi2_sf(self.g_statistic, self.df) if self.df > 0 else 1.0

    @property
    def psi_p_value(self) -> float:
        """P-value of PSI under its asymptotic chi-square null."""
        return chi2_sf(self.psi_chi, self.df) if self.df > 0 else 1.0


def _shares(counts: Sequence[float]) -> tuple[float, ...]:
    total = sum(counts)
    return tuple(count / total if total > 0 else 0.0 for count in counts)


def _collapse(
    current: Sequence[float],
    reference: Sequence[float],
    n_current: float,
    n_reference: float,
    *,
    ordered: bool,
) -> tuple[list[float], list[float]]:
    """Merge bins until every expected count on both sides reaches MIN_EXPECTED.

    Works on shares scaled to the effective sizes, so the rule is applied to the counts
    the test will actually use.
    """
    p, q = _shares(current), _shares(reference)
    total = n_current + n_reference
    groups: list[tuple[float, float]] = []
    pending_p = pending_q = 0.0
    sparse_p = sparse_q = 0.0
    for share_p, share_q in zip(p, q, strict=True):
        pooled = (n_current * share_p + n_reference * share_q) / total if total else 0.0
        if ordered:
            pending_p += share_p
            pending_q += share_q
            pooled_pending = (n_current * pending_p + n_reference * pending_q) / total
            if min(n_current, n_reference) * pooled_pending >= MIN_EXPECTED:
                groups.append((pending_p, pending_q))
                pending_p = pending_q = 0.0
        elif min(n_current, n_reference) * pooled >= MIN_EXPECTED:
            groups.append((share_p, share_q))
        else:
            sparse_p += share_p
            sparse_q += share_q
    leftover_p = pending_p + sparse_p
    leftover_q = pending_q + sparse_q
    if leftover_p > 0 or leftover_q > 0:
        pooled_left = (n_current * leftover_p + n_reference * leftover_q) / total if total else 0.0
        if groups and min(n_current, n_reference) * pooled_left < MIN_EXPECTED:
            last_p, last_q = groups[-1]
            groups[-1] = (last_p + leftover_p, last_q + leftover_q)
        else:
            groups.append((leftover_p, leftover_q))
    return [g[0] for g in groups], [g[1] for g in groups]


def _g_statistic(p: Sequence[float], q: Sequence[float], n_p: float, n_q: float) -> float:
    total = n_p + n_q
    g = 0.0
    for share_p, share_q in zip(p, q, strict=True):
        pooled = (n_p * share_p + n_q * share_q) / total
        if share_p > 0:
            g += n_p * share_p * math.log(share_p / pooled)
        if share_q > 0:
            g += n_q * share_q * math.log(share_q / pooled)
    return 2.0 * g


def _psi(p: Sequence[float], q: Sequence[float], n_p: float, n_q: float) -> float:
    bins = len(p)
    total = 0.0
    for share_p, share_q in zip(p, q, strict=True):
        sp = (share_p * n_p + _SMOOTHING) / (n_p + _SMOOTHING * bins)
        sq = (share_q * n_q + _SMOOTHING) / (n_q + _SMOOTHING * bins)
        total += (sp - sq) * math.log(sp / sq)
    return total


def _js_terms(p: Sequence[float], q: Sequence[float]) -> tuple[float, ...]:
    terms: list[float] = []
    for share_p, share_q in zip(p, q, strict=True):
        middle = 0.5 * (share_p + share_q)
        term = 0.0
        if share_p > 0:
            term += 0.5 * share_p * math.log2(share_p / middle)
        if share_q > 0:
            term += 0.5 * share_q * math.log2(share_q / middle)
        terms.append(term)
    return tuple(terms)


def compare(
    current: Sequence[float],
    reference: Sequence[float],
    *,
    n_current: float,
    n_reference: float,
    ordered: bool,
) -> Comparison:
    """Compare two binned distributions at the given effective sample sizes."""
    if len(current) != len(reference):
        raise ValueError("histograms must share bins")
    p, q = _shares(current), _shares(reference)
    terms = _js_terms(p, q)
    js = sum(terms)
    merged_p, merged_q = _collapse(current, reference, n_current, n_reference, ordered=ordered)
    df = len(merged_p) - 1 if len(merged_p) >= _MIN_BINS else 0
    if df == 0 or n_current <= 0 or n_reference <= 0:
        g = psi_chi = psi = 0.0
    else:
        g = _g_statistic(merged_p, merged_q, n_current, n_reference)
        psi = _psi(merged_p, merged_q, n_current, n_reference)
        psi_chi = psi / (1.0 / n_current + 1.0 / n_reference)
    return Comparison(
        g_statistic=g,
        df=df,
        psi_chi=psi_chi,
        psi=psi,
        js_bits=js,
        contributions=tuple(term / js if js > 0 else 0.0 for term in terms),
        current_shares=p,
        reference_shares=q,
    )
