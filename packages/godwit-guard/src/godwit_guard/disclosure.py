"""Small-cell and disclosure control: k-anonymity, complementary releases, optional DP.

WHAT THIS DOES
--------------
* :func:`enforce_segment_k` -- a segment whose population is below k is generalised
  upward (predicates dropped, fewest first) until it is not, or suppressed. Unknown
  population is small. k is never below 2.
* :func:`enforce_evidence_k` -- evidence is suppressed unless both the population behind
  its statistic and its segment clear k. A statistic about a small segment cannot be
  re-attached to a coarser one, so evidence is never generalised, only dropped.
* :class:`ReleaseLedger` -- the tractable version of complementary-release control.

WHAT THIS DOES NOT DO -- READ BEFORE RELYING ON IT
--------------------------------------------------
Two separately safe releases can intersect to re-identify. :class:`ReleaseLedger` tracks
released segment predicates per population and refuses a release that is *nested* with
an earlier one (one predicate set contains the other) when the difference in population
is between 1 and k-1: releasing ``count(A) = 100`` and then ``count(A and B) = 97``
reveals that three people are in ``A and not B``.

It does not detect: differences across three or more releases (``A - B - C``), overlaps
of non-nested segments (``A and B`` vs ``A and C``), linear-algebra reconstruction over
many counts, releases made through statistics rather than segments, or anything
released before the ledger existed. Statistical disclosure control in general is not
solved here, and nothing in this package should be read as claiming it is.

DIFFERENTIAL PRIVACY -- OFF BY DEFAULT, AND WHY
-----------------------------------------------
:func:`laplace_count` and :func:`dp_quantile` are available and deterministic given a
seed. DP noise at a useful epsilon substantially degrades drift-detection sensitivity:
at epsilon = 1 a count carries noise with standard deviation ~1.4, which swamps the
small-segment rate changes the detectors exist to find, and the privacy budget is
consumed by every repeated measurement of the same population. That is the trade-off
the buyer is choosing, not a marketing claim. The noise source is a hash-based
generator, adequate for reproducible research use but not a hardened DP library (no
defence against floating-point side channels); a production DP deployment should use a
vetted library such as OpenDP.
"""

from __future__ import annotations

import hashlib
import itertools
import math
from collections.abc import Callable, Sequence
from typing import Final

from godwit_contracts import Evidence, GodwitModel, Segment, canonical_json, content_hash

__all__ = [
    "MIN_K",
    "DifferentialPrivacy",
    "ReleaseDecision",
    "ReleaseLedger",
    "dp_quantile",
    "enforce_evidence_k",
    "enforce_segment_k",
    "laplace_count",
]

MAX_GENERALISATION_PREDICATES: Final[int] = 8
"""Upward generalisation searches predicate subsets, which is exponential. Segments
wider than this are suppressed rather than searched."""


MIN_K: Final[int] = 2
"""k-anonymity below 2 is no anonymity at all. k is never zero."""


def _check_k(k: int) -> None:
    if k < MIN_K:
        raise ValueError("k must be at least 2; k below 2 is no anonymity at all")


def enforce_segment_k(
    segment: Segment,
    *,
    k: int,
    population_of: Callable[[Segment], int | None] | None = None,
) -> Segment | None:
    """Return a segment with population >= k, or None to suppress.

    ``population_of`` counts a coarser segment (the data plane answers it from sketches).
    Without it, a small segment can only be suppressed. Coarsening drops predicates,
    fewest first, in canonical order, so the result is deterministic.
    """
    _check_k(k)
    if segment.population is not None and segment.population >= k:
        return segment
    predicates = sorted(segment.predicates, key=lambda p: p.canonical_form())
    if population_of is None or len(predicates) > MAX_GENERALISATION_PREDICATES:
        return None
    for removed in range(1, len(predicates) + 1):
        for dropped in itertools.combinations(range(len(predicates)), removed):
            kept = tuple(p for i, p in enumerate(predicates) if i not in dropped)
            population = population_of(Segment(predicates=kept))
            if population is not None and population >= k:
                return Segment(predicates=kept, population=population)
    return None


def enforce_evidence_k(evidence: Evidence, *, k: int) -> Evidence | None:
    """Return the evidence if its statistic and its segment both clear k, else None."""
    _check_k(k)
    segment_pop = evidence.segment.population
    if evidence.population is None or evidence.population < k:
        return None
    if segment_pop is None or segment_pop < k:
        return None
    return evidence


# --------------------------------------------------------------------------------------
# Complementary releases
# --------------------------------------------------------------------------------------


class ReleaseDecision(GodwitModel):
    """Whether a release is safe in combination with what has already left."""

    allowed: bool
    reason: str
    conflicts: int = 0


def _fingerprint(segment: Segment) -> frozenset[str]:
    # Hashes of canonical predicates: the ledger keeps set structure, never values.
    return frozenset(
        content_hash(canonical_json(p.canonical_form()), prefix="prd") for p in segment.predicates
    )


class ReleaseLedger:
    """Remembers which segments were released about which population. **Boundary.**

    Stores predicate *hashes* and populations, never predicate values.
    """

    def __init__(self, *, k: int) -> None:
        _check_k(k)
        self._k = k
        self._released: dict[str, list[tuple[frozenset[str], int]]] = {}

    def check(self, segment: Segment, *, scope: str) -> ReleaseDecision:
        """Would releasing ``segment`` narrow any population below k in combination?"""
        if segment.population is None:
            return ReleaseDecision(allowed=False, reason="unknown population cannot be checked")
        mine = _fingerprint(segment)
        conflicts = 0
        for other, population in self._released.get(scope, []):
            nested = mine <= other or other <= mine
            difference = abs(segment.population - population)
            if nested and 0 < difference < self._k:
                conflicts += 1
        if conflicts:
            return ReleaseDecision(
                allowed=False,
                conflicts=conflicts,
                reason=f"differencing against {conflicts} earlier release(s) isolates fewer "
                f"than k={self._k}",
            )
        return ReleaseDecision(allowed=True, reason="no nested release narrows below k")

    def record(self, segment: Segment, *, scope: str) -> None:
        """Remember a release. Call only after it actually left."""
        if segment.population is None:
            raise ValueError("cannot record a release of unknown population")
        self._released.setdefault(scope, []).append((_fingerprint(segment), segment.population))


# --------------------------------------------------------------------------------------
# Differential privacy -- off by default
# --------------------------------------------------------------------------------------


class DifferentialPrivacy(GodwitModel):
    """Opt-in DP settings. ``enabled`` is False unless a buyer chooses the trade-off."""

    enabled: bool = False
    epsilon_count: float = 1.0
    epsilon_quantile: float = 1.0


def _uniform(seed: int, index: int) -> float:
    """A reproducible uniform draw in the open interval (0, 1)."""
    digest = hashlib.blake2b(f"{seed}:{index}".encode(), digest_size=8).digest()
    return (int.from_bytes(digest, "big") + 0.5) / 2.0**64


def laplace_count(count: int, *, epsilon: float, seed: int, draw: int = 0) -> float:
    """``count`` plus Laplace(1/epsilon) noise. Sensitivity 1. Deterministic per seed."""
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    centred = _uniform(seed, draw) - 0.5
    noise = -(1.0 / epsilon) * math.copysign(1.0, centred) * math.log(1 - 2 * abs(centred))
    return count + noise


def dp_quantile(
    values: Sequence[float],
    *,
    q: float,
    epsilon: float,
    lower: float,
    upper: float,
    seed: int,
) -> float:
    """Exponential-mechanism quantile (Smith, 2011). **Data plane**: it reads values.

    Values are clipped to ``[lower, upper]``, which must be chosen without looking at
    the data, or the bounds themselves leak.
    """
    if not 0.0 <= q <= 1.0 or epsilon <= 0 or not lower < upper:
        raise ValueError("need 0<=q<=1, epsilon>0 and lower<upper")
    points = [lower, *sorted(min(max(v, lower), upper) for v in values), upper]
    n = len(values)
    log_weights: list[float] = []
    for i in range(len(points) - 1):
        width = points[i + 1] - points[i]
        utility = -abs(i - q * n)
        log_weights.append(math.log(width) + epsilon * utility / 2 if width > 0 else -math.inf)
    peak = max(log_weights)
    weights = [math.exp(w - peak) for w in log_weights]
    target = _uniform(seed, 0) * sum(weights)
    cumulative = 0.0
    chosen = len(weights) - 1
    for i, weight in enumerate(weights):
        cumulative += weight
        if weight > 0 and cumulative >= target:
            chosen = i
            break
    low, high = points[chosen], points[chosen + 1]
    return low + _uniform(seed, 1) * (high - low)
