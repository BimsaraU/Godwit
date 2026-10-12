"""Reference plugin 3: a Benford's-law detector over money columns. Control plane.

TUTORIAL. Read this after ``docs/packages/godwit-sdk.md`` section 6.

WHY BENFORD
-----------
In amounts that arise naturally and span several orders of magnitude -- invoices,
payments, expense claims -- the leading digit ``d`` appears with probability
``log10(1 + 1/d)``: a 1 about 30% of the time, a 9 under 5%. People inventing numbers
do not reproduce that, and neither do scripts generating fraudulent amounts in a fixed
band. So "this column used to follow Benford and now does not" is a classic forensic
accounting signal, and a good one to teach with: it needs no labels and no baseline
beyond the column's own past.

WHAT THE DETECTOR READS
-----------------------
No new probe is needed. A ``QUANTILES`` probe already produces a KLL sketch over the
column, and its CDF at the points ``d * 10**k`` gives the leading-digit distribution
directly: ``P(first digit = d) = sum_k F((d+1) 10^k) - F(d 10^k)``. The grid is a
constant of this module, never derived from the data, so every number the detector
computes is a statistic, not a statement about a particular row.

THE HONEST PART: SKETCH ERROR
-----------------------------
A KLL sketch's CDF is approximate (rank error ``eps``, about 1.3% at ``k = 200``). On a
million rows a plain chi-square test would detect the sketch's own error and fire on
everything. So the test's effective sample size is capped at the size at which the
*worst-case* sketch error alone produces a chi-square of its degrees of freedom:
``n_eff = min(n, 8 / (4 eps^2 * sum_d 1/p_d))`` -- about 100 at ``k = 200``. The cost
is power: only gross nonconformity is detectable. That is exactly what fabricated
amounts in a narrow band look like, and it is the right trade for a detector whose
false positives page a human.

WHEN IT ABSTAINS
----------------
* The column is not a money column (``ROLES = {AMOUNT}``, applied from the profiles).
* Fewer than ``MIN_SUPPORT`` rows, or too few positive amounts (refused / no test).
* The reference window did not itself follow Benford (p < 0.01). Many money columns
  never do -- prices clustered at 9.99, fixed fees, a single-product shop -- and a
  detector that compared them to Benford would fire every day. A test that cannot be
  run is returned with ``p_value=None`` and a note, and is not counted.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import ClassVar, Final

from godwit_detect.stats import chi2_sf
from godwit_sketch import KllQuantile

from godwit_sdk import (
    BaseSketch,
    ColumnRole,
    DetectorBase,
    Direction,
    EvidenceKind,
    HypothesisTest,
    detector,
)

__all__ = ["BENFORD", "BenfordDetector", "leading_digits"]

BENFORD: Final[tuple[float, ...]] = tuple(math.log10(1 + 1 / d) for d in range(1, 10))
"""Expected leading-digit probabilities for digits 1..9."""

_DECADES: Final[tuple[int, ...]] = tuple(range(-2, 10))
"""Amounts from 0.01 to 10^10 are covered; anything outside is ignored, not guessed."""
_BELOW: Final[float] = 1.0 - 1e-12
"""CDF points sit just below each boundary, so an amount of exactly 100 counts as a 1."""
_LAST_DIGIT: Final[int] = 9
_DF: Final[int] = 8
_SKETCH_ERROR_BUDGET: Final[float] = _DF / (4.0 * sum(1.0 / p for p in BENFORD))
"""``n_eff * eps**2`` at which worst-case sketch error alone reaches a chi-square of DF."""
_REFERENCE_CONFORMS: Final[float] = 0.01
_METHOD: Final[str] = "chi2_vs_benford"


def _boundary(digit: int, decade: int) -> float:
    return digit * 10.0**decade * _BELOW


def leading_digits(quantiles: KllQuantile) -> tuple[tuple[float, ...], float]:
    """Leading-digit probabilities (1..9, summing to 1) and the fraction of mass covered.

    Mass outside ``[0.01, 10^10)`` -- zeros, negatives, refunds below a cent -- is not
    part of the distribution and lowers the covered fraction instead.
    """
    grid = sorted(
        {_boundary(d, k) for k in _DECADES for d in range(1, 10)} | {_boundary(1, _DECADES[-1] + 1)}
    )
    cdf = dict(zip(grid, quantiles.cdf(grid), strict=True))
    mass = [0.0] * 9
    for decade in _DECADES:
        for digit in range(1, 10):
            nxt, at = (1, decade + 1) if digit == _LAST_DIGIT else (digit + 1, decade)
            upper = _boundary(nxt, at)
            mass[digit - 1] += max(0.0, cdf[upper] - cdf[_boundary(digit, decade)])
    covered = sum(mass)
    if covered <= 0.0 or math.isnan(covered):
        return tuple(math.nan for _ in mass), 0.0
    return tuple(m / covered for m in mass), covered


def _chi2(quantiles: KllQuantile) -> tuple[float, float, float, float]:
    """(chi-square, p-value, mean absolute deviation, effective n) against Benford."""
    observed, covered = leading_digits(quantiles)
    rows = quantiles.population * covered
    bound = quantiles.error_bound()
    eps = bound.epsilon if bound.kind != "exact" and bound.epsilon else 0.0
    n_eff = min(rows, _SKETCH_ERROR_BUDGET / eps**2) if eps > 0 else rows
    if n_eff <= 0 or any(math.isnan(o) for o in observed):
        return math.nan, math.nan, math.nan, 0.0
    statistic = n_eff * sum((o - e) ** 2 / e for o, e in zip(observed, BENFORD, strict=True))
    mad = sum(abs(o - e) for o, e in zip(observed, BENFORD, strict=True)) / 9
    return statistic, chi2_sf(statistic, _DF), mad, n_eff


@detector(
    name="benford",
    namespace="examples",
    version="1.0.0",
    summary="Leading digits of a money column stopped following Benford's law.",
)
class BenfordDetector(DetectorBase):
    """One chi-square test per money column, gated on the reference having conformed."""

    EVIDENCE: ClassVar[EvidenceKind] = EvidenceKind.DISTRIBUTION_SHIFT
    CODECS: ClassVar[frozenset[str]] = frozenset({"godwit-kll-v1"})
    TESTS_PER_SKETCH: ClassVar[int] = 1
    ROLES: ClassVar[frozenset[ColumnRole]] = frozenset({ColumnRole.AMOUNT})
    MIN_SUPPORT: ClassVar[int] = 500
    ALPHA: ClassVar[float] = 0.001

    def examine(
        self, current: BaseSketch, reference: Sequence[BaseSketch]
    ) -> Sequence[HypothesisTest]:
        if not isinstance(current, KllQuantile):
            return ()
        merged = current.identity(current.params)
        for window in reference:
            if isinstance(window, KllQuantile):
                merged = merged.merge(window)
        statistic, p_value, mad, n_eff = _chi2(current)
        before, p_before, mad_before, _ = _chi2(merged)
        if n_eff < 1 or math.isnan(p_value) or math.isnan(p_before):
            return (self._abstain("too few positive amounts to test"),)
        if p_before < _REFERENCE_CONFORMS:
            return (self._abstain("the reference window did not follow Benford's law"),)
        self.log.debug("benford.tested", effective_rows=n_eff, p_value=p_value)
        effect = mad - mad_before
        return (
            HypothesisTest(
                method=_METHOD,
                statistic=statistic,
                effect=effect,
                p_value=p_value,
                direction=Direction.UP if effect > 0 else Direction.DOWN,
                note="effective n capped by the sketch's rank error; see the detector docs",
                baseline=before,
                statistic_unit="chi2_df8",
                effect_unit="mean_absolute_deviation",
            ),
        )

    @staticmethod
    def _abstain(why: str) -> HypothesisTest:
        return HypothesisTest(
            method=_METHOD,
            statistic=0.0,
            effect=0.0,
            p_value=None,
            direction=Direction.CHANGED,
            note=why,
        )
