"""The four statistics the L-1 detectors share. Pure, stdlib only, no clock, no RNG.

Everything a metadata detector reports is one of these, and every one of them is a
``DERIVED_STATISTIC`` by construction: they consume counts and produce counts. That is
why the cheap tier is also the safe tier.

There is no SciPy here on purpose. ``statistics.NormalDist`` gives an exact normal CDF,
and a two-proportion z and a robust z are five lines each. A dependency added to a
data-plane package is a dependency a bank's security team reviews.

Honesty rules that the callers rely on:

* A test that cannot be run returns ``None``, never ``1.0``. A missing p-value and a
  p-value of one are different claims and only one of them is true.
* ``robust_z`` refuses a history shorter than :data:`MIN_HISTORY` and refuses a
  degenerate spread, rather than dividing by something near zero and reporting a
  spectacular z.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from statistics import NormalDist, fmean, median
from typing import Final

__all__ = [
    "MAD_TO_SIGMA",
    "MIN_HISTORY",
    "log_ratio",
    "robust_z",
    "two_proportion_z",
    "two_sided_p",
]

MAD_TO_SIGMA: Final[float] = 1.4826
"""Scales a median absolute deviation to a standard deviation under normality."""

MIN_HISTORY: Final[int] = 3
"""Fewest baseline observations ``robust_z`` will work from.

Two points have a median and a MAD, but the MAD of two points is half their gap, which
makes every third observation look like a four-sigma event.
"""

_STANDARD_NORMAL: Final[NormalDist] = NormalDist()


def two_sided_p(z: float) -> float:
    """Two-sided tail probability of ``z`` under the standard normal.

    ``two_sided_p(0) == 1.0`` and the result falls monotonically as ``abs(z)`` grows.
    A non-finite z means the test degenerated; it reports 0.0, the strongest claim,
    only for infinities, and callers must not manufacture those.
    """
    if math.isnan(z):
        raise ValueError("two_sided_p received NaN; the caller should have returned None")
    if math.isinf(z):
        return 0.0
    return 2.0 * _STANDARD_NORMAL.cdf(-abs(z))


def robust_z(*, value: float, baseline: Sequence[float]) -> float | None:
    """How many robust sigmas ``value`` sits from the median of ``baseline``.

    Median and MAD rather than mean and standard deviation, because the thing we are
    detecting is an outlier and an outlier moves a mean. Returns ``None`` when the
    baseline is too short or has no spread at all -- both are "cannot say", not "no
    drift". A tie-heavy series whose MAD is zero falls back to the mean absolute
    deviation rather than refusing, because that case is common and real.

    Translation-invariant and positively scale-equivariant, which is what the property
    tests pin: shifting every measurement by a constant must not create a detection.
    """
    if len(baseline) < MIN_HISTORY:
        return None
    if not all(math.isfinite(item) for item in baseline) or not math.isfinite(value):
        return None
    centre = median(baseline)
    deviations = [abs(item - centre) for item in baseline]
    spread = median(deviations) * MAD_TO_SIGMA
    if spread <= 0.0:
        # More than half a stable series can sit exactly on its median -- a row count
        # that is the same number four weeks running -- which drives the MAD to zero
        # without the series being constant. The mean absolute deviation still has a
        # scale there. It is less robust, which is why it is only the fallback.
        spread = fmean(deviations) * MAD_TO_SIGMA
    if spread <= 0.0:
        return None
    return (value - centre) / spread


def two_proportion_z(
    *, successes_a: int, total_a: int, successes_b: int, total_b: int
) -> float | None:
    """Pooled two-proportion z for ``a`` against ``b``.

    The workhorse behind ``null_rate_shift`` and ``ndv_ratio_shift``: both compare one
    count against a denominator at two points in time. Returns ``None`` when either
    population is empty or when the pooled proportion is degenerate (every row a
    success, or none), where the normal approximation says nothing.

    Antisymmetric: swapping ``a`` and ``b`` negates the result.
    """
    if total_a <= 0 or total_b <= 0:
        return None
    if not (0 <= successes_a <= total_a and 0 <= successes_b <= total_b):
        raise ValueError("successes must lie within their total")
    pooled = (successes_a + successes_b) / (total_a + total_b)
    if pooled <= 0.0 or pooled >= 1.0:
        return None
    standard_error = math.sqrt(pooled * (1.0 - pooled) * (1.0 / total_a + 1.0 / total_b))
    if standard_error <= 0.0:
        return None
    return (successes_a / total_a - successes_b / total_b) / standard_error


def log_ratio(*, value: float, baseline: float) -> float | None:
    """``log(value / baseline)``, or ``None`` when either side is not positive.

    Used as an effect size for quantities that are naturally multiplicative -- a
    column's range, a file count, a mean file size. A log ratio is symmetric about
    zero, so "halved" and "doubled" are the same magnitude of surprise.
    """
    if value <= 0.0 or baseline <= 0.0:
        return None
    if not (math.isfinite(value) and math.isfinite(baseline)):
        return None
    return math.log(value / baseline)
