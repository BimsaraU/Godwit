"""Distribution functions and the handful of test statistics every detector shares.

Standard library only. SciPy would supply all of this, but it ships no type information
and ``mypy --strict`` is not negotiable here; the functions below are the textbook
continued-fraction and series evaluations (Numerical Recipes, 3rd ed., sections 6.2 and
6.4), accurate to roughly 1e-12 over the range a detector can reach.

Everything is pure: no clock, no randomness, no state.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "PredictionTest",
    "beta_regularized",
    "chi2_median_ratio",
    "chi2_sf",
    "dispersion_factor",
    "fisher_combine",
    "gamma_q",
    "kolmogorov_sf",
    "norm_sf",
    "prediction_test",
    "t_sf",
    "two_sided_normal_p",
]

_EPS: Final[float] = 1e-15
_FPMIN: Final[float] = 1e-300
_ITMAX: Final[int] = 1000
_MIN_DISPERSION_SAMPLES: Final[int] = 3
_MIN_HISTORY: Final[int] = 2
_KS_NEGLIGIBLE: Final[float] = 0.2
"""Below this the Kolmogorov tail is 1 to double precision and the series converges slowly."""
_TERM_FLOOR: Final[float] = 1e-16


def norm_sf(z: float) -> float:
    """Upper tail of the standard normal, ``P(Z > z)``."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def two_sided_normal_p(z: float) -> float:
    """``P(|Z| > |z|)`` for a standard normal."""
    return math.erfc(abs(z) / math.sqrt(2.0))


def _gamma_prefactor(a: float, x: float) -> float:
    return math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_p_series(a: float, x: float) -> float:
    term = total = 1.0 / a
    denominator = a
    for _ in range(_ITMAX):
        denominator += 1.0
        term *= x / denominator
        total += term
        if abs(term) < abs(total) * _EPS:
            break
    return total * _gamma_prefactor(a, x)


def _gamma_q_fraction(a: float, x: float) -> float:
    b = x + 1.0 - a
    c = 1.0 / _FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, _ITMAX):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = _FPMIN if abs(d) < _FPMIN else d
        c = b + an / c
        c = _FPMIN if abs(c) < _FPMIN else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    return _gamma_prefactor(a, x) * h


def gamma_q(a: float, x: float) -> float:
    """Regularised upper incomplete gamma ``Q(a, x)``."""
    if a <= 0.0:
        raise ValueError(f"gamma_q needs a > 0, got {a}")
    if x <= 0.0:
        return 1.0
    if math.isinf(x):
        return 0.0
    if x < a + 1.0:
        return max(0.0, 1.0 - _gamma_p_series(a, x))
    return _gamma_q_fraction(a, x)


def chi2_sf(x: float, df: float) -> float:
    """Upper tail of a chi-square with ``df`` degrees of freedom."""
    if df <= 0:
        raise ValueError(f"chi-square needs df > 0, got {df}")
    if math.isnan(x):
        return math.nan
    return gamma_q(df / 2.0, x / 2.0)


def _beta_fraction(a: float, b: float, x: float) -> float:
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    d = _FPMIN if abs(d) < _FPMIN else d
    d = 1.0 / d
    h = d
    for m in range(1, _ITMAX):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = _FPMIN if abs(d) < _FPMIN else d
        c = 1.0 + aa / c
        c = _FPMIN if abs(c) < _FPMIN else c
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = _FPMIN if abs(d) < _FPMIN else d
        c = 1.0 + aa / c
        c = _FPMIN if abs(c) < _FPMIN else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    return h


def beta_regularized(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta ``I_x(a, b)``."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_front = (
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log1p(-x)
    )
    front = math.exp(log_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _beta_fraction(a, b, x) / a
    return 1.0 - front * _beta_fraction(b, a, 1.0 - x) / b


def t_sf(t: float, df: float) -> float:
    """Upper tail of Student's t, ``P(T > t)``."""
    if df <= 0:
        raise ValueError(f"Student's t needs df > 0, got {df}")
    if math.isinf(t):
        return 0.0 if t > 0 else 1.0
    two_sided = beta_regularized(df / 2.0, 0.5, df / (df + t * t))
    return two_sided / 2.0 if t > 0 else 1.0 - two_sided / 2.0


def kolmogorov_sf(statistic: float) -> float:
    """``P(K > statistic)`` for the Kolmogorov distribution (large-sample KS)."""
    if statistic <= _KS_NEGLIGIBLE:
        return 1.0
    total = 0.0
    for k in range(1, 101):
        term = 2.0 * (-1.0) ** (k - 1) * math.exp(-2.0 * k * k * statistic * statistic)
        total += term
        if abs(term) < _TERM_FLOOR:
            break
    return min(1.0, max(0.0, total))


def fisher_combine(p_values: Sequence[float]) -> float:
    """Fisher's method: combine independent one-sided p-values into one."""
    if not p_values:
        raise ValueError("fisher_combine needs at least one p-value")
    statistic = -2.0 * sum(math.log(max(p, 1e-300)) for p in p_values)
    return chi2_sf(statistic, 2.0 * len(p_values))


def chi2_median_ratio(df: float) -> float:
    """Median of ``chi2(df) / df`` (Wilson-Hilferty). Used to robustify dispersion."""
    return max(1e-9, 1.0 - 2.0 / (9.0 * df)) ** 3


def dispersion_factor(statistics: Sequence[tuple[float, float]]) -> float:
    """Robust quasi-likelihood dispersion from ``(chi-square statistic, df)`` pairs.

    Sampling theory says a chi-square statistic over ``df`` degrees of freedom has median
    ``df * chi2_median_ratio(df)`` when nothing but sampling noise separates the two
    sides. Real tables vary more than that: last Tuesday differs from the Tuesday before
    it for reasons no multinomial model knows about. The ratio of the observed median to
    the theoretical one estimates that extra variance, and dividing the statistic under
    test by it stops ordinary week-to-week wobble from reading as drift.

    The median, not the mean, so that one genuinely drifted reference point cannot
    inflate the factor and mask a second one. Never below 1: this only ever makes a test
    more conservative. Fewer than three pairs carries no information and returns 1.
    """
    if len(statistics) < _MIN_DISPERSION_SAMPLES:
        return 1.0
    ratios = sorted(stat / df / chi2_median_ratio(df) for stat, df in statistics if df > 0)
    if len(ratios) < _MIN_DISPERSION_SAMPLES:
        return 1.0
    middle = len(ratios) // 2
    median = ratios[middle] if len(ratios) % 2 else 0.5 * (ratios[middle - 1] + ratios[middle])
    return max(1.0, median)


@dataclass(frozen=True, slots=True)
class PredictionTest:
    """A new value tested against the spread of a short history."""

    statistic: float
    df: int
    p_two_sided: float
    p_upper: float
    p_lower: float
    reference_mean: float
    reference_sd: float


def prediction_test(value: float, history: Sequence[float]) -> PredictionTest:
    """Student-t prediction-interval test of ``value`` against ``history``.

    For ``k`` independent normal reference values with mean ``m`` and standard deviation
    ``s``, a new draw from the same distribution satisfies
    ``(x - m) / (s * sqrt(1 + 1/k)) ~ t(k - 1)`` exactly. That is the right null for a
    statistic whose sampling variance has no closed form -- a fan-in ratio out of three
    Theta estimates, say -- because the history supplies the variance empirically.

    A history with zero spread is floored at a relative 1e-9 rather than dividing by
    zero; a series that has never moved and then moves is reported as maximally
    surprising, which it is.
    """
    k = len(history)
    if k < _MIN_HISTORY:
        raise ValueError("a prediction test needs at least two reference values")
    mean = math.fsum(history) / k
    variance = math.fsum((x - mean) ** 2 for x in history) / (k - 1)
    sd = max(math.sqrt(variance), 1e-9 * abs(mean), 1e-12)
    statistic = (value - mean) / (sd * math.sqrt(1.0 + 1.0 / k))
    upper = t_sf(statistic, k - 1)
    lower = 1.0 - upper
    return PredictionTest(
        statistic=statistic,
        df=k - 1,
        p_two_sided=min(1.0, 2.0 * min(upper, lower)),
        p_upper=upper,
        p_lower=lower,
        reference_mean=mean,
        reference_sd=sd,
    )
