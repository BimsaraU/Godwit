"""Property tests for the four shared statistics.

Universal rule 4: *property tests for anything claiming a mathematical property.* These
four claim several, and each of them is load-bearing somewhere in the detector layer:

* Translation invariance is why a table whose row count grows by a constant is not
  reported as drifting.
* Antisymmetry of the two-proportion z is why "the null rate doubled" and "the null
  rate halved" are the same size of surprise.
* Monotonicity of the p-value is why a bigger z always means a smaller p, which every
  threshold in ``DetectorConfig`` silently assumes.
* Refusing rather than guessing is why a missing p-value stays missing. An example
  test would never find the case where MAD is zero and the z is infinite.
"""

from __future__ import annotations

import math

import pytest
from godwit_source.stats import (
    MIN_HISTORY,
    log_ratio,
    robust_z,
    two_proportion_z,
    two_sided_p,
)
from hypothesis import assume, given, settings
from hypothesis import strategies as st

# Hypothesis' default 200 ms per-example deadline is a wall-clock check, and a
# wall-clock check is exactly the nondeterminism universal rule 5 forbids: these
# tests fail on a loaded machine and pass on a quiet one, which is a flake rather
# than a finding. Deadlines are off; what the property asserts is unchanged.
NO_DEADLINE = settings(deadline=None)

finite = st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False)
series = st.lists(finite, min_size=MIN_HISTORY, max_size=20)
counts = st.integers(min_value=0, max_value=1_000_000)

# Well-scaled numbers for the invariance properties. Translation invariance is exact in
# the reals and only approximate in binary floats: shifting [1e-18, 1.0] by 1.0 rounds
# the first term away entirely. Restricting the generators to two decimal places over a
# bounded range keeps the arithmetic exact, so the test measures the algorithm rather
# than the width of a mantissa.
tidy = st.integers(min_value=-100_000, max_value=100_000).map(lambda item: item / 100.0)
tidy_series = st.lists(tidy, min_size=MIN_HISTORY, max_size=12)


# --------------------------------------------------------------------------------------
# two_sided_p
# --------------------------------------------------------------------------------------


@given(z=finite)
@NO_DEADLINE
def test_p_value_is_a_probability(z: float) -> None:
    assert 0.0 <= two_sided_p(z) <= 1.0


@given(z=finite)
@NO_DEADLINE
def test_p_value_is_symmetric_in_sign(z: float) -> None:
    assert two_sided_p(z) == pytest.approx(two_sided_p(-z))


@given(small=finite, large=finite)
@NO_DEADLINE
def test_p_value_falls_as_the_z_grows(small: float, large: float) -> None:
    assume(abs(small) < abs(large))
    assert two_sided_p(large) <= two_sided_p(small)


def test_a_zero_z_is_certainly_unremarkable() -> None:
    assert two_sided_p(0.0) == pytest.approx(1.0)


def test_a_nan_z_is_a_caller_bug_not_a_result() -> None:
    """Returning 1.0 for NaN would quietly turn a broken test into "no drift"."""
    with pytest.raises(ValueError, match="NaN"):
        two_sided_p(math.nan)


# --------------------------------------------------------------------------------------
# robust_z
# --------------------------------------------------------------------------------------


@given(value=tidy, baseline=tidy_series, shift=tidy)
@NO_DEADLINE
def test_robust_z_is_translation_invariant(
    value: float, baseline: list[float], shift: float
) -> None:
    """Adding a constant to every measurement must not create a detection."""
    plain = robust_z(value=value, baseline=baseline)
    shifted = robust_z(value=value + shift, baseline=[item + shift for item in baseline])
    if plain is None:
        assert shifted is None
    else:
        assert shifted is not None
        assert shifted == pytest.approx(plain, rel=1e-6, abs=1e-6)


@given(
    value=tidy,
    baseline=tidy_series,
    scale=st.sampled_from([0.25, 0.5, 2.0, 4.0, 100.0]),
)
@NO_DEADLINE
def test_robust_z_is_scale_invariant(value: float, baseline: list[float], scale: float) -> None:
    """Changing the unit -- cents to dollars -- must not change the surprise."""
    plain = robust_z(value=value, baseline=baseline)
    scaled = robust_z(value=value * scale, baseline=[item * scale for item in baseline])
    if plain is None:
        assert scaled is None
    else:
        assert scaled is not None
        assert scaled == pytest.approx(plain, rel=1e-6, abs=1e-6)


@given(baseline=st.lists(finite, max_size=MIN_HISTORY - 1), value=finite)
@NO_DEADLINE
def test_robust_z_refuses_a_short_history(baseline: list[float], value: float) -> None:
    assert robust_z(value=value, baseline=baseline) is None


@given(constant=finite, value=finite)
@NO_DEADLINE
def test_robust_z_refuses_a_flat_baseline(constant: float, value: float) -> None:
    """A baseline with no spread gives no scale, so there is nothing to divide by.

    Returning a huge z here would make the very first change after a quiet period look
    like a certainty, which is precisely when the system should say "I do not know".
    """
    assert robust_z(value=value, baseline=[constant] * 5) is None


def test_robust_z_measures_what_it_claims() -> None:
    baseline = [10.0, 11.0, 12.0, 8.0, 9.0]
    found = robust_z(value=20.0, baseline=baseline)
    assert found is not None
    assert found > 3.0


def test_robust_z_survives_a_tie_heavy_baseline() -> None:
    """A row count that repeats exactly still has a usable scale.

    Three of five values sit on the median, so the MAD is zero. Refusing here would
    silence the detector on precisely the tables that are stable enough to be worth
    watching.
    """
    found = robust_z(value=20.0, baseline=[10.0, 10.0, 12.0, 8.0, 10.0])
    assert found is not None
    assert found > 3.0


# --------------------------------------------------------------------------------------
# two_proportion_z
# --------------------------------------------------------------------------------------


@given(
    successes_a=counts,
    total_a=st.integers(min_value=1, max_value=1_000_000),
    successes_b=counts,
    total_b=st.integers(min_value=1, max_value=1_000_000),
)
@NO_DEADLINE
def test_two_proportion_z_is_antisymmetric(
    successes_a: int, total_a: int, successes_b: int, total_b: int
) -> None:
    assume(successes_a <= total_a and successes_b <= total_b)
    forward = two_proportion_z(
        successes_a=successes_a, total_a=total_a, successes_b=successes_b, total_b=total_b
    )
    backward = two_proportion_z(
        successes_a=successes_b, total_a=total_b, successes_b=successes_a, total_b=total_a
    )
    if forward is None:
        assert backward is None
    else:
        assert backward is not None
        assert backward == pytest.approx(-forward, rel=1e-9, abs=1e-9)


@given(total=st.integers(min_value=1, max_value=100_000), fraction=st.floats(0.01, 0.99))
@NO_DEADLINE
def test_identical_proportions_give_a_zero_z(total: int, fraction: float) -> None:
    successes = max(1, min(total - 1, round(total * fraction)))
    found = two_proportion_z(
        successes_a=successes, total_a=total, successes_b=successes, total_b=total
    )
    if found is not None:
        assert found == pytest.approx(0.0, abs=1e-9)


def test_two_proportion_z_refuses_a_degenerate_pooled_proportion() -> None:
    """All nulls or no nulls: the normal approximation says nothing, so neither do we."""
    assert two_proportion_z(successes_a=0, total_a=100, successes_b=0, total_b=100) is None
    assert two_proportion_z(successes_a=100, total_a=100, successes_b=100, total_b=100) is None
    assert two_proportion_z(successes_a=0, total_a=0, successes_b=1, total_b=10) is None


def test_two_proportion_z_rejects_impossible_counts() -> None:
    with pytest.raises(ValueError, match="within their total"):
        two_proportion_z(successes_a=11, total_a=10, successes_b=1, total_b=10)


# --------------------------------------------------------------------------------------
# log_ratio
# --------------------------------------------------------------------------------------


@given(
    value=st.floats(min_value=1e-6, max_value=1e9),
    baseline=st.floats(min_value=1e-6, max_value=1e9),
)
@NO_DEADLINE
def test_log_ratio_is_antisymmetric(value: float, baseline: float) -> None:
    """Doubling and halving are the same magnitude, which is why the log is there."""
    forward = log_ratio(value=value, baseline=baseline)
    backward = log_ratio(value=baseline, baseline=value)
    assert forward is not None
    assert backward is not None
    assert forward == pytest.approx(-backward, rel=1e-9, abs=1e-9)


@given(value=st.floats(min_value=1e-6, max_value=1e9))
@NO_DEADLINE
def test_log_ratio_of_no_change_is_zero(value: float) -> None:
    assert log_ratio(value=value, baseline=value) == pytest.approx(0.0, abs=1e-12)


@pytest.mark.parametrize(
    ("value", "baseline"),
    [(0.0, 1.0), (1.0, 0.0), (-1.0, 1.0), (math.inf, 1.0), (1.0, math.nan)],
)
def test_log_ratio_refuses_a_non_positive_or_non_finite_side(value: float, baseline: float) -> None:
    assert log_ratio(value=value, baseline=baseline) is None
