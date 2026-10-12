"""The distribution functions against published values, and their mathematical properties."""

from __future__ import annotations

import math

import pytest
from godwit_detect.stats import (
    beta_regularized,
    chi2_sf,
    dispersion_factor,
    fisher_combine,
    kolmogorov_sf,
    norm_sf,
    prediction_test,
    t_sf,
)
from hypothesis import given
from hypothesis import strategies as st


@pytest.mark.parametrize(
    ("x", "df", "expected"),
    [
        (3.841458820694124, 1, 0.05),
        (16.918977604620448, 9, 0.05),
        (6.634896601021213, 1, 0.01),
        (2.0, 4, 0.7357588823428847),
        (100.0, 50, 3.454931382984871e-05),
        (0.0, 3, 1.0),
    ],
)
def test_chi2_sf_matches_tables(x: float, df: int, expected: float) -> None:
    assert chi2_sf(x, df) == pytest.approx(expected, rel=1e-9)


@pytest.mark.parametrize(
    ("t", "df", "expected"),
    [
        (2.015048372669157, 5, 0.05),
        (1.6448536269514722, 1e7, 0.05),
        (0.0, 3, 0.5),
        (-2.0, 10, 0.963306),
    ],
)
def test_t_sf_matches_tables(t: float, df: float, expected: float) -> None:
    assert t_sf(t, df) == pytest.approx(expected, abs=1e-6)


def test_normal_and_kolmogorov_tails() -> None:
    assert norm_sf(1.959963984540054) == pytest.approx(0.025, rel=1e-9)
    assert kolmogorov_sf(1.3580986393225505) == pytest.approx(0.05, abs=1e-6)
    assert kolmogorov_sf(0.1) == 1.0


def test_fisher_combination_of_one_p_is_that_p() -> None:
    assert fisher_combine([0.2]) == pytest.approx(0.2, rel=1e-9)
    assert fisher_combine([0.01, 0.01]) < 0.01


@given(
    a=st.floats(0.1, 50),
    b=st.floats(0.1, 50),
    x=st.floats(1e-9, 1.0 - 1e-9),
    y=st.floats(1e-9, 1.0 - 1e-9),
)
def test_incomplete_beta_is_a_cdf(a: float, b: float, x: float, y: float) -> None:
    low, high = sorted((x, y))
    assert 0.0 <= beta_regularized(a, b, low) <= beta_regularized(a, b, high) + 1e-12 <= 1.0 + 1e-12
    assert beta_regularized(a, b, x) + beta_regularized(b, a, 1.0 - x) == pytest.approx(
        1.0, abs=1e-9
    )


@given(x=st.floats(0.0, 500.0), y=st.floats(0.0, 500.0), df=st.integers(1, 200))
def test_chi2_sf_is_a_decreasing_probability(x: float, y: float, df: int) -> None:
    low, high = sorted((x, y))
    assert 0.0 <= chi2_sf(high, df) <= chi2_sf(low, df) + 1e-12 <= 1.0 + 1e-12


@given(st.lists(st.tuples(st.floats(0.0, 1e4), st.integers(1, 30)), max_size=12))
def test_dispersion_never_makes_a_test_more_liberal(pairs: list[tuple[float, int]]) -> None:
    assert dispersion_factor([(s, float(d)) for s, d in pairs]) >= 1.0


def test_dispersion_ignores_too_few_references() -> None:
    assert dispersion_factor([(1000.0, 1.0), (1000.0, 1.0)]) == 1.0
    assert dispersion_factor([(40.0, 4.0)] * 5) == pytest.approx(10.0 / (1 - 2 / 36) ** 3)


def test_prediction_test_is_exact_on_the_reference_mean() -> None:
    result = prediction_test(5.0, [4.0, 5.0, 6.0])
    assert result.statistic == 0.0
    assert result.p_two_sided == pytest.approx(1.0)
    assert prediction_test(50.0, [4.0, 5.0, 6.0]).p_upper < 0.01


def test_prediction_test_survives_a_flat_history() -> None:
    assert prediction_test(1.0, [1.0, 1.0, 1.0]).p_two_sided == pytest.approx(1.0)
    assert math.isfinite(prediction_test(1.1, [1.0, 1.0, 1.0]).statistic)
    with pytest.raises(ValueError, match="two reference values"):
        prediction_test(1.0, [1.0])
