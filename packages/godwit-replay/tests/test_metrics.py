"""The metrics, including the identities that make tie handling correct.

The property tests are the ones worth reading. ``auc(y, s) + auc(y, -s) == 1`` holds only if
ties get half credit, and it is exactly the property a hand-rolled AUC gets wrong.
"""

from __future__ import annotations

import numpy as np
import pytest
from godwit_replay.metrics import (
    average_precision,
    bootstrap_ci,
    brier,
    expected_calibration_error,
    positive_rate,
    precision_at_k,
    recall_at_k,
    roc_auc,
)
from hypothesis import assume, given, settings
from hypothesis import strategies as st

LABELS = st.lists(st.integers(min_value=0, max_value=1), min_size=4, max_size=60)
SCORES = st.lists(
    st.floats(min_value=-100.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    min_size=4,
    max_size=60,
)


def _pair(labels: list[int], scores: list[float]) -> tuple[list[int], list[float]]:
    size = min(len(labels), len(scores))
    return labels[:size], scores[:size]


# -- known values -------------------------------------------------------------------------


def test_perfect_separation_scores_one() -> None:
    assert roc_auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0
    assert average_precision([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0


def test_reversed_separation_scores_zero() -> None:
    assert roc_auc([0, 0, 1, 1], [0.9, 0.8, 0.2, 0.1]) == 0.0


def test_all_ties_score_a_half() -> None:
    """Every pair is a tie, so every pair gets half credit. Not 1.0, not 0.0."""
    assert roc_auc([0, 1, 0, 1], [0.5, 0.5, 0.5, 0.5]) == 0.5


def test_a_single_class_is_undefined_not_a_coin_flip() -> None:
    assert np.isnan(roc_auc([1, 1, 1], [0.1, 0.5, 0.9]))
    assert np.isnan(average_precision([0, 0, 0], [0.1, 0.5, 0.9]))
    assert np.isnan(recall_at_k([0, 0, 0], [0.1, 0.5, 0.9], 2))


def test_precision_at_k_is_over_what_exists() -> None:
    """precision@100 on four rows is precision over four rows, not over a padded hundred."""
    assert precision_at_k([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1], 2) == 1.0
    assert precision_at_k([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1], 100) == 0.5


def test_recall_at_k_counts_positives_caught() -> None:
    assert recall_at_k([1, 1, 0, 0], [0.9, 0.1, 0.8, 0.2], 2) == 0.5


def test_brier_and_calibration_on_a_perfect_forecast() -> None:
    labels = [0, 0, 1, 1]
    perfect = [0.0, 0.0, 1.0, 1.0]
    assert brier(labels, perfect) == 0.0
    assert expected_calibration_error(labels, perfect) == 0.0


def test_a_constant_forecast_at_the_base_rate_is_calibrated_but_useless() -> None:
    labels = [0, 0, 1, 1]
    base = [0.5] * 4
    assert brier(labels, base) == 0.25
    assert expected_calibration_error(labels, base) == 0.0
    assert roc_auc(labels, base) == 0.5


def test_probabilities_are_required_where_they_are_required() -> None:
    with pytest.raises(ValueError, match="probabilities in"):
        brier([0, 1], [-3.0, 4.0])
    with pytest.raises(ValueError, match="probabilities in"):
        expected_calibration_error([0, 1], [-3.0, 4.0])


def test_malformed_input_is_refused() -> None:
    with pytest.raises(ValueError, match="disagree in shape"):
        roc_auc([0, 1], [0.5])
    with pytest.raises(ValueError, match="must be 0 or 1"):
        roc_auc([0, 2], [0.5, 0.6])
    with pytest.raises(ValueError, match="NaN or infinity"):
        roc_auc([0, 1], [0.5, float("nan")])
    with pytest.raises(ValueError, match="k must be positive"):
        precision_at_k([0, 1], [0.5, 0.6], 0)


def test_positive_rate() -> None:
    assert positive_rate([0, 0, 0, 1]) == 0.25
    assert np.isnan(positive_rate([]))


# -- properties ---------------------------------------------------------------------------


@given(labels=LABELS, scores=SCORES)
@settings(max_examples=200, deadline=None)
def test_auc_is_a_probability(labels: list[int], scores: list[float]) -> None:
    y, s = _pair(labels, scores)
    assume(0 < sum(y) < len(y))
    value = roc_auc(y, s)
    assert 0.0 <= value <= 1.0


@given(labels=LABELS, scores=SCORES)
@settings(max_examples=200, deadline=None)
def test_auc_of_negated_scores_is_one_minus_auc(labels: list[int], scores: list[float]) -> None:
    """The identity that only holds under average-rank tie handling."""
    y, s = _pair(labels, scores)
    assume(0 < sum(y) < len(y))
    negated = [-value for value in s]
    assert roc_auc(y, s) + roc_auc(y, negated) == pytest.approx(1.0)


@given(labels=LABELS, scores=SCORES, shift=st.floats(-10.0, 10.0), scale=st.floats(0.5, 10.0))
@settings(max_examples=100, deadline=None)
def test_auc_is_invariant_under_a_positive_monotone_transform(
    labels: list[int], scores: list[float], shift: float, scale: float
) -> None:
    """AUC depends on the ranking, not on the units the ranking is expressed in.

    The scale is bounded away from zero on purpose. A transform small enough to collapse two
    distinct float scores into the same value creates a tie that was not there, and the AUC
    then legitimately changes. That is floating point, not a bug in the metric, and a property
    test that pretended otherwise would be testing the wrong thing.
    """
    y, s = _pair(labels, scores)
    assume(0 < sum(y) < len(y))
    transformed = [value * scale + shift for value in s]
    assume(len(set(transformed)) == len(set(s)))
    assert roc_auc(y, s) == pytest.approx(roc_auc(y, transformed))


@given(labels=LABELS, scores=SCORES)
@settings(max_examples=100, deadline=None)
def test_average_precision_is_a_probability(labels: list[int], scores: list[float]) -> None:
    """AP is in [0, 1] and nothing stronger is claimed.

    In particular AP is NOT bounded below by the base rate. With every score tied, the
    step-wise sum depends on the order the tied rows happen to sit in, and can fall below it.
    A test asserting the lower bound would be asserting a folk theorem.
    """
    y, s = _pair(labels, scores)
    assume(sum(y) > 0)
    assert 0.0 <= average_precision(y, s) <= 1.0


@given(labels=LABELS, scores=SCORES, k=st.integers(1, 10))
@settings(max_examples=100, deadline=None)
def test_recall_at_k_is_monotone_in_k(labels: list[int], scores: list[float], k: int) -> None:
    y, s = _pair(labels, scores)
    assume(sum(y) > 0)
    assert recall_at_k(y, s, k) <= recall_at_k(y, s, k + 1) + 1e-12


@given(labels=LABELS, probabilities=st.lists(st.floats(0.0, 1.0), min_size=4, max_size=60))
@settings(max_examples=100, deadline=None)
def test_calibration_error_is_bounded(labels: list[int], probabilities: list[float]) -> None:
    y, p = _pair(labels, probabilities)
    assume(len(y) > 0)
    assert 0.0 <= expected_calibration_error(y, p) <= 1.0


# -- the bootstrap -------------------------------------------------------------------------


def test_the_bootstrap_is_reproducible_from_its_seed() -> None:
    labels = [0, 1] * 30
    scores = [float(index % 7) for index in range(60)]
    left = bootstrap_ci(roc_auc, labels, scores, seed=11, resamples=200)
    right = bootstrap_ci(roc_auc, labels, scores, seed=11, resamples=200)
    other = bootstrap_ci(roc_auc, labels, scores, seed=12, resamples=200)
    assert left.model_dump() == right.model_dump()
    assert (left.low, left.high) != (other.low, other.high)


def test_the_bootstrap_interval_brackets_the_point_estimate() -> None:
    labels = [0] * 40 + [1] * 40
    scores = [float(index) for index in range(80)]
    interval = bootstrap_ci(roc_auc, labels, scores, seed=3, resamples=300)
    assert interval.low <= interval.point <= interval.high
    assert interval.width >= 0.0
    assert interval.resamples <= 300


def test_the_bootstrap_reports_how_many_draws_survived() -> None:
    """One positive in eighty rows: many resamples contain none, and the count says so."""
    labels = [0] * 79 + [1]
    scores = [float(index) for index in range(80)]
    interval = bootstrap_ci(roc_auc, labels, scores, seed=5, resamples=100)
    assert interval.resamples < 100


def test_the_bootstrap_refuses_a_nonsense_level() -> None:
    with pytest.raises(ValueError, match="strictly between"):
        bootstrap_ci(roc_auc, [0, 1], [0.1, 0.9], seed=1, level=1.0)
