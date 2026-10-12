"""Match strength: temporal alignment, scope overlap, specificity, competing explanations."""

from __future__ import annotations

import datetime as _dt
from typing import Any

import pytest
from _context_support import DAY, HOUR, T0, candidate, event
from godwit_context import (
    DEFAULT_TEMPORAL,
    ContextType,
    MatchPolicy,
    OverlapTier,
    StrengthWeights,
    TemporalPolicy,
    Window,
)
from godwit_context.matching import (
    _EventView,
    match_candidate,
    scope_overlap,
    specificity,
    subject_of_candidate,
    temporal_proximity,
)
from hypothesis import given
from hypothesis import strategies as st

WINDOW = Window(start=T0 - DAY, end=T0)


def _flat(_t: ContextType, _f: str, _s: str) -> float:
    return 0.5


def test_inside_the_window_is_full_credit() -> None:
    assert temporal_proximity(WINDOW, event("d"), DEFAULT_TEMPORAL[ContextType.DEPLOY]) == 1.0


def test_deploy_explains_from_deploy_time_not_before() -> None:
    policy = DEFAULT_TEMPORAL[ContextType.DEPLOY]
    after_window = event("d", start=T0 + HOUR)
    assert temporal_proximity(WINDOW, after_window, policy) == 0.0  # no lead for deploys


def test_campaign_explains_hours_later_with_decay() -> None:
    policy = DEFAULT_TEMPORAL[ContextType.CAMPAIGN]
    early = event("c", ContextType.CAMPAIGN, start=T0 - DAY - 6 * HOUR)
    much_earlier = event("c2", ContextType.CAMPAIGN, start=T0 - 4 * DAY)
    late = event("c3", ContextType.CAMPAIGN, start=T0 - 9 * DAY)
    a, b, c = (temporal_proximity(WINDOW, e, policy) for e in (early, much_earlier, late))
    assert 1.0 > a > b > 0.0
    assert c == 0.0


def test_holiday_has_a_lead() -> None:
    policy = DEFAULT_TEMPORAL[ContextType.HOLIDAY]
    tomorrow = event("h", ContextType.HOLIDAY, start=T0 + 12 * HOUR, duration=DAY)
    assert 0.0 < temporal_proximity(WINDOW, tomorrow, policy) < 1.0


@given(gap_hours=st.integers(0, 24 * 10))
def test_temporal_credit_is_monotone_in_distance(gap_hours: int) -> None:
    policy = TemporalPolicy(lag=5 * DAY, half_life=DAY)
    near = event("n", start=T0 - DAY - _dt.timedelta(hours=gap_hours))
    far = event("f", start=T0 - DAY - _dt.timedelta(hours=gap_hours + 1))
    assert temporal_proximity(WINDOW, near, policy) >= temporal_proximity(WINDOW, far, policy)


@pytest.mark.parametrize(
    ("kwargs", "tier"),
    [
        ({"pairs": {"country": "PT"}}, OverlapTier.SEGMENT),
        ({"columns": ["amount"]}, OverlapTier.COLUMN),
        ({}, OverlapTier.SOURCE),
        ({"pairs": {"country": "PT", "status": "refund", "channel": "web"}}, OverlapTier.COARSER),
        ({"sources": []}, OverlapTier.GLOBAL),
        ({"columns": ["merchant"]}, OverlapTier.OUT_OF_SCOPE),
        ({"sources": ["src_b"]}, OverlapTier.DISJOINT),
    ],
)
def test_scope_tiers(kwargs: dict[str, Any], tier: OverlapTier) -> None:
    subject = subject_of_candidate(
        candidate("c", pairs={"country": "PT", "status": "refund"}), WINDOW
    )
    assert scope_overlap(_EventView.of(event("e", **kwargs)), subject) is tier


def test_segment_values_are_compared_not_just_columns() -> None:
    subject = subject_of_candidate(candidate("c", pairs={"country": "PT"}), WINDOW)
    other = _EventView.of(event("e", pairs={"country": "US"}))
    assert scope_overlap(other, subject) is OverlapTier.OUT_OF_SCOPE


def test_specificity_prefers_narrow_and_short() -> None:
    narrow = event("a", pairs={"country": "PT"})
    source = event("b")
    wide = event("c", sources=["s1", "s2", "s3", "s4", "s5"])
    glob = event("d", sources=[])
    long = event("e", duration=90 * DAY)
    values = [specificity(e) for e in (narrow, source, wide, glob)]
    assert values == sorted(values, reverse=True)
    assert specificity(long) < specificity(source) / 3


def test_competing_explanations_are_all_retained_and_ranked() -> None:
    subject = subject_of_candidate(candidate("c", pairs={"country": "PT"}), WINDOW)
    events = [
        event("deploy"),
        event("campaign", ContextType.CAMPAIGN, pairs={"country": "PT"}, start=T0 - 3 * HOUR),
        event("holiday", ContextType.HOLIDAY, duration=DAY, start=T0 - DAY),
        event("elsewhere", sources=["src_z"]),
    ]
    matches = match_candidate(subject, events, peers=(), prior=_flat, policy=MatchPolicy())
    assert matches[0].kind == "campaign.campaign"
    assert {m.kind for m in matches} == {"campaign.campaign", "deploy.deploy", "holiday.holiday"}
    assert [m.strength for m in matches] == sorted((m.strength for m in matches), reverse=True)


def test_prior_moves_strength() -> None:
    subject = subject_of_candidate(candidate("c"), WINDOW)
    low = match_candidate(
        subject, [event("d")], peers=(), prior=lambda *_: 0.0, policy=MatchPolicy()
    )
    high = match_candidate(
        subject, [event("d")], peers=(), prior=lambda *_: 1.0, policy=MatchPolicy()
    )
    assert high[0].strength - low[0].strength == pytest.approx(0.3 * 0.8)


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="sum to 1"):
        StrengthWeights(prior=0.5, specificity=0.5, counterfactual=0.5)
