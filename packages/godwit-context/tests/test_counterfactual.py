"""The counterfactual check: a context that did not touch the peers that also moved is
not the explanation.

The acceptance case is the first test: a deploy on source A coincides exactly with a
refund spike on A, but sources B, C and D -- never touched by the deploy -- show the same
spike at the same time. The deploy is temporally perfect and causally irrelevant.
"""

from __future__ import annotations

from _context_support import DAY, T0, candidate, event, peer
from godwit_context import (
    ContextRouter,
    CounterfactualVerdict,
    MatchPolicy,
    MemoryAuditSink,
    PeerObservation,
    Route,
    Window,
)
from godwit_context.matching import match_candidate, subject_of_candidate, subject_of_peer

WINDOW = Window(start=T0 - DAY, end=T0)


def _flat(*_: object) -> float:
    return 0.5


def _route(peers: list[PeerObservation]) -> tuple[Route, float, CounterfactualVerdict]:
    router = ContextRouter(audit=MemoryAuditSink())
    (decision,) = router.route(
        [candidate("spike", pairs={"status": "refund"}, effect=3.0)],
        events=[event("deploy", sources=["src_a"])],
        peers=peers,
        at=T0,
    )
    best = decision.matches[0]
    return decision.route, best.strength, best.counterfactual.verdict


def test_coincident_but_causally_irrelevant_context_is_downgraded() -> None:
    moved_everywhere = [
        peer(s, 2.8, pairs={"status": "refund"}) for s in ("src_b", "src_c", "src_d")
    ]
    route, strength, verdict = _route(moved_everywhere)
    assert verdict is CounterfactualVerdict.CONTRADICTED
    assert route is Route.PROCEED
    assert strength < 0.2

    quiet_elsewhere = [
        peer(s, 0.1, pairs={"status": "refund"}) for s in ("src_b", "src_c", "src_d")
    ]
    route, strength, verdict = _route(quiet_elsewhere)
    assert verdict is CounterfactualVerdict.SUPPORTED
    assert route is Route.EXPLAINED
    assert strength > 0.6


def test_batch_candidates_on_untouched_sources_count_as_changed_peers() -> None:
    router = ContextRouter(audit=MemoryAuditSink())
    batch = [
        candidate(f"c_{s}", source=s, pairs={"status": "refund"}, effect=3.0)
        for s in ("src_a", "src_b", "src_c", "src_d")
    ]
    decisions = router.route(batch, events=[event("deploy", sources=["src_a"])], at=T0)
    (on_a,) = [d for d in decisions if d.source_id == "src_a"]
    assert on_a.matches[0].counterfactual.verdict is CounterfactualVerdict.CONTRADICTED
    assert on_a.route is Route.PROCEED


def test_peers_must_be_comparable() -> None:
    subject = subject_of_candidate(candidate("c", pairs={"status": "refund"}, effect=3.0), WINDOW)
    incomparable = [
        peer("src_b", 3.0, pairs={"country": "PT"}),  # different structure
        peer("src_c", 3.0, pairs={"status": "refund"}, family="rate_change"),
        peer("src_d", 3.0, pairs={"status": "refund"}, at=T0 + 3 * DAY),  # other window
        peer("src_e", -3.0, pairs={"status": "refund"}),  # opposite direction: unchanged
    ]
    (match,) = match_candidate(
        subject,
        [event("deploy")],
        peers=[subject_of_peer(p) for p in incomparable],
        prior=_flat,
        policy=MatchPolicy(),
    )
    assert match.counterfactual.untouched_observed == 1
    assert match.counterfactual.untouched_changed == 0
    assert match.counterfactual.verdict is CounterfactualVerdict.UNTESTABLE


def test_no_peers_is_untestable_and_partially_credited() -> None:
    _, strength, verdict = _route([])
    assert verdict is CounterfactualVerdict.UNTESTABLE
    _, supported, _ = _route([peer(s, 0.0, pairs={"status": "refund"}) for s in "bcd"])
    assert strength < supported


def test_touched_peers_moving_too_supports_the_context() -> None:
    """A holiday that hit every source in its jurisdiction, and none outside it."""
    holiday = event("h", sources=["us1", "us2", "us3"], duration=DAY, start=T0 - DAY)
    subject = subject_of_candidate(candidate("c", source="us1", effect=-2.0), WINDOW)
    peers = [
        peer("us2", -2.1),
        peer("us3", -1.9),
        peer("de1", 0.1),
        peer("de2", -0.2),
        peer("de3", 0.0),
    ]
    (match,) = match_candidate(
        subject,
        [holiday],
        peers=[subject_of_peer(p) for p in peers],
        prior=_flat,
        policy=MatchPolicy(),
    )
    cf = match.counterfactual
    assert (cf.touched_observed, cf.touched_changed) == (3, 3)
    assert (cf.untouched_observed, cf.untouched_changed) == (3, 0)
    assert cf.verdict is CounterfactualVerdict.SUPPORTED


def test_a_context_whose_other_targets_stayed_flat_is_inconsistent() -> None:
    """A holiday over four sources does not explain one source's drop if the other three
    sources it closed did not move."""
    holiday = event("h", sources=["us1", "us2", "us3", "us4"], duration=DAY, start=T0 - DAY)
    subject = subject_of_candidate(candidate("c", source="us1", effect=-2.0), WINDOW)
    flat = [peer(s, 0.05) for s in ("us2", "us3", "us4", "de1", "de2", "de3")]
    (match,) = match_candidate(
        subject,
        [holiday],
        peers=[subject_of_peer(p) for p in flat],
        prior=_flat,
        policy=MatchPolicy(),
    )
    assert match.counterfactual.verdict is CounterfactualVerdict.INCONSISTENT
    assert match.downgraded


def test_peers_hit_by_a_same_type_event_are_not_controls() -> None:
    """New Year: the German drop is explained by the German holiday, so it is neither
    evidence for nor against the US holiday."""
    us = event("us", sources=["us1"], duration=DAY, start=T0 - DAY)
    de = event("de", sources=["de1", "de2", "de3"], duration=DAY, start=T0 - DAY)
    subject = subject_of_candidate(candidate("c", source="us1", effect=-2.0), WINDOW)
    peers = [subject_of_peer(peer(s, -2.0)) for s in ("de1", "de2", "de3")]
    matches = match_candidate(subject, [us, de], peers=peers, prior=_flat, policy=MatchPolicy())
    (on_us,) = [m for m in matches if m.kind == "deploy.us"]
    assert on_us.counterfactual.confounded == 3
    assert on_us.counterfactual.verdict is CounterfactualVerdict.UNTESTABLE
