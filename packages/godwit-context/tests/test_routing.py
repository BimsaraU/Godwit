"""Residual routing: thresholds, audit, reversal, learned priors, A3 persistence."""

from __future__ import annotations

from typing import Any

import pytest
from _context_support import DAY, T0, candidate, event, peer
from godwit_context import (
    ContextRouter,
    ContextType,
    MemoryAuditSink,
    Outcome,
    PriorBook,
    Route,
    RoutingPolicy,
    StoreAuditSink,
    UnknownDecisionError,
    data_quality_from_candidates,
)
from godwit_contracts import CandidateId, SourceId
from godwit_store import assert_chain_intact, audit_query, bootstrap_schema, create_store_engine
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

QUIET = [peer(s, 0.0) for s in ("src_x", "src_y", "src_z")]


def _router(**kwargs: Any) -> tuple[ContextRouter, MemoryAuditSink]:
    sink = MemoryAuditSink()
    return ContextRouter(audit=sink, **kwargs), sink


def test_explained_candidates_carry_their_explanation_and_an_audit_record() -> None:
    router, sink = _router()
    (decision,) = router.route([candidate("c1")], events=[event("deploy")], peers=QUIET, at=T0)
    assert decision.route is Route.EXPLAINED
    assert decision.explanation is not None
    assert decision.explanation.kind == "deploy.deploy"
    (audited,) = [e for e in sink.events if e.action == "context_explain"]
    assert audited.subject_id == "c1"
    assert audited.event_id == decision.decision_id
    assert audited.detail_digest is not None


def test_below_threshold_proceeds_with_context_recorded() -> None:
    router, sink = _router(routing=RoutingPolicy(threshold=0.99))
    (decision,) = router.route([candidate("c1")], events=[event("deploy")], peers=QUIET, at=T0)
    assert decision.route is Route.PROCEED
    assert decision.explanation is None
    assert len(decision.matches) == 1
    assert not [e for e in sink.events if e.action == "context_explain"]


def test_threshold_is_per_source() -> None:
    router, _ = _router(routing=RoutingPolicy(per_source={SourceId("src_a"): 0.99}))
    decisions = router.route(
        [candidate("a"), candidate("b", source="src_b")],
        events=[event("d1"), event("d2", sources=["src_b"])],
        peers=QUIET,
        at=T0,
    )
    assert [d.route for d in decisions] == [Route.PROCEED, Route.EXPLAINED]


def test_unaligned_contexts_produce_no_matches() -> None:
    router, _ = _router()
    (decision,) = router.route(
        [candidate("c1")], events=[event("old", start=T0 - 10 * DAY)], peers=QUIET, at=T0
    )
    assert decision.matches == ()
    assert decision.route is Route.PROCEED


def test_reversal_is_a_new_record_audited_and_sticky() -> None:
    router, sink = _router()
    (original,) = router.route([candidate("c1")], events=[event("deploy")], peers=QUIET, at=T0)
    reversal = router.reverse(
        original.decision_id, actor="rev_3", reason="analyst_disagrees", at=T0 + DAY
    )
    assert reversal.route is Route.PROCEED
    assert reversal.reverses == original.decision_id
    assert router.decisions == (original, reversal)
    assert router.current(CandidateId("c1")) is reversal
    (audited,) = [e for e in sink.events if e.action == "context_reverse"]
    assert audited.correlation_id == original.decision_id and audited.actor == "rev_3"

    (again,) = router.route(
        [candidate("c1")], events=[event("deploy")], peers=QUIET, at=T0 + 2 * DAY
    )
    assert again.route is Route.PROCEED
    assert again.matches  # still recorded as context

    with pytest.raises(UnknownDecisionError):
        router.reverse(original.decision_id, actor="rev_3", reason="again", at=T0 + 3 * DAY)
    with pytest.raises(UnknownDecisionError):
        router.reverse("nope", actor="rev_3", reason="x", at=T0)


def test_reversal_reason_must_not_be_free_text() -> None:
    router, _ = _router()
    (original,) = router.route([candidate("c1")], events=[event("deploy")], peers=QUIET, at=T0)
    with pytest.raises(ValueError, match="plain identifiers"):
        router.reverse(original.decision_id, actor="rev_3", reason="customer jane said so", at=T0)


def test_a_schema_change_never_explains_itself() -> None:
    schema = candidate("dq1", detector="metadata.schema_change")
    downstream = candidate("drift1")
    router, _ = _router()
    decisions = router.route(
        [schema, downstream], events=data_quality_from_candidates([schema]), peers=QUIET, at=T0
    )
    assert decisions[0].matches == ()
    assert decisions[1].matches[0].context_type is ContextType.DATA_QUALITY


def test_learned_priors_rise_with_success_and_fall_with_reversal() -> None:
    priors = PriorBook()
    router, _ = _router(priors=priors)
    family, source = "distribution_shift", SourceId("src_a")
    before = priors.prior(ContextType.DEPLOY, family, source)
    decisions = [
        router.route([candidate(f"c{i}")], events=[event(f"d{i}")], peers=QUIET, at=T0)[0]
        for i in range(5)
    ]
    after = priors.prior(ContextType.DEPLOY, family, source)
    assert before == 0.5 < after
    for d in decisions:
        router.reverse(d.decision_id, actor="rev_1", reason="wrong", at=T0 + DAY)
    assert priors.prior(ContextType.DEPLOY, family, source) < before
    assert priors.counts(ContextType.DEPLOY, family, source) == (5.0, 0.0)


def test_priors_back_off_from_source_to_family_to_type() -> None:
    priors = PriorBook()
    for _ in range(20):
        priors.observe(ContextType.HOLIDAY, "rate_change", SourceId("s1"), Outcome.EXPLAINED, at=T0)
    unseen_source = priors.prior(ContextType.HOLIDAY, "rate_change", SourceId("s9"))
    unseen_family = priors.prior(ContextType.HOLIDAY, "graph_anomaly", SourceId("s9"))
    unseen_type = priors.prior(ContextType.DEPLOY, "rate_change", SourceId("s1"))
    assert unseen_source > unseen_family > unseen_type == 0.5


@pytest.fixture
def session() -> Session:
    engine = create_store_engine("sqlite://", poolclass=StaticPool)
    bootstrap_schema(engine)
    return Session(engine)


def test_priors_and_suppressions_persist_through_the_a3_ledger(session: Session) -> None:
    sink = StoreAuditSink(session)
    priors = PriorBook(sink=sink)
    router = ContextRouter(audit=sink, priors=priors)
    (decision,) = router.route([candidate("c1")], events=[event("deploy")], peers=QUIET, at=T0)
    router.reverse(decision.decision_id, actor="rev_1", reason="wrong", at=T0 + DAY)
    router.route([candidate("c2")], events=[event("d2")], peers=QUIET, at=T0 + DAY)
    session.commit()

    reloaded = PriorBook.load(StoreAuditSink(session))
    for key in [(ContextType.DEPLOY, "distribution_shift", SourceId("src_a"))]:
        assert reloaded.prior(*key) == priors.prior(*key)
        assert reloaded.counts(*key) == priors.counts(*key)

    trail = audit_query(session, subject_kind="candidate", subject_id="c1")
    assert [(e.action, e.from_state, e.to_state) for e in trail] == [
        ("context_explain", None, "explained"),
        ("context_reverse", "explained", "proceed"),
    ]
    assert_chain_intact(session, table="audit_events")


def test_a_human_verdict_on_a_proceeding_candidate_teaches_the_prior() -> None:
    priors = PriorBook()
    router, sink = _router(priors=priors, routing=RoutingPolicy(threshold=0.99))
    key = (ContextType.DEPLOY, "distribution_shift", SourceId("src_a"))
    (first,) = router.route([candidate("c1")], events=[event("d1")], peers=QUIET, at=T0)
    assert priors.prior(*key) == 0.5  # proceeding teaches nothing on its own
    router.verdict(first.decision_id, explained_by=None, actor="rev_2", at=T0 + DAY)
    assert priors.prior(*key) < 0.5
    (second,) = router.route([candidate("c2")], events=[event("d2")], peers=QUIET, at=T0)
    router.verdict(second.decision_id, explained_by=ContextType.DEPLOY, actor="rev_2", at=T0)
    assert priors.counts(*key) == (2.0, 1.0)
    assert [e.action for e in sink.events].count("context_verdict") == 2
    with pytest.raises(UnknownDecisionError):
        router.verdict("nope", explained_by=None, actor="rev_2", at=T0)


@given(outcomes=st.lists(st.sampled_from(list(Outcome)), max_size=60))
def test_prior_is_a_probability_and_replays_exactly(outcomes: list[Outcome]) -> None:
    sink = MemoryAuditSink()
    book = PriorBook(sink=sink)
    key = (ContextType.CAMPAIGN, "rate_change", SourceId("s"))
    for outcome in outcomes:
        book.observe(*key, outcome, at=T0)
        assert 0.0 <= book.prior(*key) <= 1.0
    assert PriorBook.load(sink).prior(*key) == book.prior(*key)


@given(n=st.integers(0, 40))
def test_prior_is_monotone_in_successes(n: int) -> None:
    more, fewer = PriorBook(), PriorBook()
    key = (ContextType.DEPLOY, "rate_change", SourceId("s"))
    for book, wins in ((more, n + 1), (fewer, n)):
        for _ in range(wins):
            book.observe(*key, Outcome.EXPLAINED, at=T0)
        for _ in range(40 - wins):
            book.observe(*key, Outcome.NOT_EXPLAINED, at=T0)
    assert more.prior(*key) >= fewer.prior(*key)
