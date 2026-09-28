"""Store behaviours that do not belong to dedup, FDR, lifecycle or ranking.

Protocol conformance, the conservative narrow ``ingest``, suppression and its reversal,
the refusals a malformed detector run gets, and the contract gaps this package had to
work around -- each of the last group with an ``xfail`` that starts passing the day the
change request is accepted.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from _store_support import CandidateSpec
from godwit_contracts import (
    AuditEvent,
    ContentHash,
    Destination,
    EgressRecord,
    Instant,
    PatternLifecycle,
    Plane,
    RedactionAction,
    RunId,
    Sensitivity,
    SnapshotId,
)
from godwit_contracts import (
    PatternStore as PatternStoreProtocol,
)
from godwit_store.errors import StoreIntegrityError
from godwit_store.fdr import HoldoutKind, HoldoutPolicy, HypothesisFamily, ValidationStatus
from godwit_store.ledger import append_audit, append_egress, audit_query
from godwit_store.schema import CandidateRow, PatternRow, SuppressionRow
from godwit_store.signature import signature_of
from godwit_store.store import PatternStore
from sqlalchemy import select
from sqlalchemy.orm import Session


def _family(run_id: str, at: Instant, test_count: int = 1) -> HypothesisFamily:
    return HypothesisFamily(
        run_id=RunId(run_id),
        snapshot_id=SnapshotId("snap_2"),
        detector="segment_divergence",
        detector_version=1,
        test_count=test_count,
        declared_at=at,
    )


# ------------------------------------------------------------------------------------
# The protocol
# ------------------------------------------------------------------------------------


def test_the_store_satisfies_the_contract_protocol(session: Session) -> None:
    """Checked at runtime as well as by mypy, because a Protocol is a promise.

    ``runtime_checkable`` only verifies that the methods exist, not their signatures.
    That is still worth asserting: the failure it catches is a method renamed during a
    refactor, which mypy catches at the call site and nowhere else if nobody calls it.
    """
    assert isinstance(PatternStore(session), PatternStoreProtocol)


def test_the_narrow_ingest_bars_everything_from_the_operational_queue(
    session: Session, at: Instant
) -> None:
    """The cost of the protocol's convenience signature, made explicit.

    ``ingest`` carries no run metadata, so there is no holdout, so nothing it stores is
    ``VALIDATED``. That is the safe default: a store that let unvalidated findings into
    a fifty-a-day alert queue because the caller used the short signature would be
    optimising for the wrong thing.
    """
    store = PatternStore(session)
    touched = store.ingest([CandidateSpec(candidate_id="c1", created_at=at).build()])
    assert len(touched) == 1
    row = session.get(PatternRow, str(touched[0]))
    assert row is not None
    assert row.validation_status == ValidationStatus.NOT_TESTED.value


def test_get_returns_a_rebuilt_contract_object(session: Session, at: Instant) -> None:
    store = PatternStore(session)
    (pattern_id,) = store.ingest([CandidateSpec(candidate_id="c1", created_at=at).build()])
    pattern = store.get(pattern_id)
    assert pattern is not None
    assert pattern.pattern_id == pattern_id
    assert pattern.representative.candidate_id == "c1"
    assert pattern.lifecycle is PatternLifecycle.PROPOSED
    assert pattern.segment.predicates[0].column.sensitivity is Sensitivity.SCHEMA_NAME
    assert pattern.segment.predicates[0].values[0].sensitivity is Sensitivity.DATA_VALUE


def test_get_on_an_unknown_pattern_is_none_not_an_error(session: Session) -> None:
    from godwit_contracts import PatternId

    assert PatternStore(session).get(PatternId("pat_nothing")) is None


def test_list_open_is_deterministically_ordered(session: Session, at: Instant) -> None:
    store = PatternStore(session)
    store.ingest_batch(
        family=_family("run_1", at, test_count=3),
        candidates=[
            CandidateSpec(
                candidate_id=f"c{index}",
                created_at=at,
                pairs=(("country", code),),
                p_value=0.001 * (index + 1),
            ).build()
            for index, code in enumerate(("PT", "ES", "FR"))
        ],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    first = store.list_open(snapshot_id=SnapshotId("snap_2"), limit=10)
    second = store.list_open(snapshot_id=SnapshotId("snap_2"), limit=10)
    assert [pattern.pattern_id for pattern in first] == [pattern.pattern_id for pattern in second]
    q_values = [pattern.q_value for pattern in first if pattern.q_value is not None]
    assert q_values == sorted(q_values)


# ------------------------------------------------------------------------------------
# Refusals
# ------------------------------------------------------------------------------------


def test_a_candidate_from_another_snapshot_is_refused(session: Session, at: Instant) -> None:
    """One run is one snapshot. A mixed batch would pool two hypothesis spaces."""
    store = PatternStore(session)
    with pytest.raises(StoreIntegrityError, match="one run is one snapshot"):
        store.ingest_batch(
            family=_family("run_1", at),
            candidates=[
                CandidateSpec(candidate_id="c1", created_at=at, snapshot_id="snap_9").build()
            ],
            holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
            at=at,
        )


def test_a_candidate_from_another_detector_is_refused(session: Session, at: Instant) -> None:
    """A test family is per detector; mixing them dilutes a strong detector's findings."""
    store = PatternStore(session)
    with pytest.raises(StoreIntegrityError, match="a test family is per detector"):
        store.ingest_batch(
            family=_family("run_1", at),
            candidates=[
                CandidateSpec(candidate_id="c1", created_at=at, detector="something_else").build()
            ],
            holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
            at=at,
        )


def test_a_run_that_emitted_more_than_it_tested_is_refused(session: Session, at: Instant) -> None:
    """Surfaced as a detector bug rather than absorbed (deliverable 3)."""
    store = PatternStore(session)
    with pytest.raises(StoreIntegrityError, match="every hypothesis"):
        store.ingest_batch(
            family=_family("run_1", at, test_count=1),
            candidates=[
                CandidateSpec(candidate_id="c1", created_at=at).build(),
                CandidateSpec(candidate_id="c2", created_at=at, statistic=11.0).build(),
            ],
            holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
            at=at,
        )


def test_a_candidate_with_no_p_value_is_stored_unadjusted(session: Session, at: Instant) -> None:
    """Not silently given a p-value, and not silently dropped either.

    Its ranking strength becomes the floor, so an unadjusted finding sorts below every
    adjusted one rather than above them.
    """
    store = PatternStore(session)
    store.ingest_batch(
        family=_family("run_1", at),
        candidates=[CandidateSpec(candidate_id="c1", created_at=at, p_value=None).build()],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    row = session.get(CandidateRow, "c1")
    assert row is not None
    assert row.p_value is None
    assert row.q_value is None


# ------------------------------------------------------------------------------------
# Suppression
# ------------------------------------------------------------------------------------


def test_suppression_is_by_signature_and_survives_the_next_snapshot(
    session: Session, at: Instant
) -> None:
    candidate = CandidateSpec(candidate_id="c1", created_at=at).build()
    store = PatternStore(session)
    store.suppress(
        signature=signature_of(candidate).key,
        reason="known seasonal effect",
        actor="analyst_7",
        at=at,
    )
    report = store.ingest_batch(
        family=_family("run_1", at),
        candidates=[candidate],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    assert report.suppressed == 1
    assert report.patterns_created == ()
    assert report.candidates_stored == 1


def test_suppression_is_reversible_and_both_ends_are_recorded(
    session: Session, at: Instant
) -> None:
    """ "Who silenced this, when, and who turned it back on" has to stay answerable."""
    candidate = CandidateSpec(candidate_id="c1", created_at=at).build()
    signature = signature_of(candidate).key
    store = PatternStore(session)
    store.suppress(signature=signature, reason="noise", actor="analyst_7", at=at)

    assert store.unsuppress(signature=signature, actor="analyst_9", at=at + _dt.timedelta(days=1))
    row = session.scalars(select(SuppressionRow)).one()
    assert row.lifted_at == at + _dt.timedelta(days=1)
    assert row.lifted_by == "analyst_9"

    entries = audit_query(session, subject_kind="signature", subject_id=str(signature))
    assert [entry.action for entry in entries] == ["suppress", "unsuppress"]

    report = store.ingest_batch(
        family=_family("run_2", at),
        candidates=[candidate],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at + _dt.timedelta(days=2),
    )
    assert report.suppressed == 0
    assert len(report.patterns_created) == 1


def test_lifting_a_suppression_that_is_not_there_is_false_not_an_error(
    session: Session, at: Instant
) -> None:
    assert not PatternStore(session).unsuppress(
        signature=ContentHash("sig_nothing"), actor="analyst_7", at=at
    )


def test_suppressing_twice_returns_the_same_suppression(session: Session, at: Instant) -> None:
    store = PatternStore(session)
    signature = ContentHash("sig_1")
    first = store.suppress(signature=signature, reason="noise", actor="a", at=at)
    second = store.suppress(signature=signature, reason="noise again", actor="b", at=at)
    assert first == second
    assert len(session.scalars(select(SuppressionRow)).all()) == 1


# ------------------------------------------------------------------------------------
# Contract gaps -- each paired with a change request
# ------------------------------------------------------------------------------------


@pytest.mark.xfail(reason="CR-A3-lifecycle-has-no-stale", strict=True)
def test_the_lifecycle_has_a_state_for_unsupported_patterns() -> None:
    """``PatternLifecycle`` offers ``EXPIRED``; the brief asks for ``STALE``.

    "Unsupported for N windows" and "deliberately retired" are different facts about a
    pattern and a reviewer needs to tell them apart. ``EXPIRED`` is used, and the
    distinction is carried by the audit event's ``action`` (``expire_stale``) rather
    than by a state nobody defined. See ``docs/change-requests/``.
    """
    assert hasattr(PatternLifecycle, "STALE")


@pytest.mark.xfail(reason="CR-A3-ledger-fields-missing", strict=True)
def test_an_audit_event_can_carry_the_states_it_moved_between(at: Instant) -> None:
    """The brief requires "from what, to what, under which guardrail"; the contract
    carries none of the three. They are stored in columns of their own and passed to
    ``append_audit`` as keyword arguments. See ``docs/change-requests/``.
    """
    event = AuditEvent(
        event_id="aud_1",
        occurred_at=at,
        actor="analyst_7",
        action="lifecycle",
        subject_kind="pattern",
        subject_id="pat_1",
        plane=Plane.CONTROL,
    )
    assert hasattr(event, "from_state")


@pytest.mark.xfail(reason="CR-A3-ledger-fields-missing", strict=True)
def test_an_egress_record_can_carry_its_token_map_reference(at: Instant) -> None:
    """The brief requires "the token map reference" on every egress record.

    Stored in a column of its own and passed to ``append_egress`` as a keyword argument.
    A reference, never a map: the map does not cross the boundary.
    """
    record = EgressRecord(
        record_id="egr_1",
        occurred_at=at,
        destination=Destination.LLM_PROVIDER,
        purpose="explain",
        actor="godwit-llm",
        policy_id="pol_1",
        policy_version=1,
        content_digest=ContentHash("b2_x"),
        sensitivity_before=Sensitivity.DATA_VALUE,
        sensitivity_after=Sensitivity.TOKEN,
        actions_applied=(RedactionAction.TOKENISE,),
    )
    assert hasattr(record, "token_map_ref")


def test_the_workaround_for_those_gaps_actually_stores_the_fields(
    session: Session, at: Instant
) -> None:
    """The gaps are worked around, not ignored. Proof that nothing was lost."""
    append_audit(
        session,
        AuditEvent(
            event_id="aud_1",
            occurred_at=at,
            actor="analyst_7",
            action="lifecycle",
            subject_kind="pattern",
            subject_id="pat_1",
            plane=Plane.CONTROL,
        ),
        from_state="proposed",
        to_state="confirmed",
        guardrail_id="gr_review",
        guardrail_version=2,
    )
    entry = audit_query(session, subject_id="pat_1")[0]
    assert (entry.from_state, entry.to_state) == ("proposed", "confirmed")
    assert (entry.guardrail_id, entry.guardrail_version) == ("gr_review", 2)

    # Bound to a local first: ruff reads a string literal passed to anything named
    # "*token*" as a hardcoded credential. It is a pointer to a map in the data
    # plane, and the map is the thing that never crosses.
    map_reference = "tokmap://data-plane/2024-01-01/batch-7"
    egress = append_egress(
        session,
        EgressRecord(
            record_id="egr_1",
            occurred_at=at,
            destination=Destination.LLM_PROVIDER,
            purpose="explain",
            actor="godwit-llm",
            policy_id="pol_1",
            policy_version=1,
            content_digest=ContentHash("b2_x"),
            sensitivity_before=Sensitivity.DATA_VALUE,
            sensitivity_after=Sensitivity.TOKEN,
            actions_applied=(RedactionAction.TOKENISE,),
        ),
        token_map_ref=map_reference,
    )
    assert egress.token_map_ref == map_reference
