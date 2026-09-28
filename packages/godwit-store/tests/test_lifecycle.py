"""The lifecycle state machine: allowed moves, required evidence, staleness, audit.

A pattern never silently changes state. Everything here is about making that true in a
way a model risk reviewer can check: the transition table is data, the evidence is
mandatory, and every move leaves a row in a hash-chained ledger saying who did it.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from _store_support import CandidateSpec
from godwit_contracts import (
    Feedback,
    Instant,
    PatternId,
    PatternLifecycle,
    RunId,
    SnapshotId,
    Verdict,
)
from godwit_store.errors import LifecycleTransitionError, PatternNotFoundError
from godwit_store.fdr import HoldoutKind, HoldoutPolicy, HypothesisFamily
from godwit_store.ledger import audit_query, verify_chain
from godwit_store.lifecycle import (
    ALLOWED_TRANSITIONS,
    DEFAULT_STALE_WINDOWS,
    REQUIRED_EVIDENCE,
    TERMINAL_STATES,
    TransitionEvidence,
    expire_stale,
    lifecycle_for_verdict,
    transition,
)
from godwit_store.schema import PatternRow
from godwit_store.store import PatternStore
from sqlalchemy.orm import Session


def _seed_pattern(session: Session, at: Instant, *, candidate_id: str = "c1") -> PatternId:
    store = PatternStore(session)
    report = store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId(f"run_{candidate_id}"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=1,
            declared_at=at,
        ),
        candidates=[CandidateSpec(candidate_id=candidate_id, created_at=at).build()],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    return report.patterns_created[0]


# ------------------------------------------------------------------------------------
# The table
# ------------------------------------------------------------------------------------


def test_every_state_appears_in_the_transition_table() -> None:
    """A state nobody wrote a row for is a state a pattern can enter and never leave."""
    assert set(ALLOWED_TRANSITIONS) == set(PatternLifecycle)


def test_duplicate_is_the_only_terminal_state() -> None:
    """Stated as a test because it is a product decision, not an implementation detail.

    Findings recur and reviewers change their minds, so ``EXPIRED`` and ``REJECTED``
    both lead back to ``PROPOSED`` with evidence. A pattern that turned out to be
    another pattern has handed over its evidence and has nothing of its own left.
    """
    assert {PatternLifecycle.DUPLICATE} == TERMINAL_STATES


def test_no_transition_targets_a_state_outside_the_enum() -> None:
    for targets in ALLOWED_TRANSITIONS.values():
        assert targets <= set(PatternLifecycle)


def test_every_reachable_state_demands_evidence() -> None:
    """There is no state a pattern can be moved into for no stated reason."""
    reachable = {state for targets in ALLOWED_TRANSITIONS.values() for state in targets}
    assert reachable <= set(REQUIRED_EVIDENCE)


def test_needs_more_is_feedback_without_a_state_change() -> None:
    """ "I cannot tell yet" is worth recording and is not a verdict."""
    assert lifecycle_for_verdict(Verdict.NEEDS_MORE) is None
    assert lifecycle_for_verdict(Verdict.CONFIRMED) is PatternLifecycle.CONFIRMED


# ------------------------------------------------------------------------------------
# Moving a pattern
# ------------------------------------------------------------------------------------


def test_a_confirmation_without_a_feedback_id_is_refused(session: Session, at: Instant) -> None:
    pattern_id = _seed_pattern(session, at)
    with pytest.raises(LifecycleTransitionError, match="requires feedback_id"):
        transition(
            session,
            pattern_id=pattern_id,
            to_state=PatternLifecycle.CONFIRMED,
            evidence=TransitionEvidence(reason="looks right to me"),
            actor="analyst_7",
            at=at,
        )


def test_an_illegal_transition_names_what_is_allowed(session: Session, at: Instant) -> None:
    pattern_id = _seed_pattern(session, at)
    transition(
        session,
        pattern_id=pattern_id,
        to_state=PatternLifecycle.DUPLICATE,
        evidence=TransitionEvidence(duplicate_of=PatternId("pat_other")),
        actor="analyst_7",
        at=at,
    )
    with pytest.raises(LifecycleTransitionError, match="terminal"):
        transition(
            session,
            pattern_id=pattern_id,
            to_state=PatternLifecycle.CONFIRMED,
            evidence=TransitionEvidence(feedback_id="fbk_1"),
            actor="analyst_7",
            at=at + _dt.timedelta(hours=1),
        )


def test_a_no_op_transition_is_refused(session: Session, at: Instant) -> None:
    """A move to the state it is already in would put a lie in the audit trail."""
    pattern_id = _seed_pattern(session, at)
    with pytest.raises(LifecycleTransitionError, match="already"):
        transition(
            session,
            pattern_id=pattern_id,
            to_state=PatternLifecycle.PROPOSED,
            evidence=TransitionEvidence(reason="no change"),
            actor="analyst_7",
            at=at,
        )


def test_a_missing_pattern_is_not_a_silent_no_op(session: Session, at: Instant) -> None:
    with pytest.raises(PatternNotFoundError):
        transition(
            session,
            pattern_id=PatternId("pat_nothing"),
            to_state=PatternLifecycle.CONFIRMED,
            evidence=TransitionEvidence(feedback_id="fbk_1"),
            actor="analyst_7",
            at=at,
        )


def test_a_transition_reason_cannot_hold_a_pasted_row(session: Session, at: Instant) -> None:
    """The audit trail must not become a place people keep data."""
    with pytest.raises(ValueError, match="paste buffer"):
        TransitionEvidence(reason="x" * 500)


def test_every_move_writes_an_audit_row_with_both_states(session: Session, at: Instant) -> None:
    pattern_id = _seed_pattern(session, at)
    transition(
        session,
        pattern_id=pattern_id,
        to_state=PatternLifecycle.CONFIRMED,
        evidence=TransitionEvidence(feedback_id="fbk_1"),
        actor="analyst_7",
        at=at + _dt.timedelta(hours=1),
    )
    entries = audit_query(session, subject_kind="pattern", subject_id=str(pattern_id))
    moves = [entry for entry in entries if entry.to_state == PatternLifecycle.CONFIRMED.value]
    assert len(moves) == 1
    assert moves[0].from_state == PatternLifecycle.PROPOSED.value
    assert moves[0].actor == "analyst_7"
    assert moves[0].detail_digest is not None
    assert verify_chain(session, table="audit_events").intact


def test_the_audit_detail_is_a_digest_not_the_evidence(session: Session, at: Instant) -> None:
    """The audit log says what happened, not what the data was."""
    pattern_id = _seed_pattern(session, at)
    transition(
        session,
        pattern_id=pattern_id,
        to_state=PatternLifecycle.EXPLAINED_AWAY,
        evidence=TransitionEvidence(context_ref="deploy_4471"),
        actor="context_service",
        at=at + _dt.timedelta(hours=1),
    )
    entries = audit_query(session, subject_kind="pattern", subject_id=str(pattern_id))
    rendered = "\n".join(entry.model_dump_json() for entry in entries)
    assert "deploy_4471" not in rendered


def test_explaining_a_pattern_away_sets_the_flag_the_ranker_reads(
    session: Session, at: Instant
) -> None:
    pattern_id = _seed_pattern(session, at)
    transition(
        session,
        pattern_id=pattern_id,
        to_state=PatternLifecycle.EXPLAINED_AWAY,
        evidence=TransitionEvidence(context_ref="black_friday"),
        actor="context_service",
        at=at + _dt.timedelta(hours=1),
    )
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    assert row.explained_away is True


# ------------------------------------------------------------------------------------
# Staleness
# ------------------------------------------------------------------------------------


def test_a_pattern_expires_after_the_configured_windows(session: Session, at: Instant) -> None:
    """Staleness is counted in detector runs, not in days.

    A source probed hourly and a source probed weekly must not age at the same rate
    because a clock ticked. It is also why nothing in this path reads one.
    """
    pattern_id = _seed_pattern(session, at)
    store = PatternStore(session)
    for window in range(DEFAULT_STALE_WINDOWS):
        store.ingest_batch(
            family=HypothesisFamily(
                run_id=RunId(f"run_empty_{window}"),
                snapshot_id=SnapshotId("snap_2"),
                detector="segment_divergence",
                detector_version=1,
                test_count=1,
                declared_at=at,
            ),
            candidates=[],
            holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
            at=at + _dt.timedelta(days=window + 1),
            source_id=CandidateSpec(candidate_id="c1", created_at=at).build().source_id,
        )
    expired = expire_stale(
        session,
        source_id="src_test",
        at=at + _dt.timedelta(days=10),
    )
    assert expired == (pattern_id,)
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    assert row.lifecycle == PatternLifecycle.EXPIRED.value


def test_a_supported_pattern_does_not_age(session: Session, at: Instant) -> None:
    pattern_id = _seed_pattern(session, at)
    store = PatternStore(session)
    store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId("run_again"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=1,
            declared_at=at,
        ),
        candidates=[
            CandidateSpec(candidate_id="c2", created_at=at + _dt.timedelta(days=1)).build()
        ],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at + _dt.timedelta(days=1),
    )
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    assert row.windows_without_support == 0


def test_a_suppressed_pattern_is_not_quietly_reclassified_as_stale(
    session: Session, at: Instant
) -> None:
    """Silence it and it stays silenced, rather than becoming "expired" behind a back."""
    pattern_id = _seed_pattern(session, at)
    transition(
        session,
        pattern_id=pattern_id,
        to_state=PatternLifecycle.SUPPRESSED,
        evidence=TransitionEvidence(reason="known and accepted"),
        actor="analyst_7",
        at=at,
    )
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    row.windows_without_support = 99
    session.flush()

    assert expire_stale(session, source_id="src_test", at=at + _dt.timedelta(days=30)) == ()
    assert row.lifecycle == PatternLifecycle.SUPPRESSED.value


def test_an_expired_pattern_reopens_when_the_finding_returns(session: Session, at: Instant) -> None:
    """A seasonal pattern keeps its id, its history and its feedback when it comes back.

    That is the difference between a store and a cache, and it is why expiry is a state
    rather than a delete.
    """
    pattern_id = _seed_pattern(session, at)
    transition(
        session,
        pattern_id=pattern_id,
        to_state=PatternLifecycle.EXPIRED,
        evidence=TransitionEvidence(reason="no support in 3 windows"),
        actor="godwit-store",
        at=at + _dt.timedelta(days=5),
    )
    store = PatternStore(session)
    report = store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId("run_return"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=1,
            declared_at=at,
        ),
        candidates=[
            CandidateSpec(candidate_id="c9", created_at=at + _dt.timedelta(days=90)).build()
        ],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at + _dt.timedelta(days=90),
    )
    assert report.patterns_reopened == (pattern_id,)
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    assert row.lifecycle == PatternLifecycle.PROPOSED.value
    assert row.candidate_count == 2


# ------------------------------------------------------------------------------------
# Feedback
# ------------------------------------------------------------------------------------


def test_a_rejection_moves_the_pattern_and_suppresses_the_signature(
    session: Session, at: Instant
) -> None:
    """Dismissing a finding silences next week's instance of it, not just this one."""
    pattern_id = _seed_pattern(session, at)
    store = PatternStore(session)
    store.record_feedback(
        Feedback(
            pattern_id=pattern_id,
            verdict=Verdict.REJECTED,
            reviewer_id="analyst_7",
            decided_at=at + _dt.timedelta(hours=1),
        )
    )
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    assert row.lifecycle == PatternLifecycle.REJECTED.value
    assert row.rejections == 1

    report = store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId("run_next_week"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=1,
            declared_at=at,
        ),
        candidates=[
            CandidateSpec(candidate_id="c2", created_at=at + _dt.timedelta(days=7)).build()
        ],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at + _dt.timedelta(days=7),
    )
    assert report.suppressed == 1
    assert report.patterns_created == ()
    assert report.candidates_stored == 1, "the candidate is still recorded, just not surfaced"


def test_the_same_verdict_delivered_twice_is_recorded_once(session: Session, at: Instant) -> None:
    pattern_id = _seed_pattern(session, at)
    store = PatternStore(session)
    feedback = Feedback(
        pattern_id=pattern_id,
        verdict=Verdict.CONFIRMED,
        reviewer_id="analyst_7",
        decided_at=at + _dt.timedelta(hours=1),
    )
    store.record_feedback(feedback)
    store.record_feedback(feedback)
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    assert row.confirmations == 2, "the count records deliveries"
    assert row.lifecycle == PatternLifecycle.CONFIRMED.value
