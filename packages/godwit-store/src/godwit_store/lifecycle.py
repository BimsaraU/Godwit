"""The pattern lifecycle: allowed transitions, required evidence, automatic staleness.

A pattern never silently changes state. Every transition is checked against
:data:`ALLOWED_TRANSITIONS`, requires the evidence listed in
:data:`REQUIRED_EVIDENCE`, and appends a row to the hash-chained audit ledger recording
who moved it, when, from what and to what (protocol law 4).

WHAT "REQUIRED EVIDENCE" MEANS
------------------------------
Each state answers a different question, so each one needs a different fact:

``CONFIRMED``       a reviewer said so -> a ``feedback_id``.
``REJECTED``        a reviewer said so -> a ``feedback_id``.
``EXPLAINED_AWAY``  L3 found the deploy, campaign or holiday -> a ``context_ref``.
``DUPLICATE``       it duplicates something -> the ``duplicate_of`` pattern id.
``SUPPRESSED``      a human chose silence -> an actor and a reason.
``EXPIRED``         nothing supports it any more -> a window count, set by the store.
``PROPOSED``        it came back, or a decision was reversed -> a candidate or a reason.

The evidence is not decoration. "Confirmed by whom?" is the first question in a model
risk review, and a state machine that accepts a confirmation with nothing behind it
answers it with a shrug.

STALENESS IS AUTOMATIC, AND IT IS NOT A DELETION
------------------------------------------------
A pattern with no supporting candidate for ``max_windows`` consecutive detector runs
over its source expires. It is not removed: a seasonal pattern comes back, and when it
does, the arriving candidate moves it ``EXPIRED -> PROPOSED`` and it keeps its id, its
history and its feedback. That is the difference between a store and a cache.

THE CONTRACT HAS NO ``STALE``
-----------------------------
The brief asks for ``STALE``; ``PatternLifecycle`` offers ``EXPIRED`` and nothing
closer. ``EXPIRED`` is used, and the distinction the brief wanted -- "unsupported for N
windows" versus "deliberately retired" -- is carried by the audit event's ``action``
(``expire_stale``) rather than by a state nobody defined. See
``docs/change-requests/CR-A3-lifecycle-has-no-stale.md``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final, Self

from godwit_contracts import (
    AuditEvent,
    AuditId,
    GodwitModel,
    Instant,
    PatternId,
    PatternLifecycle,
    Plane,
    Verdict,
    canonical_json,
    content_hash,
)
from pydantic import model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from godwit_store.errors import LifecycleTransitionError, PatternNotFoundError
from godwit_store.ledger import AuditEntry, append_audit
from godwit_store.schema import PatternRow

__all__ = [
    "ALLOWED_TRANSITIONS",
    "DEFAULT_STALE_WINDOWS",
    "MAX_REASON_LENGTH",
    "REQUIRED_EVIDENCE",
    "TERMINAL_STATES",
    "TransitionEvidence",
    "expire_stale",
    "lifecycle_for_verdict",
    "transition",
]

MAX_REASON_LENGTH: Final[int] = 200
"""Longest operator note a transition reason may carry.

Short enough that a pasted row does not fit, which is the point: the audit trail
must not become a place people keep data.
"""

DEFAULT_STALE_WINDOWS: Final[int] = 3
"""Detector runs without support before a pattern expires.

Three, not one: a single missing run is usually a probe that did not get scheduled, not
a pattern that stopped happening, and expiring on the first gap makes the lifecycle
track the orchestrator's budget rather than the world.
"""

ALLOWED_TRANSITIONS: Final[Mapping[PatternLifecycle, frozenset[PatternLifecycle]]] = {
    PatternLifecycle.PROPOSED: frozenset(
        {
            PatternLifecycle.CONFIRMED,
            PatternLifecycle.REJECTED,
            PatternLifecycle.EXPLAINED_AWAY,
            PatternLifecycle.DUPLICATE,
            PatternLifecycle.SUPPRESSED,
            PatternLifecycle.EXPIRED,
        }
    ),
    PatternLifecycle.CONFIRMED: frozenset(
        {
            PatternLifecycle.EXPLAINED_AWAY,
            PatternLifecycle.REJECTED,
            PatternLifecycle.SUPPRESSED,
            PatternLifecycle.EXPIRED,
        }
    ),
    PatternLifecycle.EXPLAINED_AWAY: frozenset(
        {
            PatternLifecycle.PROPOSED,
            PatternLifecycle.CONFIRMED,
            PatternLifecycle.SUPPRESSED,
            PatternLifecycle.EXPIRED,
        }
    ),
    PatternLifecycle.SUPPRESSED: frozenset({PatternLifecycle.PROPOSED, PatternLifecycle.EXPIRED}),
    PatternLifecycle.EXPIRED: frozenset({PatternLifecycle.PROPOSED}),
    PatternLifecycle.REJECTED: frozenset({PatternLifecycle.PROPOSED}),
    PatternLifecycle.DUPLICATE: frozenset(),
}
"""The complete transition table.

``EXPIRED -> PROPOSED`` and ``REJECTED -> PROPOSED`` exist because findings recur and
reviewers change their minds; both require evidence, so neither is a quiet undo.
``DUPLICATE`` is the one genuinely terminal state: a pattern that turned out to be
another pattern has nothing of its own left to say, and un-duplicating it would fork
the evidence it already handed over.
"""

TERMINAL_STATES: Final[frozenset[PatternLifecycle]] = frozenset(
    state for state, targets in ALLOWED_TRANSITIONS.items() if not targets
)

REQUIRED_EVIDENCE: Final[Mapping[PatternLifecycle, frozenset[str]]] = {
    PatternLifecycle.CONFIRMED: frozenset({"feedback_id"}),
    PatternLifecycle.REJECTED: frozenset({"feedback_id"}),
    PatternLifecycle.EXPLAINED_AWAY: frozenset({"context_ref"}),
    PatternLifecycle.DUPLICATE: frozenset({"duplicate_of"}),
    PatternLifecycle.SUPPRESSED: frozenset({"reason"}),
    PatternLifecycle.EXPIRED: frozenset({"reason"}),
    PatternLifecycle.PROPOSED: frozenset({"reason"}),
}
"""Which field of :class:`TransitionEvidence` each destination state demands."""


class TransitionEvidence(GodwitModel):
    """What justifies a lifecycle move. Exactly one kind of justification is required.

    Everything here is one of our own identifiers or a short operator-written reason.
    There is deliberately no free-text field that could hold a pasted row: a reviewer's
    notes belong on ``Feedback``, which is tainted, and this object is referenced from
    an audit event, which must never contain a value.
    """

    feedback_id: str | None = None
    context_ref: str | None = None
    duplicate_of: PatternId | None = None
    candidate_id: str | None = None
    reason: str | None = None
    windows_without_support: int | None = None

    @model_validator(mode="after")
    def _reason_is_not_a_row(self) -> Self:
        if self.reason is not None and len(self.reason) > MAX_REASON_LENGTH:
            raise ValueError(
                "a transition reason is a short operator note, not a paste buffer; "
                "anything longer belongs on Feedback, which is tainted"
            )
        return self

    def digest(self) -> str:
        """Stable hash of this evidence, recorded as the audit event's detail digest.

        The audit log says *what happened*, not what the data was, so the evidence is
        hashed rather than stored inline -- the same rule that makes ``AuditEvent``
        carry ``detail_digest`` and no ``detail``.
        """
        return str(
            content_hash(
                canonical_json(
                    {
                        "feedback_id": self.feedback_id,
                        "context_ref": self.context_ref,
                        "duplicate_of": None
                        if self.duplicate_of is None
                        else str(self.duplicate_of),
                        "candidate_id": self.candidate_id,
                        "reason": self.reason,
                        "windows_without_support": self.windows_without_support,
                    }
                ),
                prefix="evd",
            )
        )


def lifecycle_for_verdict(verdict: Verdict) -> PatternLifecycle | None:
    """The state a human verdict moves a pattern into, or None when it moves nothing.

    ``NEEDS_MORE`` is the None case on purpose: "I cannot tell yet" is feedback worth
    recording and is not a state change. Collapsing it into ``PROPOSED`` would erase the
    difference between a pattern nobody has looked at and one somebody could not judge.
    """
    return {
        Verdict.CONFIRMED: PatternLifecycle.CONFIRMED,
        Verdict.REJECTED: PatternLifecycle.REJECTED,
        Verdict.EXPLAINED_AWAY: PatternLifecycle.EXPLAINED_AWAY,
        Verdict.DUPLICATE: PatternLifecycle.DUPLICATE,
        Verdict.NEEDS_MORE: None,
    }[verdict]


def _check_evidence(to_state: PatternLifecycle, evidence: TransitionEvidence) -> None:
    required = REQUIRED_EVIDENCE.get(to_state, frozenset())
    missing = [field for field in sorted(required) if getattr(evidence, field) is None]
    if missing:
        raise LifecycleTransitionError(
            f"moving a pattern to {to_state.value} requires {', '.join(missing)}; "
            "a state change with nothing behind it cannot be defended in a review"
        )


def transition(
    session: Session,
    *,
    pattern_id: PatternId,
    to_state: PatternLifecycle,
    evidence: TransitionEvidence,
    actor: str,
    at: Instant,
    action: str | None = None,
    guardrail_id: str | None = None,
    guardrail_version: int | None = None,
    correlation_id: str | None = None,
) -> AuditEntry:
    """Move a pattern to ``to_state``, or refuse and explain why.

    ``at`` is injected; nothing here reads a clock. The audit entry is written in the
    same transaction as the state change, so a state that moved without an audit row is
    not a reachable outcome.
    """
    row = session.get(PatternRow, str(pattern_id))
    if row is None:
        raise PatternNotFoundError(f"no pattern {pattern_id}")

    from_state = PatternLifecycle(row.lifecycle)
    if from_state is to_state:
        raise LifecycleTransitionError(
            f"pattern {pattern_id} is already {to_state.value}; a no-op transition "
            "would put a misleading row in the audit trail"
        )
    if to_state not in ALLOWED_TRANSITIONS[from_state]:
        allowed = ", ".join(sorted(state.value for state in ALLOWED_TRANSITIONS[from_state]))
        raise LifecycleTransitionError(
            f"pattern {pattern_id} cannot move {from_state.value} -> {to_state.value}; "
            f"allowed: {allowed or 'nothing, this state is terminal'}"
        )
    _check_evidence(to_state, evidence)

    row.lifecycle = to_state.value
    if to_state is PatternLifecycle.EXPLAINED_AWAY:
        row.explained_away = True
    if to_state is PatternLifecycle.PROPOSED:
        row.explained_away = False
        row.windows_without_support = 0

    event = AuditEvent(
        event_id=_event_id(pattern_id=pattern_id, to_state=to_state, at=at, actor=actor),
        occurred_at=at,
        actor=actor,
        action=action or f"lifecycle:{from_state.value}->{to_state.value}",
        subject_kind="pattern",
        subject_id=str(pattern_id),
        plane=Plane.CONTROL,
        detail_digest=None,
        correlation_id=correlation_id,
    )
    return append_audit(
        session,
        event.model_copy(update={"detail_digest": evidence.digest()}),
        from_state=from_state.value,
        to_state=to_state.value,
        guardrail_id=guardrail_id,
        guardrail_version=guardrail_version,
    )


def _event_id(*, pattern_id: PatternId, to_state: PatternLifecycle, at: Instant, actor: str) -> str:
    """Deterministic event id, so replaying the same transition is idempotent.

    Derived rather than random for universal rule 5: a store that minted a UUID here
    would produce a different audit trail on every replay of the same history, and the
    trail is the thing being replayed.
    """
    return str(
        content_hash(
            canonical_json(
                {
                    "pattern_id": str(pattern_id),
                    "to_state": to_state.value,
                    "at": at.isoformat(),
                    "actor": actor,
                }
            ),
            prefix="aud",
        )
    )


def expire_stale(
    session: Session,
    *,
    source_id: str,
    at: Instant,
    actor: str = "godwit-store",
    max_windows: int = DEFAULT_STALE_WINDOWS,
    correlation_id: str | None = None,
) -> tuple[PatternId, ...]:
    """Expire every open pattern of a source with no support for ``max_windows`` runs.

    Returns the patterns expired, in id order, so a caller gets a deterministic result
    it can assert on. States that are already terminal, already expired or deliberately
    suppressed are left alone: silence a pattern and it stays silenced, rather than
    being quietly reclassified as stale.
    """
    open_states = (
        PatternLifecycle.PROPOSED.value,
        PatternLifecycle.CONFIRMED.value,
        PatternLifecycle.EXPLAINED_AWAY.value,
    )
    rows = session.scalars(
        select(PatternRow)
        .where(PatternRow.source_id == source_id)
        .where(PatternRow.lifecycle.in_(open_states))
        .where(PatternRow.windows_without_support >= max_windows)
        .order_by(PatternRow.pattern_id)
    ).all()

    expired: list[PatternId] = []
    for row in rows:
        transition(
            session,
            pattern_id=PatternId(row.pattern_id),
            to_state=PatternLifecycle.EXPIRED,
            evidence=TransitionEvidence(
                reason=f"no supporting candidate in {row.windows_without_support} windows",
                windows_without_support=row.windows_without_support,
            ),
            actor=actor,
            at=at,
            action="expire_stale",
            correlation_id=correlation_id,
        )
        expired.append(PatternId(row.pattern_id))
    return tuple(expired)


def audit_ids_for(entries: Sequence[AuditEntry]) -> tuple[AuditId, ...]:
    """Narrow a sequence of audit entries to their contract-typed ids."""
    return tuple(AuditId(entry.event_id) for entry in entries)
