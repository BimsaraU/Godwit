"""Where the gate writes what it did: egress records and audit events.

The gate writes an ``EgressRecord`` BEFORE it returns a ``SafePayload`` (EgressGate law
1). If the write fails, nothing leaves. Refusals, policy publications, access grants and
backstop hits are written as ``AuditEvent`` s, because the contract's ``EgressRecord``
has no way to say "refused" (see ``CR-A5-egress-record-cannot-record-a-refusal``).

Two implementations:

* :class:`MemoryLedger` -- for tests and for embedding; keeps everything in lists.
* :class:`StoreLedger` -- the production path, writing through A3's hash-chained,
  append-only ledger in ``godwit_store.ledger``. One transaction per write, committed
  before the gate proceeds.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Protocol

from godwit_contracts import (
    AuditEvent,
    EgressRecord,
    Instant,
    Plane,
    canonical_json,
    content_hash,
)
from godwit_store.ledger import append_audit, append_egress
from sqlalchemy.orm import Session

__all__ = [
    "EgressLedger",
    "MemoryLedger",
    "StoreLedger",
    "audit_event",
]


class EgressLedger(Protocol):
    """Somewhere the gate can durably record what it did. Raising means "not recorded"."""

    def append_egress(self, record: EgressRecord, *, token_map_ref: str | None) -> None:
        """Persist one egress record. Must not return until it is durable."""
        ...

    def append_audit(self, event: AuditEvent) -> None:
        """Persist one audit event."""
        ...


class MemoryLedger:
    """An in-process ledger. Deterministic and inspectable; not durable."""

    def __init__(self) -> None:
        self.egress: list[tuple[EgressRecord, str | None]] = []
        self.audit: list[AuditEvent] = []

    def append_egress(self, record: EgressRecord, *, token_map_ref: str | None) -> None:
        """Append to :attr:`egress`."""
        self.egress.append((record, token_map_ref))

    def append_audit(self, event: AuditEvent) -> None:
        """Append to :attr:`audit`."""
        self.audit.append(event)

    def actions(self) -> tuple[str, ...]:
        """The ``action`` of every audit event, in order. Handy in tests and dashboards."""
        return tuple(event.action for event in self.audit)


class StoreLedger:
    """Writes through godwit-store's append-only, hash-chained ledger (A3).

    ``session_factory`` returns a context-managed SQLAlchemy session; each write runs in
    its own transaction and is committed before this method returns, so the gate never
    hands out a payload whose record is still sitting in an open transaction.
    """

    def __init__(self, session_factory: Callable[[], AbstractContextManager[Session]]) -> None:
        self._session_factory = session_factory

    def append_egress(self, record: EgressRecord, *, token_map_ref: str | None) -> None:
        """Append one egress record to ``egress_records`` and commit."""
        with self._session_factory() as session, session.begin():
            append_egress(session, record, token_map_ref=token_map_ref)

    def append_audit(self, event: AuditEvent) -> None:
        """Append one audit event to ``audit_events`` and commit."""
        with self._session_factory() as session, session.begin():
            append_audit(session, event)


def audit_event(
    *,
    action: str,
    actor: str,
    subject_kind: str,
    subject_id: str,
    at: Instant,
    detail: object | None = None,
    plane: Plane = Plane.BOUNDARY,
) -> AuditEvent:
    """Build an audit event with a deterministic id.

    ``detail`` is hashed, never stored: the audit log says what happened, not what the
    data was. It must be JSON-renderable and must already be free of values.
    """
    detail_digest = None if detail is None else content_hash(canonical_json(detail))
    identity = canonical_json(
        [action, actor, subject_kind, subject_id, at.isoformat(), detail_digest or ""]
    )
    return AuditEvent(
        event_id=content_hash(identity, prefix="aud"),
        occurred_at=at,
        actor=actor,
        action=action,
        subject_kind=subject_kind,
        subject_id=subject_id,
        plane=plane,
        detail_digest=detail_digest,
    )
