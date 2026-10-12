"""Where this package's audit trail and learned priors go: A3's hash-chained ledger.

``StoreAuditSink`` writes through ``godwit_store.append_audit`` and reads back through
``godwit_store.audit_query``. ``MemoryAuditSink`` is the same contract in a list, for
tests and for a dry run.

Nothing written here holds a value. An audit event carries our ids, a context type, a
detector family, an outcome and a digest of the decision -- the decision itself holds
only ids and derived numbers (``RoutingDecision``), so even the digest is of nothing
sensitive.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from godwit_contracts import AuditEvent, Instant
from godwit_store import append_audit, audit_query
from sqlalchemy.orm import Session

__all__ = ["AuditRecord", "AuditSink", "MemoryAuditSink", "StoreAuditSink"]

_READ_LIMIT: Final = 10_000_000
"""``audit_query`` has a limit and no cursor. Ten million priors observations is far past
where replaying them on load would be the bottleneck."""


@dataclass(frozen=True)
class AuditRecord:
    """What this package reads back from the ledger."""

    action: str
    subject_kind: str
    subject_id: str
    occurred_at: Instant
    from_state: str | None
    to_state: str | None


class AuditSink(Protocol):
    def append(
        self, event: AuditEvent, *, from_state: str | None = None, to_state: str | None = None
    ) -> None:
        """Append one event. Must not return until it is durable in the sink."""
        ...

    def records(self, *, subject_kind: str) -> Sequence[AuditRecord]:
        """Every event of ``subject_kind``, oldest first."""
        ...


class MemoryAuditSink:
    """An in-process ledger. Same ordering contract as the store's."""

    def __init__(self) -> None:
        self._events: list[tuple[AuditEvent, str | None, str | None]] = []

    def append(
        self, event: AuditEvent, *, from_state: str | None = None, to_state: str | None = None
    ) -> None:
        self._events.append((event, from_state, to_state))

    def records(self, *, subject_kind: str) -> Sequence[AuditRecord]:
        return tuple(
            AuditRecord(e.action, e.subject_kind, e.subject_id, e.occurred_at, f, t)
            for e, f, t in self._events
            if e.subject_kind == subject_kind
        )

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(e for e, _, _ in self._events)


class StoreAuditSink:
    """A3's audit ledger. The caller owns the session and commits it."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(
        self, event: AuditEvent, *, from_state: str | None = None, to_state: str | None = None
    ) -> None:
        append_audit(self._session, event, from_state=from_state, to_state=to_state)

    def records(self, *, subject_kind: str) -> Sequence[AuditRecord]:
        return tuple(
            AuditRecord(
                e.action, e.subject_kind, e.subject_id, e.occurred_at, e.from_state, e.to_state
            )
            for e in audit_query(self._session, subject_kind=subject_kind, limit=_READ_LIMIT)
        )
