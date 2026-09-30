"""The append-only, hash-chained audit and egress ledgers, and the export a bank asks for.

Two questions have to be answerable in front of an auditor, in one query, with no
caveats:

1. *"Show me everything that ever changed the state of a finding, and who did it."*
   -> ``audit_events``, and :func:`audit_query`.
2. *"Show me everything you ever sent to a model provider."*
   -> ``egress_records``, and :func:`egress_query` / :func:`export_egress`.

THE CHAIN
---------
Each row carries ``seq``, ``prev_hash`` and ``row_hash``, where::

    row_hash = blake2b(canonical_json({"prev": prev_hash, "seq": seq, "fields": ...}))

The first row of each chain points at :data:`GENESIS_HASH`. Deleting row *n* leaves row
*n+1* pointing at a hash that nothing in the table produces; amending row *n* changes
its own hash and breaks the same link. :func:`verify_chain` walks it and names the first
sequence number that does not reconcile.

Be precise about the claim. This is **tamper-evident**, not tamper-proof: whoever can
write to the table can also recompute every subsequent hash. What makes that expensive
is verifying from outside -- export the head hash, sign it, keep it somewhere the
database cannot reach -- and what makes casual tampering impossible is the grants and
triggers in :mod:`godwit_store.appendonly`. Three layers, each covering a hole in the
next, and none of them stops a superuser.

WHAT THE LEDGERS MAY NOT CONTAIN
--------------------------------
A value. ``audit_events`` stores ``detail_digest``, never ``detail``: an audit log full
of PII is a second breach with better indexing. ``egress_records`` stores field *names*,
a content digest and a token-map *reference*; the map itself never leaves the data
plane. Every column on both tables is a plain type, so there is no field a tainted value
could sit in even by accident.

TWO CONTRACT FIELDS THAT DO NOT EXIST
-------------------------------------
``AuditEvent`` has no ``from_state``/``to_state`` and no guardrail reference, and
``EgressRecord`` has no token-map reference, although the brief requires all four. They
are accepted here as keyword arguments alongside the contract object and stored in
their own columns. See ``docs/change-requests/CR-A3-ledger-fields-missing.md``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from godwit_contracts import (
    AuditEvent,
    EgressRecord,
    GodwitModel,
    Instant,
    NonNegInt,
    canonical_json,
    content_hash,
)
from sqlalchemy import Select, func, select, text
from sqlalchemy.orm import Session

from godwit_store.errors import ChainBrokenError
from godwit_store.schema import AuditEventRow, EgressRecordRow

__all__ = [
    "GENESIS_HASH",
    "AuditEntry",
    "ChainVerification",
    "EgressEntry",
    "append_audit",
    "append_egress",
    "assert_chain_intact",
    "audit_query",
    "chain_hash",
    "chain_length",
    "egress_query",
    "export_egress",
    "verify_chain",
]

GENESIS_HASH: Final[str] = "chn_genesis"
"""What the first row of a chain points at. A literal, not a hash of anything: a genesis
marker needs to be recognisable, not unguessable."""

_LOCK_KEYS: Final[dict[str, int]] = {"audit_events": 5_100_001, "egress_records": 5_100_002}
"""Advisory lock keys, one per chain. A hash chain is inherently serial -- two writers
computing ``max(seq) + 1`` at once produce two rows claiming the same link. On Postgres
the transaction-scoped advisory lock serialises them; on SQLite the database-wide write
lock already does. The ``uq_..._sequence`` constraint is the backstop that turns a
missed lock into a refused write rather than a silently forked chain."""


def chain_hash(*, prev_hash: str, seq: int, fields: Mapping[str, Any]) -> str:
    """The hash linking one ledger row to the one before it.

    ``fields`` must render through :func:`godwit_contracts.canonical_json`, which means
    every float, date and decimal has already been rendered to a string. Two
    independently written verifiers agree byte for byte, or the chain is worthless.
    """
    return str(
        content_hash(
            canonical_json({"prev": prev_hash, "seq": seq, "fields": dict(fields)}),
            prefix="chn",
        )
    )


class AuditEntry(GodwitModel):
    """One persisted audit event, as read back.

    Returned instead of the ORM row so a caller holds an immutable value with no
    session attached, and so an export cannot accidentally trigger a lazy load.
    """

    event_id: str
    seq: NonNegInt
    occurred_at: Instant
    actor: str
    action: str
    subject_kind: str
    subject_id: str
    plane: str
    from_state: str | None = None
    to_state: str | None = None
    guardrail_id: str | None = None
    guardrail_version: int | None = None
    detail_digest: str | None = None
    correlation_id: str | None = None
    prev_hash: str
    row_hash: str


class EgressEntry(GodwitModel):
    """One persisted egress record, as read back. Contains no value, by construction."""

    record_id: str
    seq: NonNegInt
    occurred_at: Instant
    destination: str
    purpose: str
    actor: str
    policy_id: str
    policy_version: int
    guardrail_ids: tuple[str, ...] = ()
    content_digest: str
    field_names: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    sensitivity_before: str
    sensitivity_after: str
    actions_applied: tuple[str, ...] = ()
    min_population: int | None = None
    approval_id: str | None = None
    token_map_ref: str | None = None
    prev_hash: str
    row_hash: str


class ChainVerification(GodwitModel):
    """The result of walking one chain end to end.

    ``head_hash`` is the value worth exporting and signing: a verifier holding last
    week's head can prove that this week's chain still contains it.
    """

    table: str
    length: NonNegInt
    head_hash: str
    intact: bool
    first_broken_seq: int | None = None


def _audit_fields(row: AuditEventRow) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "occurred_at": row.occurred_at.isoformat(),
        "actor": row.actor,
        "action": row.action,
        "subject_kind": row.subject_kind,
        "subject_id": row.subject_id,
        "plane": row.plane,
        "from_state": row.from_state,
        "to_state": row.to_state,
        "guardrail_id": row.guardrail_id,
        "guardrail_version": row.guardrail_version,
        "detail_digest": row.detail_digest,
        "correlation_id": row.correlation_id,
    }


def _egress_fields(row: EgressRecordRow) -> dict[str, Any]:
    return {
        "record_id": row.record_id,
        "occurred_at": row.occurred_at.isoformat(),
        "destination": row.destination,
        "purpose": row.purpose,
        "actor": row.actor,
        "policy_id": row.policy_id,
        "policy_version": row.policy_version,
        "guardrail_ids": list(row.guardrail_ids),
        "content_digest": row.content_digest,
        "field_names": list(row.field_names),
        "source_ids": list(row.source_ids),
        "sensitivity_before": row.sensitivity_before,
        "sensitivity_after": row.sensitivity_after,
        "actions_applied": list(row.actions_applied),
        "min_population": row.min_population,
        "approval_id": row.approval_id,
        "token_map_ref": row.token_map_ref,
    }


def _lock_chain(session: Session, table: str) -> None:
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _LOCK_KEYS[table]})


def _next_link(session: Session, table: str, *, is_audit: bool) -> tuple[int, str]:
    _lock_chain(session, table)
    if is_audit:
        head = session.execute(
            select(AuditEventRow.seq, AuditEventRow.row_hash)
            .order_by(AuditEventRow.seq.desc())
            .limit(1)
        ).first()
    else:
        head = session.execute(
            select(EgressRecordRow.seq, EgressRecordRow.row_hash)
            .order_by(EgressRecordRow.seq.desc())
            .limit(1)
        ).first()
    if head is None:
        return 1, GENESIS_HASH
    return int(head[0]) + 1, str(head[1])


def append_audit(
    session: Session,
    event: AuditEvent,
    *,
    from_state: str | None = None,
    to_state: str | None = None,
    guardrail_id: str | None = None,
    guardrail_version: int | None = None,
) -> AuditEntry:
    """Append one audit event and return it, linked into the chain.

    The four keyword arguments are the fields the brief requires and the contract does
    not carry -- "from what, to what, under which guardrail". See
    ``CR-A3-ledger-fields-missing.md``.

    Nothing here reads a clock: ``event.occurred_at`` is injected by the caller
    (universal rule 5).
    """
    seq, prev_hash = _next_link(session, "audit_events", is_audit=True)
    row = AuditEventRow(
        event_id=event.event_id,
        occurred_at=event.occurred_at,
        actor=event.actor,
        action=event.action,
        subject_kind=event.subject_kind,
        subject_id=event.subject_id,
        plane=event.plane.value,
        from_state=from_state,
        to_state=to_state,
        guardrail_id=guardrail_id,
        guardrail_version=guardrail_version,
        detail_digest=None if event.detail_digest is None else str(event.detail_digest),
        correlation_id=event.correlation_id,
        seq=seq,
        prev_hash=prev_hash,
        row_hash="",
    )
    row.row_hash = chain_hash(prev_hash=prev_hash, seq=seq, fields=_audit_fields(row))
    session.add(row)
    session.flush()
    return _to_audit_entry(row)


def append_egress(
    session: Session,
    record: EgressRecord,
    *,
    token_map_ref: str | None = None,
) -> EgressEntry:
    """Append one egress record and return it, linked into the chain.

    ``token_map_ref`` points at the tokenisation map entry in the data plane. It is a
    reference, never a map: the map does not cross the boundary, which is what makes a
    token one-way outside the data plane.
    """
    seq, prev_hash = _next_link(session, "egress_records", is_audit=False)
    row = EgressRecordRow(
        record_id=record.record_id,
        occurred_at=record.occurred_at,
        destination=record.destination.value,
        purpose=record.purpose,
        actor=record.actor,
        policy_id=record.policy_id,
        policy_version=int(record.policy_version),
        guardrail_ids=list(record.guardrail_ids),
        content_digest=str(record.content_digest),
        field_names=list(record.field_names),
        source_ids=list(record.source_ids),
        sensitivity_before=record.sensitivity_before.value,
        sensitivity_after=record.sensitivity_after.value,
        actions_applied=[action.value for action in record.actions_applied],
        min_population=record.min_population,
        approval_id=record.approval_id,
        token_map_ref=token_map_ref,
        seq=seq,
        prev_hash=prev_hash,
        row_hash="",
    )
    row.row_hash = chain_hash(prev_hash=prev_hash, seq=seq, fields=_egress_fields(row))
    session.add(row)
    session.flush()
    return _to_egress_entry(row)


def _to_audit_entry(row: AuditEventRow) -> AuditEntry:
    return AuditEntry(
        event_id=row.event_id,
        seq=row.seq,
        occurred_at=row.occurred_at,
        actor=row.actor,
        action=row.action,
        subject_kind=row.subject_kind,
        subject_id=row.subject_id,
        plane=row.plane,
        from_state=row.from_state,
        to_state=row.to_state,
        guardrail_id=row.guardrail_id,
        guardrail_version=row.guardrail_version,
        detail_digest=row.detail_digest,
        correlation_id=row.correlation_id,
        prev_hash=row.prev_hash,
        row_hash=row.row_hash,
    )


def _to_egress_entry(row: EgressRecordRow) -> EgressEntry:
    return EgressEntry(
        record_id=row.record_id,
        seq=row.seq,
        occurred_at=row.occurred_at,
        destination=row.destination,
        purpose=row.purpose,
        actor=row.actor,
        policy_id=row.policy_id,
        policy_version=row.policy_version,
        guardrail_ids=tuple(row.guardrail_ids),
        content_digest=row.content_digest,
        field_names=tuple(row.field_names),
        source_ids=tuple(row.source_ids),
        sensitivity_before=row.sensitivity_before,
        sensitivity_after=row.sensitivity_after,
        actions_applied=tuple(row.actions_applied),
        min_population=row.min_population,
        approval_id=row.approval_id,
        token_map_ref=row.token_map_ref,
        prev_hash=row.prev_hash,
        row_hash=row.row_hash,
    )


def audit_query(
    session: Session,
    *,
    subject_kind: str | None = None,
    subject_id: str | None = None,
    actor: str | None = None,
    since: Instant | None = None,
    until: Instant | None = None,
    limit: int = 1000,
) -> tuple[AuditEntry, ...]:
    """Everything that happened to a subject, oldest first.

    Ordering is by ``seq``, not by ``occurred_at``: two events stamped with the same
    injected instant still have a defined order, and a deterministic read order is what
    lets a test assert on an audit trail at all.
    """
    statement: Select[Any] = select(AuditEventRow)
    if subject_kind is not None:
        statement = statement.where(AuditEventRow.subject_kind == subject_kind)
    if subject_id is not None:
        statement = statement.where(AuditEventRow.subject_id == subject_id)
    if actor is not None:
        statement = statement.where(AuditEventRow.actor == actor)
    if since is not None:
        statement = statement.where(AuditEventRow.occurred_at >= since)
    if until is not None:
        statement = statement.where(AuditEventRow.occurred_at <= until)
    statement = statement.order_by(AuditEventRow.seq).limit(limit)
    return tuple(_to_audit_entry(row) for row in session.scalars(statement))


def egress_query(
    session: Session,
    *,
    destination: str | None = None,
    actor: str | None = None,
    purpose: str | None = None,
    content_digest: str | None = None,
    since: Instant | None = None,
    until: Instant | None = None,
    limit: int = 10_000,
) -> tuple[EgressEntry, ...]:
    """Everything that left the perimeter, filtered, oldest first.

    This is the query that gets run in front of an auditor. With
    ``destination="llm_provider"`` it answers "show me everything you ever sent to a
    model provider" exactly, because there is no other route out: a ``SafePayload`` is
    produced only by the gate, and the gate writes a record before it returns one.
    """
    statement: Select[Any] = select(EgressRecordRow)
    if destination is not None:
        statement = statement.where(EgressRecordRow.destination == destination)
    if actor is not None:
        statement = statement.where(EgressRecordRow.actor == actor)
    if purpose is not None:
        statement = statement.where(EgressRecordRow.purpose == purpose)
    if content_digest is not None:
        statement = statement.where(EgressRecordRow.content_digest == content_digest)
    if since is not None:
        statement = statement.where(EgressRecordRow.occurred_at >= since)
    if until is not None:
        statement = statement.where(EgressRecordRow.occurred_at <= until)
    statement = statement.order_by(EgressRecordRow.seq).limit(limit)
    return tuple(_to_egress_entry(row) for row in session.scalars(statement))


def export_egress(entries: Sequence[EgressEntry]) -> str:
    """Render egress records as newline-delimited canonical JSON.

    Newline-delimited rather than one array, because the answer to "everything you ever
    sent" can be millions of rows and an auditor wants to ``grep`` it. Canonical JSON,
    so that two exports of the same rows are byte-identical and can be diffed or
    signed.

    Every field in the output is a name, a hash, a count or a decision. Handing this
    file to someone is not an egress of customer data, which is the property that makes
    the export usable at all.
    """
    return "\n".join(canonical_json(entry.model_dump(mode="json")) for entry in entries)


def verify_chain(session: Session, *, table: str) -> ChainVerification:
    """Recompute every link in a chain and report the first that does not reconcile.

    Walks in ``seq`` order. A gap in the sequence is a break: the chain claims row
    *n+1* follows row *n*, and if row *n* is gone there is nothing for it to follow.
    """
    if table not in {"audit_events", "egress_records"}:
        raise ValueError(f"{table!r} is not a hash-chained ledger")
    is_audit = table == "audit_events"
    rows: Sequence[Any]
    if is_audit:
        rows = list(session.scalars(select(AuditEventRow).order_by(AuditEventRow.seq)))
    else:
        rows = list(session.scalars(select(EgressRecordRow).order_by(EgressRecordRow.seq)))

    prev_hash = GENESIS_HASH
    expected_seq = 1
    first_broken: int | None = None
    for row in rows:
        fields = _audit_fields(row) if is_audit else _egress_fields(row)
        recomputed = chain_hash(prev_hash=prev_hash, seq=row.seq, fields=fields)
        if row.seq != expected_seq or row.prev_hash != prev_hash or row.row_hash != recomputed:
            first_broken = int(row.seq)
            break
        prev_hash = row.row_hash
        expected_seq += 1

    return ChainVerification(
        table=table,
        length=len(rows),
        head_hash=prev_hash,
        intact=first_broken is None,
        first_broken_seq=first_broken,
    )


def assert_chain_intact(session: Session, *, table: str) -> ChainVerification:
    """Verify a chain and raise if it is broken. For a startup check or a cron job."""
    verification = verify_chain(session, table=table)
    if not verification.intact:
        raise ChainBrokenError(
            f"{table} does not verify at seq {verification.first_broken_seq}; "
            "treat this as a tamper indication, not as a bug to patch"
        )
    return verification


def chain_length(session: Session, *, table: str) -> int:
    """How many rows are in a chain. Cheap; does not rehash anything."""
    if table == "audit_events":
        return int(session.scalar(select(func.count()).select_from(AuditEventRow)) or 0)
    if table == "egress_records":
        return int(session.scalar(select(func.count()).select_from(EgressRecordRow)) or 0)
    raise ValueError(f"{table!r} is not a hash-chained ledger")
