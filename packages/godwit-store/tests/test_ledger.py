"""The audit and egress ledgers: append-only, hash-chained, and exportable.

Two acceptance criteria meet here:

* *"UPDATE and DELETE on ``audit_events`` and ``egress_records`` fail at the database."*
* the egress export -- *"a bank will ask 'show me everything you ever sent to a model
  provider'; you must be able to answer exactly, with a query, in front of them."*

The append-only tests assert a refusal **from the database**, not from Python. That
distinction is the whole point: an application-level rule is enforced only against
applications that agree to it, and the session a security reviewer opens is ``psql``.
"""

from __future__ import annotations

import datetime as _dt
from itertools import pairwise

import pytest
from godwit_contracts import (
    AuditEvent,
    ContentHash,
    Destination,
    EgressRecord,
    Instant,
    Plane,
    RedactionAction,
    Sensitivity,
)
from godwit_store.appendonly import APPEND_ONLY_TABLES, append_only_statements
from godwit_store.errors import ChainBrokenError, classify_driver_error
from godwit_store.ledger import (
    GENESIS_HASH,
    append_audit,
    append_egress,
    assert_chain_intact,
    audit_query,
    chain_length,
    egress_query,
    export_egress,
    verify_chain,
)
from sqlalchemy import text
from sqlalchemy.orm import Session

_MUTATIONS = {
    "audit_events": (
        "UPDATE audit_events SET actor = 'x'",
        "DELETE FROM audit_events",
    ),
    "egress_records": (
        "UPDATE egress_records SET actor = 'x'",
        "DELETE FROM egress_records",
    ),
}
"""The statements the ledgers must refuse, written out per table.

Literals rather than an f-string over the table name: interpolating an identifier into
SQL is the habit that becomes an injection somewhere less careful, and there are two
tables.
"""


def _audit(index: int, at: Instant, *, actor: str = "orchestrator") -> AuditEvent:
    return AuditEvent(
        event_id=f"aud_{index:04d}",
        occurred_at=at + _dt.timedelta(minutes=index),
        actor=actor,
        action="pattern_created",
        subject_kind="pattern",
        subject_id=f"pat_{index:04d}",
        plane=Plane.CONTROL,
    )


def _egress(index: int, at: Instant, *, destination: Destination) -> EgressRecord:
    return EgressRecord(
        record_id=f"egr_{index:04d}",
        occurred_at=at + _dt.timedelta(minutes=index),
        destination=destination,
        purpose="explain_pattern",
        actor="godwit-llm",
        policy_id="pol_default",
        policy_version=3,
        guardrail_ids=("gr_pii_deny",),
        content_digest=ContentHash(f"b2_{index:032x}"),
        field_names=("segment_label", "effect_size"),
        source_ids=("src_test",),
        sensitivity_before=Sensitivity.DATA_VALUE,
        sensitivity_after=Sensitivity.TOKEN,
        actions_applied=(RedactionAction.TOKENISE,),
        min_population=500,
    )


# ------------------------------------------------------------------------------------
# The chain
# ------------------------------------------------------------------------------------


def test_the_first_row_points_at_genesis(session: Session, at: Instant) -> None:
    entry = append_audit(session, _audit(1, at))
    assert entry.seq == 1
    assert entry.prev_hash == GENESIS_HASH


def test_each_row_links_to_the_one_before_it(session: Session, at: Instant) -> None:
    entries = [append_audit(session, _audit(index, at)) for index in range(1, 6)]
    for earlier, later in pairwise(entries):
        assert later.prev_hash == earlier.row_hash
        assert later.seq == earlier.seq + 1
    assert verify_chain(session, table="audit_events").intact


def test_an_intact_chain_reports_its_head(session: Session, at: Instant) -> None:
    """The head hash is the value worth exporting and signing.

    A verifier holding last week's head can prove this week's chain still contains it,
    which is the only part of this that survives someone with write access.
    """
    last = None
    for index in range(1, 4):
        last = append_audit(session, _audit(index, at))
    verification = assert_chain_intact(session, table="audit_events")
    assert last is not None
    assert verification.head_hash == last.row_hash
    assert verification.length == 3


def test_a_tampered_row_breaks_the_chain_at_its_own_sequence(session: Session, at: Instant) -> None:
    """Tamper-evident, not tamper-proof. Stated precisely because it matters.

    The row is altered here through raw SQL with the triggers dropped, which is what an
    attacker with database access would do. The chain still notices, because the stored
    hash no longer matches the row's contents.
    """
    for index in range(1, 4):
        append_audit(session, _audit(index, at))
    session.commit()

    _drop_append_only_triggers(session)
    session.execute(
        text("UPDATE audit_events SET actor = :actor WHERE seq = 2"),
        {"actor": "someone_else"},
    )
    session.commit()

    verification = verify_chain(session, table="audit_events")
    assert not verification.intact
    assert verification.first_broken_seq == 2
    with pytest.raises(ChainBrokenError, match="tamper"):
        assert_chain_intact(session, table="audit_events")


def test_a_deleted_row_breaks_the_chain(session: Session, at: Instant) -> None:
    for index in range(1, 5):
        append_audit(session, _audit(index, at))
    session.commit()

    _drop_append_only_triggers(session)
    session.execute(text("DELETE FROM audit_events WHERE seq = 2"))
    session.commit()

    verification = verify_chain(session, table="audit_events")
    assert not verification.intact
    assert verification.first_broken_seq == 3


def test_the_two_ledgers_have_independent_chains(session: Session, at: Instant) -> None:
    append_audit(session, _audit(1, at))
    entry = append_egress(session, _egress(1, at, destination=Destination.LLM_PROVIDER))
    assert entry.seq == 1
    assert entry.prev_hash == GENESIS_HASH
    assert chain_length(session, table="audit_events") == 1
    assert chain_length(session, table="egress_records") == 1


def test_verify_refuses_a_table_that_is_not_a_ledger(session: Session) -> None:
    with pytest.raises(ValueError, match="not a hash-chained ledger"):
        verify_chain(session, table="patterns")


# ------------------------------------------------------------------------------------
# Append-only, enforced by the database
# ------------------------------------------------------------------------------------


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_update_is_refused_by_the_database(session: Session, at: Instant, table: str) -> None:
    """**Acceptance criterion.** UPDATE fails at the database, not in Python."""
    _seed(session, at)
    session.commit()
    with pytest.raises(Exception) as caught:
        session.execute(text(_MUTATIONS[table][0]))
        session.commit()
    session.rollback()
    assert "GODWIT_APPEND_ONLY" in str(caught.value)


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_delete_is_refused_by_the_database(session: Session, at: Instant, table: str) -> None:
    """**Acceptance criterion.** DELETE fails at the database, not in Python."""
    _seed(session, at)
    session.commit()
    with pytest.raises(Exception) as caught:
        session.execute(text(_MUTATIONS[table][1]))
        session.commit()
    session.rollback()
    assert "GODWIT_APPEND_ONLY" in str(caught.value)


def test_the_refusal_reaches_python_without_a_driver_message(session: Session, at: Instant) -> None:
    """Driver messages quote the offending row (leak path 10). Ours does not.

    Only the sentinel is inspected; nothing else from the driver's text is kept, which
    is why the classifier can recognise the refusal without handling the message.
    """
    _seed(session, at)
    session.commit()
    try:
        session.execute(text("DELETE FROM audit_events"))
        session.commit()
    except Exception as exc:  # the driver type varies by dialect
        session.rollback()
        classified = classify_driver_error(exc)
        assert "append-only" in str(classified)
        assert "GODWIT_APPEND_ONLY" not in str(classified)
    else:
        pytest.fail("the database allowed a DELETE on an append-only ledger")


def test_inserting_is_still_allowed(session: Session, at: Instant) -> None:
    """A ledger nobody can write to is not append-only, it is read-only."""
    _seed(session, at)
    session.commit()
    append_audit(session, _audit(99, at))
    session.commit()
    assert chain_length(session, table="audit_events") == 2


def test_postgres_enforcement_revokes_as_well_as_refusing() -> None:
    """Grants and a trigger, because each alone has a hole.

    Grants do not stop the table's owner, who holds every privilege implicitly. The
    trigger stops the owner too. Neither stops a superuser, and this asserts that both
    are emitted rather than one -- checked as SQL text so it holds on every machine,
    not only where a Postgres container happens to be running.
    """
    statements = append_only_statements("postgresql", role="godwit_service")
    joined = "\n".join(statements)
    for table in APPEND_ONLY_TABLES:
        assert f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM PUBLIC" in joined
        assert f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM godwit_service" in joined
        assert f"GRANT INSERT, SELECT ON {table} TO godwit_service" in joined
        assert f"CREATE TRIGGER {table}_is_append_only" in joined


def test_an_unknown_dialect_has_no_enforcement_and_says_so() -> None:
    """Failing closed. A ledger without database-level enforcement is a convention."""
    with pytest.raises(ValueError, match="no append-only enforcement"):
        append_only_statements("mysql")


# ------------------------------------------------------------------------------------
# The query a regulator asks for
# ------------------------------------------------------------------------------------


def test_everything_ever_sent_to_a_model_provider(session: Session, at: Instant) -> None:
    """**The question a bank asks.** One query, filtered by destination, no caveats."""
    append_egress(session, _egress(1, at, destination=Destination.LLM_PROVIDER))
    append_egress(session, _egress(2, at, destination=Destination.UI))
    append_egress(session, _egress(3, at, destination=Destination.LLM_PROVIDER))

    sent = egress_query(session, destination=Destination.LLM_PROVIDER.value)
    assert [entry.record_id for entry in sent] == ["egr_0001", "egr_0003"]
    assert all(entry.destination == "llm_provider" for entry in sent)


def test_the_egress_query_filters_by_time_actor_and_digest(session: Session, at: Instant) -> None:
    append_egress(session, _egress(1, at, destination=Destination.LLM_PROVIDER))
    append_egress(session, _egress(2, at, destination=Destination.LLM_PROVIDER))

    assert len(egress_query(session, since=at + _dt.timedelta(minutes=2))) == 1
    assert len(egress_query(session, actor="godwit-llm")) == 2
    assert len(egress_query(session, actor="nobody")) == 0
    assert len(egress_query(session, content_digest=f"b2_{1:032x}")) == 1


def test_the_export_is_deterministic_and_carries_no_value(session: Session, at: Instant) -> None:
    """Handing this file to an auditor must not itself be an egress of customer data."""
    append_egress(session, _egress(1, at, destination=Destination.LLM_PROVIDER))
    append_egress(session, _egress(2, at, destination=Destination.LLM_PROVIDER))
    entries = egress_query(session, destination=Destination.LLM_PROVIDER.value)

    first = export_egress(entries)
    assert first == export_egress(entries), "two exports of the same rows must be byte-identical"
    assert first.count("\n") == 1, "newline-delimited, so it can be grepped"
    assert "segment_label" in first, "field NAMES are the point of the record"
    assert "b2_" in first, "and the digest of what left"


def test_the_audit_query_orders_by_sequence_not_timestamp(session: Session, at: Instant) -> None:
    """Two events stamped with the same injected instant still have a defined order."""
    for index in range(1, 4):
        append_audit(session, _audit(index, at.replace(microsecond=0)))
    entries = audit_query(session, subject_kind="pattern")
    assert [entry.seq for entry in entries] == [1, 2, 3]


def test_an_egress_record_has_no_field_a_value_could_sit_in(session: Session, at: Instant) -> None:
    """Asserted structurally: every column is a plain type, so there is nowhere to put one.

    A weaker version of this test would search the stored row for known PII strings.
    That is a backstop and would pass on a schema with a ``notes`` column nobody filled
    in yet, which is exactly the schema that leaks next year.
    """
    entry = append_egress(session, _egress(1, at, destination=Destination.LLM_PROVIDER))
    for name, value in entry.model_dump().items():
        assert not hasattr(value, "sensitivity"), f"{name} holds a tainted value"


def _seed(session: Session, at: Instant) -> None:
    append_audit(session, _audit(1, at))
    append_egress(session, _egress(1, at, destination=Destination.LLM_PROVIDER))


def _drop_append_only_triggers(session: Session) -> None:
    """Remove the refusing triggers, so a tamper test can actually tamper.

    Simulates an attacker with database rights. Dropping the trigger is exactly what
    they would have to do first, and the point of the chain is that doing so is still
    not enough.
    """
    bind = session.get_bind()
    for table in APPEND_ONLY_TABLES:
        if bind.dialect.name == "postgresql":
            session.execute(text(f"DROP TRIGGER IF EXISTS {table}_is_append_only ON {table}"))
        else:
            for verb in ("update", "delete"):
                session.execute(text(f"DROP TRIGGER IF EXISTS {table}_no_{verb}"))
    session.commit()
