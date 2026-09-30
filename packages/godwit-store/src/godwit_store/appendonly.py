"""Append-only enforcement for the two ledgers, in the database rather than in Python.

``audit_events`` and ``egress_records`` support INSERT and SELECT. They do not support
UPDATE, DELETE or TRUNCATE, and that is enforced by the database, because an
application-level rule is enforced only against applications that agree to it -- and
the thing a bank's security team asks about is the ``psql`` session, not the service.

TWO MECHANISMS, BECAUSE EITHER ONE ALONE HAS A HOLE
---------------------------------------------------
**Grants** stop the application role. They do not stop the table's owner: in Postgres
the owner holds every privilege implicitly and can re-grant to itself, so a migration
that only revokes has secured the service and nothing else.

**A refusing trigger** stops the owner too, and stops anything that reaches the table
by any route, including a hand-typed ``DELETE``. It does not stop a superuser, who can
disable it -- ``ALTER TABLE ... DISABLE TRIGGER`` -- and nothing inside Postgres stops a
superuser. That is a deployment property: the ledgers' owner must not be the role the
service connects as, and the superuser must not be a person.

The **hash chain** in :mod:`godwit_store.ledger` is the third layer and the only one
that survives a superuser: a row removed or amended by any means leaves the chain
unverifiable. It makes tampering *evident*, which is a different and weaker claim than
preventing it, and the documentation says so rather than implying otherwise.

WHY THE TRIGGER MESSAGE CARRIES A SENTINEL
------------------------------------------
``GODWIT_APPEND_ONLY`` appears in the refusal text so that
:func:`godwit_store.errors.classify_driver_error` can recognise the refusal without
reading the rest of the driver's message. Driver messages routinely quote the offending
row (leak path 10); this one is text we wrote, and only the sentinel is inspected.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy.engine import Connection

__all__ = [
    "APPEND_ONLY_SENTINEL",
    "APPEND_ONLY_TABLES",
    "append_only_statements",
    "install_append_only",
]

APPEND_ONLY_TABLES: Final[tuple[str, ...]] = ("audit_events", "egress_records")
"""The ledgers. Adding a table here is a policy decision, not a refactor."""

APPEND_ONLY_SENTINEL: Final[str] = "GODWIT_APPEND_ONLY"
"""Token in the refusal message. Matched instead of parsing a driver string."""

_PG_FUNCTION: Final[str] = f"""
CREATE OR REPLACE FUNCTION godwit_refuse_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        '{APPEND_ONLY_SENTINEL}: % is append-only; UPDATE, DELETE and TRUNCATE are '
        'refused. Correct a mistaken entry by appending a correcting one.',
        TG_TABLE_NAME;
END;
$$
"""


def _postgres_statements(table: str, *, role: str | None) -> tuple[str, ...]:
    statements = [
        f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM PUBLIC",
        f"DROP TRIGGER IF EXISTS {table}_is_append_only ON {table}",
        (
            f"CREATE TRIGGER {table}_is_append_only "
            f"BEFORE UPDATE OR DELETE OR TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION godwit_refuse_mutation()"
        ),
    ]
    if role is not None:
        statements.insert(1, f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM {role}")
        statements.insert(2, f"GRANT INSERT, SELECT ON {table} TO {role}")
    return tuple(statements)


def _sqlite_statements(table: str) -> tuple[str, ...]:
    """SQLite has no grants, so the trigger is the whole control.

    SQLite is the test dialect, not the deployment target. These triggers exist so that
    ``test_append_only.py`` asserts a refusal from the database on every developer's
    machine rather than only where a container happens to be running.
    """
    return tuple(
        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{verb} BEFORE {verb.upper()} ON {table} "
        f"BEGIN SELECT RAISE(ABORT, "
        f"'{APPEND_ONLY_SENTINEL}: {table} is append-only'); END"
        for verb in ("update", "delete")
    )


def append_only_statements(dialect: str, *, role: str | None = None) -> tuple[str, ...]:
    """The DDL that makes the ledgers append-only on ``dialect``.

    ``role`` is the database role the service connects as. When given, Postgres gets an
    explicit revoke-and-regrant for it as well as the revoke from ``PUBLIC``; a role
    that inherits from ``PUBLIC`` is covered either way, and one that does not is not.
    """
    if dialect == "postgresql":
        statements: list[str] = [_PG_FUNCTION.strip()]
        for table in APPEND_ONLY_TABLES:
            statements.extend(_postgres_statements(table, role=role))
        return tuple(statements)
    if dialect == "sqlite":
        return tuple(
            statement for table in APPEND_ONLY_TABLES for statement in _sqlite_statements(table)
        )
    raise ValueError(
        f"no append-only enforcement is defined for dialect {dialect!r}; a ledger "
        "without database-level enforcement is a ledger with a convention"
    )


def install_append_only(connection: Connection, *, role: str | None = None) -> None:
    """Apply the append-only DDL to an open connection.

    Called by the Alembic migration and by the test fixture, so that both paths produce
    the same database. Idempotent on both dialects.
    """
    for statement in append_only_statements(connection.dialect.name, role=role):
        connection.exec_driver_sql(statement)
