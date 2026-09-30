"""Engines, sessions and schema bootstrap.

One place that knows how to build a database, so that the Alembic migration, the test
fixture and a running service all produce the same one. A schema that differs between
"what migrations built" and "what tests ran against" is a schema whose tests prove
nothing.

WHY SQLITE IS SUPPORTED AT ALL
------------------------------
Postgres 16 with pgvector is the deployment target and the only one that matters. The
test suite runs on SQLite because ``make test`` must work on a clean checkout with no
Docker, and a schema exercised only where a container happens to be running is a schema
exercised rarely. The three dialect differences are wrapped in
:mod:`godwit_store.columns`, the append-only enforcement is wrapped in
:mod:`godwit_store.appendonly`, and everything else is the same SQL.

What SQLite does **not** cover, and what therefore needs the Postgres path in CI:
ivfflat index behaviour, grant-based enforcement, advisory locks, and JSONB operators.
Those are marked in the test suite rather than assumed.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from godwit_store.appendonly import install_append_only
from godwit_store.errors import StoreUnavailableError, classify_driver_error
from godwit_store.schema import Base

__all__ = [
    "bootstrap_schema",
    "check_connection",
    "create_store_engine",
    "session_factory",
    "store_session",
]


def create_store_engine(url: str, *, echo: bool = False, **kwargs: object) -> Engine:
    """Build an engine for the control-plane database.

    On SQLite, foreign keys are switched on per connection: SQLite ignores them by
    default, which would silently disable the composite key that stops an unaudited
    artifact being deployed -- the one constraint in this schema it would be worst to
    lose in the environment the tests run in.
    """
    engine = create_engine(url, echo=echo, future=True, **kwargs)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: object) -> None:  # noqa: ANN401
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def bootstrap_schema(engine: Engine, *, role: str | None = None) -> None:
    """Create every table, view and append-only control from the ORM metadata.

    For tests and for a throwaway local database. **Production uses Alembic**, which
    applies the same DDL through :mod:`godwit_store.migrations` -- there is one
    definition of the schema and both paths read it.
    """
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        Base.metadata.create_all(connection)
        install_append_only(connection, role=role)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """A session maker with autoflush off.

    Autoflush off on purpose: ingest builds a pattern, then reads back to find its
    ancestor, and an implicit flush between those two steps would make the new pattern
    its own ancestor. Flushes here are explicit and are written where they belong.
    """
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def store_session(engine: Engine) -> Iterator[Session]:
    """A session that commits on success and rolls back on any failure.

    Driver exceptions are classified on the way out and their messages discarded: a
    psycopg ``IntegrityError`` renders the conflicting row in ``DETAIL``, so letting one
    reach a log is an egress nobody gated (leak path 10).
    """
    session = session_factory(engine)()
    try:
        yield session
        session.commit()
    except Exception as exc:
        session.rollback()
        raise classify_driver_error(exc) from None
    finally:
        session.close()


def check_connection(engine: Engine) -> None:
    """Raise :class:`StoreUnavailableError` if the database is not reachable.

    For a service's readiness probe. Deliberately not called on engine creation: a
    process that cannot start because a database is briefly down is a worse outage than
    one that starts and reports itself unready.
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        raise StoreUnavailableError(
            f"control-plane database unreachable ({type(exc).__name__}); message withheld"
        ) from None
