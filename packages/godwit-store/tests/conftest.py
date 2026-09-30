"""Fixtures for godwit-store's tests.

The suite runs against SQLite in memory, so ``make test`` works on a clean checkout
with no Docker. Set ``GODWIT_STORE_TEST_URL`` to a Postgres URL to run the same suite
against the real target -- the schema, the append-only DDL and the store code are
dialect-agnostic apart from the three wrappers in ``godwit_store.columns``.

Nothing here reads a clock. ``frozen_now`` comes from the repository-wide conftest and
every instant in these tests is derived from it (universal rule 5).
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from godwit_contracts import Instant
from godwit_store.engine import bootstrap_schema, create_store_engine, session_factory
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    # The workspace runs pytest with --import-mode=importlib, under which a test module
    # cannot ``import conftest``. conftest is imported before the modules beside it, so
    # putting this directory on sys.path here is what makes ``from _support import ...``
    # work -- the same arrangement godwit-sketch uses, for the same reason.
    #
    # The module is called ``_store_support`` and not ``_support`` because every
    # package puts its tests directory on sys.path this way, and the first one to be
    # collected wins the name. godwit-sketch already owns ``_support``.
    sys.path.insert(0, _HERE)

_URL_ENV = "GODWIT_STORE_TEST_URL"


@pytest.fixture(scope="session")
def store_url() -> str:
    """Where the tests point. In-memory SQLite unless told otherwise."""
    return os.environ.get(_URL_ENV, "sqlite://")


@pytest.fixture
def engine(store_url: str) -> Iterator[Engine]:
    """A freshly built database per test.

    Per test rather than per session: several tests assert on the *whole* contents of
    an append-only ledger, and those cannot share a database with anything.
    """
    if store_url.startswith("sqlite://") and "/" not in store_url[9:]:
        # An in-memory SQLite database lives inside one connection, so the pool has
        # to hand out the same one every time or each session gets an empty schema.
        created = create_store_engine(store_url, poolclass=StaticPool)
    else:
        created = create_store_engine(store_url)
    bootstrap_schema(created)
    yield created
    created.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """A session bound to the per-test database, rolled back at the end."""
    factory = session_factory(engine)
    with factory() as active:
        yield active
        active.rollback()


@pytest.fixture
def is_postgres(engine: Engine) -> bool:
    """True when the suite is running against the real deployment target."""
    return engine.dialect.name == "postgresql"


@pytest.fixture
def at(frozen_now: _dt.datetime) -> Instant:
    """The one instant these tests use. Derived from the repository-wide fixture."""
    return frozen_now
