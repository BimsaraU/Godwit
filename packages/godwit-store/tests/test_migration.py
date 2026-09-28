"""The Alembic migration and ``bootstrap_schema`` build the same database.

The initial migration calls ``Base.metadata.create_all`` rather than listing 27 tables,
so that there is exactly one definition of the schema. That is only worth anything if
it is checked: a hand-written migration drifts from the metadata the first time someone
adds a column, and at that point the database the tests ran against and the database
the migration built are different, and every test result is about the wrong one.

This test runs the real migration against a real file database and compares what it
produced with what ``bootstrap_schema`` produces -- tables, views, indexes and the
append-only triggers.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from godwit_store.engine import bootstrap_schema, create_store_engine
from sqlalchemy import Engine, inspect, text

_ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def _shape(engine: Engine) -> Mapping[str, tuple[str, ...]]:
    """Everything about a database that two build paths must agree on."""
    inspector = inspect(engine)
    tables = tuple(
        sorted(name for name in inspector.get_table_names() if name != "alembic_version")
    )
    indexes = tuple(
        sorted(
            f"{table}.{index['name']}"
            for table in tables
            for index in inspector.get_indexes(table)
            if index["name"]
        )
    )
    with engine.connect() as connection:
        triggers = tuple(
            sorted(
                row[0]
                for row in connection.execute(
                    text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
                )
            )
        )
    return {
        "tables": tables,
        "views": tuple(sorted(inspector.get_view_names())),
        "indexes": indexes,
        "triggers": triggers,
    }


@pytest.fixture
def migrated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Engine:
    """A database built by running the migration, exactly as production would."""
    target = tmp_path / "migrated.db"
    url = f"sqlite:///{target.as_posix()}"
    monkeypatch.setenv("GODWIT_STORE_URL", url)
    command.upgrade(Config(str(_ALEMBIC_INI)), "head")
    return create_store_engine(url)


@pytest.fixture
def bootstrapped(tmp_path: Path) -> Engine:
    """A database built from the ORM metadata, as the test suite does."""
    target = tmp_path / "bootstrapped.db"
    engine = create_store_engine(f"sqlite:///{target.as_posix()}")
    bootstrap_schema(engine)
    return engine


def test_the_migration_and_the_metadata_agree(migrated: Engine, bootstrapped: Engine) -> None:
    """One definition of the schema, checked rather than asserted in a comment."""
    assert _shape(migrated) == _shape(bootstrapped)


def test_the_migration_creates_every_table(migrated: Engine) -> None:
    shape = _shape(migrated)
    assert len(shape["tables"]) == 27
    assert "audit_events" in shape["tables"]
    assert "egress_records" in shape["tables"]


def test_the_migration_installs_the_append_only_controls(migrated: Engine) -> None:
    """A migration that built the ledgers without locking them would be worse than none."""
    triggers = _shape(migrated)["triggers"]
    for table in ("audit_events", "egress_records"):
        assert f"{table}_no_update" in triggers
        assert f"{table}_no_delete" in triggers


def test_the_migration_creates_the_safe_views(migrated: Engine) -> None:
    assert _shape(migrated)["views"] == (
        "candidates_safe",
        "column_profiles_safe",
        "labels_safe",
        "patterns_safe",
    )


def test_the_url_is_not_stored_in_the_ini(monkeypatch: pytest.MonkeyPatch) -> None:
    """A connection string in a file in the repository is a credential in the repository."""
    monkeypatch.delenv("GODWIT_STORE_URL", raising=False)
    config = Config(str(_ALEMBIC_INI))
    assert not config.get_main_option("sqlalchemy.url")
    with pytest.raises(RuntimeError, match="deliberately not"):
        command.upgrade(config, "head")
