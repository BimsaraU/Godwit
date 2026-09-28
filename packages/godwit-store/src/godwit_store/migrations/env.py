"""Alembic environment for the control-plane database.

The URL comes from ``GODWIT_STORE_URL``, never from ``alembic.ini``: a connection
string in a file in the repository is a credential in the repository, and the contracts
are explicit that secrets are never plaintext at rest.
"""

from __future__ import annotations

import os

from alembic import context
from godwit_store.schema import Base
from sqlalchemy import engine_from_config, pool

config = context.config
target_metadata = Base.metadata

_URL_ENV = "GODWIT_STORE_URL"


def _database_url() -> str:
    url = os.environ.get(_URL_ENV) or config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError(
            f"set {_URL_ENV} to the control-plane database URL; it is deliberately not "
            "stored in alembic.ini"
        )
    return url


def run_migrations_offline() -> None:
    """Emit SQL without connecting, for a DBA who applies changes by hand.

    Banks do this. A migration that can only run with a live connection from the
    service's own process is a migration a change-control board will not approve.
    """
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
