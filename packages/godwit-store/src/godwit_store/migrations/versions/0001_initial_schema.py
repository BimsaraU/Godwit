"""Initial control-plane schema: tables, safe views, append-only ledgers.

Revision ID: 0001_initial_schema
Revises:
Create Date: injected, not read -- this file contains no wall-clock stamp.

WHY THIS MIGRATION CALLS ``create_all`` INSTEAD OF LISTING 27 TABLES
--------------------------------------------------------------------
Because there must be exactly one definition of the schema. A hand-written initial
migration is a second copy of :mod:`godwit_store.schema`, and the two drift the first
time someone adds a column -- at which point the database the tests ran against and the
database the migration built are different, and every test result is about the wrong
thing.

Subsequent migrations are ordinary hand-written ``op.add_column`` / ``op.alter_column``
revisions produced by ``alembic revision --autogenerate``, which diffs against this same
metadata. Only the initial one is generated wholesale, and only because at revision one
the metadata *is* the migration.

The append-only controls -- the revoking grants and the refusing trigger -- come from
:mod:`godwit_store.appendonly`, so ``bootstrap_schema`` and this migration install
byte-identical DDL.
"""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import op
from godwit_store.appendonly import install_append_only
from godwit_store.schema import Base

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

_ROLE_ENV = "GODWIT_STORE_ROLE"
"""Database role the service connects as. When set, the append-only grants name it
explicitly as well as revoking from PUBLIC -- a role that does not inherit from PUBLIC
is not covered by the blanket revoke."""


def upgrade() -> None:
    """Create everything, then take away the privileges the ledgers must not have."""
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(connection)
    install_append_only(connection, role=os.environ.get(_ROLE_ENV))
    if connection.dialect.name == "postgresql":
        _create_vector_index(connection)


def _create_vector_index(connection: sa.Connection) -> None:
    """An ivfflat index over the dedup embedding.

    ``vector_cosine_ops`` because the embedding is already unit-normalised, so cosine
    distance and inner product agree and cosine reads more obviously. A hundred lists is
    right for tens of thousands of patterns; past a million, rebuild it with more.

    Postgres only: SQLite holds the vector as a JSON array and similarity is computed in
    Python by :func:`godwit_store.signature.cosine`. That is fine for tests and would not
    be fine for a queue.
    """
    connection.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS ix_patterns_embedding ON patterns "
            "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
        )
    )


def downgrade() -> None:
    """Drop everything this revision created.

    Note what this means for the ledgers: downgrading **destroys the audit and egress
    history**, which is exactly the operation the grants and triggers exist to prevent
    in normal running. It is here because Alembic expects it and because revision one
    has to be reversible during development. Running it against a production control
    plane is a deliberate act of destroying evidence, and whoever runs it should have to
    say so out loud first.
    """
    connection = op.get_bind()
    Base.metadata.drop_all(connection)
