"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}

Write the upgrade and the downgrade. A revision with an empty downgrade is a revision
nobody can roll back, and a change-control board will say so before you do.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
