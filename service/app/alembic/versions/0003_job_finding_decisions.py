"""jobs.finding_decisions — per-subtype approve/keep decisions for
approve-default policy cells. Without this column (and the API/worker
plumbing that fills it), production's approve-default subtypes had no way
to ever resolve to anything but "keep": plan_actions treats a missing
decision as no_decision -> keep, so production sanitize was effectively a
no-op strip through the shipped API.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-23
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003"
down_revision: Union[str, Sequence[str], None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# JSONB on Postgres, JSON on SQLite (see 0001 for why this is edited in
# place rather than shipped as its own revision).
_PG_JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(
            sa.Column("finding_decisions", _PG_JSON, nullable=False, server_default="{}")
        )


def downgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_column("finding_decisions")
