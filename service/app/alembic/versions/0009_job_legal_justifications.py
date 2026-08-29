"""jobs.legal_justifications -- structured basis for surviving findings

Adds a JSON column alongside jobs.finding_decisions. finding_decisions
records the mechanical approve/keep choice; legal_justifications records
the operator-facing basis and optional note for findings that survive in a
derivative. Existing rows backfill to {}, which plan_actions treats as an
honest unspecified basis rather than inventing a legal ground.

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0009"
down_revision: Union[str, Sequence[str], None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PG_JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(
            sa.Column("legal_justifications", _PG_JSON, nullable=False, server_default="{}")
        )


def downgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_column("legal_justifications")
