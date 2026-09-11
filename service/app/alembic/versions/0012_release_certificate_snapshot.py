"""Add an internal, nullable certificate snapshot to releases.

Existing rows remain SQL NULL; the runtime records a snapshot when needed.
No historical certificate contents are inferred or backfilled.

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-11
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0012"
down_revision: Union[str, Sequence[str], None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("releases") as batch_op:
        batch_op.add_column(
            sa.Column(
                "certificate_snapshot",
                sa.JSON(none_as_null=True).with_variant(JSONB(none_as_null=True), "postgresql"),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("releases") as batch_op:
        batch_op.drop_column("certificate_snapshot")
