"""matters.is_demo -- explicit flag for a demo-seeded matter

Adds a single boolean column so a matter created by the evaluation-flow
seed path (POST /v1/matters/demo-seed) can be excluded from cross-matter
dashboard aggregation without relying on a name-prefix convention. Server
default 0/false so existing rows backfill safely with no data migration.

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-27
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, Sequence[str], None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "matters",
        sa.Column("is_demo", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("matters", "is_demo")
