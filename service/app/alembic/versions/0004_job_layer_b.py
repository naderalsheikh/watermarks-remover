"""jobs.layer_b — per-job record of a Layer B (statistical watermark)
rewrite executed under a signed attestation. Nullable: ordinary Layer A
jobs carry NULL; only jobs that ran a watermark rewrite under a consumed
attestation token set {strength, label, subject, jti}. The jti column ties
the job back to the single-use attestation in the audit chain, so a
post-hoc review can prove exactly which authorization authorized the
content-altering rewrite.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-24
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0004"
down_revision: Union[str, Sequence[str], None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# JSONB on Postgres, JSON on SQLite (see 0001 for why this is edited in
# place rather than shipped as its own revision).
_PG_JSON = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(sa.Column("layer_b", _PG_JSON, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_column("layer_b")
