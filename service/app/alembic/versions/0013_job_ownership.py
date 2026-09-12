"""Durable job actor, lease, attempt fencing and parent-observed outcomes.

Revision ID: 0013
Revises: 0012
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "job_queue",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("capacity", sa.Integer(), nullable=False),
    )
    with op.batch_alter_table("jobs") as batch:
        batch.add_column(sa.Column("requested_by", sa.String(64), nullable=True))
        batch.add_column(sa.Column("lease_token", sa.String(32), nullable=True))
        batch.add_column(sa.Column("lease_expires_epoch", sa.BigInteger(), nullable=True))
        batch.add_column(
            sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column(
                "execution_receipt", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=True
            )
        )
        batch.create_index("ix_jobs_lease_expires_epoch", ["lease_expires_epoch"])


def downgrade():
    with op.batch_alter_table("jobs") as batch:
        batch.drop_index("ix_jobs_lease_expires_epoch")
        for name in (
            "execution_receipt",
            "attempt_number",
            "lease_expires_epoch",
            "lease_token",
            "requested_by",
        ):
            batch.drop_column(name)
    op.drop_table("job_queue")
