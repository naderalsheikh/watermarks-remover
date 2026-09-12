"""Durable whole-message admission and outbox; no transport listener.

Revision ID: 0017
Revises: 0016
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade():
    json_type = sa.JSON().with_variant(JSONB(), "postgresql")
    op.create_table(
        "mail_submissions",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("request_key", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(200), nullable=False),
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(128), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("transport", sa.String(200), nullable=False),
        sa.Column("peer_identity", sa.String(200), nullable=False),
        sa.Column("binding_sha256", sa.String(64), nullable=False),
        sa.Column("envelope", json_type, nullable=False),
        sa.Column("limits", json_type, nullable=False),
        sa.Column("input_ref", sa.Text(), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("input_bytes", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("retryable", sa.Boolean(), nullable=False),
        sa.Column("reasons", json_type, nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("lease_token", sa.String(32)),
        sa.Column("lease_expires_epoch", sa.BigInteger()),
        sa.Column("output_ref", sa.Text()),
        sa.Column("output_sha256", sa.String(64)),
        sa.Column("output_bytes", sa.BigInteger()),
        sa.Column("delivery_token", sa.String(32)),
        sa.Column("delivery_expires_epoch", sa.BigInteger()),
        sa.Column("acknowledgment_sha256", sa.String(64)),
        sa.Column("created_epoch", sa.BigInteger(), nullable=False),
        sa.Column("updated_epoch", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("tenant_id", "request_key", name="uq_mail_tenant_request"),
    )
    op.create_index("ix_mail_submissions_matter_id", "mail_submissions", ["matter_id"])
    op.create_index("ix_mail_submissions_status", "mail_submissions", ["status"])


def downgrade():
    if op.get_bind().execute(sa.text("SELECT COUNT(*) FROM mail_submissions")).scalar():
        raise RuntimeError("cannot discard retained mail submissions during downgrade")
    op.drop_table("mail_submissions")
