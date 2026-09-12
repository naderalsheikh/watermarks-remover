"""Durable request retry identities.

Revision ID: 0014
Revises: 0013
"""

from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admissions",
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), primary_key=True),
        sa.Column("requested_by", sa.String(64), primary_key=True),
        sa.Column("operation", sa.String(32), primary_key=True),
        sa.Column("key_sha256", sa.String(64), primary_key=True),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("resource_kind", sa.String(16), nullable=False),
        sa.Column("resource_id", sa.String(16), nullable=False),
        sa.Column("created_utc", sa.String(32), nullable=False),
    )


def downgrade():
    op.drop_table("admissions")
