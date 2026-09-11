"""Pin the execution mode alongside the existing worker-image column.

Revision ID: 0016
Revises: 0015
"""

from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("jobs", sa.Column("worker_mode", sa.String(16), nullable=True))


def downgrade():
    op.drop_column("jobs", "worker_mode")
