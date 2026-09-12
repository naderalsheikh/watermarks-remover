"""Matter organization and explicit document revision links.

Additive metadata only; no original, job, release or certificate is rewritten.
"""

from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "matters", sa.Column("client_name", sa.String(200), nullable=False, server_default="")
    )
    op.add_column(
        "matters", sa.Column("matter_number", sa.String(80), nullable=False, server_default="")
    )
    op.add_column(
        "matters", sa.Column("status", sa.String(12), nullable=False, server_default="active")
    )
    op.add_column(
        "matters",
        sa.Column("organization_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "documents", sa.Column("category", sa.String(80), nullable=False, server_default="")
    )
    op.add_column("documents", sa.Column("previous_revision_id", sa.String(16), nullable=True))
    op.add_column(
        "documents",
        sa.Column("organization_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_documents_previous_revision_id", "documents", ["previous_revision_id"])


def downgrade():
    op.drop_index("ix_documents_previous_revision_id", table_name="documents")
    for column in ("organization_version", "previous_revision_id", "category"):
        op.drop_column("documents", column)
    for column in ("organization_version", "status", "matter_number", "client_name"):
        op.drop_column("matters", column)
