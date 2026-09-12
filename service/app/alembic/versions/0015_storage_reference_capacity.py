"""Keep complete opaque storage references, including long object version identifiers.

Revision ID: 0015
Revises: 0014
"""

from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("documents") as batch:
        batch.alter_column(
            "storage_path", existing_type=sa.String(1024), type_=sa.Text(), existing_nullable=False
        )


def downgrade():
    connection = op.get_bind()
    if connection.scalar(
        sa.text("SELECT count(*) FROM documents WHERE length(storage_path) > 1024")
    ):
        raise RuntimeError(
            "cannot downgrade: storage references exceed the old 1024-character limit"
        )
    with op.batch_alter_table("documents") as batch:
        batch.alter_column(
            "storage_path", existing_type=sa.Text(), type_=sa.String(1024), existing_nullable=False
        )
