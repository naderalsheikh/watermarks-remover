"""batches -- first-class async bulk-run resource, plus jobs.batch_id

Introduces `batches` (one row per POST .../batches submission) and adds a
nullable `batch_id` FK on `jobs` so a batch's children are ordinary Job
rows, reusing every existing job/manifest/bundle route unchanged. NULL on
every job created by the synchronous single-document routes or the
legacy synchronous bulk-jobs route -- both are untouched by this pass.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-26
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, Sequence[str], None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "batches",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("policy_id", sa.String(40), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("created_utc", sa.String(32), nullable=False),
        sa.Column("finished_utc", sa.String(32), nullable=True),
    )
    op.create_index("ix_batches_matter_id", "batches", ["matter_id"])
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(sa.Column("batch_id", sa.String(16), nullable=True))
        batch_op.create_foreign_key(
            "fk_jobs_batch_id_batches", "batches", ["batch_id"], ["id"]
        )
    op.create_index("ix_jobs_batch_id", "jobs", ["batch_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_batch_id", table_name="jobs")
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_constraint("fk_jobs_batch_id_batches", type_="foreignkey")
        batch_op.drop_column("batch_id")
    op.drop_index("ix_batches_matter_id", table_name="batches")
    op.drop_table("batches")
