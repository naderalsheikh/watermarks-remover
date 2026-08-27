"""releases -- first-class business/custody event wrapping a Job

Introduces `releases`: one row per release attempt, 1:1 with the Job it
wraps (job_id unique), optionally grouped by an existing Batch (batch_id,
same nullable pattern jobs.batch_id already uses). Job stays exactly what
it is -- the execution mechanism -- and this table adds the facts a Job
was never meant to carry: recipient/purpose/policy context, and whether
the release was intended to leave the organization.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-27
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, Sequence[str], None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "releases",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), nullable=False),
        sa.Column("document_id", sa.String(16), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("batch_id", sa.String(16), sa.ForeignKey("batches.id"), nullable=True),
        sa.Column("job_id", sa.String(16), sa.ForeignKey("jobs.id"), nullable=False, unique=True),
        sa.Column("policy_id", sa.String(40), nullable=False),
        sa.Column("profile_id", sa.String(40), nullable=False),
        sa.Column("recipient_type", sa.String(40), nullable=False),
        sa.Column("recipient_name", sa.String(200), nullable=False),
        sa.Column("purpose", sa.String(500), nullable=False),
        sa.Column("intended_external", sa.Boolean(), nullable=False),
        sa.Column("requested_by", sa.String(64), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("created_utc", sa.String(32), nullable=False),
        sa.Column("finished_utc", sa.String(32), nullable=True),
    )
    op.create_index("ix_releases_matter_id", "releases", ["matter_id"])
    op.create_index("ix_releases_document_id", "releases", ["document_id"])
    op.create_index("ix_releases_batch_id", "releases", ["batch_id"])
    op.create_index("ix_releases_job_id", "releases", ["job_id"], unique=True)
    op.create_index("ix_releases_status", "releases", ["status"])


def downgrade() -> None:
    op.drop_index("ix_releases_status", table_name="releases")
    op.drop_index("ix_releases_job_id", table_name="releases")
    op.drop_index("ix_releases_batch_id", table_name="releases")
    op.drop_index("ix_releases_document_id", table_name="releases")
    op.drop_index("ix_releases_matter_id", table_name="releases")
    op.drop_table("releases")
