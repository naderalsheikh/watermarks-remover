"""initial counselclear tables including ACL and audit chain

Revision ID: 0001
Revises:
Create Date: 2026-08-21
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "matters",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_utc", sa.String(32), nullable=False),
    )
    op.create_table(
        "documents",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False),
        sa.Column("storage_path", sa.String(1024), nullable=False),
        sa.Column("created_utc", sa.String(32), nullable=False),
    )
    op.create_index("ix_documents_matter_id", "documents", ["matter_id"])
    op.create_index("ix_documents_sha256", "documents", ["sha256"])
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), nullable=False),
        sa.Column("document_id", sa.String(16), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("policy_id", sa.String(40), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("attestation", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("error", sa.String(1000), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("bundle_dir", sa.String(1024), nullable=False),
        sa.Column("worker_image", sa.String(200), nullable=False),
        sa.Column("created_utc", sa.String(32), nullable=False),
        sa.Column("finished_utc", sa.String(32), nullable=True),
    )
    op.create_index("ix_jobs_matter_id", "jobs", ["matter_id"])
    op.create_index("ix_jobs_document_id", "jobs", ["document_id"])
    op.create_index("ix_jobs_status", "jobs", ["status"])
    op.create_table(
        "matter_acl",
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), primary_key=True),
        sa.Column("user_id", sa.String(64), primary_key=True),
        sa.Column("perm", sa.String(32), primary_key=True),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("matter_id", sa.String(16), sa.ForeignKey("matters.id"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False),
        sa.Column("at", sa.String(32), nullable=False),
    )
    op.create_index("ix_audit_events_matter_id", "audit_events", ["matter_id"])
    op.create_index("ix_audit_events_row_hash", "audit_events", ["row_hash"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("matter_acl")
    op.drop_table("jobs")
    op.drop_table("documents")
    op.drop_table("matters")
