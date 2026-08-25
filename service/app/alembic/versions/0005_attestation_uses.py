"""attestation_uses — durable, race-free single-use record for a Layer B
attestation jti.

Layer B single-use was enforced by app.security's in-memory
_consumed_jtis set (a per-process fast path) plus a query against
jobs.layer_b->>'jti' at job-creation time. Neither is race-free: the
in-memory set doesn't survive a restart or share state across gunicorn
workers, and the DB query is a read-then-write check with a TOCTOU window
under concurrent requests (two threads/workers can both read "no prior
job for this jti" before either commits its job row).

This table makes the guarantee a real database constraint instead: jti is
the primary key, so a second INSERT for the same token raises
IntegrityError rather than racing a check. It's written in the same
transaction as the Job row it authorizes (app.main.sanitize_job), so the
two can never diverge. jobs.layer_b (added in 0004) is untouched — this
table is purely the uniqueness backstop, not a replacement for the
audit-facing column or the audit chain.

The backfill below seeds one row per jti already recorded on an existing
job's layer_b column, so a token that was consumed before this migration
ran cannot be replayed against a job created after it (ON CONFLICT/OR
IGNORE guards the vanishingly unlikely case where the old TOCTOU window
already let two jobs record the same jti — first-created wins).

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-24
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

revision: str = "0005"
down_revision: Union[str, Sequence[str], None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attestation_uses",
        sa.Column("jti", sa.String(32), primary_key=True),
        sa.Column("job_id", sa.String(16), sa.ForeignKey("jobs.id"), nullable=False),
        sa.Column("matter_id", sa.String(16), nullable=False),
        sa.Column("created_utc", sa.String(32), nullable=False),
    )
    op.create_index("ix_attestation_uses_job_id", "attestation_uses", ["job_id"])
    op.create_index("ix_attestation_uses_matter_id", "attestation_uses", ["matter_id"])

    if context.is_offline_mode():
        # --sql rendering (see test_migrations_emit_jsonb_for_fresh_postgres_
        # offline): no live connection to read jobs from, and a fresh
        # install has none to backfill anyway.
        return

    bind = op.get_bind()
    jobs = sa.table(
        "jobs",
        sa.column("id", sa.String),
        sa.column("matter_id", sa.String),
        sa.column("layer_b", sa.JSON),
        sa.column("created_utc", sa.String),
    )
    rows = bind.execute(
        sa.select(jobs.c.id, jobs.c.matter_id, jobs.c.layer_b, jobs.c.created_utc)
        .where(jobs.c.layer_b.isnot(None))
        .order_by(jobs.c.created_utc.asc())
    ).fetchall()

    attestation_uses = sa.table(
        "attestation_uses",
        sa.column("jti", sa.String),
        sa.column("job_id", sa.String),
        sa.column("matter_id", sa.String),
        sa.column("created_utc", sa.String),
    )
    seen: set[str] = set()
    for job_id, matter_id, layer_b, created_utc in rows:
        jti = (layer_b or {}).get("jti") if isinstance(layer_b, dict) else None
        if not jti or jti in seen:
            continue
        seen.add(jti)
        bind.execute(
            attestation_uses.insert().values(
                jti=jti, job_id=job_id, matter_id=matter_id, created_utc=created_utc
            )
        )


def downgrade() -> None:
    op.drop_table("attestation_uses")
