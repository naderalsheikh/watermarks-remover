"""unique (matter_id, seq) on audit_events — database-level backstop
against a forked audit chain if two writers ever race past the
application-level serialization (a second worker process, a future bug).

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-23
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.create_unique_constraint(
            "uq_audit_events_matter_seq", ["matter_id", "seq"]
        )


def downgrade() -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint("uq_audit_events_matter_seq", type_="unique")
