"""releases.last_anchor_* -- the observed outcome of packet anchoring

Lane E3 (docs/counselclear-custody-truthfulness-plan.md). Two problems,
one column set.

**The UI could not answer a question it was asked to display.** Every
anchor-related string in web/ asserted "not externally anchored"
unconditionally, which became false the moment RFC 3161 anchoring merged.
Nothing persisted the outcome: the anchor is computed inside job_bundle
while the packet is assembled and then travels only inside the packet, so
no read-scoped route could report it. The interim copy fix (claim-copy
audit rows A3/A7/A9) had to name where the answer lives instead of giving
it. These columns are what let a later pass give it.

**A TSA failure left no trace in the operator's own records.** When the
timestamp authority is unreachable the release still succeeds -- one
retry, 5s timeout, then the packet is issued unanchored with that fact in
its own `anchor` field. Correct behaviour: a release must never block on a
third party. But the only record of it lived in the packet the RECIPIENT
holds. The operator's audit log said a bundle was downloaded and nothing
about whether the timestamp they believe they are getting was actually
obtained. The paired `bundle.anchored` audit event closes that; these
columns are its read-scoped denormalization.

**Why "last_", and why this is not a property of the release.** A packet
is rebuilt on every download and legitimately differs each time: each
download is its own audited custody event, so `audit_refs` advances and
the Ed25519 signature over the packet's facts follows. The TSA token
attests to those signature bytes, so it is a fact about ONE download, not
about the release. Naming the columns `last_anchor_*` keeps that honest --
they record the most recent observation, and the audit chain holds every
one. A column called `anchor_type` would have implied a stability the
protocol does not give us.

Nullable throughout: a release whose packet has never been downloaded has
no observation to report, and NULL is the honest "not yet known" rather
than a fabricated "unanchored".

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-05
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, Sequence[str], None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("releases") as batch_op:
        # "rfc3161-tsa" | "ed25519-operator" -- the packet's own anchor
        # vocabulary, not a second one to keep in sync.
        batch_op.add_column(sa.Column("last_anchor_type", sa.String(32), nullable=True))
        batch_op.add_column(sa.Column("last_anchor_at", sa.String(32), nullable=True))
        # sha256 hex of the signature bytes the token attests to. Lets a
        # reader tie this row to a specific packet they hold instead of
        # trusting that "the last download" was theirs.
        batch_op.add_column(sa.Column("last_anchor_digest", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("releases") as batch_op:
        batch_op.drop_column("last_anchor_digest")
        batch_op.drop_column("last_anchor_at")
        batch_op.drop_column("last_anchor_type")
