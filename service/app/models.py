"""Domain models: matters -> documents -> jobs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _uuid() -> str:
    return uuid.uuid4().hex[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Matter(Base):
    __tablename__ = "matters"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    matter_id: Mapped[str] = mapped_column(ForeignKey("matters.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    bytes: Mapped[int] = mapped_column()
    storage_path: Mapped[str] = mapped_column(String(1024))
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)


class MatterAcl(Base):
    __tablename__ = "matter_acl"

    matter_id: Mapped[str] = mapped_column(String(16), ForeignKey("matters.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    perm: Mapped[str] = mapped_column(String(32), primary_key=True)


class AuditEvent(Base):
    """Per-matter tamper-evident log: sha256(prev_hash | seq | actor | action | payload).

    Appends are serialized per matter (see app.audit) so seq is gapless and
    the chain is total. `seq` — not the uuid `id` — defines chain order.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    matter_id: Mapped[str] = mapped_column(ForeignKey("matters.id"), index=True)
    seq: Mapped[int] = mapped_column()
    actor_id: Mapped[str] = mapped_column(String(64), default="operator")
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64), index=True)
    at: Mapped[str] = mapped_column(String(32), default=_now)


# --- PR 16 permissions ----------------------------------------------------------

KNOWN_PERMS = (
    "read",  # see matter, documents, jobs, manifests
    "upload",  # add documents to the matter
    "inspect",  # run inspection jobs
    "sanitize",  # run sanitize jobs
    "download_original",  # include the WORM original in bundle downloads
    "admin",  # manage ACL and view the audit chain
)

# download_original is deliberately NOT bootstrapped: originals leave the
# custody store only after an explicit, audit-chained grant (PR 16).
OWNER_PERMS: tuple[str, ...] = tuple(p for p in KNOWN_PERMS if p != "download_original")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    matter_id: Mapped[str] = mapped_column(ForeignKey("matters.id"), index=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # inspect | sanitize
    policy_id: Mapped[str] = mapped_column(String(40), default="external_sharing")
    reason: Mapped[str] = mapped_column(String(500), default="")
    attestation: Mapped[bool] = mapped_column(default=False)
    # queued | running | done | refused | failed
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)
    error: Mapped[str] = mapped_column(String(1000), default="")
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    bundle_dir: Mapped[str] = mapped_column(String(1024), default="")
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)
    finished_utc: Mapped[str | None] = mapped_column(String(32), nullable=True)
