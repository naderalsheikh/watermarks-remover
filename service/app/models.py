"""Domain models: matters -> documents -> jobs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _uuid() -> str:
    return uuid.uuid4().hex[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# JSON columns: plain JSON on SQLite, real indexable JSONB on Postgres.
# (with_variant only changes the DDL the Postgres dialect renders; SQLite
# behaviour is untouched.)
JSONColumn = JSON().with_variant(JSONB(), "postgresql")


class Matter(Base):
    __tablename__ = "matters"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)
    # PR 45: a matter created by POST /v1/matters/demo-seed for the
    # evaluation-flow walkthrough. An explicit column, not a name-prefix
    # convention (name is free text an operator could rename or collide
    # with) -- the one place this is used today is GET /v1/dashboard,
    # which excludes is_demo matters from its cross-matter aggregation so
    # a demo doesn't pollute an operator's real attention/audit totals.
    # Everywhere else (list_matters, matter view, audit) treats a demo
    # matter exactly like any other -- it's real data in the same tables,
    # just clearly labeled, never hidden from the person who created it.
    is_demo: Mapped[bool] = mapped_column(default=False)


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

    Appends are serialized per matter (see app.audit: a process-local lock
    plus the engine's BEGIN IMMEDIATE, db.py) so seq is gapless and the
    chain is total. `seq` — not the uuid `id` — defines chain order. The
    unique (matter_id, seq) constraint is the database-level backstop: if
    two writers ever raced past the application-level serialization (a
    second worker process the lock can't see, a future bug), SQLite refuses
    the second insert with an IntegrityError instead of silently forking
    the chain with two rows claiming the same seq.
    """

    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("matter_id", "seq", name="uq_audit_events_matter_seq"),)

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    matter_id: Mapped[str] = mapped_column(ForeignKey("matters.id"), index=True)
    seq: Mapped[int] = mapped_column()
    actor_id: Mapped[str] = mapped_column(String(64), default="operator")
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSONColumn, default=dict)
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


class Batch(Base):
    """PR 31: one row per async bulk-run submission; children are ordinary
    Job rows carrying this id in Job.batch_id. finished_utc is set exactly
    once, by BatchDispatcher's atomic completion claim, when every child
    has left queued/running -- see service/app/dispatcher.py.
    """

    __tablename__ = "batches"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    matter_id: Mapped[str] = mapped_column(ForeignKey("matters.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # inspect | sanitize
    policy_id: Mapped[str] = mapped_column(String(40), default="")
    reason: Mapped[str] = mapped_column(String(500), default="")
    requested_by: Mapped[str] = mapped_column(String(64))
    total: Mapped[int] = mapped_column()
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)
    finished_utc: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    matter_id: Mapped[str] = mapped_column(ForeignKey("matters.id"), index=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    # PR 31: set only for children of an async Batch; NULL for jobs created
    # by the synchronous single-document routes (the synchronous
    # /bulk-jobs endpoint that used to also leave this NULL was retired in
    # PR 31 commit 3).
    batch_id: Mapped[str | None] = mapped_column(ForeignKey("batches.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))  # inspect | sanitize
    policy_id: Mapped[str] = mapped_column(String(40), default="external_sharing")
    reason: Mapped[str] = mapped_column(String(500), default="")
    attestation: Mapped[bool] = mapped_column(default=False)
    # {subtype: "approve"|"keep"} for approve-default policy cells (e.g.
    # production's comments_and_notes) — plan_actions defaults an omitted
    # decision to "keep", so without this every approve-default cell was
    # unreachable through the API and production sanitize was effectively
    # a no-op strip.
    finding_decisions: Mapped[dict] = mapped_column(JSONColumn, default=dict)
    # PR 20: set only when the sanitize job ran a Layer B (statistical
    # watermark) rewrite under a signed attestation. {strength, label,
    # subject, jti} — the jti is the single-use attestation token id so
    # the audit chain can tie the job back to the exact authorization.
    # None for ordinary (Layer A only) jobs.
    layer_b: Mapped[dict | None] = mapped_column(JSONColumn, nullable=True)
    # queued | running | done | refused | failed
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)
    error: Mapped[str] = mapped_column(String(1000), default="")
    result_json: Mapped[dict | None] = mapped_column(JSONColumn, nullable=True)
    bundle_dir: Mapped[str] = mapped_column(String(1024), default="")
    # digest-pinned image that executed this job (PR 17), "" for subprocess
    worker_image: Mapped[str] = mapped_column(String(200), default="")
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)
    finished_utc: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Release(Base):
    """The business/custody event: a document was prepared for release to
    someone, for some purpose, under some policy, and it ended in exactly
    one of two ways -- a release packet, or a refused/failed record with
    reasons. `Job` remains the execution mechanism underneath (1:1,
    `job_id` always set); Release adds the facts a Job was never meant to
    carry -- who this was for, why, and whether it was intended to leave
    the organization at all. `status` mirrors `Job.status`'s own
    vocabulary deliberately (queued|done|refused|failed): no separate
    vocabulary to keep in sync, no drift-prone mapping table.

    Always 1:1 with a document, even inside a server-side batch (see
    `batch_id`) -- a Release is never a multi-document aggregate. This is
    what keeps "batch completed" and "each release completed" from
    blurring into each other: the Batch is only the grouping/execution
    envelope (unchanged, PR 31); each of its child Jobs may have its own
    sibling Release, completing independently as that one Job finishes,
    not when the batch as a whole does.
    """

    __tablename__ = "releases"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default=_uuid)
    matter_id: Mapped[str] = mapped_column(ForeignKey("matters.id"), index=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    # Set only when created via the batch-release path -- same nullable-FK
    # pattern Job.batch_id already uses. NULL means "not part of a
    # server-side Batch", which covers both a true single-document release
    # and a client-driven sequence of independent releases (e.g. the
    # Airlock CLI's own folder loop, which never touches Batch at all).
    batch_id: Mapped[str | None] = mapped_column(ForeignKey("batches.id"), nullable=True, index=True)
    # 1:1 with its Job, always -- created in the same transaction as the
    # Job it wraps, never pointed at an existing/shared Job.
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), unique=True, index=True)
    # Display-facing selection (RELEASE_PROFILES in main.py) resolves to
    # this at creation time; policy_id itself stays the stable, internal
    # sanitizer identifier -- never renamed or reinterpreted by profile
    # framing. Copied here (not joined through Job) so a Release is
    # self-describing on its own, matching how AuditEvent.payload already
    # duplicates fields for evidentiary independence.
    policy_id: Mapped[str] = mapped_column(String(40))
    profile_id: Mapped[str] = mapped_column(String(40), default="")
    # Controlled vocabulary (e.g. opposing_counsel|court|client|regulator|
    # internal_reviewer|other) -- the field the learning layer can safely
    # aggregate on. Deliberately separate from recipient_name (below),
    # which is free text and must never be conflated with this one.
    recipient_type: Mapped[str] = mapped_column(String(40), default="")
    recipient_name: Mapped[str] = mapped_column(String(200), default="")
    purpose: Mapped[str] = mapped_column(String(500), default="")
    # Operator's stated INTENT that this release leaves the organization --
    # never proof that it did. CounselClear has no way to confirm actual
    # transmission; "Release" means "prepared for release", not "sent". No
    # certificate/packet/UI copy may claim otherwise (see docs).
    intended_external: Mapped[bool] = mapped_column(default=True)
    requested_by: Mapped[str] = mapped_column(String(64))
    # queued | done | refused | failed -- exactly Job.status's own
    # vocabulary, synced from the wrapped Job at the same moment the Job
    # itself transitions (see dispatcher.py's per-job completion hook and
    # main.py's inline single-document path) -- never a separate poll.
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)
    finished_utc: Mapped[str | None] = mapped_column(String(32), nullable=True)


class AttestationUse(Base):
    """Durable, race-free single-use record for a Layer B attestation jti.

    A dedicated table (rather than a uniqueness check against
    Job.layer_b->>'jti') so the guarantee is a real database constraint:
    the jti is the primary key, so a second INSERT for the same token
    raises IntegrityError instead of racing a read-then-write check across
    threads, gunicorn workers, or process restarts (app.security's
    _consumed_jtis in-memory set is only the fast path for the common
    single-process case). Written in the same transaction as the Job row
    it authorizes (see app.main.sanitize_job) so the two can never diverge:
    either both commit or neither does. Job.layer_b keeps carrying the jti
    too — this table is purely the uniqueness backstop, not a replacement
    for the audit-facing column.
    """

    __tablename__ = "attestation_uses"

    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), index=True)
    matter_id: Mapped[str] = mapped_column(String(16), index=True)
    created_utc: Mapped[str] = mapped_column(String(32), default=_now)
