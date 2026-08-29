"""Per-matter audit hash chain (PR 16).

Tamper-evident: every event commits to its predecessor via
sha256(prev_hash | seq | actor_id | action | canonical payload).

Three layers keep the chain from forking under concurrent appends:
1. A process-local threading.Lock per matter (below) — fast, in-process
   ordering for the common case.
2. A database-level write lock that also covers multiple processes: on
   SQLite, BEGIN IMMEDIATE (db.py's make_engine); on Postgres, the
   unique-constraint conflict handled by the retry below (MVCC lets both
   transactions read the same max(seq), so serialization happens at
   commit time instead of lock-acquisition time).
3. A unique (matter_id, seq) constraint (models.AuditEvent) as the final
   backstop: if two writers ever raced past both of the above, the
   database refuses the second insert with IntegrityError instead of
   silently creating two rows that claim the same seq.
Gapless `seq` and the recomputed-hash walk in verify_chain() are what
detect a chain that was tampered with after the fact, not what prevents
one from forking during a race — that's what 1-3 are for.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import AuditEvent, Job

GENESIS = "0" * 64

# Bounded retries for layer-3 conflicts (only reachable across processes
# on Postgres). Each attempt re-reads max(seq), so a loser simply appends
# at the winner's seq+1; three attempts is far beyond any realistic
# contention for a per-matter serialized log.
_APPEND_ATTEMPTS = 3

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _matter_lock(matter_id: str) -> threading.Lock:
    with _locks_guard:
        lock = _locks.get(matter_id)
        if lock is None:
            lock = threading.Lock()
            _locks[matter_id] = lock
        return lock


def event_hash(prev_hash: str, seq: int, actor_id: str, action: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    material = f"{prev_hash}|{seq}|{actor_id}|{action}|{canonical}".encode()
    return hashlib.sha256(material).hexdigest()


def append_event(
    s: Session, *, matter_id: str, actor_id: str, action: str, payload: dict
) -> AuditEvent:
    """Serialized per-matter append. Commits.

    Callers routinely s.add() other rows (a Matter, a Document, ACL grants)
    on the same session before calling this, expecting append_event's own
    commit to persist those too as one atomic unit. A seq collision retry
    used to call the plain s.rollback() — which discards the *entire*
    transaction, not just this insert, silently dropping whatever the
    caller had already staged. Each attempt now runs inside its own
    SAVEPOINT (Session.begin_nested()): a collision unwinds only that
    attempt's insert, leaving earlier pending objects intact for the next
    attempt (or the final commit) to still pick up.
    """
    with _matter_lock(matter_id):
        for _attempt in range(_APPEND_ATTEMPTS):
            last_seq = s.execute(
                select(func.max(AuditEvent.seq)).where(AuditEvent.matter_id == matter_id)
            ).scalar_one()
            seq = 0 if last_seq is None else last_seq + 1
            prev = (
                s.execute(
                    select(AuditEvent)
                    .where(AuditEvent.matter_id == matter_id, AuditEvent.seq == last_seq)
                    .limit(1)
                ).scalar_one_or_none()
                if seq > 0
                else None
            )
            prev_hash = GENESIS if prev is None else prev.row_hash
            ev = AuditEvent(
                id=uuid.uuid4().hex[:16],
                matter_id=matter_id,
                seq=seq,
                actor_id=actor_id,
                action=action,
                payload=payload,
                prev_hash=prev_hash,
                row_hash=event_hash(prev_hash, seq, actor_id, action, payload),
            )
            try:
                with s.begin_nested():
                    s.add(ev)
                    s.commit()
            except IntegrityError:
                # Another process claimed this seq between our read and our
                # commit (possible only on Postgres — SQLite's BEGIN IMMEDIATE
                # holds the write lock across the whole transaction). The
                # begin_nested() SAVEPOINT already rolled back just this
                # attempt's insert; re-read and append at the winner's seq+1.
                continue
            else:
                s.commit()
                return ev
        raise RuntimeError(f"audit append kept colliding on seq for matter {matter_id}")


def _terminal_hash_facts(job: Job) -> dict[str, str]:
    """Chain-commitment facts for a finished sanitize job's audit event.

    MUST-1 (custody review 2026-08-29): the release packet's
    manifest_json_sha256 was previously computed at download time from
    whatever bytes sat on disk -- nothing earlier and immutable bound the
    manifest to the audit chain, so a tampered manifest re-hashed
    "clean". This helper re-hashes the bundle's manifest.json bytes at
    job-terminal time so every job.sanitize event carries the hashes the
    offline verifier can later cross-check the packet against.

    Returns {} when there is nothing to commit -- refused/failed jobs
    produce no manifest, and keys are omitted entirely (not nulled) so
    "no bundle produced" stays distinguishable from "hash unknown".
    The manifest hash comes from the disk bytes, never from
    result_json's embedded manifest dict: the dict is semantically equal
    but not byte-equal to the file (custody.write_manifest's indent/sort
    formatting), so a dict-derived hash would disagree with the packet's
    download-time hash on every packet. The derivative hash, by contrast,
    is a plain string inside the manifest dict and is taken from there.

    Never raises: a bundle read failure must not take down the terminal
    path (dispatcher._append_child_audit calls this inside a try/except
    that would otherwise silently drop the whole audit event).
    """
    if job.status != "done" or not job.bundle_dir:
        return {}
    result = job.result_json or {}
    manifest_sha = None
    try:
        manifest_bytes = (Path(job.bundle_dir) / "manifest.json").read_bytes()
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    except OSError:
        manifest_sha = None
    deriv_sha = (result.get("manifest") or {}).get("derivative", {}).get("sha256")
    facts: dict[str, str] = {}
    if manifest_sha:
        facts["manifest_sha256"] = manifest_sha
    if deriv_sha:
        facts["derivative_sha256"] = deriv_sha
    return facts


def verify_chain(events: list[AuditEvent]) -> tuple[bool, str]:
    """Recompute the whole chain in seq order. Returns (ok, detail)."""
    expected_prev = GENESIS
    for i, ev in enumerate(sorted(events, key=lambda e: e.seq)):
        if ev.seq != i or ev.prev_hash != expected_prev:
            return False, f"chain break at seq {ev.seq}"
        if event_hash(ev.prev_hash, ev.seq, ev.actor_id, ev.action, ev.payload) != ev.row_hash:
            return False, f"hash mismatch at seq {ev.seq}"
        expected_prev = ev.row_hash
    return True, f"{len(events)} events intact"
