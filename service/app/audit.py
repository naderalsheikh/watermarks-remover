"""Per-matter audit hash chain (PR 16).

Tamper-evident: every event commits to its predecessor via
sha256(prev_hash | seq | actor_id | action | canonical payload).
Appends are serialized per matter with a process-local lock so concurrent
jobs cannot fork the chain; gapless `seq` is the backstop and the
recomputed-hash walk in verify_chain() is the detector.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AuditEvent

GENESIS = "0" * 64

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
    """Serialized per-matter append. Commits."""
    with _matter_lock(matter_id):
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
        s.add(ev)
        s.commit()
        return ev


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
