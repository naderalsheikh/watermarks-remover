"""Request retry identity, committed atomically with the admitted resource."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException

from .audit import append_event, lock_matter
from .models import Admission, Document, Job
from .storage import original_key


@dataclass(frozen=True)
class Ticket:
    matter_id: str
    requested_by: str
    operation: str
    key_sha256: str
    request_sha256: str


def lookup_admission(s, *, matter_id, actor_id, operation, key, payload):
    """Call after authorization. Hold the matter lock through admission commit."""
    if key is None:
        return None, None
    if not 1 <= len(key) <= 200 or any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise HTTPException(400, "Idempotency-Key must contain 1-200 visible ASCII characters")
    key_hash = hashlib.sha256(key.encode("ascii")).hexdigest()
    request_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    lock_matter(s, matter_id)
    existing = s.get(Admission, (matter_id, actor_id, operation, key_hash))
    if existing is not None and existing.request_sha256 != request_hash:
        raise HTTPException(409, "Idempotency-Key was already used for a different request")
    return existing, Ticket(matter_id, actor_id, operation, key_hash, request_hash)


def remember_admission(s, ticket: Ticket | None, *, resource_kind: str, resource_id: str):
    if ticket is not None:
        s.add(
            Admission(
                matter_id=ticket.matter_id,
                requested_by=ticket.requested_by,
                operation=ticket.operation,
                key_sha256=ticket.key_sha256,
                request_sha256=ticket.request_sha256,
                resource_kind=resource_kind,
                resource_id=resource_id,
            )
        )


def new_job(cfg, **values):
    """Record the execution target at admission for every transport."""
    return Job(
        worker_mode=cfg.worker_mode,
        worker_image=cfg.worker_image if cfg.worker_mode == "docker" else "",
        **values,
    )


def stage_document(
    s, *, cfg, storage, scanner, matter_id, filename, data, actor_id, audit_append=append_event
):
    """Stage an original and its upload event in the caller's transaction.

    Immutable storage writes precede the database commit. A failed commit can
    leave an unreferenced original; it cannot authorize or execute a job.
    """
    name = Path(filename or "upload").name
    verdict = scanner.scan(data, name)
    if not verdict.clean:
        raise HTTPException(422, f"malware scanner flagged upload ({verdict.scanner})")
    doc = Document(
        id=uuid.uuid4().hex[:16],
        matter_id=matter_id,
        filename=name,
        sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        storage_path="",
    )
    doc.storage_path = storage.write_once(original_key(cfg.org, matter_id, doc.id, name), data)
    s.add(doc)
    audit_append(
        s,
        matter_id=matter_id,
        actor_id=actor_id,
        action="document.upload",
        payload={
            "document_id": doc.id,
            "filename_ext": Path(name).suffix,
            "sha256": doc.sha256,
            "bytes": doc.bytes,
        },
        commit=False,
    )
    return doc
