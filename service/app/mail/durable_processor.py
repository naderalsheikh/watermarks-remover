"""Internal attachment bridge to the shared durable queue; no mail listener.

A trusted transport configures the tenant/matter/service-principal binding.
This bridge checks that binding and the matter ACL, retains one attachment job
per transport request/part, and revalidates its retained artifacts. It neither
authenticates Exchange nor admits/delivers whole SMTP messages.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.exc import OperationalError

from ..acl import has_perm
from ..admission import lookup_admission, new_job, remember_admission, stage_document
from ..audit import append_event
from ..models import Document, Job
from ..runner import _confined_basename, _validated_bundle, job_root
from ..storage import StorageError
from .contract import PolicyReference
from .processor import ProcessRequest, ProcessResult


@dataclass(frozen=True)
class TenantJobBinding:
    """Server configuration, never a binding inferred from message headers."""

    tenant_id: str
    matter_id: str
    actor_id: str
    policy: PolicyReference

    def __post_init__(self):
        for value, limit in ((self.tenant_id, 128), (self.matter_id, 16), (self.actor_id, 64)):
            if not isinstance(value, str) or not value.strip() or len(value) > limit:
                raise ValueError("invalid tenant job binding")
        if self.policy.version != 1:
            raise ValueError("the installed policy contract supports version 1 only")


class DurableAttachmentProcessor:
    name = "shared-durable-job-runner"

    def __init__(
        self,
        *,
        cfg,
        session_factory,
        storage,
        scanner,
        dispatcher,
        binding: TenantJobBinding,
        wait_s: float = 30,
        max_attachment_bytes: int = 25 * 1024 * 1024,
        allow_development: bool = False,
    ):
        if cfg.worker_mode != "docker" and not allow_development:
            raise ValueError("mail attachment processing requires the Docker runner")
        if cfg.worker_mode == "docker" and not re.search(
            r"@sha256:[0-9a-f]{64}$", cfg.worker_image
        ):
            raise ValueError("mail attachment processing requires a digest-pinned worker image")
        if max_attachment_bytes < 1 or not 0 <= wait_s <= 300:
            raise ValueError("invalid attachment processing limits")
        self.cfg, self.sessions, self.storage = cfg, session_factory, storage
        self.scanner, self.dispatcher, self.binding = scanner, dispatcher, binding
        self.wait_s, self.max_bytes = wait_s, max_attachment_bytes
        if cfg.worker_mode != "docker":
            self.name = "shared-durable-job-runner-development"

    def _answer(self, request, status, detail="", **fields):
        return ProcessResult(
            status=status,
            source_sha256=request.source_sha256,
            policy=request.policy,
            detail=detail,
            processor=self.name,
            **fields,
        )

    def _request_problem(self, request):
        caller = request.caller
        if not caller.is_trusted() or caller.tenant_id != self.binding.tenant_id:
            return "caller does not match the configured tenant binding"
        if request.policy != self.binding.policy:
            return "request does not match the configured policy"
        if any(
            not isinstance(value, str) or not value.strip() or len(value) > 200
            for value in (caller.request_id, request.part_id, caller.transport)
        ):
            return "invalid attachment request identity"
        if not _confined_basename(request.engine_name) or len(request.engine_name) > 255:
            return "attachment engine name is not a safe basename"
        if not isinstance(request.content, bytes) or len(request.content) > self.max_bytes:
            return "attachment exceeds the processor input limit"
        if hashlib.sha256(request.content).hexdigest() != request.source_sha256:
            return "attachment bytes differ from the declared source hash"
        return None

    def _authorize(self, s):
        if not all(
            has_perm(s, self.binding.matter_id, self.binding.actor_id, permission)
            for permission in ("upload", "sanitize", "read")
        ):
            raise HTTPException(403, "service principal lacks attachment permissions")

    def _admit(self, request):
        caller, binding = request.caller, self.binding
        key = hashlib.sha256(
            json.dumps(
                [binding.tenant_id, caller.request_id, request.part_id],
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        with self.sessions() as s:
            self._authorize(s)
            existing, ticket = lookup_admission(
                s,
                matter_id=binding.matter_id,
                actor_id=binding.actor_id,
                operation="mail_attachment",
                key=key,
                payload={
                    "tenant_id": binding.tenant_id,
                    "request_id": caller.request_id,
                    "part_id": request.part_id,
                    "transport": caller.transport,
                    "peer_identity": caller.peer_identity,
                    "policy_id": request.policy.policy_id,
                    "policy_version": request.policy.version,
                    "sha256": request.source_sha256,
                    "bytes": len(request.content),
                    "engine_name": request.engine_name,
                    "detected_format": request.detected_format,
                },
            )
            if existing is not None:
                return existing.resource_id
            doc = stage_document(
                s,
                cfg=self.cfg,
                storage=self.storage,
                scanner=self.scanner,
                matter_id=binding.matter_id,
                filename=request.engine_name,
                data=request.content,
                actor_id=binding.actor_id,
            )
            s.flush()
            job = new_job(
                self.cfg,
                matter_id=binding.matter_id,
                document_id=doc.id,
                kind="sanitize",
                policy_id=binding.policy.policy_id,
                requested_by=binding.actor_id,
            )
            s.add(job)
            s.flush()
            remember_admission(s, ticket, resource_kind="job", resource_id=job.id)
            append_event(
                s,
                matter_id=binding.matter_id,
                actor_id=binding.actor_id,
                action="mail.attachment.admitted",
                commit=False,
                payload={
                    "tenant_id": binding.tenant_id,
                    "request_id": caller.request_id,
                    "part_id": request.part_id,
                    "job_id": job.id,
                    "document_id": doc.id,
                    "source_sha256": doc.sha256,
                    "policy_id": request.policy.policy_id,
                    "policy_version": request.policy.version,
                },
            )
            s.commit()
            return job.id

    def _read_result(self, request, job_id):
        with self.sessions() as s:
            self._authorize(s)
            job = s.get(Job, job_id)
            doc = s.get(Document, job.document_id) if job else None
            if (
                job is None
                or doc is None
                or job.matter_id != self.binding.matter_id
                or doc.matter_id != self.binding.matter_id
                or job.requested_by != self.binding.actor_id
                or job.policy_id != request.policy.policy_id
                or doc.sha256 != request.source_sha256
                or doc.bytes != len(request.content)
                or doc.filename != request.engine_name
                or job.kind != "sanitize"
            ):
                return self._answer(request, "failed", "retained job does not match the attachment")
            if job.status in ("queued", "running"):
                return None
            evidence = f"counselclear:job:{job.matter_id}:{job.id}"
            if job.status in ("failed", "refused"):
                return self._answer(
                    request, job.status, "attachment job " + job.status, evidence_ref=evidence
                )
            if job.status != "done" or not job.bundle_dir:
                return self._answer(request, "failed", "attachment job has no retained bundle")
            bundle = Path(job.bundle_dir)
            expected_root = job_root(self.cfg, job.matter_id, job.id).resolve()
            if not bundle.resolve().is_relative_to(expected_root):
                return self._answer(request, "failed", "retained bundle is outside its job")
            try:
                verified = _validated_bundle(
                    bundle.parent, {"bundle_dir": "bundle", "result": job.result_json}, job, doc
                )
                manifest = job.result_json["manifest"]
                policy = manifest["policy"]
                if policy.get("version") != request.policy.version:
                    raise ValueError("retained policy version differs from request")
                derivative = manifest["derivative"]
                if (
                    not isinstance(derivative.get("bytes"), int)
                    or derivative["bytes"] > self.max_bytes
                ):
                    raise ValueError("retained derivative exceeds processor output limit")
                with (verified / "derivative" / derivative["filename"]).open("rb") as stream:
                    output = stream.read(self.max_bytes + 1)
                digest = hashlib.sha256(output).hexdigest()
                if len(output) != derivative["bytes"] or digest != derivative["sha256"]:
                    raise ValueError("retained derivative changed during read")
            except (OSError, ValueError, KeyError, TypeError):
                return self._answer(
                    request,
                    "failed",
                    "retained attachment evidence failed validation",
                    evidence_ref=evidence,
                )
            return self._answer(
                request,
                "released",
                output=output,
                output_sha256=digest,
                output_bytes=len(output),
                output_name=derivative["filename"],
                verification="engine_verified",
                evidence_ref=evidence,
            )

    def process(self, request: ProcessRequest) -> ProcessResult:
        problem = self._request_problem(request)
        if problem:
            return self._answer(request, "refused", problem)
        try:
            job_id = self._admit(request)
            self.dispatcher.wake()
            deadline = time.monotonic() + self.wait_s
            while True:
                result = self._read_result(request, job_id)
                if result is not None:
                    return result
                if time.monotonic() >= deadline:
                    return self._answer(
                        request,
                        "unavailable",
                        "attachment job is pending",
                        evidence_ref=f"counselclear:job:{self.binding.matter_id}:{job_id}",
                    )
                time.sleep(0.05)
        except HTTPException as exc:
            # A contradictory retry or revoked service permission cannot release.
            status = "refused" if exc.status_code in (400, 403, 409, 422) else "unavailable"
            return self._answer(request, status, "attachment admission rejected")
        except (OperationalError, StorageError, OSError):
            return self._answer(request, "unavailable", "attachment storage or queue unavailable")
