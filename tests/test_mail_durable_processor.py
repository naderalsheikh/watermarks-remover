"""The adapter consumes retained, fenced jobs rather than an in-process engine."""

from __future__ import annotations

import hashlib
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app.audit import verify_chain
from app.config import Config
from app.mail import AdapterRequest, Envelope, MailAdapter, PolicyReference, TrustedCallerContext
from app.mail.durable_processor import DurableAttachmentProcessor, TenantJobBinding
from app.mail.fixtures import AttachmentSpec, build_message, synthetic_docx
from app.mail.processor import ProcessRequest
from app.main import create_app
from app.malware import get_scanner
from app.models import Admission, AuditEvent, Document, Job, MatterAcl
from app.storage import StorageError, storage_from_config


@pytest.fixture
def bridge(tmp_path, monkeypatch, queue_backend):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "synthetic-mail-test")
    cfg = Config(tmp_path / "data")
    c = TestClient(create_app(cfg.data_root))
    c.post("/v1/auth/login", json={"password": "synthetic-mail-test"}).raise_for_status()
    matter = c.post("/v1/matters", json={"name": "Synthetic mail"}).json()["id"]
    actor = "mail:tenant-a"
    for permission in ("read", "upload", "sanitize"):
        c.put(
            f"/v1/matters/{matter}/acl", json={"user_id": actor, "perm": permission}
        ).raise_for_status()
    dispatcher = c.app.state.batch_dispatcher
    sessions = dispatcher._session_factory
    binding = TenantJobBinding("tenant-a", matter, actor, PolicyReference("external_sharing", 1))
    options = dict(
        cfg=cfg,
        session_factory=sessions,
        storage=storage_from_config(cfg),
        scanner=get_scanner(),
        dispatcher=SimpleNamespace(wake=lambda: None),
        binding=binding,
        wait_s=0,
        allow_development=True,
    )
    processor = DurableAttachmentProcessor(**options)
    content = synthetic_docx("Synthetic agreement", creator="Synthetic Author")
    caller = TrustedCallerContext(
        "tenant-a", "fixture-transport", True, "request-1", "fixture-peer"
    )
    request = ProcessRequest(
        "part-1",
        "Agreement.docx",
        "Agreement.docx",
        content,
        hashlib.sha256(content).hexdigest(),
        "docx",
        binding.policy,
        caller,
    )
    yield SimpleNamespace(
        c=c,
        cfg=cfg,
        sessions=sessions,
        options=options,
        processor=processor,
        request=request,
        dispatcher=dispatcher,
        binding=binding,
    )
    dispatcher.stop()
    c.close()


def test_production_default_refuses_plain_subprocess(bridge):
    options = dict(bridge.options, allow_development=False)
    with pytest.raises(ValueError, match="Docker runner"):
        DurableAttachmentProcessor(**options)


def test_concurrent_retry_creates_one_document_and_durable_job(bridge):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: bridge.processor.process(bridge.request), range(4)))
    assert {r.status for r in results} == {"unavailable"}
    assert len({r.evidence_ref for r in results}) == 1
    with bridge.sessions() as s:
        assert s.query(Document).count() == s.query(Job).count() == s.query(Admission).count() == 1
        assert s.query(Job).one().requested_by == bridge.binding.actor_id
        assert s.query(AuditEvent).filter_by(action="mail.attachment.admitted").count() == 1
        assert verify_chain(s.query(AuditEvent).all())[0]


@pytest.mark.parametrize(
    "field,value",
    [
        ("content", b"changed"),
        ("engine_name", "../Agreement.docx"),
        ("part_id", ""),
        ("policy", PolicyReference("production", 1)),
        ("caller", TrustedCallerContext("tenant-b", "fixture-transport", True, "request-1")),
        ("caller", TrustedCallerContext("tenant-a", "fixture-transport", False, "request-1")),
    ],
)
def test_invalid_identity_or_binding_cannot_admit(bridge, field, value):
    result = bridge.processor.process(replace(bridge.request, **{field: value}))
    assert result.status == "refused"
    with bridge.sessions() as s:
        assert s.query(Job).count() == s.query(Document).count() == 0


def test_conflicting_retry_and_revoked_permission_cannot_read_or_create(bridge):
    assert bridge.processor.process(bridge.request).status == "unavailable"
    changed = replace(bridge.request, engine_name="Different.docx")
    assert bridge.processor.process(changed).status == "refused"
    with bridge.sessions() as s:
        s.query(MatterAcl).filter_by(
            matter_id=bridge.binding.matter_id, user_id=bridge.binding.actor_id, perm="read"
        ).delete()
        s.commit()
    assert bridge.processor.process(bridge.request).status == "refused"
    with bridge.sessions() as s:
        assert s.query(Job).count() == s.query(Document).count() == 1


def test_receipt_failure_rolls_back_document_job_and_upload_audit(bridge):
    def fail(*args):
        raise RuntimeError("synthetic receipt failure")

    event.listen(Admission, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError, match="synthetic receipt"):
            bridge.processor.process(bridge.request)
    finally:
        event.remove(Admission, "before_insert", fail)
    with bridge.sessions() as s:
        assert s.query(Document).count() == s.query(Job).count() == s.query(Admission).count() == 0
        assert (
            s.query(AuditEvent)
            .filter(AuditEvent.action.in_(("document.upload", "mail.attachment.admitted")))
            .count()
            == 0
        )
        assert verify_chain(s.query(AuditEvent).all())[0]
    assert bridge.processor.process(bridge.request).status == "unavailable"


def test_storage_failure_is_retryable_and_leaves_no_job(bridge, monkeypatch):
    def fail(*args):
        raise StorageError("synthetic temporary storage failure")

    monkeypatch.setattr(bridge.options["storage"], "write_once", fail)
    assert bridge.processor.process(bridge.request).status == "unavailable"
    with bridge.sessions() as s:
        assert s.query(Job).count() == 0


def test_pending_attachment_resumes_through_real_runner_after_processor_restart(bridge):
    first = bridge.processor.process(bridge.request)
    assert first.status == "unavailable"
    resumed = DurableAttachmentProcessor(
        **dict(bridge.options, dispatcher=bridge.dispatcher, wait_s=30)
    )
    result = resumed.process(bridge.request)
    assert result.status == "released", result.detail
    assert result.verification == "engine_verified"
    assert result.evidence_ref == first.evidence_ref
    assert result.output != bridge.request.content
    again = DurableAttachmentProcessor(**bridge.options).process(bridge.request)
    assert again.output == result.output
    with bridge.sessions() as s:
        job = s.query(Job).one()
        assert job.result_json["manifest"]["operator"] == {"id": bridge.binding.actor_id}
        assert s.query(Admission).count() == 1
        assert verify_chain(s.query(AuditEvent).all())[0]
        derivative = Path(job.bundle_dir) / "derivative" / job.result_json["derivative"]
    derivative.chmod(0o600)
    derivative.write_bytes(b"tampered retained artifact")
    assert resumed.process(bridge.request).status == "failed"


def test_whole_adapter_holds_pending_then_releases_same_retained_job(bridge):
    request = AdapterRequest(
        raw_message=build_message(
            attachments=(
                AttachmentSpec(
                    "Agreement.docx",
                    bridge.request.content,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ),
            )
        ),
        envelope=Envelope("sender@example.test", ("to@example.test", "bcc@example.test")),
        caller=bridge.request.caller,
        policy=bridge.request.policy,
    )
    held = MailAdapter(bridge.processor).process(request)
    assert held.decision == "hold" and held.outbound is None
    resumed = DurableAttachmentProcessor(
        **dict(bridge.options, dispatcher=bridge.dispatcher, wait_s=30)
    )
    result = MailAdapter(resumed).process(request)
    assert result.decision == "release", (result.reasons, result.attachments)
    assert result.outbound.envelope == request.envelope
    assert all(a.verification == "engine_verified" for a in result.attachments)
    with bridge.sessions() as s:
        assert s.query(Job).count() == 1
