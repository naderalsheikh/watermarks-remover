"""Durable mail admission, ownership, and no-resend delivery boundaries."""

from __future__ import annotations

import hashlib
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
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
from app.mail import AdapterLimits, Envelope, PolicyReference, TrustedCallerContext
from app.mail.adapter import MailAdapter
from app.mail.durable_processor import DurableAttachmentProcessor, TenantJobBinding
from app.mail.fixtures import AttachmentSpec, build_message, synthetic_docx
from app.mail.submissions import (
    BindingDenied,
    LeaseLost,
    MailSubmissionRegistry,
    SubmissionConflict,
)
from app.main import create_app
from app.malware import get_scanner
from app.models import AuditEvent, Job, MailSubmission, MatterAcl
from app.storage import StorageError, storage_from_config


@pytest.fixture
def spool(tmp_path, monkeypatch, queue_backend):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "synthetic-spool-test")
    cfg = Config(tmp_path / "data")
    app = create_app(cfg.data_root)
    # Control dispatcher startup explicitly so pending/restart cases cannot race a poll.
    with ExitStack() as cleanup:
        client = TestClient(app)
        cleanup.callback(client.close)
        cleanup.callback(app.state.batch_dispatcher.stop)
        client.post("/v1/auth/login", json={"password": "synthetic-spool-test"}).raise_for_status()
        matter = client.post("/v1/matters", json={"name": "Synthetic spool"}).json()["id"]
        actor = "mail:tenant-a"
        for permission in ("read", "upload", "sanitize"):
            client.put(
                f"/v1/matters/{matter}/acl", json={"user_id": actor, "perm": permission}
            ).raise_for_status()
        dispatcher = app.state.batch_dispatcher
        sessions = dispatcher._session_factory
        binding = TenantJobBinding(
            "tenant-a", matter, actor, PolicyReference("external_sharing", 1)
        )
        storage = storage_from_config(cfg)
        options = dict(cfg=cfg, session_factory=sessions, storage=storage, binding=binding)
        processor_options = dict(
            options,
            scanner=get_scanner(),
            dispatcher=SimpleNamespace(wake=lambda: None),
            wait_s=0,
            allow_development=True,
        )
        yield SimpleNamespace(
            client=client,
            cfg=cfg,
            sessions=sessions,
            binding=binding,
            storage=storage,
            options=options,
            registry=MailSubmissionRegistry(**options),
            processor=DurableAttachmentProcessor(**processor_options),
            processor_options=processor_options,
            dispatcher=dispatcher,
            raw=build_message(),
            envelope=Envelope("sender@example.test", ("to@example.test", "bcc@example.test")),
            caller=TrustedCallerContext(
                "tenant-a", "fixture", True, "transport-request-1", "tenant-bound-peer"
            ),
        )
    sessions.kw["bind"].dispose()


def admit(spool):
    return spool.registry.admit(spool.raw, spool.envelope, spool.caller)


def release(spool):
    row = admit(spool)
    result = spool.registry.process(row.id, spool.processor)
    assert result.status == "released", result
    return result


def expire(spool, submission_id, column="lease_expires_epoch"):
    with spool.sessions() as s:
        setattr(s.get(MailSubmission, submission_id), column, 0)
        s.commit()


def test_concurrent_admission_is_one_receipt_and_keeps_complete_envelope(spool):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: admit(spool), range(4)))
    assert len({r.id for r in results}) == 1
    with spool.sessions() as s:
        row = s.query(MailSubmission).one()
        assert row.envelope["rcpt_to"] == list(spool.envelope.rcpt_to)
        assert (
            spool.storage.read_expected(
                row.input_ref, sha256=row.input_sha256, size=row.input_bytes
            )
            == spool.raw
        )
        events = s.query(AuditEvent).all()
        assert sum(e.action == "mail.admitted" for e in events) == 1
        assert verify_chain(events)[0]
        audit = repr([e.payload for e in events if e.action.startswith("mail.")])
        assert "bcc@example.test" not in audit and spool.caller.request_id not in audit


@pytest.mark.parametrize(
    "change", ["bytes", "sender", "bcc", "order", "policy", "limits", "peer", "transport", "actor"]
)
def test_same_request_identity_cannot_be_rebound(spool, change):
    admit(spool)
    raw, envelope, caller, registry = spool.raw, spool.envelope, spool.caller, spool.registry
    if change == "bytes":
        raw += b"changed"
    elif change == "sender":
        envelope = replace(envelope, mail_from="other@example.test")
    elif change == "bcc":
        envelope = replace(envelope, rcpt_to=("to@example.test", "other-bcc@example.test"))
    elif change == "order":
        envelope = replace(envelope, rcpt_to=tuple(reversed(envelope.rcpt_to)))
    elif change in {"peer", "transport"}:
        caller = replace(
            caller, **{"peer_identity" if change == "peer" else "transport": "changed"}
        )
    elif change == "limits":
        registry = MailSubmissionRegistry(**spool.options, limits=AdapterLimits(max_parts=1))
    else:
        binding = replace(spool.binding, policy=PolicyReference("production", 1))
        if change == "actor":
            for permission in ("read", "upload", "sanitize"):
                spool.client.put(
                    f"/v1/matters/{spool.binding.matter_id}/acl",
                    json={"user_id": "second-service", "perm": permission},
                ).raise_for_status()
            binding = replace(spool.binding, actor_id="second-service")
        registry = MailSubmissionRegistry(**dict(spool.options, binding=binding))
    with pytest.raises(SubmissionConflict):
        registry.admit(raw, envelope, caller)
    with spool.sessions() as s:
        assert s.query(MailSubmission).count() == 1


def test_message_id_is_not_transport_identity(spool):
    first = admit(spool)
    second = spool.registry.admit(
        spool.raw, spool.envelope, replace(spool.caller, request_id="different-receive")
    )
    assert first.id != second.id


@pytest.mark.parametrize(
    "change", ["untrusted", "tenant", "peer", "request", "oversize", "envelope"]
)
def test_invalid_admission_leaves_no_receipt(spool, change):
    raw, envelope, caller, registry = spool.raw, spool.envelope, spool.caller, spool.registry
    if change == "untrusted":
        caller = replace(caller, provenance_verified=False)
    elif change == "tenant":
        caller = replace(caller, tenant_id="other")
    elif change == "peer":
        caller = replace(caller, peer_identity=None)
    elif change == "request":
        caller = replace(caller, request_id="contains spaces")
    elif change == "oversize":
        registry = MailSubmissionRegistry(
            **spool.options, limits=AdapterLimits(max_message_bytes=1)
        )
    else:
        registry = MailSubmissionRegistry(**spool.options, max_recipients=1)
    with pytest.raises((BindingDenied, ValueError)):
        registry.admit(raw, envelope, caller)
    with spool.sessions() as s:
        assert s.query(MailSubmission).count() == 0


def test_acl_revocation_blocks_reads_claims_and_retries(spool):
    row = admit(spool)
    with spool.sessions() as s:
        s.query(MatterAcl).filter_by(
            matter_id=spool.binding.matter_id, user_id=spool.binding.actor_id, perm="read"
        ).delete()
        s.commit()
    for operation in (
        lambda: admit(spool),
        lambda: spool.registry.get(row.id),
        lambda: spool.registry.claim(row.id),
    ):
        with pytest.raises(BindingDenied):
            operation()


def test_admission_audit_failure_is_atomic(spool):
    def fail(mapper, connection, target):
        if target.action == "mail.admitted":
            raise RuntimeError("injected audit failure")

    event.listen(AuditEvent, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            admit(spool)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    with spool.sessions() as s:
        assert s.query(MailSubmission).count() == 0
        assert s.query(AuditEvent).filter_by(action="mail.admitted").count() == 0
    assert admit(spool).status == "admitted"


def test_claim_race_and_expiry_fence_stale_publication(spool):
    row = admit(spool)
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda _: spool.registry.claim(row.id), range(4)))
    old = next(c for c in claims if c)
    assert sum(c is not None for c in claims) == 1
    request = spool.registry._request(old)
    result = MailAdapter(spool.processor).process(request)
    expire(spool, row.id)
    restarted = MailSubmissionRegistry(**spool.options)
    new = restarted.claim(row.id)
    assert new.attempt == old.attempt + 1
    for operation in (lambda: restarted.renew(old), lambda: restarted._publish(old, result)):
        with pytest.raises(LeaseLost):
            operation()
    assert restarted._publish(new, result).status == "released"


def test_pending_whole_message_resumes_same_job_through_real_engine(spool):
    spool.raw = build_message(
        attachments=(
            AttachmentSpec(
                "Agreement.docx",
                synthetic_docx("Synthetic agreement", creator="Private author"),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
        )
    )
    row = admit(spool)
    first = spool.registry.process(row.id, spool.processor)
    assert first.status == "held" and first.retryable
    restarted = MailSubmissionRegistry(**spool.options)
    processor = DurableAttachmentProcessor(
        **dict(spool.processor_options, dispatcher=spool.dispatcher, wait_s=90)
    )
    result = restarted.process(row.id, processor)
    assert result.status == "released", result
    ticket = restarted.prepare_delivery(row.id)
    assert ticket.envelope == spool.envelope
    assert ticket.raw != spool.raw
    assert hashlib.sha256(ticket.raw).hexdigest() == ticket.sha256
    with spool.sessions() as s:
        assert s.query(Job).count() == 1
        assert s.query(Job).one().status == "done"
        assert verify_chain(s.query(AuditEvent).all())[0]
    assert restarted.acknowledge(ticket, "trusted-exchange-receipt").status == "acknowledged"


def test_permanent_hold_cannot_be_claimed_or_delivered(spool):
    spool.raw = build_message(
        attachments=(AttachmentSpec("archive.zip", b"PK\x03\x04unsupported", "application/zip"),)
    )
    row = admit(spool)
    result = spool.registry.process(row.id, spool.processor)
    assert result.status == "held" and not result.retryable
    assert spool.registry.claim(row.id) is None
    with pytest.raises(SubmissionConflict):
        spool.registry.prepare_delivery(row.id)


def test_only_bound_durable_processor_can_run(spool):
    row = admit(spool)
    with pytest.raises(BindingDenied):
        spool.registry.process(row.id, SimpleNamespace())
    assert spool.registry.get(row.id).status == "admitted"


def test_input_corruption_never_releases(spool, monkeypatch):
    row = admit(spool)

    def corrupt(*args, **kwargs):
        raise StorageError("retained object differs")

    monkeypatch.setattr(spool.storage, "read_expected", corrupt)
    assert spool.registry.process(row.id, spool.processor).status == "processing"
    expire(spool, row.id)
    assert spool.registry.recover(row.id).retryable
    with pytest.raises(SubmissionConflict):
        spool.registry.prepare_delivery(row.id)


def test_output_corruption_never_returns_delivery_ticket(spool, monkeypatch):
    row = release(spool)

    def corrupt(*args, **kwargs):
        raise StorageError("retained output differs")

    monkeypatch.setattr(spool.storage, "read_expected", corrupt)
    with pytest.raises(StorageError):
        spool.registry.prepare_delivery(row.id)
    assert spool.registry.get(row.id).status == "released"


@pytest.mark.parametrize(
    "action", ["mail.decision", "mail.delivery.submitted", "mail.delivery.acknowledged"]
)
def test_state_and_audit_commit_together(spool, action):
    row = admit(spool)
    if action != "mail.decision":
        spool.registry.process(row.id, spool.processor)
    ticket = (
        spool.registry.prepare_delivery(row.id) if action == "mail.delivery.acknowledged" else None
    )
    before = spool.registry.get(row.id).status

    def fail(mapper, connection, target):
        if target.action == action:
            raise RuntimeError("injected transition failure")

    event.listen(AuditEvent, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            if action == "mail.decision":
                spool.registry.process(row.id, spool.processor)
            elif ticket:
                spool.registry.acknowledge(ticket, "receipt-1")
            else:
                spool.registry.prepare_delivery(row.id)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    assert spool.registry.get(row.id).status == (
        "processing" if action == "mail.decision" else before
    )
    with spool.sessions() as s:
        assert s.query(AuditEvent).filter_by(action=action).count() == 0
        assert verify_chain(s.query(AuditEvent).all())[0]


def test_delivery_committed_before_bytes_escape_and_no_resend(spool):
    row = release(spool)
    ticket = spool.registry.prepare_delivery(row.id)
    restarted = MailSubmissionRegistry(**spool.options)
    assert restarted.get(row.id).status == "submitted"
    assert ticket.raw == spool.raw and ticket.envelope == spool.envelope
    with pytest.raises(SubmissionConflict):
        restarted.prepare_delivery(row.id)
    with pytest.raises(LeaseLost):
        restarted.acknowledge(replace(ticket, token="wrong"), "receipt")  # noqa: S106 - invalid test ticket
    assert restarted.acknowledge(ticket, "receipt").status == "acknowledged"
    assert restarted.acknowledge(ticket, "receipt").status == "acknowledged"
    with pytest.raises(SubmissionConflict):
        restarted.acknowledge(ticket, "different-receipt")
    assert restarted.claim(row.id) is None
    with pytest.raises(SubmissionConflict):
        restarted.prepare_delivery(row.id)


@pytest.mark.parametrize("transition", ["explicit", "recover", "late_ack"])
def test_unknown_delivery_outcome_is_terminal_ambiguity(spool, transition):
    row = release(spool)
    ticket = spool.registry.prepare_delivery(row.id)
    restarted = MailSubmissionRegistry(**spool.options)
    if transition == "explicit":
        result = restarted.mark_ambiguous(ticket)
    else:
        expire(spool, row.id, "delivery_expires_epoch")
        result = (
            restarted.recover(row.id)
            if transition == "recover"
            else restarted.acknowledge(ticket, "late")
        )
    assert result.status == "ambiguous" and not result.retryable
    assert restarted.mark_ambiguous(ticket).status == "ambiguous"
    assert restarted.claim(row.id) is None
    with pytest.raises(SubmissionConflict):
        restarted.prepare_delivery(row.id)


def test_retained_binding_tampering_is_detected(spool):
    row = admit(spool)
    with spool.sessions() as s:
        stored = s.get(MailSubmission, row.id)
        stored.envelope = {
            "mail_from": "changed@example.test",
            "rcpt_to": stored.envelope["rcpt_to"],
        }
        s.commit()
    with pytest.raises(SubmissionConflict, match="facts changed"):
        spool.registry.claim(row.id)


def test_cross_matter_tenant_identity_race_has_one_winner(spool, monkeypatch, queue_backend):
    matter = spool.client.post("/v1/matters", json={"name": "Second matter"}).json()["id"]
    for permission in ("read", "upload", "sanitize"):
        spool.client.put(
            f"/v1/matters/{matter}/acl",
            json={"user_id": spool.binding.actor_id, "perm": permission},
        ).raise_for_status()
    other = MailSubmissionRegistry(
        **dict(spool.options, binding=replace(spool.binding, matter_id=matter))
    )

    if queue_backend == "postgres":
        # Different matter locks permit both prior lookups to miss. Force that
        # window to exercise the unique-constraint recovery, not just lookup.
        barrier = threading.Barrier(2)
        write_once = spool.storage.write_once

        def simultaneous_stage(*args, **kwargs):
            barrier.wait(timeout=30)
            return write_once(*args, **kwargs)

        monkeypatch.setattr(spool.storage, "write_once", simultaneous_stage)

    def attempt(registry):
        try:
            return registry.admit(spool.raw, spool.envelope, spool.caller)
        except SubmissionConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (spool.registry, other)))
    assert sum(outcome is not None for outcome in outcomes) == 1
    winner = next(outcome for outcome in outcomes if outcome is not None)
    loser = other if outcomes[0] is not None else spool.registry
    with pytest.raises(BindingDenied):
        loser.get(winner.id)
    with spool.sessions() as s:
        assert s.query(MailSubmission).count() == 1
        assert s.query(AuditEvent).filter_by(action="mail.admitted").count() == 1


@pytest.mark.parametrize("stage", ["input", "output"])
def test_failed_storage_write_never_publishes_a_receipt_or_output(spool, monkeypatch, stage):
    row = admit(spool) if stage == "output" else None

    def fail(*args, **kwargs):
        raise StorageError("injected staging failure")

    monkeypatch.setattr(spool.storage, "write_once", fail)
    with pytest.raises(StorageError):
        if row:
            spool.registry.process(row.id, spool.processor)
        else:
            admit(spool)
    with spool.sessions() as s:
        if row:
            retained = s.get(MailSubmission, row.id)
            assert retained.status == "processing" and retained.output_ref is None
        else:
            assert s.query(MailSubmission).count() == 0


def test_lease_expiring_during_output_write_cannot_publish(spool, monkeypatch):
    import app.mail.submissions as module

    row = admit(spool)
    claim = spool.registry.claim(row.id)
    result = MailAdapter(spool.processor).process(spool.registry._request(claim))
    write_once = spool.storage.write_once

    def expires_after_write(*args, **kwargs):
        reference = write_once(*args, **kwargs)
        monkeypatch.setattr(module, "database_now", lambda session: 9_999_999_999)
        return reference

    monkeypatch.setattr(spool.storage, "write_once", expires_after_write)
    with pytest.raises(LeaseLost):
        spool.registry._publish(claim, result)
    with spool.sessions() as s:
        retained = s.get(MailSubmission, row.id)
        assert retained.status == "processing" and retained.output_ref is None
        assert s.query(AuditEvent).filter_by(action="mail.decision").count() == 0


def test_simultaneous_delivery_claims_return_only_one_ticket(spool):
    row = release(spool)

    def prepare(_):
        try:
            return spool.registry.prepare_delivery(row.id)
        except SubmissionConflict:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        tickets = list(pool.map(prepare, range(4)))
    assert sum(ticket is not None for ticket in tickets) == 1
    assert spool.registry.get(row.id).status == "submitted"


def test_migration_downgrade_cannot_discard_retained_mail(spool):
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from app.migrate import _ALEMBIC_DIR, _ALEMBIC_INI

    row = admit(spool)
    migration = AlembicConfig(str(_ALEMBIC_INI))
    migration.set_main_option("script_location", str(_ALEMBIC_DIR))
    migration.set_main_option("sqlalchemy.url", spool.cfg.db_url())
    with pytest.raises(RuntimeError, match="cannot discard retained mail"):
        command.downgrade(migration, "0016")
    assert spool.registry.get(row.id).status == "admitted"
