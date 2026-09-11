"""HTTP retries must retain one durable resource without spending authorization twice."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app.audit import verify_chain
from app.main import create_app
from app.models import Admission, AttestationUse, AuditEvent, Batch, Document, Job, Release


@pytest.fixture
def env(tmp_path, monkeypatch, queue_backend):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "test-password")
    monkeypatch.setenv("COUNSELCLEAR_WATERMARK_TOOLS", "1")
    monkeypatch.setattr("app.dispatcher.BatchDispatcher.wake", lambda self: None)
    root = tmp_path / "data"
    client = TestClient(create_app(root))
    assert client.post("/v1/auth/login", json={"password": "test-password"}).status_code == 200
    mid = client.post("/v1/matters", json={"name": "Synthetic retry tests"}).json()["id"]
    docs = [
        client.post(
            f"/v1/matters/{mid}/documents",
            files={"file": (f"sample{n}.txt", b"Synthetic document", "text/plain")},
        ).json()["id"]
        for n in range(2)
    ]
    yield client, client.app.state.batch_dispatcher._session_factory, mid, docs, root
    client.close()


def submission(mid, docs, operation):
    root = f"/v1/matters/{mid}"
    if operation == "batch":
        return root + "/batches", {"document_ids": docs, "kind": "inspect"}
    if operation == "batch_release":
        return root + "/releases", {
            "document_ids": docs,
            "profile_id": "counterparty_deal_room",
            "recipient_type": "client",
        }
    base = root + f"/documents/{docs[0]}"
    if operation == "release":
        return base + "/releases", {
            "profile_id": "counterparty_deal_room",
            "recipient_type": "client",
        }
    return base + f"/{operation}-jobs", {} if operation == "sanitize" else None


def identity(body, operation):
    if operation == "release":
        return body["release"]["id"]
    if operation == "batch_release":
        return body["batch"]["id"]
    return body["id"]


@pytest.mark.parametrize("operation", ["inspect", "sanitize", "release", "batch", "batch_release"])
def test_concurrent_identical_retries_create_one_admission(env, operation):
    c, sessions, mid, docs, _ = env
    url, body = submission(mid, docs, operation)
    headers = {"Idempotency-Key": "same-request", "Prefer": "respond-async"}
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: c.post(url, json=body, headers=headers), range(4)))
    assert all(r.status_code in (200, 202) for r in responses), [r.text for r in responses]
    ids = {identity(r.json(), operation) for r in responses}
    assert len(ids) == 1
    if operation in ("inspect", "sanitize", "release"):
        assert all(r.status_code == 202 for r in responses)
        assert c.get(responses[0].headers["Location"]).status_code == 200
    with sessions() as s:
        assert s.query(Admission).count() == 1
        assert s.query(Job).count() == (2 if operation.startswith("batch") else 1)
        assert s.query(Batch).count() == int(operation.startswith("batch"))
        assert s.query(Release).count() == (
            2 if operation == "batch_release" else int(operation == "release")
        )
        assert verify_chain(s.query(AuditEvent).order_by(AuditEvent.seq).all())[0]


@pytest.mark.parametrize("operation", ["inspect", "sanitize", "release", "batch", "batch_release"])
def test_same_key_changed_request_conflicts(env, operation):
    c, sessions, mid, docs, _ = env
    url, body = submission(mid, docs, operation)
    headers = {"Idempotency-Key": "same-request", "Prefer": "respond-async"}
    assert c.post(url, json=body, headers=headers).status_code in (200, 202)
    if operation == "inspect":
        url = url.replace(docs[0], docs[1])
    else:
        body = {**body, "reason": "A different authorized purpose"}
    assert c.post(url, json=body, headers=headers).status_code == 409
    with sessions() as s:
        assert s.query(Admission).count() == 1


def test_replay_after_restart_and_changed_original_is_refused(env):
    c, sessions, mid, docs, root = env
    url, body = submission(mid, docs, "inspect")
    headers = {"Idempotency-Key": "restart-request", "Prefer": "respond-async"}
    original = c.post(url, json=body, headers=headers).json()
    with TestClient(create_app(root)) as restarted:
        restarted.post("/v1/auth/login", json={"password": "test-password"})
        replay = restarted.post(url, json=body, headers=headers)
        assert replay.status_code in (200, 202)
        assert replay.json()["id"] == original["id"]
        with sessions() as s:
            s.get(Document, docs[0]).sha256 = "f" * 64
            s.commit()
        assert restarted.post(url, json=body, headers=headers).status_code == 409


@pytest.mark.parametrize("operation", ["sanitize", "release"])
def test_replay_does_not_reconsume_token_and_failed_admission_can_retry(env, operation):
    c, sessions, mid, docs, _ = env
    issued = c.post(
        "/v1/attestations", json={"matter_id": mid, "document_id": docs[0], "strength": "preserve"}
    )
    assert issued.status_code == 200, issued.text
    token = issued.json()["token"]
    url, body = submission(mid, docs, operation)
    body = {**body, "layer_b": {"strength": "preserve", "token": token}}
    headers = {"Idempotency-Key": "authorized-request", "Prefer": "respond-async"}

    def fail(*_):
        raise RuntimeError("synthetic admission receipt failure")

    event.listen(Admission, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError, match="synthetic admission"):
            c.post(url, json=body, headers=headers)
    finally:
        event.remove(Admission, "before_insert", fail)
    with sessions() as s:
        assert (
            s.query(Job).count()
            == s.query(AttestationUse).count()
            == s.query(Admission).count()
            == 0
        )
    first = c.post(url, json=body, headers=headers)
    replay = c.post(url, json=body, headers=headers)
    assert first.status_code == replay.status_code == 202
    assert identity(first.json(), operation) == identity(replay.json(), operation)
    with sessions() as s:
        assert (
            s.query(Job).count()
            == s.query(AttestationUse).count()
            == s.query(Admission).count()
            == 1
        )


def test_authorization_precedes_receipt_lookup(env):
    c, _, mid, docs, _ = env
    url, body = submission(mid, docs, "inspect")
    headers = {"Idempotency-Key": "known-request", "Prefer": "respond-async"}
    assert c.post(url, json=body, headers=headers).status_code == 202
    c.post("/v1/auth/logout")
    assert c.post(url, json=body, headers=headers).status_code == 401


@pytest.mark.parametrize("key", ["", "two words", "x" * 201])
def test_invalid_retry_key_is_rejected_before_creating_work(env, key):
    c, sessions, mid, docs, _ = env
    url, body = submission(mid, docs, "inspect")
    response = c.post(url, json=body, headers={"Idempotency-Key": key, "Prefer": "respond-async"})
    assert response.status_code == 400
    with sessions() as s:
        assert s.query(Job).count() == s.query(Admission).count() == 0


def test_key_is_scoped_to_authorized_principal(env):
    from app.models import MatterAcl

    c, sessions, mid, docs, _ = env
    url, body = submission(mid, docs, "inspect")
    headers = {"Idempotency-Key": "principal-scoped", "Prefer": "respond-async"}
    first = c.post(url, json=body, headers=headers)
    assert first.status_code == 202
    route = next(r for r in c.app.routes if getattr(r, "path", "").endswith("/inspect-jobs"))
    principal = next(d.call for d in route.dependant.dependencies if d.name == "user")
    c.app.dependency_overrides[principal] = lambda: "bob"
    assert c.post(url, json=body, headers=headers).status_code == 403
    with sessions() as s:
        s.add(MatterAcl(matter_id=mid, user_id="bob", perm="inspect"))
        s.commit()
    second = c.post(url, json=body, headers=headers)
    assert second.status_code == 202
    assert first.json()["id"] != second.json()["id"]
    with sessions() as s:
        assert s.query(Job).count() == s.query(Admission).count() == 2


@pytest.mark.parametrize("operation", ["inspect", "batch", "batch_release"])
def test_receipt_insert_failure_rolls_back_whole_admission(env, operation):
    c, sessions, mid, docs, _ = env
    url, body = submission(mid, docs, operation)
    headers = {"Idempotency-Key": "rollback", "Prefer": "respond-async"}
    with sessions() as s:
        before = s.query(AuditEvent).count()

    def fail(*_):
        raise RuntimeError("synthetic receipt failure")

    event.listen(Admission, "before_insert", fail)
    try:
        with pytest.raises(RuntimeError, match="synthetic receipt"):
            c.post(url, json=body, headers=headers)
    finally:
        event.remove(Admission, "before_insert", fail)
    with sessions() as s:
        assert s.query(Job).count() == s.query(Release).count() == s.query(Batch).count() == 0
        assert s.query(Admission).count() == 0
        assert s.query(AuditEvent).count() == before
    assert c.post(url, json=body, headers=headers).status_code in (200, 202)
