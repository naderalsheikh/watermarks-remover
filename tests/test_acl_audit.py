"""PR 16 — matter ACL, hash-chained audit log, download_original gating."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "service" / "scripts"), str(REPO / "service")):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.main import create_app

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw16")
    root = tmp_path / "data"
    app = create_app(root)
    c = TestClient(app)
    r = c.post("/v1/auth/login", json={"password": "pw16"})
    assert r.status_code == 200
    matter = c.post("/v1/matters", json={"name": "Project Juniper"}).json()
    doc = c.post(
        f"/v1/matters/{matter['id']}/documents",
        files={
            "file": ("spa.txt", (FIXTURES / "spa.txt").read_bytes(), "application/octet-stream")
        },
    ).json()
    job = c.post(f"/v1/matters/{matter['id']}/documents/{doc['id']}/sanitize-jobs", json={}).json()
    assert job["status"] == "done", job["error"]
    plain = c.get(f"/v1/matters/{matter['id']}/jobs/{job['id']}/bundle")
    assert plain.status_code == 200
    return c, matter, doc, job, root / "counselclear.sqlite3"


def _audit(client, matter_id):
    return client.get(f"/v1/matters/{matter_id}/audit").json()


def test_auth_me_returns_operator_in_local_mode(env):
    """The Access panel's "Your principal ID" display needs somewhere to
    read the caller's own identity from. Local mode has exactly one:
    the shared "operator" subject."""
    c, _, _, _, _ = env
    r = c.get("/v1/auth/me")
    assert r.status_code == 200
    assert r.json() == {"principal": "operator"}


def test_auth_me_requires_authentication(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw-me")
    c = TestClient(create_app(tmp_path / "data"))
    r = c.get("/v1/auth/me")
    assert r.status_code == 401


def test_audit_chain_is_intact_and_ordered(env):
    c, matter, _, _, _ = env
    body = _audit(c, matter["id"])
    assert body["chain_ok"] is True
    seqs = [e["seq"] for e in body["events"]]
    assert seqs == list(range(len(seqs)))
    kinds = [e["action"] for e in body["events"]]
    assert kinds[0] == "matter.create"
    assert "document.upload" in kinds and "bundle.download" in kinds
    assert "job.sanitize" in kinds


def test_audit_document_upload_carries_document_id(env):
    """The audit timeline's document cross-link (web/app/matters/audit/
    page.tsx) needs a document_id to link to -- it was missing from this
    payload entirely before this test's fix."""
    c, matter, doc, _, _ = env
    events = _audit(c, matter["id"])["events"]
    upload_event = next(e for e in events if e["action"] == "document.upload")
    assert upload_event["payload"]["document_id"] == doc["id"]


def test_audit_chain_detects_tampering(env):
    c, matter, _, _, db_path = env

    # Tamper directly in the store behind the API's back.
    import sqlite3

    con = sqlite3.connect(db_path)
    con.execute(
        "UPDATE audit_events SET action = 'matter.destroyed' "
        "WHERE matter_id = ? AND action = 'matter.create'",
        (matter["id"],),
    )
    con.commit()
    con.close()

    body = _audit(c, matter["id"])
    assert body["chain_ok"] is False
    assert "hash mismatch" in body["chain_detail"]


def test_download_original_requires_explicit_grant(env):
    c, matter, _, job, _ = env
    url = f"/v1/matters/{matter['id']}/jobs/{job['id']}/bundle"

    # not bootstrapped: even the operator needs an explicit, audited grant
    denied = c.get(f"{url}?include_original=true")
    assert denied.status_code == 403
    assert "permission" in denied.json()["detail"]

    granted = c.put(
        f"/v1/matters/{matter['id']}/acl",
        json={"user_id": "operator", "perm": "download_original"},
    )
    assert granted.status_code == 200
    ok = c.get(f"{url}?include_original=true")
    assert ok.status_code == 200
    with zipfile.ZipFile(io.BytesIO(ok.content)) as zf:
        assert any(n.startswith("original/") for n in zf.namelist())

    r = c.request(
        "DELETE",
        f"/v1/matters/{matter['id']}/acl",
        json={"user_id": "operator", "perm": "download_original"},
    )
    assert r.status_code == 200
    assert c.get(f"{url}?include_original=true").status_code == 403

    # derivative-only bundle still works without the permission
    plain = c.get(url)
    assert plain.status_code == 200


def test_grant_unknown_perm_is_400(env):
    c, matter, _, _, _ = env
    r = c.put(
        f"/v1/matters/{matter['id']}/acl",
        json={"user_id": "someone", "perm": "delete_everything"},
    )
    assert r.status_code == 400


def test_get_acl_lists_current_grants(env):
    """The Access panel (web/app/matters/access/page.tsx) needs to show
    who currently has what -- there was no read endpoint for that at all
    before this test's fix, only grant/revoke."""
    c, matter, _, _, _ = env
    r = c.get(f"/v1/matters/{matter['id']}/acl")
    assert r.status_code == 200
    grants = r.json()["grants"]
    operator_row = next(g for g in grants if g["user_id"] == "operator")
    assert set(operator_row["perms"]) == {"read", "upload", "inspect", "sanitize", "admin"}

    c.put(f"/v1/matters/{matter['id']}/acl", json={"user_id": "paralegal", "perm": "read"})
    grants = c.get(f"/v1/matters/{matter['id']}/acl").json()["grants"]
    paralegal_row = next(g for g in grants if g["user_id"] == "paralegal")
    assert paralegal_row["perms"] == ["read"]

    c.request(
        "DELETE",
        f"/v1/matters/{matter['id']}/acl",
        json={"user_id": "paralegal", "perm": "read"},
    )
    grants = c.get(f"/v1/matters/{matter['id']}/acl").json()["grants"]
    assert not any(g["user_id"] == "paralegal" for g in grants)


def test_audit_records_acl_changes(env):
    c, matter, _, _, _ = env
    c.put(
        f"/v1/matters/{matter['id']}/acl",
        json={"user_id": "paralegal", "perm": "read"},
    )
    c.request(
        "DELETE",
        f"/v1/matters/{matter['id']}/acl",
        json={"user_id": "paralegal", "perm": "read"},
    )
    actions = [e["action"] for e in _audit(c, matter["id"])["events"]]
    assert "acl.grant" in actions and "acl.revoke" in actions


def test_audit_records_inspect_and_sanitize_execution(env):
    """Before this test's fix, the audit chain covered matter.create,
    document.upload, and acl.* -- but never the inspect/sanitize jobs
    themselves, which is the one thing a "chain of custody" claim is
    actually about. The env fixture already ran one sanitize job; assert
    its event and payload here, then run an inspect job too."""
    c, matter, doc, job, _ = env
    events = _audit(c, matter["id"])["events"]
    sanitize_events = [e for e in events if e["action"] == "job.sanitize"]
    assert len(sanitize_events) == 1
    payload = sanitize_events[0]["payload"]
    assert payload["job_id"] == job["id"]
    assert payload["document_id"] == doc["id"]
    assert payload["policy_id"] == "external_sharing"
    assert payload["status"] == "done"
    assert payload["verification_pass"] is True
    assert payload["no_decision_count"] == 0
    assert sanitize_events[0]["actor_id"] == "operator"

    inspect_job = c.post(f"/v1/matters/{matter['id']}/documents/{doc['id']}/inspect-jobs").json()
    assert inspect_job["status"] == "done", inspect_job.get("error")
    events = _audit(c, matter["id"])["events"]
    inspect_events = [e for e in events if e["action"] == "job.inspect"]
    assert len(inspect_events) == 1
    payload = inspect_events[0]["payload"]
    assert payload["job_id"] == inspect_job["id"]
    assert payload["document_id"] == doc["id"]
    assert payload["status"] == "done"
    assert isinstance(payload["findings_count"], int)


def test_audit_no_decision_count_reflects_production_findings_kept(tmp_path, monkeypatch):
    """The audit trail must surface the same "kept without review" signal
    the manifest does (see policies.py's _approve_default_keep_records / test_
    apply_production_docx_discloses_findings_kept_without_a_decision) --
    not just leave it buried in the manifest's actions list. spa.docx has
    one comment and tracked changes, both approve-default under
    production, so a production sanitize with zero decisions must show
    no_decision_count >= 2 in the audit payload."""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw-nodecision")
    c = TestClient(create_app(tmp_path / "data"))
    assert c.post("/v1/auth/login", json={"password": "pw-nodecision"}).status_code == 200
    matter = c.post("/v1/matters", json={"name": "m"}).json()
    doc = c.post(
        f"/v1/matters/{matter['id']}/documents",
        files={"file": ("spa.docx", (FIXTURES / "spa.docx").read_bytes(), "application/octet-stream")},
    ).json()
    job = c.post(
        f"/v1/matters/{matter['id']}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "production", "signature_break_attestation": True},
    ).json()
    assert job["status"] == "done", job["error"]

    events = _audit(c, matter["id"])["events"]
    sanitize_events = [e for e in events if e["action"] == "job.sanitize"]
    assert len(sanitize_events) == 1
    assert sanitize_events[0]["payload"]["no_decision_count"] >= 2


def test_cross_matter_document_and_job_access_is_404_not_leaked(env):
    """A document/job id from one matter must not be reachable through a
    different matter's URL, even for the (today, only) operator account —
    matter-scoped URLs are the isolation boundary multi-user ACL will sit
    on top of later, and id confusion here would silently defeat it."""
    c, matter_a, doc_a, job_a, _ = env
    matter_b = c.post("/v1/matters", json={"name": "Unrelated Matter"}).json()

    r = c.get(f"/v1/matters/{matter_b['id']}/documents/{doc_a['id']}")
    assert r.status_code == 404

    r = c.get(f"/v1/matters/{matter_b['id']}/jobs/{job_a['id']}")
    assert r.status_code == 404

    r = c.get(f"/v1/matters/{matter_b['id']}/jobs/{job_a['id']}/manifest")
    assert r.status_code == 404

    r = c.get(f"/v1/matters/{matter_b['id']}/jobs/{job_a['id']}/bundle")
    assert r.status_code == 404

    # and the reverse: matter_b's (nonexistent) doc id looked up under matter_a
    r = c.get(f"/v1/matters/{matter_a['id']}/documents/{matter_b['id']}")
    assert r.status_code == 404


def test_manifest_carries_no_matter_name(env):
    c, matter, _, job, _ = env
    manifest = c.get(f"/v1/matters/{matter['id']}/jobs/{job['id']}/manifest").json()
    blob = json.dumps(manifest)
    assert "Project Juniper" not in blob


def test_audit_chain_cannot_fork_even_if_the_process_lock_is_bypassed(tmp_path):
    """The regression this exists for: two writers that both read
    max(seq) before either commits must not both succeed at inserting the
    same (matter_id, seq) — that's a forked, no-longer-tamper-evident
    chain. This deliberately bypasses audit.append_event's own
    threading.Lock (two separate sessions racing on purpose) to prove the
    *database* layer (BEGIN IMMEDIATE + the unique constraint) is what
    actually prevents the fork, not just the in-process lock a second
    worker process wouldn't share anyway."""
    import threading

    from app.config import Config
    from app.db import make_engine, make_session_factory
    from app.migrate import upgrade_head
    from app.models import AuditEvent, Matter

    cfg = Config(tmp_path / "data")
    cfg.ensure_dirs()
    upgrade_head(f"sqlite:///{cfg.db_path}")
    engine = make_engine(cfg)
    factory = make_session_factory(engine)

    s0 = factory()
    s0.add(Matter(id="m1", name="Race Matter"))
    s0.commit()
    s0.close()

    results: list[str] = []
    start = threading.Barrier(2)

    def racer(actor: str):
        s = factory()
        try:
            start.wait()  # maximize the chance both threads read seq=None together
            last = s.query(AuditEvent).filter_by(matter_id="m1").count()
            ev = AuditEvent(
                matter_id="m1", seq=last, actor_id=actor, action="matter.create",
                payload={}, prev_hash="0" * 64, row_hash=f"hash-{actor}",
            )
            s.add(ev)
            s.commit()
            results.append(f"{actor}:ok")
        except Exception as e:
            s.rollback()
            results.append(f"{actor}:blocked({type(e).__name__})")
        finally:
            s.close()

    threads = [threading.Thread(target=racer, args=(f"actor{i}",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    s = factory()
    rows = s.query(AuditEvent).filter_by(matter_id="m1").all()
    seqs = [r.seq for r in rows]
    assert len(seqs) == len(set(seqs)), f"duplicate seq values: {seqs} (results: {results})"
    s.close()
