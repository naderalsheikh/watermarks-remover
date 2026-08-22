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


def test_audit_chain_is_intact_and_ordered(env):
    c, matter, _, _, _ = env
    body = _audit(c, matter["id"])
    assert body["chain_ok"] is True
    seqs = [e["seq"] for e in body["events"]]
    assert seqs == list(range(len(seqs)))
    kinds = [e["action"] for e in body["events"]]
    assert kinds[0] == "matter.create"
    assert "document.upload" in kinds and "bundle.download" in kinds


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
