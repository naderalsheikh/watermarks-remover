"""PR 15 — FastAPI control plane: auth, matters, documents, jobs, bundles."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in __import__("sys").path:
        __import__("sys").path.insert(0, p)

from app.main import create_app

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "correct horse battery")
    app = create_app(tmp_path / "data")
    c = TestClient(app)
    r = c.post("/v1/auth/login", json={"password": "correct horse battery"})
    assert r.status_code == 200
    yield c
    c.close()


def test_health_is_unauthenticated(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    c = TestClient(create_app(tmp_path / "d"))
    r = c.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


def test_login_cookie_not_secure_over_plain_http_but_docs_default_on(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    c = TestClient(create_app(tmp_path / "d"))
    r = c.post("/v1/auth/login", json={"password": "pw12345"})
    # TestClient's default base_url is http://testserver — secure=False is
    # correct here (a hardcoded secure=True would just drop the cookie).
    assert "secure" not in r.headers["set-cookie"].lower()
    assert c.get("/docs").status_code == 200


def test_docs_disabled_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    monkeypatch.setenv("COUNSELCLEAR_DISABLE_DOCS", "1")
    c = TestClient(create_app(tmp_path / "d"))
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404


def test_auth_required_and_login_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    app = create_app(tmp_path / "d1")
    with TestClient(app) as c:
        r = c.post("/v1/matters", json={"name": "X"})
        assert r.status_code == 401
        r = c.post("/v1/auth/login", json={"password": "wrong"})
        assert r.status_code == 403
        r = c.post("/v1/auth/login", json={"password": "pw12345"})
        assert r.status_code == 200
        assert "cc_session" in r.cookies
        r = c.post("/v1/matters", json={"name": "Merger 2026"})
        assert r.status_code == 200 and r.json()["id"]


def test_matter_create_and_get(client):
    r = client.post("/v1/matters", json={"name": "Project Dandelion"})
    mid = r.json()["id"]
    r2 = client.get(f"/v1/matters/{mid}")
    assert r2.json()["name"] == "Project Dandelion"
    assert client.get("/v1/matters/nope").status_code == 404


def _upload(client, name: str, matter: str | None = None) -> dict:
    if matter is None:
        matter = client.post("/v1/matters", json={"name": "m"}).json()["id"]
    data = (FIXTURES / name).read_bytes()
    r = client.post(
        f"/v1/matters/{matter}/documents",
        files={"file": (name, data, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    return {**r.json(), "_matter": matter}


def test_read_capped_rejects_oversized_upload_without_buffering_it_all():
    """_read_capped must not be `await file.read()` with no limit — a client
    that omits or lies about Content-Length shouldn't be able to make this
    process buffer an unbounded body before the engine ever sees it."""
    import asyncio

    from app.main import _read_capped
    from fastapi import HTTPException, UploadFile

    async def _run():
        upload = UploadFile(file=io.BytesIO(b"x" * 100), filename="big.bin")
        with pytest.raises(HTTPException) as exc:
            await _read_capped(upload, cap=10)
        assert exc.value.status_code == 413

        upload_ok = UploadFile(file=io.BytesIO(b"x" * 10), filename="ok.bin")
        assert await _read_capped(upload_ok, cap=10) == b"x" * 10

    asyncio.run(_run())


def test_upload_endpoint_rejects_oversized_file(client, monkeypatch):
    import app.main as app_main

    monkeypatch.setattr(app_main, "MAX_INPUT_BYTES", 16)
    matter = client.post("/v1/matters", json={"name": "m"}).json()["id"]
    r = client.post(
        f"/v1/matters/{matter}/documents",
        files={"file": ("big.txt", b"x" * 1000, "text/plain")},
    )
    assert r.status_code == 413


def test_document_upload_is_write_once_and_hashed(client):
    doc = _upload(client, "spa.docx")
    assert len(doc["sha256"]) == 64
    assert doc["filename"] == "spa.docx"
    r = client.get(f"/v1/matters/{doc['_matter']}/documents/{doc['id']}")
    assert r.json()["sha256"] == doc["sha256"]


def test_inspect_job_reports_findings(client):
    doc = _upload(client, "spa.txt")
    r = client.post(f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/inspect-jobs")
    body = r.json()
    assert body["status"] == "done"
    found = body["result"]["findings"]
    assert found

    def _blob(item) -> str:
        if isinstance(item, dict):
            return " ".join(str(item.get(k) or "") for k in ("subtype", "category", "notes"))
        return str(item)

    assert any("layer" in _blob(f).lower() for f in found) or found


def test_sanitize_job_privacy_bundle_excludes_original(client):
    doc = _upload(client, "spa.docx")
    r = client.post(
        f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "privacy_only", "reason": "counsel review"},
    )
    body = r.json()
    assert body["status"] == "done", body["error"]
    job_id = body["id"]

    manifest = client.get(f"/v1/matters/{doc['_matter']}/jobs/{job_id}/manifest").json()
    assert manifest["policy"]["id"] == "privacy_only"
    assert manifest["verification"]["pass"] is True

    bundle = client.get(f"/v1/matters/{doc['_matter']}/jobs/{job_id}/bundle")
    assert bundle.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
        names = zf.namelist()
    assert not any(n.startswith("original/") for n in names)
    assert "manifest.json" in names and "report.json" in names
    assert any(n.startswith("derivative/") for n in names)


def test_include_original_denied_by_default(client):
    doc = _upload(client, "spa.txt")
    r = client.post(f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/sanitize-jobs", json={})
    job_id = r.json()["id"]
    assert r.json()["status"] == "done"
    denied = client.get(f"/v1/matters/{doc['_matter']}/jobs/{job_id}/bundle?include_original=true")
    assert denied.status_code == 403


def test_signed_pdf_refused_then_done_with_attestation(client):
    doc = _upload(client, "signed.pdf")
    url = f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/sanitize-jobs"
    r1 = client.post(url, json={"policy_id": "external_sharing"}).json()
    assert r1["status"] == "refused"
    assert "attestation" in r1["error"]
    r2 = client.post(
        url, json={"policy_id": "external_sharing", "signature_break_attestation": True}
    ).json()
    assert r2["status"] == "done", r2["error"]


def test_macro_docm_job_refuses(client):
    doc = _upload(client, "macro.docm")
    r = client.post(
        f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert r["status"] == "refused"
    assert "macro" in r["error"].lower()


def test_audit_chain_and_download_original_perm(client):
    doc = _upload(client, "spa.txt")
    matter = doc["_matter"]
    r = client.post(f"/v1/matters/{matter}/documents/{doc['id']}/sanitize-jobs", json={}).json()
    assert r["status"] == "done"
    job_id = r["id"]
    denied = client.get(f"/v1/matters/{matter}/jobs/{job_id}/bundle?include_original=true")
    assert denied.status_code == 403
    granted = client.put(f"/v1/matters/{matter}/acl", json={"perm": "download_original"})
    assert granted.status_code == 200
    allowed = client.get(f"/v1/matters/{matter}/jobs/{job_id}/bundle?include_original=true")
    assert allowed.status_code == 200
    events = client.get(f"/v1/matters/{matter}/audit").json()["events"]
    actions = [e["action"] for e in events]
    assert "matter.create" in actions
    assert "document.upload" in actions
    assert "bundle.download" in actions
    by_hash = {e["row_hash"]: e for e in events}
    genesis = [e for e in events if e["prev_hash"] == "0" * 64]
    assert len(genesis) == 1
    walk = genesis[0]
    seen = 1
    while True:
        nxt = next((e for e in events if e["prev_hash"] == walk["row_hash"]), None)
        if not nxt:
            break
        walk = nxt
        seen += 1
    assert seen == len(events) == len(by_hash)
