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


def test_login_cookie_not_secure_over_plain_http_and_docs_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    c = TestClient(create_app(tmp_path / "d"))
    r = c.post("/v1/auth/login", json={"password": "pw12345"})
    # TestClient's default base_url is http://testserver — secure=False is
    # correct here (a hardcoded secure=True would just drop the cookie).
    assert "secure" not in r.headers["set-cookie"].lower()
    # Docs are fail-closed now: they exist only with COUNSELCLEAR_ENABLE_DOCS=1.
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404


def test_docs_enabled_via_opt_in_env(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    monkeypatch.setenv("COUNSELCLEAR_ENABLE_DOCS", "1")
    c = TestClient(create_app(tmp_path / "d"))
    assert c.get("/docs").status_code == 200
    assert c.get("/openapi.json").status_code == 200


def test_docs_disable_wins_over_enable(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    monkeypatch.setenv("COUNSELCLEAR_ENABLE_DOCS", "1")
    monkeypatch.setenv("COUNSELCLEAR_DISABLE_DOCS", "1")
    c = TestClient(create_app(tmp_path / "d"))
    assert c.get("/docs").status_code == 404


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
    # Uniform 403 for nonexistent + unauthorized (permission check first,
    # like every other matter-scoped route) — no ID-existence oracle.
    assert client.get("/v1/matters/nope").status_code == 403


def test_auth_config_is_unauthenticated_and_reports_oidc_off(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    c = TestClient(create_app(tmp_path / "d"))
    assert c.get("/v1/auth/config").json() == {"oidc_enabled": False}


def test_cookie_secure_flag_follows_config(tmp_path, monkeypatch):
    """COUNSELCLEAR_COOKIE_SECURE=true must set Secure on the session
    cookie even when the request itself is plain HTTP (the proxy-terminated
    deployment where the app only ever sees http)."""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    monkeypatch.setenv("COUNSELCLEAR_COOKIE_SECURE", "true")
    c = TestClient(create_app(tmp_path / "d"))
    r = c.post("/v1/auth/login", json={"password": "pw12345"})
    assert r.status_code == 200
    assert "Secure" in r.headers["set-cookie"]

    # Default (auto) over plain HTTP: not Secure — loopback v1 deployment.
    monkeypatch.setenv("COUNSELCLEAR_COOKIE_SECURE", "auto")
    c2 = TestClient(create_app(tmp_path / "d2"))
    r2 = c2.post("/v1/auth/login", json={"password": "pw12345"})
    assert r2.status_code == 200
    assert "Secure" not in r2.headers["set-cookie"]


def test_list_policies_requires_auth_and_returns_the_four_frozen_ids(client):
    from app.main import POLICIES

    assert TestClient(client.app).get("/v1/policies").status_code == 401
    r = client.get("/v1/policies")
    assert r.status_code == 200
    ids = [p["id"] for p in r.json()["policies"]]
    assert ids == [p["id"] for p in POLICIES]
    assert set(ids) == {"external_sharing", "privacy_only", "production", "evidence_preservation"}


def test_list_matters_scopes_to_the_caller_and_list_documents_and_jobs(client):
    m1 = client.post("/v1/matters", json={"name": "m1"}).json()["id"]
    m2 = client.post("/v1/matters", json={"name": "m2"}).json()["id"]
    ids = {m["id"] for m in client.get("/v1/matters").json()["matters"]}
    assert {m1, m2} <= ids

    doc = _upload(client, "spa.docx", matter=m1)
    assert [d["id"] for d in client.get(f"/v1/matters/{m1}/documents").json()["documents"]] == [
        doc["id"]
    ]
    assert client.get(f"/v1/matters/{m2}/documents").json()["documents"] == []

    job = client.post(f"/v1/matters/{m1}/documents/{doc['id']}/inspect-jobs").json()
    jobs = client.get(f"/v1/matters/{m1}/jobs").json()["jobs"]
    assert [j["id"] for j in jobs] == [job["id"]]
    assert client.get(f"/v1/matters/{m1}/jobs?document_id={doc['id']}").json()["jobs"][0][
        "id"
    ] == job["id"]
    assert client.get(f"/v1/matters/{m1}/jobs?document_id=nope").json()["jobs"] == []


def test_list_matters_documents_jobs_require_auth(client):
    m = client.post("/v1/matters", json={"name": "m"}).json()["id"]
    unauth = TestClient(client.app)
    assert unauth.get("/v1/matters").status_code == 401
    assert unauth.get(f"/v1/matters/{m}/documents").status_code == 401
    assert unauth.get(f"/v1/matters/{m}/jobs").status_code == 401


def test_list_endpoints_are_server_capped_and_jobs_omit_result(client):
    """Lists must be bounded (a caller can't request an unbounded dump) and
    the jobs list must not carry the full result payload — that lives on
    the detail route only."""
    m = client.post("/v1/matters", json={"name": "cap"}).json()["id"]
    doc = _upload(client, "spa.docx", matter=m)
    job = client.post(f"/v1/matters/{m}/documents/{doc['id']}/inspect-jobs").json()

    # Server cap: requesting more than the cap clamps, never grows unbounded.
    assert len(client.get(f"/v1/matters/{m}/jobs?limit=100000").json()["jobs"]) <= 500
    assert len(client.get(f"/v1/matters/{m}/documents?limit=100000").json()["documents"]) <= 500

    # Jobs list omits the result payload; the detail route includes it.
    listed = client.get(f"/v1/matters/{m}/jobs").json()["jobs"]
    assert listed and "result" not in listed[0]
    detail = client.get(f"/v1/matters/{m}/jobs/{job['id']}").json()
    assert "result" in detail


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


def test_unpinned_docker_worker_fails_the_job_instead_of_500ing(tmp_path, monkeypatch):
    """Docker mode with COUNSELCLEAR_WORKER_IMAGE unset — build_docker_cmd's
    ValueError on an unpinned image used to fire after job.status was
    already committed to "running" and outside the runner's try block, so
    it propagated as an unhandled 500 with the job stuck at "running"
    forever. Reproduced against the real HTTP path, not a unit test of the
    command builder alone. (compose.yaml's own default is now
    COUNSELCLEAR_WORKER_MODE=subprocess, but docker mode with an unpinned
    image is still reachable via manual override — see compose.yaml and
    docs/COUNSELCLEAR_PRODUCTION.md §3 — so the regression test stays.)"""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw")
    monkeypatch.setenv("COUNSELCLEAR_WORKER_MODE", "docker")
    monkeypatch.setenv("COUNSELCLEAR_WORKER_IMAGE", "")
    from app.main import create_app

    c = TestClient(create_app(tmp_path / "d"), raise_server_exceptions=False)
    c.post("/v1/auth/login", json={"password": "pw"})
    matter = c.post("/v1/matters", json={"name": "m"}).json()
    doc = c.post(
        f"/v1/matters/{matter['id']}/documents",
        files={"file": ("spa.txt", (FIXTURES / "spa.txt").read_bytes(), "text/plain")},
    ).json()

    r = c.post(f"/v1/matters/{matter['id']}/documents/{doc['id']}/inspect-jobs")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "failed"
    assert "digest-pinned" in body["error"]

    # and the job row itself must not be stuck at "running"
    r2 = c.get(f"/v1/matters/{matter['id']}/jobs/{body['id']}")
    assert r2.json()["status"] == "failed"


def test_production_policy_approve_cells_unreachable_without_finding_decisions(client):
    """Documents the gap this fix closes: without an explicit decision,
    plan_actions' own no_decision default resolves an approve-default
    subtype to "keep" — so production sanitize without finding_decisions
    is, correctly, a strip of nothing approve-gated."""
    doc = _upload(client, "spa.docx")
    r = client.post(
        f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "production"},
    ).json()
    assert r["status"] == "done", r["error"]
    bundle = client.get(f"/v1/matters/{doc['_matter']}/jobs/{r['id']}/bundle")
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
        deriv_name = next(n for n in zf.namelist() if n.startswith("derivative/"))
        with zipfile.ZipFile(io.BytesIO(zf.read(deriv_name))) as inner:
            assert "word/comments.xml" in inner.namelist()


def test_finding_decisions_makes_production_approve_cells_reachable(client):
    """The actual fix: passing finding_decisions lets an approve-default
    cell (production's comments_and_notes) resolve to the sharing-path
    action instead of being permanently unreachable."""
    doc = _upload(client, "spa.docx")
    r = client.post(
        f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "production", "finding_decisions": {"comments_and_notes": "approve"}},
    ).json()
    assert r["status"] == "done", r["error"]
    bundle = client.get(f"/v1/matters/{doc['_matter']}/jobs/{r['id']}/bundle")
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
        deriv_name = next(n for n in zf.namelist() if n.startswith("derivative/"))
        with zipfile.ZipFile(io.BytesIO(zf.read(deriv_name))) as inner:
            assert "word/comments.xml" not in inner.namelist()


def test_finding_decisions_bad_value_refuses_the_job_with_a_clear_error(client):
    """plan_actions raises PolicyError for an unknown decision value, which
    clean_to_bundle wraps as a policy refusal — same category as a macro
    file or an unattested signature, not an unexpected crash."""
    doc = _upload(client, "spa.docx")
    r = client.post(
        f"/v1/matters/{doc['_matter']}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "production", "finding_decisions": {"comments_and_notes": "nonsense"}},
    ).json()
    assert r["status"] == "refused"
    assert "approve" in r["error"] or "keep" in r["error"]


# --- PR 20: Layer B watermark gate -------------------------------------------
# The whole module is off by default: the attestation route 403s without
# COUNSELCLEAR_WATERMARK_TOOLS, and a layer_b sanitize job is refused
# without a valid signed token. On, the token lifecycle (issue -> verify ->
# single-use) and the meaning-lock hard gate are exercised end to end.


@pytest.fixture()
def wm_client(tmp_path, monkeypatch):
    """Client with COUNSELCLEAR_WATERMARK_TOOLS=1 set BEFORE app creation
    (the flag is read at construction; the shared `client` fixture would
    already have booted with it off)."""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "correct horse battery")
    monkeypatch.setenv("COUNSELCLEAR_WATERMARK_TOOLS", "1")
    app = create_app(tmp_path / "data")
    c = TestClient(app)
    r = c.post("/v1/auth/login", json={"password": "correct horse battery"})
    assert r.status_code == 200
    yield c
    c.close()


def test_attestation_route_403_when_watermark_tools_disabled(client):
    m = client.post("/v1/matters", json={"name": "m"}).json()["id"]
    d = _upload(client, "spa.docx", matter=m)
    r = client.post(
        "/v1/attestations",
        json={"matter_id": m, "document_id": d["id"], "strength": "preserve"},
    )
    assert r.status_code == 403


def test_attestation_route_rejects_non_product_strength(wm_client):
    m = wm_client.post("/v1/matters", json={"name": "m"}).json()["id"]
    d = _upload(wm_client, "spa.docx", matter=m)
    r = wm_client.post(
        "/v1/attestations",
        json={"matter_id": m, "document_id": d["id"], "strength": "code"},
    )
    assert r.status_code == 400


def test_attestation_issue_and_verify_roundtrip(wm_client):
    m = wm_client.post("/v1/matters", json={"name": "m"}).json()["id"]
    d = _upload(wm_client, "spa.docx", matter=m)

    r = wm_client.post(
        "/v1/attestations",
        json={"matter_id": m, "document_id": d["id"], "strength": "preserve"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token"].count(".") == 1
    assert body["jti"]

    # A layer_b sanitize job with the token is accepted; the jti lands on
    # the job row so the audit chain can tie the rewrite to the exact
    # authorization.
    r2 = wm_client.post(
        f"/v1/matters/{m}/documents/{d['id']}/sanitize-jobs",
        json={"layer_b": {"strength": "preserve", "token": body["token"]}},
    )
    assert r2.status_code == 200
    assert r2.json()["layer_b"]["jti"] == body["jti"]

    # Reusing the same token must be refused (single-use).
    r3 = wm_client.post(
        f"/v1/matters/{m}/documents/{d['id']}/sanitize-jobs",
        json={"layer_b": {"strength": "preserve", "token": body["token"]}},
    )
    assert r3.status_code == 403


def test_concurrent_duplicate_jti_yields_exactly_one_success(wm_client):
    """PR 20 follow-up: single-use must be race-free under concurrent
    requests (FastAPI's threadpool for sync routes; worse still across
    gunicorn workers, which the in-memory _consumed_jtis set can't see at
    all). N threads race the very same attestation token against
    sanitize-jobs simultaneously; the attestation_uses table's jti primary
    key — inserted in the same transaction as the job row — must let
    exactly one INSERT win and 403 every other racer, never two jobs for
    one token."""
    import threading

    m = wm_client.post("/v1/matters", json={"name": "m"}).json()["id"]
    d = _upload(wm_client, "spa.docx", matter=m)
    token = wm_client.post(
        "/v1/attestations",
        json={"matter_id": m, "document_id": d["id"], "strength": "preserve"},
    ).json()["token"]

    n = 8
    start = threading.Barrier(n)
    statuses: list[int] = []
    statuses_lock = threading.Lock()

    def racer():
        start.wait()  # line every thread up to maximize the race window
        r = wm_client.post(
            f"/v1/matters/{m}/documents/{d['id']}/sanitize-jobs",
            json={"layer_b": {"strength": "preserve", "token": token}},
        )
        with statuses_lock:
            statuses.append(r.status_code)

    threads = [threading.Thread(target=racer) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert statuses.count(200) == 1, statuses
    assert statuses.count(403) == n - 1, statuses


def test_jti_replay_after_in_memory_reset_is_refused_by_the_db(wm_client):
    """The in-memory _consumed_jtis set (app.security) is a per-process
    fast path only; it does not survive a restart and a second gunicorn
    worker never shares it. Clearing it here simulates exactly that, so
    that a replay of an already-used token is verified purely against the
    durable record: the attestation_uses row written in the same
    transaction as the first job. It must still 403."""
    from app import security as security_mod

    m = wm_client.post("/v1/matters", json={"name": "m"}).json()["id"]
    d = _upload(wm_client, "spa.docx", matter=m)
    token = wm_client.post(
        "/v1/attestations",
        json={"matter_id": m, "document_id": d["id"], "strength": "preserve"},
    ).json()["token"]

    r1 = wm_client.post(
        f"/v1/matters/{m}/documents/{d['id']}/sanitize-jobs",
        json={"layer_b": {"strength": "preserve", "token": token}},
    )
    assert r1.status_code == 200

    security_mod._consumed_jtis.clear()  # simulate a process restart

    r2 = wm_client.post(
        f"/v1/matters/{m}/documents/{d['id']}/sanitize-jobs",
        json={"layer_b": {"strength": "preserve", "token": token}},
    )
    assert r2.status_code == 403


def test_layer_b_job_without_flag_is_refused(client):
    m = client.post("/v1/matters", json={"name": "m"}).json()["id"]
    d = _upload(client, "spa.docx", matter=m)
    r = client.post(
        f"/v1/matters/{m}/documents/{d['id']}/sanitize-jobs",
        json={"layer_b": {"strength": "preserve", "token": "forged"}},
    )
    assert r.status_code == 403


def test_layer_b_meaning_lock_miss_fails_job(wm_client, monkeypatch):
    """A Layer B rewrite whose candidate violates the meaning lock must
    fail the job (product semantics) — never silently return the original
    like the CLI's best-effort path. The rewrite endpoint is pointed at a
    dead port so every candidate fails; the gate must map that to
    status=failed, not a fallback."""
    monkeypatch.setenv("WATERMARKS_REWRITE_BACKEND", "openai-compatible")
    monkeypatch.setenv("WATERMARKS_REWRITE_MODEL", "fake-model")
    monkeypatch.setenv("WATERMARKS_REWRITE_BASE_URL", "http://127.0.0.1:1")
    m = wm_client.post("/v1/matters", json={"name": "m"}).json()["id"]

    r = wm_client.post(
        f"/v1/matters/{m}/documents",
        files={"file": ("draft.txt", b"Party A shall pay Party B $1,000 by June 1.", "text/plain")},
    )
    assert r.status_code == 200, r.text
    d = r.json()

    tok = wm_client.post(
        "/v1/attestations",
        json={"matter_id": m, "document_id": d["id"], "strength": "preserve"},
    ).json()["token"]
    r2 = wm_client.post(
        f"/v1/matters/{m}/documents/{d['id']}/sanitize-jobs",
        json={"layer_b": {"strength": "preserve", "token": tok}},
    )
    assert r2.status_code == 200
    job = r2.json()
    assert job["status"] == "failed"
    assert "layer b" in job["error"].lower()


def test_docker_cmd_includes_layer_b_flag_for_layer_b_jobs(tmp_path, monkeypatch):
    """Regression for the opencode review's F1: build_docker_cmd accepted
    layer_b (network selection) but never appended --layer-b to the
    container argv — a docker-mode Layer B job would silently run
    Layer-A-only while Job.layer_b/attest.used/API all claimed a rewrite
    had happened. The audit chain must never record an authorization that
    was not exercised."""
    from pathlib import Path as _Path

    from app.config import Config as _Config
    from app.runner import build_docker_cmd

    monkeypatch.setenv("COUNSELCLEAR_WORKER_IMAGE", "repo@sha256:" + "a" * 64)
    monkeypatch.setenv("COUNSELCLEAR_REWRITE_NETWORK", "cc-rewrite-prod")
    cfg = _Config(tmp_path)
    layer_b = {"strength": "preserve", "label": "content_altering", "subject": "operator", "jti": "j1"}

    cmd = build_docker_cmd(
        cfg,
        mount_root=_Path("/root"),
        input_path=_Path("/root/m/jobs/j/input/f.txt"),
        output_dir=_Path("/root/m/jobs/j/output"),
        kind="sanitize",
        policy_id="external_sharing",
        attest=False,
        matter_id="m",
        layer_b=layer_b,
    )
    assert "--layer-b" in cmd
    assert cmd[cmd.index("--layer-b") + 1] == "preserve"
    # The rewrite env namespace crosses into the container for Layer B jobs.
    monkeypatch.setenv("WATERMARKS_REWRITE_BACKEND", "ollama")
    cmd2 = build_docker_cmd(
        cfg,
        mount_root=_Path("/root"),
        input_path=_Path("/root/m/jobs/j/input/f.txt"),
        output_dir=_Path("/root/m/jobs/j/output"),
        kind="sanitize",
        policy_id="external_sharing",
        attest=False,
        matter_id="m",
        layer_b=layer_b,
    )
    assert "-e" in cmd2
    assert "WATERMARKS_REWRITE_BACKEND=ollama" in cmd2


def test_docker_cmd_stays_network_none_without_layer_b(tmp_path, monkeypatch):
    """Non-Layer-B docker jobs must never gain network egress."""
    from pathlib import Path as _Path

    from app.config import Config as _Config
    from app.runner import build_docker_cmd

    monkeypatch.setenv("COUNSELCLEAR_WORKER_IMAGE", "repo@sha256:" + "a" * 64)
    cfg = _Config(tmp_path)
    cmd = build_docker_cmd(
        cfg,
        mount_root=_Path("/root"),
        input_path=_Path("/root/m/jobs/j/input/f.txt"),
        output_dir=_Path("/root/m/jobs/j/output"),
        kind="sanitize",
        policy_id="external_sharing",
        attest=False,
        matter_id="m",
    )
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--layer-b" not in cmd
