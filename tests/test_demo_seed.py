"""POST /v1/matters/demo-seed (PR 45): the evaluation-flow walkthrough seed.

Creates a real, Release-native demo matter -- three fixtures, released
through the exact same _upload_document_bytes/create_release path a human
clicking through the UI uses -- so a first-time evaluator has something to
look at without inferring the product model or hunting for their own test
file. Covers: the three real outcomes (done/refused/done-with-a-kept-
finding), idempotency, the local-password-only gate, is_demo surfacing on
the matter payload, and dashboard exclusion of demo matters from
cross-matter aggregation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import create_app
from app.migrate import upgrade_head
from app.models import Matter, Release
from app.oidc import principal_for
from app.security import issue_session

PW = "pw12345"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    sf = make_session_factory(engine)
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    yield c, sf, cfg
    c.close()


@pytest.fixture()
def oidc_env(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("COUNSELCLEAR_OIDC_CLIENT_ID", "counselclear")
    monkeypatch.setenv("COUNSELCLEAR_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("COUNSELCLEAR_OIDC_ALLOWED", "alice@example.com")
    monkeypatch.delenv("COUNSELCLEAR_LOCAL_PASSWORD", raising=False)
    cfg = Config(tmp_path / "data")
    make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    c = TestClient(create_app(cfg.data_root))
    # No live IdP here (same approach test_oidc.py's own fixtures use): mint
    # a real session token directly via issue_session rather than driving
    # the full authorize/callback exchange, so this test can reach the
    # demo-seed route's own gate as an authenticated OIDC principal instead
    # of failing earlier at the unauthenticated-401 layer.
    tok = issue_session(cfg, principal_for("sub-alice"))
    c.cookies.set("cc_session", tok)
    yield c
    c.close()


def test_auth_config_reports_demo_seed_enabled_in_local_password_mode(env):
    c, _sf, _cfg = env
    body = c.get("/v1/auth/config").json()
    assert body == {"oidc_enabled": False, "demo_seed_enabled": True}


def test_auth_config_reports_demo_seed_disabled_under_oidc(oidc_env):
    c = oidc_env
    body = c.get("/v1/auth/config").json()
    assert body["oidc_enabled"] is True
    assert body["demo_seed_enabled"] is False


def test_demo_seed_refused_under_oidc(oidc_env):
    c = oidc_env
    r = c.post("/v1/matters/demo-seed")
    assert r.status_code == 403


def test_demo_seed_creates_matter_with_three_documents_and_releases(env):
    c, sf, _cfg = env
    r = c.post("/v1/matters/demo-seed")
    assert r.status_code == 200, r.text
    matter = r.json()
    assert matter["is_demo"] is True
    assert "id" in matter

    matter_id = matter["id"]
    docs = c.get(f"/v1/matters/{matter_id}/documents").json()["documents"]
    assert len(docs) == 3
    filenames = {d["filename"] for d in docs}
    assert filenames == {
        "Sample - Stock Purchase Agreement.docx",
        "Sample - Macro-Enabled Draft.docm",
        "Sample - Deal Terms Workbook.xlsx",
    }

    jobs = c.get(f"/v1/matters/{matter_id}/jobs").json()["jobs"]
    assert len(jobs) == 3
    by_filename = {next(d["filename"] for d in docs if d["id"] == j["document_id"]): j for j in jobs}

    # spa.docx: a done release with both a strip (the comment) and a
    # flag-only kept finding (hidden/vanish text) -- the "What was found"
    # vs "Actions taken" distinction the job page now explains.
    spa = by_filename["Sample - Stock Purchase Agreement.docx"]
    assert spa["status"] == "done"
    assert spa["release_id"] is not None
    spa_full = c.get(f"/v1/matters/{matter_id}/jobs/{spa['id']}").json()
    spa_findings = spa_full["result"]["manifest"]["findings_before"]
    spa_actions = spa_full["result"]["manifest"]["actions"]
    assert any("hidden-text" in f.lower() or "vanish" in f.lower() for f in spa_findings)
    assert any("comment" in f.lower() for f in spa_findings)
    assert any("comment" in a.lower() for a in spa_actions)  # comment: stripped
    assert not any("hidden" in a.lower() or "vanish" in a.lower() for a in spa_actions)  # hidden text: flagged, kept

    # macro.docm: a deterministic refusal, no attestation ambiguity.
    macro = by_filename["Sample - Macro-Enabled Draft.docm"]
    assert macro["status"] == "refused"
    assert "macro" in macro["error"].lower()
    assert macro["release_id"] is not None

    # hidden.xlsx: a done release with a visible kept/limited finding (the
    # hidden sheet survives, flag-only under this policy).
    hidden = by_filename["Sample - Deal Terms Workbook.xlsx"]
    assert hidden["status"] == "done"
    assert hidden["release_id"] is not None
    full = c.get(f"/v1/matters/{matter_id}/jobs/{hidden['id']}").json()
    findings_before = full["result"]["manifest"]["findings_before"]
    actions = full["result"]["manifest"]["actions"]
    assert any("hidden" in f.lower() for f in findings_before)
    assert not any("hidden" in a.lower() for a in actions)  # flagged, never stripped

    with sf() as s:
        row = s.get(Matter, matter_id)
        assert row is not None
        assert row.is_demo is True
        releases = s.query(Release).filter_by(matter_id=matter_id).all()
        assert len(releases) == 3


def test_demo_seed_is_idempotent(env):
    c, sf, _cfg = env
    first = c.post("/v1/matters/demo-seed").json()
    second = c.post("/v1/matters/demo-seed").json()
    assert first["id"] == second["id"]

    with sf() as s:
        matters = s.query(Matter).filter_by(is_demo=True).all()
        assert len(matters) == 1
        releases = s.query(Release).filter_by(matter_id=first["id"]).all()
        assert len(releases) == 3  # not duplicated by the second call


def test_release_result_download_has_correct_filename_for_the_verifier(env):
    """The verifier's own auto-detection (tools/counselclear_verify_
    release_packet.py's main()) requires the literal filename
    release_result.json -- without a Content-Disposition header a browser
    infers a name from the URL path instead, and the documented "download
    it and verify it offline" flow silently doesn't work."""
    c, _sf, _cfg = env
    matter = c.post("/v1/matters/demo-seed").json()
    jobs = c.get(f"/v1/matters/{matter['id']}/jobs").json()["jobs"]
    refused = next(j for j in jobs if j["status"] == "refused")
    r = c.get(f"/v1/matters/{matter['id']}/releases/{refused['release_id']}/result")
    assert r.status_code == 200
    assert r.headers["content-disposition"] == 'attachment; filename="release_result.json"'


def test_dashboard_excludes_demo_matter_from_aggregation(env):
    c, _sf, _cfg = env
    # A real matter with a real document, so dashboard totals are
    # observably non-zero -- then confirm the demo matter never adds to
    # either total instead of asserting only "totals are zero" (which a
    # bug that just skipped the count query would also satisfy).
    real = c.post("/v1/matters", json={"name": "Real Matter"}).json()
    fixtures = Path(__file__).resolve().parent / "fixtures" / "legal"
    data = (fixtures / "spa.docx").read_bytes()
    c.post(
        f"/v1/matters/{real['id']}/documents",
        files={"file": ("spa.docx", data, "application/octet-stream")},
    )
    before = c.get("/v1/dashboard").json()

    demo = c.post("/v1/matters/demo-seed").json()
    assert demo["id"] != real["id"]

    after = c.get("/v1/dashboard").json()
    assert after["totals"]["matters"] == before["totals"]["matters"]
    assert after["totals"]["documents"] == before["totals"]["documents"]
    assert after["totals"]["jobs"] == before["totals"]["jobs"]
    assert all(item["matter_id"] != demo["id"] for item in after["attention"])

    # The demo matter is still fully visible everywhere else -- list_matters,
    # matter detail -- dashboard exclusion is the one deliberate exception.
    listed_ids = {m["id"] for m in c.get("/v1/matters").json()["matters"]}
    assert demo["id"] in listed_ids
    assert c.get(f"/v1/matters/{demo['id']}").status_code == 200
