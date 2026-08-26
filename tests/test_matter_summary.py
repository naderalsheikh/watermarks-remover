"""GET /v1/matters/{id}/summary — HTML reviewer-handoff report for one matter.

Totals, job-status counts, and attention items reuse the exact same
_attention_items() helper GET /v1/dashboard calls (see service/app/main.py),
so these tests focus on what's specific to the summary route: HTML escaping
of user-supplied content, the admin-perm gate, the "showing N of M" partial
audit-coverage disclosure, and the chain verification verdict rendering.
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
from app.main import NO_DECISION_MARKER, create_app
from app.migrate import upgrade_head
from app.models import Job
from app.security import issue_session

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"
PW = "pw-summary"


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


def _upload(c, mid, name, fixture="spa.txt"):
    data = (FIXTURES / fixture).read_bytes()
    r = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": (name, data, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_summary_requires_admin_perm(env):
    c, _, cfg = env
    mid = c.post("/v1/matters", json={"name": "m"}).json()["id"]
    alice = "oidc:alice"
    c.put(f"/v1/matters/{mid}/acl", json={"user_id": alice, "perm": "read"})

    c.cookies.set("cc_session", issue_session(cfg, alice))
    r = c.get(f"/v1/matters/{mid}/summary")
    assert r.status_code == 403


def test_summary_requires_admin_specifically_not_just_broad_perms(env):
    """read + upload + inspect + sanitize (everything but admin) must
    still 403 -- the summary report discloses audit-chain status and
    refusal/failure reasons, the same class of detail GET .../audit
    gates, so it isn't enough to be a heavily-permissioned reviewer."""
    c, _, cfg = env
    mid = c.post("/v1/matters", json={"name": "m"}).json()["id"]
    bob = "oidc:bob"
    for perm in ("read", "upload", "inspect", "sanitize"):
        c.put(f"/v1/matters/{mid}/acl", json={"user_id": bob, "perm": perm})

    c.cookies.set("cc_session", issue_session(cfg, bob))
    assert c.get(f"/v1/matters/{mid}/summary").status_code == 403


def test_summary_shows_totals_and_verified_chain(env):
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "Totals Matter"}).json()["id"]
    d1 = _upload(c, mid, "one.txt")
    d2 = _upload(c, mid, "two.txt")
    c.post(f"/v1/matters/{mid}/documents/{d1}/inspect-jobs")
    c.post(f"/v1/matters/{mid}/documents/{d2}/inspect-jobs")

    r = c.get(f"/v1/matters/{mid}/summary")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert "Totals Matter" in body
    assert "Documents: 2" in body
    assert "Verified intact" in body
    assert "No open attention items" in body
    # Uses this matter's own audit trail, not a blanket claim.
    assert f"/v1/matters/{mid}/audit/export" in body


def test_summary_lists_unreviewed_findings_and_refused(env):
    c, sf, _ = env
    mid = c.post("/v1/matters", json={"name": "Attention Matter"}).json()["id"]
    good = _upload(c, mid, "good.docm", fixture="spa.docx")
    macro = _upload(c, mid, "macro.docm", fixture="macro.docm")

    # Real refusal through the actual policy engine.
    refused = c.post(
        f"/v1/matters/{mid}/documents/{macro}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert refused["status"] == "refused"

    # A no-decision "kept without review" job is seeded directly -- there's
    # no way to force this outcome by hand through the live production
    # per-finding UI flow without a much larger fixture, and this is
    # exactly the same technique tests/test_dashboard.py uses for the
    # same signal (a manifest actions list containing NO_DECISION_MARKER).
    with sf() as s:
        s.add(
            Job(
                id="j-unreviewed",
                matter_id=mid,
                document_id=good,
                kind="sanitize",
                policy_id="production",
                status="done",
                result_json={
                    "manifest": {
                        "actions": [
                            f"comments_and_notes: kept: {NO_DECISION_MARKER}",
                        ]
                    }
                },
            )
        )
        s.commit()

    r = c.get(f"/v1/matters/{mid}/summary")
    body = r.text
    assert "Unreviewed findings (1)" in body
    assert "Refused jobs (1)" in body
    assert "good.docm" in body
    assert "macro.docm" in body
    assert "j-unreviewed" in body
    # PR 33: every attention item with a job_id links to that job's
    # custody certificate, so a reviewer can go straight from "why does
    # this need attention" to the disclosure document for it.
    assert f'href="/v1/matters/{mid}/jobs/j-unreviewed/certificate"' in body
    assert f'href="/v1/matters/{mid}/jobs/{refused["id"]}/certificate"' in body


def test_summary_recent_events_disclose_partial_coverage(env):
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "Busy Matter"}).json()["id"]
    for i in range(12):
        c.put(f"/v1/matters/{mid}/acl", json={"user_id": f"reviewer{i}", "perm": "read"})

    full_total = c.get(f"/v1/matters/{mid}/audit").json()["total"]
    assert full_total >= 13  # matter.create + 12 grants

    r = c.get(f"/v1/matters/{mid}/summary")
    body = r.text
    assert f"Showing the most recent 10 of {full_total} total event(s)." in body
    # 13 total events (matter.create + 12 grants); the most recent 10 by
    # seq excludes matter.create (seq 0) entirely, so exactly 10 acl.grant
    # rows should appear in the recent-activity table, not all 12.
    assert body.count("acl.grant") == 10


def test_summary_escapes_html_in_matter_name_and_error(env):
    c, _, _ = env
    evil_name = '<script>alert(1)</script> & "quotes"'
    mid = c.post("/v1/matters", json={"name": evil_name}).json()["id"]

    r = c.get(f"/v1/matters/{mid}/summary")
    body = r.text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_summary_403s_for_unknown_matter(env):
    """Matches the rest of the API's ordering: the permission check runs
    before the matter lookup (service/app/main.py _require then _matter),
    so an id with no ACL grant reads as "missing permission," the same as
    GET /v1/matters/nope already does."""
    c, _, _ = env
    assert c.get("/v1/matters/nope-not-real/summary").status_code == 403
