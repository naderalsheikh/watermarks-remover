"""/v1/dashboard — server-backed totals and trust-critical attention queues.

The endpoint's contract (service/app/main.py dashboard): every number is a
server-computed total over the *full* ACL-visible corpus — never a
loaded-so-far page — so the frontend may present it as global truth. These
tests seed rows directly (fast, deterministic) and exercise one real
production-sanitize flow end to end so the marker detection is proven
against the actual worker output, not against a hand-written manifest.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.acl import OPERATOR
from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import NO_DECISION_MARKER, create_app
from app.migrate import upgrade_head
from app.models import OWNER_PERMS, AuditEvent, Document, Job, Matter, MatterAcl
from app.security import issue_session

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"
PW = "pw12345"


def _ts(days_ago: int, hours: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago, hours=hours)).isoformat(
        timespec="seconds"
    )


def _seed_matter(s, mid: str, name: str, *, created_days_ago: int = 0, docs=(), user=OPERATOR):
    s.add(Matter(id=mid, name=name, created_utc=_ts(created_days_ago)))
    s.flush()
    for perm in OWNER_PERMS:
        s.add(MatterAcl(matter_id=mid, user_id=user, perm=perm))
    for did, filename in docs:
        s.add(
            Document(
                id=did,
                matter_id=mid,
                filename=filename,
                sha256="0" * 64,
                bytes=0,
                storage_path="",
            )
        )
    s.flush()


def _seed_job(
    s,
    job_id: str,
    mid: str,
    did: str,
    *,
    kind="sanitize",
    status="done",
    error="",
    manifest_actions=None,
    created_days_ago=0,
):
    s.add(
        Job(
            id=job_id,
            matter_id=mid,
            document_id=did,
            kind=kind,
            policy_id="production" if kind == "sanitize" else "default",
            status=status,
            error=error,
            result_json=(
                {"manifest": {"actions": manifest_actions}}
                if manifest_actions is not None
                else None
            ),
            created_utc=_ts(created_days_ago),
            finished_utc=_ts(created_days_ago),
        )
    )
    s.flush()


def _seed_audit(s, event_id: str, mid: str, seq: int, action: str, at: str, payload=None):
    s.add(
        AuditEvent(
            id=event_id,
            matter_id=mid,
            seq=seq,
            actor_id="operator",
            action=action,
            payload={} if payload is None else payload,
            prev_hash="0" * 64,
            row_hash="0" * 64,
            at=at,
        )
    )
    s.flush()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """App + login for the operator, plus a session factory to seed rows
    directly and the Config (session-cookie secret is file-derived, so
    issue_session(cfg, ...) mints tokens this app instance accepts)."""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    sf = make_session_factory(engine)
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    yield c, sf, cfg
    c.close()


# --- totals + attention queues ------------------------------------------------


def test_dashboard_totals_and_attention_queues(env):
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Merger", docs=[("d1", "spa.docx"), ("d2", "nda.pdf")])
        _seed_matter(s, "m2", "Litigation", docs=[("d3", "brief.docx")])
        _seed_matter(s, "m3", "Stale Estate", created_days_ago=10)
        # m1: one sanitize job whose manifest kept findings without an
        # operator decision (the trust-critical queue), one clean sanitize,
        # one refused, one failed.
        _seed_job(
            s,
            "j1",
            "m1",
            "d1",
            status="done",
            manifest_actions=[
                f"comments_and_notes: kept: {NO_DECISION_MARKER} for this "
                "approve-default finding (per-finding review is not yet "
                "available in this build)",
                "external_links: stripped",
            ],
        )
        _seed_job(
            s,
            "j2",
            "m1",
            "d1",
            status="done",
            manifest_actions=["comments_and_notes: stripped", "external_links: stripped"],
        )
        _seed_job(s, "j3", "m1", "d2", kind="inspect", status="refused", error="macro present")
        _seed_job(s, "j4", "m1", "d2", status="failed", error="worker crashed")
        # m2: one benign done job.
        _seed_job(s, "j5", "m2", "d3", kind="inspect", status="done")
        s.commit()

    r = c.get("/v1/dashboard")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totals"] == {
        "matters": 3,
        "documents": 3,
        "jobs": {"queued": 0, "running": 0, "done": 3, "failed": 1, "refused": 1},
    }

    # Attention order is severity order: unreviewed findings first, then
    # refused, failed, stale.
    types = [a["type"] for a in body["attention"]]
    assert types == ["unreviewed_findings", "refused", "failed", "stale"]

    unreviewed = body["attention"][0]
    assert unreviewed["matter_id"] == "m1"
    assert unreviewed["matter_name"] == "Merger"
    assert unreviewed["document_id"] == "d1"
    assert unreviewed["document_name"] == "spa.docx"
    assert unreviewed["job_id"] == "j1"
    assert unreviewed["detail"] == "1 finding(s) kept without operator review"

    # The clean sanitize job (j2) must NOT be flagged — only j1 carries
    # the no-decision marker. (Stale items have no job_id, hence .get.)
    assert all(a.get("job_id") != "j2" for a in body["attention"])

    refused = body["attention"][1]
    assert refused["job_id"] == "j3" and refused["detail"] == "macro present"

    failed = body["attention"][2]
    assert failed["job_id"] == "j4" and failed["detail"] == "worker crashed"

    stale = body["attention"][3]
    assert stale["matter_id"] == "m3"
    assert stale["detail"].startswith("no audit or job activity since")


def test_dashboard_stale_matter_is_not_stale_with_recent_activity(env):
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Active", created_days_ago=10, docs=[("d1", "a.docx")])
        _seed_job(s, "j1", "m1", "d1", kind="inspect", status="done", created_days_ago=1)
        s.commit()

    body = c.get("/v1/dashboard").json()
    assert all(a["type"] != "stale" for a in body["attention"])


def test_dashboard_unknown_job_status_is_ignored(env):
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "M", docs=[("d1", "a.docx")])
        _seed_job(s, "j1", "m1", "d1", kind="inspect", status="weird")
        s.commit()

    body = c.get("/v1/dashboard").json()
    assert body["totals"]["jobs"] == {
        "queued": 0,
        "running": 0,
        "done": 0,
        "failed": 0,
        "refused": 0,
    }


def test_dashboard_empty_corpus(env):
    c, _, _ = env
    body = c.get("/v1/dashboard").json()
    assert body["totals"] == {
        "matters": 0,
        "documents": 0,
        "jobs": {"queued": 0, "running": 0, "done": 0, "failed": 0, "refused": 0},
    }
    assert body["attention"] == []
    assert body["recent"] == []


# --- ACL scoping --------------------------------------------------------------


def test_dashboard_scopes_everything_to_readable_matters(env):
    """A principal with read on one matter must see exactly that corpus's
    totals -- no cross-matter leakage -- but audit-derived detail (stale,
    recent) requires admin on that specific matter, not just read (operator
    decision, 2026-08-25): read alone must not surface "stale" (it's
    derived from AuditEvent timestamps, the same audit content GET
    .../audit gates behind admin) or the recent-activity feed."""
    c, sf, cfg = env
    alice = "oidc:alice"
    with sf() as s:
        _seed_matter(s, "m1", "Alice's", created_days_ago=10, docs=[("d1", "a.docx")])
        _seed_matter(s, "m2", "Operator's", docs=[("d2", "b.docx")])
        _seed_job(s, "j1", "m2", "d2", status="failed", error="boom")
        # Alice gets read on m1 only (created 10 days ago, no activity) --
        # deliberately not admin.
        s.add(MatterAcl(matter_id="m1", user_id=alice, perm="read"))
        s.commit()

    c.cookies.set("cc_session", issue_session(cfg, alice))
    body = c.get("/v1/dashboard").json()
    assert body["totals"]["matters"] == 1
    assert body["totals"]["documents"] == 1
    assert body["totals"]["jobs"]["failed"] == 0  # m2's failure invisible
    assert body["attention"] == []  # "stale" hidden: read only, not admin
    assert body["recent"] == []  # audit-event feed hidden: no admin matters
    assert body["admin_matters"] == 0

    # Grant alice admin on the same matter too -- the stale item and m1's
    # audit activity now surface. (Seeded directly, like the ACL grant
    # above, so a real AuditEvent row -- normally written by the PUT
    # .../acl route's append_event() call -- is added by hand here too.
    # Backdated to match m1's own "10 days ago, no activity" staleness --
    # a *recent* event would un-stale the matter and defeat the point.)
    with sf() as s:
        s.add(MatterAcl(matter_id="m1", user_id=alice, perm="admin"))
        _seed_audit(s, "ev-m1", "m1", 0, "matter.create", _ts(10))
        s.commit()
    body = c.get("/v1/dashboard").json()
    assert [a["type"] for a in body["attention"]] == ["stale"]
    assert body["attention"][0]["matter_id"] == "m1"
    assert body["admin_matters"] == 1
    assert len(body["recent"]) >= 1
    assert all(e["matter_id"] == "m1" for e in body["recent"])

    # The operator still sees the full corpus (admin on both matters).
    c.cookies.set("cc_session", issue_session(cfg, OPERATOR))
    body = c.get("/v1/dashboard").json()
    assert body["totals"]["matters"] == 2
    assert [a["type"] for a in body["attention"]] == ["failed", "stale"]
    assert body["admin_matters"] == 2


def test_dashboard_shows_refused_failed_and_unreviewed_detail_to_read_only_principal(env):
    """Unlike "stale", refused/failed/unreviewed_findings detail is already
    visible through read-gated per-job routes (job.error via GET .../jobs/
    {id}, the manifest's actions list via GET .../jobs/{id}/manifest) -- so
    a read-only, non-admin principal must still see the FULL item, not a
    count with detail withheld. Not admin-gated, unlike "stale"."""
    c, sf, cfg = env
    alice = "oidc:alice"
    with sf() as s:
        _seed_matter(s, "m1", "Read Only Matter", docs=[("d1", "a.docx"), ("d2", "b.docx")])
        _seed_job(s, "j-failed", "m1", "d1", status="failed", error="boom")
        _seed_job(
            s,
            "j-unreviewed",
            "m1",
            "d2",
            status="done",
            manifest_actions=[f"comments_and_notes: kept: {NO_DECISION_MARKER}"],
        )
        s.add(MatterAcl(matter_id="m1", user_id=alice, perm="read"))
        s.commit()

    c.cookies.set("cc_session", issue_session(cfg, alice))
    body = c.get("/v1/dashboard").json()
    assert body["admin_matters"] == 0  # confirms this isn't "she's secretly admin"
    types = {a["type"] for a in body["attention"]}
    assert types == {"failed", "unreviewed_findings"}
    failed_item = next(a for a in body["attention"] if a["type"] == "failed")
    assert failed_item["detail"] == "boom"


# --- recent activity ----------------------------------------------------------


def test_dashboard_recent_activity_ordered_across_matters(env):
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Merger")
        _seed_matter(s, "m2", "Litigation")
        _seed_audit(s, "e1", "m2", 0, "matter.create", _ts(3))
        _seed_audit(s, "e2", "m1", 0, "matter.create", _ts(2))
        _seed_audit(s, "e3", "m1", 1, "document.upload", _ts(1))
        s.commit()

    recent = c.get("/v1/dashboard").json()["recent"]
    assert [(r["action"], r["matter_name"]) for r in recent] == [
        ("document.upload", "Merger"),
        ("matter.create", "Merger"),
        ("matter.create", "Litigation"),
    ]


def test_dashboard_recent_activity_from_api_events(env):
    """The API's own audit events (matter.create, document.upload,
    job.sanitize) must show up with matter names attached."""
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "Project Dandelion"}).json()["id"]
    with open(FIXTURES / "spa.docx", "rb") as f:
        doc = c.post(
            f"/v1/matters/{mid}/documents", files={"file": ("spa.docx", f, "application/octet-stream")}
        ).json()
    r = c.post(
        f"/v1/matters/{mid}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "production", "finding_decisions": {"comments_and_notes": "approve"}},
    )
    assert r.status_code == 200, r.text

    recent = c.get("/v1/dashboard").json()["recent"]
    actions = [e["action"] for e in recent]
    # job.sanitize is strictly newest (the worker subprocess spans at least
    # a second); matter.create and document.upload can share a timestamp
    # second, so only their presence — not their relative order — is
    # guaranteed.
    assert actions[0] == "job.sanitize"
    assert set(actions[1:3]) == {"document.upload", "matter.create"}
    assert all(e["matter_name"] == "Project Dandelion" for e in recent[:3])


def test_dashboard_recent_rows_carry_payload_ids_for_deep_links(env):
    """recent[] must echo whichever of job_id/document_id each event's
    AuditEvent payload actually carries (dashboard deep-links, operator
    decision 2026-08-29), and nothing else: a job-bearing row links to
    that exact job, a document-only row to the document, a matter-level
    event stays a matter link. Payloads here mirror the append sites'
    real shapes (service/app/main.py): job.sanitize carries both ids,
    release.terminal/bundle.download job only, document.upload document
    only, matter.create neither.
    """
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Merger")
        # newest first
        _seed_audit(
            s, "e1", "m1", 5, "bundle.download", _ts(0),
            payload={"job_id": "j9", "include_original": True},
        )
        _seed_audit(
            s, "e2", "m1", 4, "release.terminal", _ts(1),
            payload={"release_id": "r1", "job_id": "j8", "status": "done"},
        )
        _seed_audit(
            s, "e3", "m1", 3, "job.sanitize", _ts(2),
            payload={"job_id": "j7", "document_id": "d3", "policy_id": "production"},
        )
        _seed_audit(
            s, "e4", "m1", 2, "document.upload", _ts(3),
            payload={"document_id": "d3", "sha256": "ab" * 32, "bytes": 12},
        )
        _seed_audit(s, "e5", "m1", 1, "matter.create", _ts(4), payload={"name": "Merger"})
        # malformed/foreign-typed values must degrade to a matter link,
        # never surface as e.g. a job_id: null href
        _seed_audit(s, "e6", "m1", 0, "job.sanitize", _ts(5), payload={"job_id": 7, "document_id": ""})
        s.commit()

    recent = c.get("/v1/dashboard").json()["recent"]
    # Two job.sanitize rows exist (one well-formed, one malformed), so
    # keying by action alone would collapse them; (action, at) is unique.
    by_key = {(r["action"], r["at"]): r for r in recent}
    bd = by_key[("bundle.download", _ts(0))]
    assert bd["job_id"] == "j9"
    assert "document_id" not in bd
    rt = by_key[("release.terminal", _ts(1))]
    assert rt["job_id"] == "j8"
    assert "document_id" not in rt
    js = by_key[("job.sanitize", _ts(2))]
    assert js["job_id"] == "j7"
    assert js["document_id"] == "d3"
    du = by_key[("document.upload", _ts(3))]
    assert du["document_id"] == "d3"
    assert "job_id" not in du
    # matter-level: neither id — the frontend falls back to a matter link
    mc = by_key[("matter.create", _ts(4))]
    assert "job_id" not in mc
    assert "document_id" not in mc
    # non-string / empty values are dropped, not echoed
    malformed = by_key[("job.sanitize", _ts(5))]
    assert "job_id" not in malformed
    assert "document_id" not in malformed


# --- end-to-end: real worker output feeds the queue ---------------------------


def test_dashboard_unreviewed_findings_from_real_production_run(env):
    """A real production sanitize WITHOUT finding_decisions keeps comments
    (no-decision default) — the worker's manifest must land in the
    dashboard attention queue exactly as the audit event counts it."""
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "End to End"}).json()["id"]
    with open(FIXTURES / "spa.docx", "rb") as f:
        doc = c.post(
            f"/v1/matters/{mid}/documents", files={"file": ("spa.docx", f, "application/octet-stream")}
        ).json()
    r = c.post(
        f"/v1/matters/{mid}/documents/{doc['id']}/sanitize-jobs",
        json={"policy_id": "production"},
    ).json()
    assert r["status"] == "done", r.get("error")

    # Sanity: the job really did keep something without a decision.
    manifest = c.get(f"/v1/matters/{mid}/jobs/{r['id']}/manifest").json()
    assert any(NO_DECISION_MARKER in a for a in manifest["actions"])

    body = c.get("/v1/dashboard").json()
    assert body["totals"]["jobs"]["done"] == 1
    unreviewed = [a for a in body["attention"] if a["type"] == "unreviewed_findings"]
    assert len(unreviewed) == 1
    assert unreviewed[0]["job_id"] == r["id"]
    assert unreviewed[0]["matter_id"] == mid
    assert unreviewed[0]["document_name"] == "spa.docx"
    assert "kept without operator review" in unreviewed[0]["detail"]
