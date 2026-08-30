"""GET /v1/jobs — the cross-matter terminal-problem job list.

The dashboard's "Failed / refused jobs" card's destination (2026-08-29
operator decision). The load-bearing contract these tests pin:

- the list spans every readable matter — a cross-matter query bug
  (a missing IN filter, a join that collapses rows) can only be caught
  by fixtures with failed/refused jobs in MORE than one matter;
- the disclosure argument: rows and their error detail stay at read
  scope (already visible through the read-gated per-job detail route),
  and a read-only principal sees their readable matters' rows while a
  stranger sees none;
- the row shape is AttentionItem-shaped so the frontend reuses the
  dashboard's link machinery — release_id/profile_id present when a
  Release wraps the job, the error string carried as `detail`.
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

from app.acl import OPERATOR
from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import create_app
from app.migrate import upgrade_head
from app.models import OWNER_PERMS, Document, Job, Matter, MatterAcl, Release
from app.security import issue_session

PW = "pw12345"


def _ts(days_ago: int) -> str:
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat(timespec="seconds")


def _seed_matter(s, mid: str, name: str, *, user: str = OPERATOR):
    s.add(Matter(id=mid, name=name, created_utc=_ts(0)))
    s.flush()
    for perm in OWNER_PERMS:
        s.add(MatterAcl(matter_id=mid, user_id=user, perm=perm))
    s.flush()


def _seed_doc(s, did: str, mid: str, filename: str):
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
    kind: str = "sanitize",
    status: str = "refused",
    error: str = "",
    created_days_ago: int = 0,
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
            created_utc=_ts(created_days_ago),
            finished_utc=_ts(created_days_ago),
        )
    )
    s.flush()


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


def _get_jobs(c: TestClient, status: str = "refused,failed"):
    r = c.get(f"/v1/jobs?status={status}")
    assert r.status_code == 200, r.text
    return r.json()


# --- cross-matter coverage: the query must span matters ----------------------


def test_failed_refused_jobs_across_multiple_matters(env):
    """THE cross-matter regression: two matters each carrying a refused
    and/or failed job must all appear in one list. A query that
    accidentally scopes to a single matter (a missing IN filter, a
    wrong join) passes any single-matter fixture; this one fails."""
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Merger")
        _seed_matter(s, "m2", "Litigation")
        _seed_doc(s, "d1", "m1", "spa.docx")
        _seed_doc(s, "d2", "m1", "nda.pdf")
        _seed_doc(s, "d3", "m2", "brief.docx")
        _seed_doc(s, "d4", "m2", "exhibit.docx")
        _seed_job(s, "j1", "m1", "d1", status="refused", error="macro present", created_days_ago=3)
        _seed_job(s, "j2", "m1", "d2", status="failed", error="worker crash", created_days_ago=2)
        _seed_job(s, "j3", "m2", "d3", status="refused", error="signed without attestation", created_days_ago=1)
        _seed_job(s, "j4", "m2", "d4", status="done")
        _seed_job(s, "j5", "m2", "d4", kind="inspect", status="done")
        s.commit()  # session-exit is rollback-without-commit; helpers only flush

    body = _get_jobs(c)
    assert body["total"] == 3, body
    by_job = {j["job_id"]: j for j in body["jobs"]}
    # Both matters represented, never just the first.
    assert set(by_job) == {"j1", "j2", "j3"}
    assert {j["matter_id"] for j in by_job.values()} == {"m1", "m2"}
    # AttentionItem shape: the error is the detail, the document name
    # rides along, kind carries for the badge, and type mirrors status.
    assert by_job["j1"]["detail"] == "macro present"
    assert by_job["j1"]["document_name"] == "spa.docx"
    assert by_job["j1"]["matter_name"] == "Merger"
    assert by_job["j1"]["type"] == "refused"
    assert by_job["j3"]["kind"] == "sanitize"
    # Newest first (created_utc desc): j3 (1 day ago) before j2 (2) before j1 (3).
    assert [j["job_id"] for j in body["jobs"]] == ["j3", "j2", "j1"]
    # done jobs never appear in the refused,failed filter.
    assert "j4" not in by_job and "j5" not in by_job


def test_release_wrapped_rows_carry_release_and_profile_ids(env):
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Merger")
        _seed_doc(s, "d1", "m1", "spa.docx")
        _seed_job(s, "j1", "m1", "d1", status="refused", error="macro present")
        s.add(
            Release(
                matter_id="m1",
                document_id="d1",
                job_id="j1",
                policy_id="production",
                profile_id="ediscovery_production",
                recipient_type="opposing_counsel",
                recipient_name="",
                purpose="",
                intended_external=True,
                requested_by=OPERATOR,
                status="refused",
            )
        )
        s.commit()

    body = _get_jobs(c)
    assert body["total"] == 1
    row = body["jobs"][0]
    assert row["release_id"] is not None
    assert row["profile_id"] == "ediscovery_production"


# --- filtering and validation ------------------------------------------------


def test_status_filter_selects_and_rejects(env):
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Merger")
        _seed_doc(s, "d1", "m1", "spa.docx")
        _seed_job(s, "j1", "m1", "d1", status="refused", error="macro")
        _seed_job(s, "j2", "m1", "d1", status="failed", error="crash")
        s.commit()  # session-exit is rollback-without-commit

    only_refused = _get_jobs(c, "refused")
    assert [j["job_id"] for j in only_refused["jobs"]] == ["j1"]
    only_failed = _get_jobs(c, "failed")
    assert [j["job_id"] for j in only_failed["jobs"]] == ["j2"]

    r = c.get("/v1/jobs?status=refused,banana")
    assert r.status_code == 400
    assert "banana" in r.json()["detail"]
    r = c.get("/v1/jobs?status=,,,")
    assert r.status_code == 400


# --- scoping -----------------------------------------------------------------


def test_scoped_to_readable_matters_and_excludes_demo(env):
    c, sf, _ = env
    with sf() as s:
        _seed_matter(s, "m1", "Real Merger")
        s.add(Matter(id="m2", name="Demo Matter", created_utc=_ts(0), is_demo=True))
        s.flush()
        for perm in OWNER_PERMS:
            s.add(MatterAcl(matter_id="m2", user_id=OPERATOR, perm=perm))
        _seed_doc(s, "d1", "m1", "spa.docx")
        _seed_doc(s, "d2", "m2", "sample.docx")
        _seed_job(s, "j1", "m1", "d1", status="refused", error="macro")
        _seed_job(s, "j2", "m2", "d2", status="refused", error="macro")
        s.commit()

    body = _get_jobs(c)
    assert [j["job_id"] for j in body["jobs"]] == ["j1"]
    assert body["total"] == 1


def test_read_only_principal_sees_readable_matters_stranger_sees_none(env):
    """Same disclosure argument as the dashboard's refused/failed attention
    queues: the error detail is already visible through the read-gated
    per-job detail route, so this list is read-scoped, not admin."""
    c, sf, cfg = env
    with sf() as s:
        _seed_matter(s, "m1", "Merger", user="oidc:operator")
        _seed_doc(s, "d1", "m1", "spa.docx")
        _seed_job(s, "j1", "m1", "d1", status="refused", error="macro")
        s.add(MatterAcl(matter_id="m1", user_id="oidc:reader", perm="read"))
        s.commit()

    c.cookies.set("cc_session", issue_session(cfg, "oidc:reader"))
    body = _get_jobs(c)
    assert body["total"] == 1
    assert body["jobs"][0]["job_id"] == "j1"

    c.cookies.set("cc_session", issue_session(cfg, "oidc:stranger"))
    body = _get_jobs(c)
    assert body["total"] == 0
    assert body["jobs"] == []
