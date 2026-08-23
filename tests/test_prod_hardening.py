"""Production-hardening pass: orphan sweep, SQLite pragmas, login throttle,
logout/session revocation, deep health, request logging, bundle guard."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import create_app
from app.migrate import upgrade_head
from app.models import Document, Job, Matter
from app.security import LoginThrottle

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


def _seed_app(tmp_path):
    """Build the DB layer directly so tests can insert pre-crash rows."""
    monkey_pw = "pw12345"
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    return cfg, make_session_factory(engine), monkey_pw


def _seed_matter_doc(s, matter_id="m", doc_id="d"):
    # Flush between parent and child: the models declare no ORM
    # relationship(), so unit-of-work ordering can't infer it.
    s.add(Matter(id=matter_id, name="m"))
    s.flush()
    s.add(
        Document(
            id=doc_id,
            matter_id=matter_id,
            filename="f.txt",
            sha256="0" * 64,
            bytes=0,
            storage_path="",
        )
    )
    s.flush()
    from app.acl import OPERATOR
    from app.models import OWNER_PERMS, MatterAcl

    for perm in OWNER_PERMS:
        s.add(MatterAcl(matter_id=matter_id, user_id=OPERATOR, perm=perm))
    s.flush()


# --- orphan sweep ------------------------------------------------------------


def test_orphaned_jobs_are_failed_on_startup(tmp_path):
    cfg, sf, pw = _seed_app(tmp_path)
    with sf() as s:
        _seed_matter_doc(s)
        s.flush()
        s.add(Job(id="jrunning", matter_id="m", document_id="d", kind="inspect", status="running"))
        s.add(Job(id="jqueued", matter_id="m", document_id="d", kind="sanitize", status="queued"))
        s.add(Job(id="jdone", matter_id="m", document_id="d", kind="inspect", status="done"))
        s.commit()

    # A fresh boot of the same data root must reconcile the dead process's jobs.
    monkey = pytest.MonkeyPatch()
    monkey.setenv("COUNSELCLEAR_LOCAL_PASSWORD", pw)
    try:
        c = TestClient(create_app(cfg.data_root))
        assert c.get("/health").status_code == 200
    finally:
        monkey.undo()

    with sf() as s:
        assert s.get(Job, "jrunning").status == "failed"
        assert "restart" in s.get(Job, "jrunning").error
        assert s.get(Job, "jqueued").status == "failed"
        assert s.get(Job, "jdone").status == "done"


def test_clean_boot_sweeps_nothing(tmp_path):
    cfg, sf, pw = _seed_app(tmp_path)
    monkey = pytest.MonkeyPatch()
    monkey.setenv("COUNSELCLEAR_LOCAL_PASSWORD", pw)
    try:
        TestClient(create_app(cfg.data_root))
    finally:
        monkey.undo()
    with sf() as s:
        assert s.query(Job).filter(Job.status.in_(("queued", "running"))).count() == 0


# --- SQLite pragmas ----------------------------------------------------------


def test_sqlite_wal_busy_timeout_and_foreign_keys(tmp_path):
    cfg = Config(tmp_path / "d")
    engine = make_engine(cfg)
    conn = engine.raw_connection()
    driver = conn.driver_connection if hasattr(conn, "driver_connection") else conn.connection
    assert driver.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert driver.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    assert driver.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    conn.close()


def test_foreign_key_violation_is_rejected(tmp_path):
    _cfg, sf, _pw = _seed_app(tmp_path)
    with sf() as s:
        s.add(Job(matter_id="no-such-matter", document_id="x", kind="inspect"))
        with pytest.raises(IntegrityError):
            s.commit()


# --- login throttle ----------------------------------------------------------


def test_login_throttle_blocks_after_max_failures(tmp_path):
    monkey = pytest.MonkeyPatch()
    monkey.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "right-pw-1")
    t = LoginThrottle(max_failures=3, window_s=300, lockout_s=300)
    for i in range(3):
        assert t.allow("1.2.3.4"), f"attempt {i} should be allowed"
        t.record_failure("1.2.3.4")
    assert not t.allow("1.2.3.4")
    assert t.retry_after_s("1.2.3.4") >= 1
    # Other peers are unaffected.
    assert t.allow("5.6.7.8")
    monkey.undo()


def test_login_throttle_success_resets(tmp_path):
    t = LoginThrottle(max_failures=2, window_s=300, lockout_s=300)
    t.record_failure("h")
    t.record_failure("h")
    assert not t.allow("h")
    t.record_success("h")
    assert t.allow("h")


def test_login_endpoint_returns_429_then_recovers(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "right-pw-2")
    c = TestClient(create_app(tmp_path / "d"))
    for _ in range(5):  # default max failures
        r = c.post("/v1/auth/login", json={"password": "wrong"})
        assert r.status_code == 403
    locked = c.post("/v1/auth/login", json={"password": "right-pw-2"})
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) >= 1
    wrong_during_lockout = c.post("/v1/auth/login", json={"password": "also-wrong"})
    assert wrong_during_lockout.status_code == 429


# --- logout / session revocation --------------------------------------------


def test_logout_clears_cookie(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    c = TestClient(create_app(tmp_path / "d"))
    c.post("/v1/auth/login", json={"password": "pw12345"})
    assert c.post("/v1/matters", json={"name": "m"}).status_code == 200
    r = c.post("/v1/auth/logout")
    assert r.status_code == 200
    # The cleared Set-Cookie expires the client's copy, so the next request
    # is unauthenticated.
    assert c.post("/v1/matters", json={"name": "m2"}).status_code == 401


def test_revoke_sessions_invalidates_outstanding_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    c = TestClient(create_app(tmp_path / "d"))
    c.post("/v1/auth/login", json={"password": "pw12345"})
    assert c.post("/v1/matters", json={"name": "before"}).status_code == 200

    r = c.post("/v1/auth/revoke-sessions")
    assert r.status_code == 200
    # Even the revoking client's own cookie is now invalid.
    assert c.post("/v1/matters", json={"name": "after"}).status_code == 401
    # Re-login works against the rotated secret.
    c.post("/v1/auth/login", json={"password": "pw12345"})
    assert c.post("/v1/matters", json={"name": "post"}).status_code == 200


def test_logout_and_revoke_require_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    c = TestClient(create_app(tmp_path / "d"))
    assert c.post("/v1/auth/logout").status_code == 401
    assert c.post("/v1/auth/revoke-sessions").status_code == 401


# --- deep health + request logging -------------------------------------------


def test_request_id_header_and_json_access_log(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    with caplog.at_level(logging.INFO, logger="counselclear"):
        c = TestClient(create_app(tmp_path / "d"))
        r = c.get("/health")
    assert r.status_code == 200
    rid = r.headers["X-Request-ID"]
    records = [
        rec.getMessage() for rec in caplog.records if '"event":"http_request"' in rec.getMessage()
    ]
    assert records, "expected at least one JSON access-log line"
    line = json.loads(records[-1])
    assert line["request_id"] == rid
    assert line["method"] == "GET" and line["path"] == "/health" and line["status"] == 200
    assert "duration_ms" in line and "client" in line


def test_access_log_can_be_silenced(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    monkeypatch.setenv("COUNSELCLEAR_ACCESS_LOG", "0")
    with caplog.at_level(logging.INFO, logger="counselclear"):
        c = TestClient(create_app(tmp_path / "d"))
        c.get("/health")
    assert not [rec for rec in caplog.records if '"event":"http_request"' in rec.getMessage()]


# --- incomplete-bundle guard --------------------------------------------------


def test_incomplete_bundle_returns_409_not_500(tmp_path):
    cfg, sf, pw = _seed_app(tmp_path)
    with sf() as s:
        _seed_matter_doc(s)
        s.flush()
        s.add(
            Job(
                id="jincomplete",
                matter_id="m",
                document_id="d",
                kind="sanitize",
                status="done",
                result_json={"manifest": {}},
                bundle_dir=str(tmp_path / "empty-bundle"),
            )
        )
        s.commit()
    (tmp_path / "empty-bundle").mkdir()

    monkey = pytest.MonkeyPatch()
    monkey.setenv("COUNSELCLEAR_LOCAL_PASSWORD", pw)
    try:
        c = TestClient(create_app(cfg.data_root))
        c.post("/v1/auth/login", json={"password": pw})
        r = c.get("/v1/matters/m/jobs/jincomplete/bundle")
        assert r.status_code == 409
    finally:
        monkey.undo()


# --- clamscan db-dir flag -----------------------------------------------------


def test_clamscan_cmd_includes_runtime_db_dir(monkeypatch):
    from app.malware import _clamscan_cmd

    target = str(Path.cwd() / "scan-target.bin")
    monkeypatch.delenv("COUNSELCLEAR_CLAMAV_DB_DIR", raising=False)
    base = _clamscan_cmd("clamscan", target)
    assert "--database" not in " ".join(base)

    missing = Path("/nonexistent-clamav-defs-xyz")
    monkeypatch.setenv("COUNSELCLEAR_CLAMAV_DB_DIR", str(missing))
    assert "--database" not in " ".join(_clamscan_cmd("clamscan", target))

    real = Path(FIXTURES)  # any existing dir
    monkeypatch.setenv("COUNSELCLEAR_CLAMAV_DB_DIR", str(real))
    cmd = _clamscan_cmd("clamscan", target)
    assert f"--database={real}" in cmd
    assert cmd[-1] == target
