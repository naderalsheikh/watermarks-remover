"""POST /v1/matters/{id}/batches — async counterpart to bulk-jobs (PR 31).

Covers exactly the guarantees the approved async-bulk proposal required:
create returns immediately with queued/running state, polling shows
partial mixed results, the concurrency cap is enforced, audit events
carry batch_id plus batch.created/batch.completed, ACL is checked before
any child is created, and the 100-document cap still holds. Restart-sweep
behavior for batch children is covered separately in
tests/test_prod_hardening.py (it needs direct DB setup, not a live app).
"""

from __future__ import annotations

import sys
import threading
import time
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
from app.models import AuditEvent, MatterAcl
from app.runner import RunnerResult
from app.security import issue_session

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"
PW = "pw12345"


def _build_env(tmp_path, monkeypatch, **extra_env):
    """Like the `env` fixture below, but lets a caller set env vars (e.g.
    COUNSELCLEAR_BATCH_MAX_CONCURRENT) *before* create_app reads them --
    the `env` fixture's app is already built by the time a test body runs,
    which is too late for anything Config() only reads at construction.
    """
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    for k, v in extra_env.items():
        monkeypatch.setenv(k, v)
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    sf = make_session_factory(engine)
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    return c, sf, cfg


@pytest.fixture()
def env(tmp_path, monkeypatch):
    c, sf, cfg = _build_env(tmp_path, monkeypatch)
    yield c, sf, cfg
    c.close()


def _matter(c) -> str:
    return c.post("/v1/matters", json={"name": "Batch Matter"}).json()["id"]


def _upload(c, mid: str, name: str) -> str:
    data = (FIXTURES / name).read_bytes()
    r = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": (name, data, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _create_batch(c, mid, doc_ids, kind, policy_id="external_sharing", reason=""):
    return c.post(
        f"/v1/matters/{mid}/batches",
        json={"document_ids": doc_ids, "kind": kind, "policy_id": policy_id, "reason": reason},
    )


def _wait_batch_done(c, mid, bid, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = c.get(f"/v1/matters/{mid}/batches/{bid}").json()
        if body["finished_utc"] is not None:
            return body
        time.sleep(0.05)
    raise AssertionError(f"batch {bid} did not finish within {timeout}s")


def _audit_actions(c, mid) -> list[dict]:
    return c.get(f"/v1/matters/{mid}/audit").json()["events"]


# --- controllable fake worker: lets tests observe in-flight state --------------


class _ControlledWorker:
    """Replaces app.dispatcher.run_job so tests can hold a job "running"
    until they choose to release it, and count how many are running
    concurrently -- real subprocess timing can't give deterministic
    control over either.
    """

    def __init__(self):
        self.started = []  # job_ids, in claim order
        self.max_concurrent_seen = 0
        self._current = 0
        self._lock = threading.Lock()
        self._release: dict[str, threading.Event] = {}

    def release(self, job_id: str) -> None:
        self._release.setdefault(job_id, threading.Event()).set()

    def release_all_started(self) -> None:
        """Release every job claimed so far, by job id (worker.started is
        job ids, not document ids -- callers that only know document ids
        can't target `release` directly)."""
        with self._lock:
            job_ids = list(self.started)
        for jid in job_ids:
            self.release(jid)

    def __call__(self, cfg, s, job_id, kind="inspect", storage=None):
        ev = self._release.setdefault(job_id, threading.Event())
        with self._lock:
            self._current += 1
            self.max_concurrent_seen = max(self.max_concurrent_seen, self._current)
            self.started.append(job_id)
        try:
            ev.wait(5)
        finally:
            with self._lock:
                self._current -= 1
        return RunnerResult(rc=0, stderr_tail="", timed_out=False, output_dir=Path("/nonexistent-output"))


# --- create returns immediately -------------------------------------------------


def test_batch_create_returns_immediately_with_queued_or_running_state(env, monkeypatch):
    c, _, _ = env
    worker = _ControlledWorker()
    monkeypatch.setattr("app.dispatcher.run_job", worker)
    mid = _matter(c)
    d1 = _upload(c, mid, "spa.docx")
    d2 = _upload(c, mid, "spa.txt")

    start = time.monotonic()
    r = _create_batch(c, mid, [d1, d2], "inspect")
    elapsed = time.monotonic() - start
    assert r.status_code == 200, r.text
    body = r.json()

    # The response never blocks on job execution -- both fake workers are
    # still parked on their un-set Events at this point, so nothing could
    # have finished yet if the route were actually synchronous.
    assert elapsed < 2.0
    assert body["finished_utc"] is None
    assert {res["status"] for res in body["results"]} <= {"queued", "running"}
    assert body["total"] == 2

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        worker.release_all_started()  # let the dispatcher's threads exit cleanly
        if c.get(f"/v1/matters/{mid}/batches/{body['id']}").json()["finished_utc"] is not None:
            break
        time.sleep(0.02)
    else:
        raise AssertionError("batch never finished after releasing workers")


# --- polling shows partial mixed results ----------------------------------------


def test_polling_shows_partial_mixed_results(tmp_path, monkeypatch):
    c, _, _ = _build_env(tmp_path, monkeypatch, COUNSELCLEAR_BATCH_MAX_CONCURRENT="2")
    worker = _ControlledWorker()
    monkeypatch.setattr("app.dispatcher.run_job", worker)
    mid = _matter(c)
    docs = [_upload(c, mid, "spa.docx"), _upload(c, mid, "spa.txt"), _upload(c, mid, "spa.docx")]

    r = _create_batch(c, mid, docs, "inspect")
    assert r.status_code == 200, r.text
    bid = r.json()["id"]

    deadline = time.monotonic() + 5
    while len(worker.started) < 2 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert len(worker.started) >= 1, "dispatcher never claimed any child"

    # Release exactly one -- the batch must now show a real mix: at least
    # one terminal result and at least one still queued/running, not an
    # all-or-nothing snapshot.
    worker.release(worker.started[0])
    deadline = time.monotonic() + 5
    mixed_seen = False
    while time.monotonic() < deadline:
        body = c.get(f"/v1/matters/{mid}/batches/{bid}").json()
        statuses = {res["status"] for res in body["results"]}
        if statuses & {"failed"} and statuses & {"queued", "running"}:
            mixed_seen = True
            break
        time.sleep(0.02)
    assert mixed_seen, "never observed a mixed in-flight/terminal snapshot while polling"

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        worker.release_all_started()
        if c.get(f"/v1/matters/{mid}/batches/{bid}").json()["finished_utc"] is not None:
            break
        time.sleep(0.02)
    else:
        raise AssertionError("batch never finished after releasing workers")


# --- concurrency cap is enforced -------------------------------------------------


def test_concurrency_cap_is_enforced(tmp_path, monkeypatch):
    c, _, _ = _build_env(tmp_path, monkeypatch, COUNSELCLEAR_BATCH_MAX_CONCURRENT="2")
    worker = _ControlledWorker()
    monkeypatch.setattr("app.dispatcher.run_job", worker)
    mid = _matter(c)
    docs = [_upload(c, mid, "spa.docx") for _ in range(5)]
    # Same doc row can be reused across the batch requests below because
    # each _upload call above creates its own Document row from the same
    # bytes -- distinct document_ids, which is all the batch endpoint cares
    # about.

    r = _create_batch(c, mid, docs, "inspect")
    assert r.status_code == 200, r.text
    bid = r.json()["id"]

    # Let the dispatcher run for a bit with nothing released -- every
    # child that CAN start, does, and the cap must stop it there.
    deadline = time.monotonic() + 3
    while len(worker.started) < 5 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert worker.max_concurrent_seen <= 2, worker.max_concurrent_seen
    assert len(worker.started) < 5, "cap did not hold back the remaining children"

    deadline = time.monotonic() + 10
    finished = None
    while time.monotonic() < deadline:
        worker.release_all_started()
        body = c.get(f"/v1/matters/{mid}/batches/{bid}").json()
        if body["finished_utc"] is not None:
            finished = body
            break
        time.sleep(0.02)
    assert finished is not None, f"batch {bid} did not finish within 10s"


# --- audit events carry batch_id, plus batch.created/batch.completed ------------


def test_audit_events_include_batch_id_and_batch_summary_events(env):
    c, _, _ = env
    mid = _matter(c)
    good = _upload(c, mid, "spa.docx")
    macro = _upload(c, mid, "macro.docm")

    r = _create_batch(c, mid, [good, macro], "inspect")
    assert r.status_code == 200, r.text
    bid = r.json()["id"]
    final = _wait_batch_done(c, mid, bid)
    assert final["summary"]["done"] == 2  # inspect never refuses on macro content

    events = _audit_actions(c, mid)
    created = [e for e in events if e["action"] == "batch.created"]
    completed = [e for e in events if e["action"] == "batch.completed"]
    children = [e for e in events if e["action"] == "job.inspect"]

    assert len(created) == 1
    assert created[0]["payload"]["batch_id"] == bid
    assert created[0]["payload"]["total"] == 2

    assert len(children) == 2
    assert all(e["payload"]["batch_id"] == bid for e in children)
    assert {e["payload"]["document_id"] for e in children} == {good, macro}

    assert len(completed) == 1
    assert completed[0]["payload"]["batch_id"] == bid
    assert completed[0]["payload"]["total"] == 2
    assert completed[0]["payload"]["done"] == 2


# --- ACL validation happens before creating children -----------------------------


def test_acl_validation_happens_before_creating_children(env):
    c, sf, cfg = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")
    alice = "oidc:alice"
    with sf() as s:
        s.add(MatterAcl(matter_id=mid, user_id=alice, perm="read"))
        s.commit()

    c.cookies.set("cc_session", issue_session(cfg, alice))
    r = _create_batch(c, mid, [d], "sanitize")
    assert r.status_code == 403
    assert "sanitize" in r.json()["detail"]
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0
    with sf() as s:
        assert s.query(AuditEvent).filter(AuditEvent.action == "batch.created").count() == 0


# --- 100-document cap still enforced ---------------------------------------------


def test_100_doc_cap_still_enforced_on_batches(env):
    c, sf, _ = env
    mid = _matter(c)
    too_many = [f"x{i}" for i in range(101)]
    r = _create_batch(c, mid, too_many, "inspect")
    assert r.status_code == 400
    assert "100" in r.json()["detail"]
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0
    with sf() as s:
        from app.models import Batch

        assert s.query(Batch).count() == 0


# --- request validation: nothing starts on a bad request ------------------------


def test_batch_rejects_unknown_documents_before_creating_anything(env):
    c, sf, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    r = _create_batch(c, mid, [d, "nope123"], "inspect")
    assert r.status_code == 400
    assert "not documents of this matter" in r.json()["detail"]
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0
    with sf() as s:
        from app.models import Batch

        assert s.query(Batch).count() == 0


# --- cancel: queued-only ---------------------------------------------------------


def test_cancel_batch_only_touches_still_queued_children(tmp_path, monkeypatch):
    c, _, _ = _build_env(tmp_path, monkeypatch, COUNSELCLEAR_BATCH_MAX_CONCURRENT="1")
    worker = _ControlledWorker()
    monkeypatch.setattr("app.dispatcher.run_job", worker)
    mid = _matter(c)
    docs = [_upload(c, mid, "spa.docx"), _upload(c, mid, "spa.txt")]

    r = _create_batch(c, mid, docs, "inspect")
    bid = r.json()["id"]
    deadline = time.monotonic() + 5
    while not worker.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert worker.started, "dispatcher never claimed the first child"

    cancel = c.post(f"/v1/matters/{mid}/batches/{bid}/cancel")
    assert cancel.status_code == 200, cancel.text
    body = cancel.json()
    # worker.started holds job ids, not document ids -- key results by
    # job_id to tell the one the (single-slot) dispatcher already claimed
    # apart from the one still sitting queued.
    by_job = {res["job_id"]: res for res in body["results"]}
    running_job = worker.started[0]
    other = next(res for res in body["results"] if res["job_id"] != running_job)
    assert by_job[running_job]["status"] == "running"  # untouched -- v1 doesn't kill it
    assert other["status"] == "failed"
    assert "cancelled" in other["error"]

    worker.release(running_job)
    _wait_batch_done(c, mid, bid)
