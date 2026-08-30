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
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, update

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import create_app
from app.migrate import upgrade_head
from app.models import AuditEvent, Job, MatterAcl
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
    c.app.state.batch_dispatcher.stop()
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


def _wait_batch_done(c, mid, bid, timeout=60.0):
    deadline = time.monotonic() + timeout
    last_body = None
    delay = 0.05
    while time.monotonic() < deadline:
        body = c.get(f"/v1/matters/{mid}/batches/{bid}").json()
        last_body = body
        if body["finished_utc"] is not None:
            return body
        time.sleep(delay)
        delay = min(delay * 1.5, 0.5)
    raise AssertionError(f"batch {bid} did not finish within {timeout}s; last={last_body!r}")


def _close_client(c) -> None:
    c.app.state.batch_dispatcher.stop()
    c.close()


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
    try:
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
    finally:
        _close_client(c)


# --- concurrency cap is enforced -------------------------------------------------


def test_concurrency_cap_is_enforced(tmp_path, monkeypatch):
    c, _, _ = _build_env(tmp_path, monkeypatch, COUNSELCLEAR_BATCH_MAX_CONCURRENT="2")
    try:
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
    finally:
        _close_client(c)


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
    try:
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
    finally:
        _close_client(c)


def test_cancel_batch_concurrent_claim_does_not_flip_running_job(tmp_path, monkeypatch):
    """Regression: cancel_batch used to collect the still-queued child ids
    with a SELECT, then bulk-UPDATE by id alone -- no status guard. If the
    dispatcher claimed a child (queued -> running) in between, the UPDATE
    force-flipped it to failed anyway: a running job that hadn't failed
    was recorded as failed, the batch.cancelled audit event said 2 when
    only 1 was actually cancelled, and sync_release then wrote that
    stale "failed" into the claimed job's sibling Release.

    The SELECT-then-UPDATE interleaving can't be won deterministically
    against a live poll loop, so the race is simulated exactly: the poll
    loop is disabled (start() -> no-op, nothing is ever claimed), and a
    SQLAlchemy `before_execute` listener flips one child to "running"
    the moment cancel_batch issues its bulk UPDATE -- that is, after the
    pre-SELECT, before the UPDATE runs: the same window a real dispatcher
    claim would land in.
    """
    monkeypatch.setattr("app.dispatcher.BatchDispatcher.start", lambda self: None)
    c, sf, _ = _build_env(tmp_path, monkeypatch)
    try:
        mid = _matter(c)
        docs = [_upload(c, mid, "spa.docx"), _upload(c, mid, "spa.txt")]

        r = _create_batch(c, mid, docs, "inspect")
        assert r.status_code == 200, r.text
        bid = r.json()["id"]
        with sf() as s:
            ids = [row[0] for row in s.query(Job.id).filter(Job.batch_id == bid).order_by(Job.id).all()]
        claimed = ids[0]  # the one "the dispatcher claims" mid-race

        def _claim_mid_race(conn, clauseelement, multiparams, params, execution_options):
            # This listener sees every statement the app's engine runs;
            # only the bulk cancel UPDATE targets jobs AND writes the
            # route's literal error, so that pair alone identifies it.
            # The inner flip below re-enters the listener, hence the flag.
            if _claim_mid_race.armed is False:
                return
            stmt = clauseelement
            table = getattr(stmt, "table", None)
            if table is None or table.name != "jobs":
                return
            if "cancelled by operator" not in str(getattr(stmt, "_values", "")):
                return
            _claim_mid_race.armed = False
            # Simulate the dispatcher's claim landing between the
            # pre-SELECT and this UPDATE: the row reads "running" to the
            # UPDATE that's about to execute. Same connection, so the
            # flip is already visible -- exactly as a real claim's
            # committed queued->running would be.
            conn.execute(
                update(Job)
                .where(Job.id == claimed)
                .values(status="running", error="", finished_utc=None)
            )

        _claim_mid_race.armed = True

        # The listener must sit on the app's own engine -- create_app
        # builds its own (the sf the test holds is a different instance
        # against the same file); the app's engine is the one the
        # cancel request actually executes on.
        app_engine = c.app.state.batch_dispatcher._session_factory.kw["bind"]
        event.listen(app_engine, "before_execute", _claim_mid_race)
        try:
            cancel = c.post(f"/v1/matters/{mid}/batches/{bid}/cancel")
        finally:
            event.remove(app_engine, "before_execute", _claim_mid_race)
        assert _claim_mid_race.armed is False, "listener never saw the bulk cancel UPDATE"
        assert cancel.status_code == 200, cancel.text
        body = cancel.json()

        by_job = {res["job_id"]: res for res in body["results"]}
        # The claimed child is the dispatcher's now -- cancel must not
        # have flipped it to failed or stamped a cancel error on it.
        assert by_job[claimed]["status"] == "running"
        assert not (by_job[claimed]["error"] or "").strip(), by_job[claimed]["error"]
        others = [res for res in body["results"] if res["job_id"] != claimed]
        assert len(others) == 1
        assert others[0]["status"] == "failed"
        assert "cancelled" in others[0]["error"]

        # Truthful counts: one cancel actually happened, not two, and the
        # summary must not count the still-running child as failed.
        assert body["summary"]["failed"] == 1
        assert body["summary"]["running"] == 1
        assert body["finished_utc"] is None  # a live child means the batch isn't done

        events = _audit_actions(c, mid)
        cancelled_ev = [e for e in events if e["action"] == "batch.cancelled"]
        assert len(cancelled_ev) == 1
        assert cancelled_ev[0]["payload"]["cancelled"] == 1
        # No batch.completed -- the claimed child is still running, so
        # nothing has legitimately finished this batch yet.
        assert not [e for e in events if e["action"] == "batch.completed"]

        # The mid-race flip bypassed the dispatcher's own claim path, so
        # no worker will ever finish the running row. Finish it the way
        # the dispatcher would have (a plain terminal UPDATE -- it had
        # already claimed the row, cancel never owned it), then make the
        # same completion check the dispatcher's end-of-run path would
        # have (the poll loop is off here, so nothing else runs it).
        with sf() as s:
            s.execute(
                update(Job)
                .where(Job.id == claimed)
                .values(status="done", finished_utc=datetime.now(UTC).isoformat(timespec="seconds"))
            )
            s.commit()
        with c.app.state.batch_dispatcher._session_factory() as s:
            c.app.state.batch_dispatcher.check_batch_completion(s, bid)
        final = _wait_batch_done(c, mid, bid)
        # Counts that state what ACTUALLY happened: one cancel, one
        # normal finish -- not "two cancels".
        assert final["summary"] == {"requested": 2, "done": 1, "refused": 0, "failed": 1, "queued": 0, "running": 0}
        done_ev = [e for e in _audit_actions(c, mid) if e["action"] == "batch.completed"]
        assert len(done_ev) == 1
        assert done_ev[0]["payload"] == {"batch_id": bid, "total": 2, "done": 1, "refused": 0, "failed": 1}
    finally:
        _close_client(c)


def test_cancel_all_before_any_child_claimed_completes_the_batch(tmp_path, monkeypatch):
    """Regression: cancelling a batch used to only touch the child Job
    rows -- nothing ever re-checked the batch itself for completion
    unless the dispatcher had claimed and finished at least one child.
    A batch cancelled in its entirety before the dispatcher claims
    anything (every child still queued) used to be left with
    finished_utc=None forever and no batch.completed event, even though
    every child had reached a terminal state.

    The dispatcher's own poll thread is disabled here (monkeypatched
    start() -> no-op) so this is deterministic: no child is ever claimed,
    by construction, rather than by winning a race against a live poll
    loop.
    """
    monkeypatch.setattr("app.dispatcher.BatchDispatcher.start", lambda self: None)
    c, sf, _ = _build_env(tmp_path, monkeypatch)
    try:
        mid = _matter(c)
        docs = [_upload(c, mid, "spa.docx"), _upload(c, mid, "spa.txt")]

        r = _create_batch(c, mid, docs, "inspect")
        assert r.status_code == 200, r.text
        bid = r.json()["id"]
        assert r.json()["summary"]["queued"] == 2  # nothing claimed -- the poll loop never ran

        cancel = c.post(f"/v1/matters/{mid}/batches/{bid}/cancel")
        assert cancel.status_code == 200, cancel.text
        body = cancel.json()
        assert body["finished_utc"] is not None
        assert all(res["status"] == "failed" for res in body["results"])
        assert body["summary"]["failed"] == 2

        with sf() as s:
            from app.models import Batch

            assert s.get(Batch, bid).finished_utc is not None
        completed = [e for e in _audit_actions(c, mid) if e["action"] == "batch.completed"]
        assert len(completed) == 1
        assert completed[0]["payload"] == {"batch_id": bid, "total": 2, "done": 0, "refused": 0, "failed": 2}
    finally:
        _close_client(c)


# --- dispatcher exception hardening -----------------------------------------------


def test_unexpected_dispatcher_exception_fails_the_child_and_completes_the_batch(env, monkeypatch):
    """Regression: run_job/sync_job raising something neither anticipates
    (not a caught worker timeout/launch failure) used to leave the job
    stuck at "running" forever -- it had already been claimed -- and the
    batch polling forever alongside it, since nothing else would ever
    re-check it for completion.
    """

    def _boom(cfg, s, job_id, kind="inspect", storage=None):
        raise RuntimeError("simulated unexpected dispatcher failure")

    monkeypatch.setattr("app.dispatcher.run_job", _boom)
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    r = _create_batch(c, mid, [d], "inspect")
    assert r.status_code == 200, r.text
    bid = r.json()["id"]

    final = _wait_batch_done(c, mid, bid)  # must not hang -- this is the regression
    assert final["results"][0]["status"] == "failed"
    assert "internal dispatcher error" in final["results"][0]["error"]
    assert "RuntimeError" in final["results"][0]["error"]
    assert final["summary"] == {
        "requested": 1,
        "done": 0,
        "refused": 0,
        "failed": 1,
        "queued": 0,
        "running": 0,
    }
    completed = [e for e in _audit_actions(c, mid) if e["action"] == "batch.completed"]
    assert len(completed) == 1
    assert completed[0]["payload"]["failed"] == 1


def test_dispatcher_finalization_exception_does_not_wedge_batch(env, monkeypatch):
    """A child can reach a terminal status before audit/release finalization.
    If that finalizer raises, the batch must still complete; otherwise
    polling clients wait forever even though there is no running work left.
    """

    def _boom(self, s, job, batch):
        raise RuntimeError("simulated audit finalization failure")

    monkeypatch.setattr("app.dispatcher.BatchDispatcher._append_child_audit", _boom)
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.txt")

    r = _create_batch(c, mid, [d], "inspect")
    assert r.status_code == 200, r.text
    final = _wait_batch_done(c, mid, r.json()["id"])
    assert final["finished_utc"] is not None
    assert final["summary"]["done"] == 1
    completed = [e for e in _audit_actions(c, mid) if e["action"] == "batch.completed"]
    assert len(completed) == 1
    assert completed[0]["payload"]["done"] == 1


# --- ported from the retired tests/test_bulk_jobs.py (PR 31 commit 3) -----------
#
# The synchronous /bulk-jobs endpoint (PR 23) was retired once the frontend
# cut over to async batches (commit 2). Its own test file tested the route
# directly and is gone with it; these scenarios still matter for
# create_batch (same validation, same "never a vague blanket success"
# guarantee) and are ported here rather than lost.


def test_batch_sanitize_mixed_outcomes_are_per_document(env):
    """One document sanitizes clean; the other two hit refusal classes
    (macro-enabled file, signed PDF without attestation). The final batch
    must show each status where it happened -- never a blanket success."""
    c, _, _ = env
    mid = _matter(c)
    good = _upload(c, mid, "spa.docx")
    macro = _upload(c, mid, "macro.docm")
    signed = _upload(c, mid, "signed.pdf")

    r = _create_batch(c, mid, [good, macro, signed], "sanitize", policy_id="external_sharing")
    assert r.status_code == 200, r.text
    final = _wait_batch_done(c, mid, r.json()["id"])
    assert final["summary"] == {
        "requested": 3,
        "done": 1,
        "refused": 2,
        "failed": 0,
        "queued": 0,
        "running": 0,
    }
    by_doc = {res["document_id"]: res for res in final["results"]}
    assert by_doc[good]["status"] == "done" and by_doc[good]["error"] == ""
    assert by_doc[macro]["status"] == "refused"
    assert "macro" in by_doc[macro]["error"].lower()
    assert by_doc[signed]["status"] == "refused"
    assert "signature" in by_doc[signed]["error"].lower()

    events = [e for e in _audit_actions(c, mid) if e["action"] == "job.sanitize"]
    assert len(events) == 3
    statuses = {e["payload"]["document_id"]: e["payload"]["status"] for e in events}
    assert statuses == {good: "done", macro: "refused", signed: "refused"}


def test_batch_sanitize_privacy_only_leaves_no_no_decision_marker(env):
    """privacy_only is bulk-safe: it has no approve-default cells, so its
    keeps are policy-default keeps -- the manifest must contain no
    NO_DECISION_MARKER (which would mean findings kept without review)."""
    from app.main import NO_DECISION_MARKER

    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    r = _create_batch(c, mid, [d], "sanitize", policy_id="privacy_only")
    assert r.status_code == 200, r.text
    final = _wait_batch_done(c, mid, r.json()["id"])
    res = final["results"][0]
    assert res["status"] == "done"
    assert res["policy_id"] == "privacy_only"

    manifest = c.get(f"/v1/matters/{mid}/jobs/{res['job_id']}/manifest").json()
    assert all(NO_DECISION_MARKER not in a for a in manifest["actions"])


def test_batch_rejects_non_bulk_safe_policies(env):
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    for policy_id in ("production", "evidence_preservation"):
        r = _create_batch(c, mid, [d], "sanitize", policy_id=policy_id)
        assert r.status_code == 400, policy_id
        assert "per-finding decisions" in r.json()["detail"] or "no derivative" in r.json()["detail"]
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0
    assert all(
        e["action"] not in ("job.inspect", "job.sanitize") for e in _audit_actions(c, mid)
    )


def test_batch_rejects_empty_duplicates_and_unknown_kind(env):
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    assert _create_batch(c, mid, [], "inspect").status_code == 400
    assert _create_batch(c, mid, [d, d], "inspect").status_code == 400
    assert _create_batch(c, mid, [d], "frobnicate").status_code == 400
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0


def test_batch_inspect_and_sanitize_perms_are_independent(env):
    """A principal with only inspect can batch-inspect but not batch-
    sanitize, and vice versa -- the two kinds don't imply each other,
    matching the per-document routes' own separate perm checks."""
    c, sf, cfg = env
    mid = _matter(c)
    d1 = _upload(c, mid, "spa.docx")
    d2 = _upload(c, mid, "spa.txt")
    inspector, sanitizer = "oidc:inspector", "oidc:sanitizer"
    with sf() as s:
        s.add(MatterAcl(matter_id=mid, user_id=inspector, perm="read"))
        s.add(MatterAcl(matter_id=mid, user_id=inspector, perm="inspect"))
        s.add(MatterAcl(matter_id=mid, user_id=sanitizer, perm="read"))
        s.add(MatterAcl(matter_id=mid, user_id=sanitizer, perm="sanitize"))
        s.commit()

    c.cookies.set("cc_session", issue_session(cfg, inspector))
    assert _create_batch(c, mid, [d1], "inspect").status_code == 200
    r = _create_batch(c, mid, [d2], "sanitize")
    assert r.status_code == 403 and "sanitize" in r.json()["detail"]

    c.cookies.set("cc_session", issue_session(cfg, sanitizer))
    assert _create_batch(c, mid, [d2], "sanitize").status_code == 200
    r = _create_batch(c, mid, [d1], "inspect")
    assert r.status_code == 403 and "inspect" in r.json()["detail"]


def test_bulk_safe_flags_match_policy_engine():
    """main.py's POLICIES literal (bulk_safe) must stay in sync with the
    engine's actual subtype table, the same way NO_DECISION_MARKER does:
    a bulk_safe policy must have NO approve-default subtype cells (a
    sanitize without per-finding decisions would silently keep them), and
    only the two decision-free derivative-producing policies are bulk-safe.
    """
    import policies as policies_mod
    from app.main import POLICIES as main_policies

    declared = {p["id"]: p["bulk_safe"] for p in main_policies}
    assert set(declared) == set(policies_mod.DEFAULT_POLICIES)
    for pid, bulk_safe in declared.items():
        if bulk_safe:
            assert "approve" not in set(policies_mod.DEFAULT_POLICIES[pid].values()), pid
    assert declared["external_sharing"] is True
    assert declared["privacy_only"] is True
    assert declared["production"] is False
    assert declared["evidence_preservation"] is False
