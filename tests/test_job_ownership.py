"""Independent processes must obey one queue capacity and one fenced owner."""

from __future__ import annotations

import json
import multiprocessing
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app.audit import verify_chain
from app.config import Config
from app.db import make_engine, make_session_factory
from app.dispatcher import BatchDispatcher
from app.job_lifecycle import finalize_job
from app.job_queue import (
    Heartbeat,
    LostLease,
    claim_job,
    configure_queue,
    database_now,
    record_execution,
    recover_expired,
    renew_lease,
)
from app.migrate import upgrade_head
from app.models import AuditEvent, Document, Job, Matter
from app.runner import RunnerResult, job_root


def _process_claim(root, job_id, gate, results):
    engine = make_engine(Config(root))
    try:
        with make_session_factory(engine)() as s:
            gate.wait(15)
            claim = claim_job(s, job_id, 30)
            results.put((job_id, claim.token if claim else None))
    except BaseException as exc:
        results.put(("error", repr(exc)))
    finally:
        engine.dispose()


@pytest.fixture
def database(tmp_path, monkeypatch, queue_backend):
    monkeypatch.setenv("COUNSELCLEAR_BATCH_MAX_CONCURRENT", "1")
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(cfg.db_url())
    sessions = make_session_factory(engine)
    with sessions() as s:
        s.add(Matter(id="m", name="Synthetic"))
        s.flush()
        s.add(
            Document(
                id="d",
                matter_id="m",
                filename="sample.txt",
                sha256="0" * 64,
                bytes=0,
                storage_path="synthetic",
            )
        )
        s.flush()
        for jid in ("j1", "j2"):
            s.add(Job(id=jid, matter_id="m", document_id="d", kind="inspect", requested_by="alice"))
        s.commit()
        configure_queue(s, 1)
    yield cfg, sessions
    engine.dispose()


@pytest.mark.parametrize("same_job", [True, False])
def test_independent_processes_share_claim_and_capacity(database, same_job):
    cfg, sessions = database
    context = multiprocessing.get_context("spawn")
    gate, results = context.Event(), context.Queue()
    processes = [
        context.Process(target=_process_claim, args=(str(cfg.data_root), jid, gate, results))
        for jid in ("j1", "j1" if same_job else "j2")
    ]
    for process in processes:
        process.start()
    try:
        gate.set()
        outcomes = [results.get(timeout=25) for _ in processes]
        assert all(jid != "error" for jid, _ in outcomes), outcomes
        assert sum(token is not None for _, token in outcomes) == 1
    finally:
        for process in processes:
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join(5)
            assert process.exitcode == 0
    with sessions() as s:
        assert s.query(Job).filter(Job.status == "running").count() == 1


def _expire(s, job_id):
    s.get(Job, job_id).lease_expires_epoch = database_now(s) - 1
    s.commit()


def test_live_lease_survives_startup_and_only_expired_owner_is_recovered(database, monkeypatch):
    from app.main import create_app

    cfg, sessions = database
    with sessions() as s:
        owner = claim_job(s, "j1", 30)
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "test-password")
    app = create_app(cfg.data_root)
    try:
        with sessions() as s:
            assert recover_expired(s, max_attempts=3) == 0
            assert s.get(Job, "j1").lease_token == owner.token
            assert s.get(Job, "j1").status == "running"
            assert s.get(Job, "j2").status == "queued"
            _expire(s, "j1")
            assert not renew_lease(s, owner, 30)
            assert recover_expired(s, max_attempts=3) == 1
            assert s.get(Job, "j1").status == "queued"
            assert s.get(Job, "j1").lease_token is None
    finally:
        app.state.batch_dispatcher.stop()


def test_expired_completion_cannot_overwrite_new_attempt(database):
    _, sessions = database
    with sessions() as s:
        old = claim_job(s, "j1", 30)
        _expire(s, "j1")
        recover_expired(s, max_attempts=3)
        current = claim_job(s, "j1", 30)
        assert current.attempt == old.attempt + 1
        assert current.token != old.token
        with pytest.raises(LostLease):
            finalize_job(
                s,
                "j1",
                RunnerResult(1, "stale error", False),
                actor_id="alice",
                no_decision_marker="none",
                claim=old,
            )
        assert s.get(Job, "j1").status == "running"
        s.rollback()
        finalize_job(
            s,
            "j1",
            RunnerResult(1, "current error", False),
            actor_id="alice",
            no_decision_marker="none",
            claim=current,
        )
        assert "current error" in s.get(Job, "j1").error
        rows = s.query(AuditEvent).order_by(AuditEvent.seq).all()
        assert [r.action for r in rows] == ["job.interrupted", "job.inspect"]
        assert verify_chain(rows)[0]


def test_persisted_exit_resumes_publication_without_rerunning_worker(database, monkeypatch):
    cfg, sessions = database
    with sessions() as s:
        old = claim_job(s, "j1", 30)
        output = job_root(cfg, "m", "j1") / "attempts" / f"{old.attempt}-{old.token}" / "output"
        output.mkdir(parents=True)
        (output / "result.json").write_text(
            json.dumps({"status": "done", "result": {"findings": []}})
        )
        record_execution(s, old, RunnerResult(0, "", False, output))
        _expire(s, "j1")
        recover_expired(s, max_attempts=3)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(1)
        raise AssertionError("worker must not rerun a persisted exit")

    monkeypatch.setattr("app.dispatcher.run_job", forbidden)
    dispatcher = BatchDispatcher(
        cfg=cfg, session_factory=sessions, storage=None, max_concurrent=1, no_decision_marker="none"
    )
    dispatcher._run_one_inner("j1")
    assert calls == []
    with sessions() as s:
        assert s.get(Job, "j1").status == "done"
        assert s.get(Job, "j1").attempt_number == 2
        rows = s.query(AuditEvent).all()
        assert sum(r.action == "job.inspect" for r in rows) == 1
        assert verify_chain(rows)[0]


def test_abandoned_execution_retries_are_bounded(database):
    _, sessions = database
    with sessions() as s:
        claim_job(s, "j1", 30)
        _expire(s, "j1")
        recover_expired(s, max_attempts=1)
        assert s.get(Job, "j1").status == "failed"
        assert s.get(Job, "j1").finished_utc is not None
        assert claim_job(s, "j1", 30) is None
        rows = s.query(AuditEvent).all()
        assert [r.action for r in rows] == ["job.inspect"]
        assert verify_chain(rows)[0]


def _own_until_killed(root, results):
    engine = make_engine(Config(root))
    with make_session_factory(engine)() as s:
        claim = claim_job(s, "j1", 3)
        results.put(claim.token)
    # Simulate a process dying while its worker is still outstanding.
    multiprocessing.Event().wait(30)


def test_killed_owner_recovers_after_expiry_with_new_attempt(database):
    cfg, sessions = database
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(target=_own_until_killed, args=(str(cfg.data_root), results))
    process.start()
    try:
        token = results.get(timeout=20)
        process.terminate()
        process.join(5)
        assert not process.is_alive()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            with sessions() as s:
                if recover_expired(s, max_attempts=3):
                    break
            time.sleep(0.1)
        else:
            pytest.fail("expired killed owner was not recovered")
        with sessions() as s:
            new = claim_job(s, "j1", 30)
            assert new.token != token and new.attempt == 2
            assert verify_chain(s.query(AuditEvent).all())[0]
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)


def test_heartbeat_keeps_long_execution_owned(database):
    _, sessions = database
    with sessions() as s:
        owner = claim_job(s, "j1", 3)
        initial_expiry = s.get(Job, "j1").lease_expires_epoch
    with Heartbeat(sessions, owner, 3):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with sessions() as s:
                assert recover_expired(s, max_attempts=3) == 0
                expiry = s.get(Job, "j1").lease_expires_epoch
                if database_now(s) > initial_expiry:
                    assert expiry > initial_expiry
                    assert s.get(Job, "j1").lease_token == owner.token
                    break
            time.sleep(0.1)
        else:
            pytest.fail("database clock did not pass the original expiry")
