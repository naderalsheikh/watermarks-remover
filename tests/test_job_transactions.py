"""A terminal result and its custody records are one publication unit."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
from sqlalchemy import event

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app.audit import append_event, verify_chain
from app.config import Config
from app.db import make_engine, make_session_factory
from app.job_lifecycle import finalize_job
from app.migrate import upgrade_head
from app.models import AuditEvent, Batch, Document, Job, Matter, Release
from app.runner import RunnerResult


@pytest.fixture
def database(tmp_path, queue_backend):
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(cfg.db_url())
    sessions = make_session_factory(engine)
    with sessions() as s:
        s.add(Matter(id="m", name="Synthetic matter"))
        s.flush()
        s.add(
            Document(
                id="d",
                matter_id="m",
                filename="fixture.txt",
                sha256="0" * 64,
                bytes=0,
                storage_path="synthetic",
            )
        )
        s.add(Batch(id="b", matter_id="m", kind="inspect", requested_by="requester", total=1))
        s.flush()
        s.add(
            Job(
                id="j",
                matter_id="m",
                document_id="d",
                batch_id="b",
                kind="inspect",
                status="running",
            )
        )
        s.flush()
        s.add(
            Release(
                id="r",
                matter_id="m",
                document_id="d",
                job_id="j",
                batch_id="b",
                policy_id="external_sharing",
                requested_by="requester",
                status="queued",
            )
        )
        s.commit()
    output = tmp_path / "output"
    output.mkdir()
    (output / "result.json").write_text(json.dumps({"status": "done", "result": {"findings": []}}))
    yield cfg, engine, sessions, RunnerResult(0, "", False, output)
    engine.dispose()


def finish(session, result):
    return finalize_job(
        session, "j", result, actor_id="requester", no_decision_marker="no-decision"
    )


def test_terminal_job_release_and_batch_publish_with_all_events(database):
    cfg, _, sessions, result = database
    observed = []

    def observe(_mapper, _connection, target):
        if target.action == "batch.completed":
            # A separate database reader must see only committed state.
            if cfg.database_url:
                from sqlalchemy import create_engine

                reader_engine = create_engine(cfg.db_url())
                try:
                    with reader_engine.connect() as reader:
                        observed.append(
                            (
                                reader.exec_driver_sql(
                                    "select status from jobs where id='j'"
                                ).scalar_one(),
                                reader.exec_driver_sql(
                                    "select count(*) from audit_events"
                                ).scalar_one(),
                            )
                        )
                finally:
                    reader_engine.dispose()
            else:
                with sqlite3.connect(cfg.db_path) as reader:
                    observed.append(
                        (
                            reader.execute("select status from jobs where id='j'").fetchone()[0],
                            reader.execute("select count(*) from audit_events").fetchone()[0],
                        )
                    )

    event.listen(AuditEvent, "after_insert", observe)
    try:
        with sessions() as s:
            assert finish(s, result) == 1
    finally:
        event.remove(AuditEvent, "after_insert", observe)
    assert observed == [("running", 0)]
    with sessions() as s:
        assert s.get(Job, "j").status == s.get(Release, "r").status == "done"
        assert s.get(Batch, "b").finished_utc is not None
        rows = s.query(AuditEvent).order_by(AuditEvent.seq).all()
        assert [e.action for e in rows] == ["job.inspect", "release.terminal", "batch.completed"]
        assert verify_chain(rows)[0]
        assert {e.actor_id for e in rows} == {"requester"}


@pytest.mark.parametrize("failed_action", ["job.inspect", "release.terminal", "batch.completed"])
def test_failed_event_rolls_back_every_terminal_record_and_retry_is_idempotent(
    database, failed_action
):
    _, _, sessions, result = database

    def fail(_mapper, _connection, target):
        if target.action == failed_action:
            raise RuntimeError("injected storage failure")

    event.listen(AuditEvent, "before_insert", fail)
    try:
        with sessions() as s, pytest.raises(RuntimeError, match="injected"):
            finish(s, result)
    finally:
        event.remove(AuditEvent, "before_insert", fail)
    with sessions() as s:
        assert s.get(Job, "j").status == "running"
        assert s.get(Job, "j").result_json is None
        assert s.get(Release, "r").status == "queued"
        assert s.get(Batch, "b").finished_utc is None
        assert s.query(AuditEvent).count() == 0
        s.rollback()
        finish(s, result)
        finish(s, result)
    with sessions() as s:
        assert s.query(AuditEvent).count() == 3
        assert verify_chain(s.query(AuditEvent).all())[0]


def test_caller_owned_audit_append_does_not_commit_pending_business_rows(database):
    _, _, sessions, _ = database
    with sessions() as s:
        s.get(Matter, "m").name = "Uncommitted change"
        append_event(
            s, matter_id="m", actor_id="requester", action="test", payload={}, commit=False
        )
        append_event(
            s, matter_id="m", actor_id="requester", action="test2", payload={}, commit=False
        )
        s.rollback()
    with sessions() as s:
        assert s.get(Matter, "m").name == "Synthetic matter"
        assert s.query(AuditEvent).count() == 0
