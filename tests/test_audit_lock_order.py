"""Audit appends must acquire SQLite and Python locks in a consistent order."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest
from sqlalchemy import event

SERVICE = Path(__file__).resolve().parents[1] / "service"
if str(SERVICE) not in sys.path:
    sys.path.insert(0, str(SERVICE))

from app.audit import append_event, verify_chain
from app.config import Config
from app.db import make_engine, make_session_factory
from app.migrate import upgrade_head
from app.models import AuditEvent, Matter


@pytest.fixture
def database(tmp_path):
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(cfg.db_url())
    sessions = make_session_factory(engine)
    with sessions() as s:
        s.add(Matter(id="matter", name="Before append"))
        s.commit()
    yield engine, sessions
    engine.dispose()


def test_read_started_and_fresh_append_do_not_invert_sqlite_locks(database):
    engine, sessions = database
    reader_holds_database = threading.Event()
    fresh_append_begins = threading.Event()
    errors = []

    @event.listens_for(engine, "before_cursor_execute")
    def observe_begin(_conn, _cursor, statement, _parameters, _context, _executemany):
        if threading.current_thread().name == "fresh-append" and statement == "BEGIN IMMEDIATE":
            # The fresh append is about to wait for the reader's database
            # transaction. It must not hold the matter's Python mutex here.
            fresh_append_begins.set()

    def read_started_append():
        try:
            with sessions() as s:
                matter = s.get(Matter, "matter")
                matter.name = "Committed with read-started append"
                s.add(Matter(id="staged", name="Pending caller row"))
                reader_holds_database.set()
                assert fresh_append_begins.wait(10), "fresh append never began"
                append_event(
                    s, matter_id="matter", actor_id="reader", action="read.append", payload={}
                )
        except BaseException as exc:
            errors.append(("reader", exc))

    def fresh_append():
        try:
            assert reader_holds_database.wait(10), "reader never opened its transaction"
            with sessions() as s:
                append_event(
                    s, matter_id="matter", actor_id="fresh", action="fresh.append", payload={}
                )
        except BaseException as exc:
            errors.append(("fresh", exc))

    threads = [
        threading.Thread(target=read_started_append, name="read-started-append"),
        threading.Thread(target=fresh_append, name="fresh-append"),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(15)
    assert not any(thread.is_alive() for thread in threads), "audit append threads did not finish"
    assert not errors, [(name, str(exc)) for name, exc in errors]

    with sessions() as s:
        events = s.query(AuditEvent).order_by(AuditEvent.seq).all()
        assert [ev.action for ev in events] == ["read.append", "fresh.append"]
        assert verify_chain(events) == (True, "2 events intact")
        assert s.get(Matter, "matter").name == "Committed with read-started append"
        assert s.get(Matter, "staged").name == "Pending caller row"


def test_failed_append_does_not_commit_the_callers_pending_changes(database):
    engine, sessions = database

    @event.listens_for(engine, "before_cursor_execute")
    def reject_audit_insert(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("INSERT INTO audit_events"):
            raise RuntimeError("simulated audit write failure")

    with sessions() as s:
        s.get(Matter, "matter").name = "Must roll back with audit"
        s.add(Matter(id="staged", name="Must not be published alone"))
        with pytest.raises(RuntimeError, match="simulated audit write failure"):
            append_event(
                s, matter_id="matter", actor_id="reader", action="failed.append", payload={}
            )
        s.rollback()

    with sessions() as s:
        assert s.get(Matter, "matter").name == "Before append"
        assert s.get(Matter, "staged") is None
        assert s.query(AuditEvent).count() == 0
