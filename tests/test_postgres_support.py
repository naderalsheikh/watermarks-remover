"""Phase 3: optional Postgres backend.

These tests never require a running Postgres server:
- engine construction is lazy in SQLAlchemy, so we can assert dialect
  selection without connecting;
- migration DDL is validated through Alembic's offline (--sql) mode,
  which renders SQL from the migration chain without touching a server.

A live end-to-end run happens in deployment (compose pg profile), not in
unit tests — CI has no Postgres service.
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.audit import GENESIS, append_event, verify_chain
from app.config import Config
from app.db import make_engine, make_session_factory
from app.migrate import _ALEMBIC_DIR, _ALEMBIC_INI, upgrade_head
from app.models import AuditEvent, Matter

_PG_URL = "postgresql+psycopg://counselclear:pw@db.internal:5432/counselclear"


def test_default_backend_is_sqlite(tmp_path):
    cfg = Config(tmp_path)
    assert cfg.database_url == ""
    assert cfg.db_url() == f"sqlite:///{tmp_path / 'counselclear.sqlite3'}"


def test_database_url_env_selects_postgres(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_DATABASE_URL", _PG_URL)
    cfg = Config(tmp_path)
    assert cfg.db_url() == _PG_URL


def test_make_engine_postgres_dialect_without_connecting(tmp_path, monkeypatch):
    """create_engine() is lazy: no connection is attempted here. The
    meaningful guarantee — no SQLite pragmas fired against Postgres — holds
    structurally: the pragma listener is attached inside the SQLite-only
    branch of make_engine, past an early return for non-sqlite URLs."""
    monkeypatch.setenv("COUNSELCLEAR_DATABASE_URL", _PG_URL)
    cfg = Config(tmp_path)
    engine = make_engine(cfg)
    try:
        assert engine.dialect.name == "postgresql"
        assert engine.dialect.driver == "psycopg"
        assert engine.url.render_as_string(hide_password=False) == _PG_URL
    finally:
        engine.dispose()


def test_make_engine_sqlite_still_default(tmp_path):
    cfg = Config(tmp_path)
    engine = make_engine(cfg)
    try:
        assert engine.dialect.name == "sqlite"
        # Pragmas themselves are asserted against live connections in
        # test_prod_hardening.py; here we pin only backend selection.
    finally:
        engine.dispose()


def _create_table_sql(table, dialect) -> str:
    from sqlalchemy.schema import CreateTable

    return str(CreateTable(table).compile(dialect=dialect)).upper()


@pytest.mark.parametrize("table", [AuditEvent.__table__], ids=["audit_events"])
def test_json_columns_render_jsonb_on_postgres_only(table):
    pg_sql = _create_table_sql(table, postgresql.dialect())
    lite_sql = _create_table_sql(table, sqlite.dialect())
    assert "JSONB" in pg_sql
    assert "JSONB" not in lite_sql


def test_job_json_columns_render_jsonb_on_postgres():
    from app.models import Job

    pg_sql = _create_table_sql(Job.__table__, postgresql.dialect())
    assert pg_sql.count("JSONB") == 2  # result_json, finding_decisions


def test_migrations_emit_jsonb_for_fresh_postgres_offline():
    """Alembic --sql renders the whole chain without a server: proves a
    fresh Postgres install gets JSONB DDL from the edited migrations."""
    from alembic import command
    from alembic.config import Config as AlembicConfig

    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", _PG_URL)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        command.upgrade(cfg, "head", sql=True)
    out = buf.getvalue().upper()
    assert "CREATE TABLE MATTERS" in out
    assert "JSONB" in out


def test_migrations_still_apply_to_sqlite_after_pg_edits(tmp_path):
    """The with_variant edits must leave the SQLite chain byte-equivalent."""
    upgrade_head(f"sqlite:///{tmp_path / 'x.sqlite3'}")  # must not raise


def test_append_event_retries_after_seq_collision(tmp_path, monkeypatch):
    """Postgres cross-process race: two writers read the same max(seq); the
    unique constraint rejects one at commit. The loser must roll back,
    re-read, and append at winner_seq+1 — keeping the chain gapless."""
    cfg = Config(tmp_path)
    upgrade_head(cfg.db_url())
    engine = make_engine(cfg)
    factory = make_session_factory(engine)

    with factory() as s:
        s.add(Matter(id="m", name="m"))
        s.commit()

    # Patch only now: the seed commit above must go through untouched.
    real_commit = Session.commit
    state = {"fail_next": True}

    def racing_commit(self):
        if state["fail_next"]:
            from sqlalchemy.exc import IntegrityError

            state["fail_next"] = False
            raise IntegrityError("INSERT", {}, Exception("duplicate key"))
        return real_commit(self)

    monkeypatch.setattr(Session, "commit", racing_commit)

    with factory() as s:
        ev = append_event(s, matter_id="m", actor_id="operator", action="upload", payload={"n": 1})
        assert ev.seq == 0  # first attempt collided; retry appended fine
        ev2 = append_event(
            s, matter_id="m", actor_id="operator", action="sanitize", payload={"n": 2}
        )
        assert ev2.seq == 1
    with factory() as s:
        events = list(s.execute(select(AuditEvent)).scalars())
        ok, detail = verify_chain(events)
        assert ok, detail
        assert events[0].prev_hash == GENESIS


def test_append_event_gives_up_after_bounded_retries(tmp_path, monkeypatch):
    """If every attempt collides (pathological contention), fail loudly
    instead of looping forever."""
    cfg = Config(tmp_path)
    upgrade_head(cfg.db_url())
    engine = make_engine(cfg)
    factory = make_session_factory(engine)

    from sqlalchemy.exc import IntegrityError

    with factory() as s:
        s.add(Matter(id="m", name="m"))
        s.commit()

    def always_collide(self):
        raise IntegrityError("INSERT", {}, Exception("duplicate key"))

    monkeypatch.setattr(Session, "commit", always_collide)

    with factory() as s, pytest.raises(RuntimeError, match="kept colliding"):
        append_event(s, matter_id="m", actor_id="operator", action="upload", payload={})


def test_data_root_not_required_for_postgres_engine(tmp_path, monkeypatch, recwarn):
    """make_engine on Postgres must not touch the filesystem (custody dirs
    are the API's job, not the engine's)."""
    monkeypatch.setenv("COUNSELCLEAR_DATABASE_URL", _PG_URL)
    missing = tmp_path / "no-such-root"
    engine = make_engine(Config(missing))
    try:
        assert not missing.exists()
    finally:
        engine.dispose()
