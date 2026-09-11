"""Queued work must retain the admitted executor across deployment changes."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app import runner
from app.config import Config
from app.db import make_engine, make_session_factory
from app.migrate import _ALEMBIC_DIR, _ALEMBIC_INI, upgrade_head
from app.models import Document, Job, Matter

OLD_IMAGE = "example.invalid/counselclear@sha256:" + "a" * 64
NEW_IMAGE = "example.invalid/counselclear@sha256:" + "b" * 64


@pytest.fixture
def queued(tmp_path, monkeypatch, queue_backend):
    monkeypatch.setenv("COUNSELCLEAR_WORKER_MODE", "docker")
    monkeypatch.setenv("COUNSELCLEAR_WORKER_IMAGE", NEW_IMAGE)
    cfg = Config(tmp_path / "data")
    cfg.data_root.mkdir()
    upgrade_head(cfg.db_url())
    engine = make_engine(cfg)
    source = cfg.data_root / "source.txt"
    source.write_bytes(b"Synthetic pending work")
    with make_session_factory(engine)() as s:
        s.add(Matter(id="m", name="Synthetic"))
        s.flush()
        s.add(
            Document(
                id="d",
                matter_id="m",
                filename="source.txt",
                storage_path=str(source),
                bytes=source.stat().st_size,
                sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            )
        )
        s.flush()
        s.add(
            Job(
                id="j",
                matter_id="m",
                document_id="d",
                kind="inspect",
                worker_mode="docker",
                worker_image=OLD_IMAGE,
                requested_by="oidc:test",
            )
        )
        s.commit()
        yield cfg, s
    engine.dispose()


def test_dispatch_uses_admitted_digest_after_deployment_changes(queued, monkeypatch):
    cfg, s = queued
    seen = []

    def execute(cmd, **kwargs):
        seen.append(cmd)
        return SimpleNamespace(returncode=1, stderr="Synthetic worker failure")

    monkeypatch.setattr(runner.subprocess, "run", execute)
    runner.run_job(cfg, s, "j", kind="inspect")
    assert len(seen) == 1
    assert OLD_IMAGE in seen[0]
    assert NEW_IMAGE not in seen[0]
    assert f"COUNSELCLEAR_IMAGE_DIGEST={OLD_IMAGE}" in seen[0]
    assert seen[0][seen[0].index("--operator-id") + 1] == "oidc:test"
    assert cfg.worker_image == NEW_IMAGE
    assert s.get(Job, "j").worker_image == OLD_IMAGE


def test_mode_change_never_downgrades_queued_container_to_subprocess(queued, monkeypatch):
    cfg, s = queued
    cfg.worker_mode = "subprocess"

    def forbidden(*args, **kwargs):
        pytest.fail("changed execution mode must never start a worker")

    monkeypatch.setattr(runner.subprocess, "run", forbidden)
    result = runner.run_job(cfg, s, "j", kind="inspect")
    assert "worker mode changed since admission" in result.stderr_tail
    runner.sync_job(s, "j", result)
    assert s.get(Job, "j").status == "failed"
    assert s.get(Job, "j").worker_image == OLD_IMAGE


def test_upgrade_preserves_legacy_execution_and_round_trips_new_pin(tmp_path, queue_backend):
    cfg = Config(tmp_path)
    migration = AlembicConfig(str(_ALEMBIC_INI))
    migration.set_main_option("script_location", str(_ALEMBIC_DIR))
    migration.set_main_option("sqlalchemy.url", cfg.db_url())
    command.upgrade(migration, "0015")
    engine = make_engine(cfg)
    with engine.begin() as con:
        # The legacy schema has no mode column. No historical mode is invented.
        columns = (
            {row[0] for row in con.execute(text("SELECT name FROM pragma_table_info('jobs')"))}
            if engine.dialect.name == "sqlite"
            else {
                row[0]
                for row in con.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns WHERE table_name='jobs'"
                    )
                )
            }
        )
        assert "worker_mode" not in columns
        con.execute(Matter.__table__.insert().values(id="m", name="Synthetic"))
        con.execute(
            Document.__table__.insert().values(
                id="d",
                matter_id="m",
                filename="x.txt",
                bytes=0,
                sha256="0" * 64,
                storage_path="legacy",
            )
        )
        con.execute(
            Job.__table__.insert().values(
                id="j", matter_id="m", document_id="d", kind="inspect", worker_image=OLD_IMAGE
            )
        )
    upgrade_head(cfg.db_url())
    with make_session_factory(engine)() as s:
        assert s.get(Job, "j").worker_image == OLD_IMAGE
        assert s.get(Job, "j").worker_mode is None
        s.get(Job, "j").worker_mode = "docker"
        s.get(Job, "j").worker_image = OLD_IMAGE
        s.commit()
        s.expire_all()
        assert s.get(Job, "j").worker_mode == "docker"
        assert s.get(Job, "j").worker_image == OLD_IMAGE
    engine.dispose()
