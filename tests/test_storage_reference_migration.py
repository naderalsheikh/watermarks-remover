"""Long opaque references survive real upgrades; downgrade never truncates one."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app.config import Config
from app.db import make_engine, make_session_factory
from app.migrate import _ALEMBIC_DIR, _ALEMBIC_INI, upgrade_head
from sqlalchemy import text


def test_upgrade_preserves_reference_and_long_versions_cannot_be_truncated(tmp_path, queue_backend):
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    migration = AlembicConfig(str(_ALEMBIC_INI))
    migration.set_main_option("script_location", str(_ALEMBIC_DIR))
    migration.set_main_option("sqlalchemy.url", cfg.db_url())
    command.upgrade(migration, "0014")
    sessions = make_session_factory(engine)
    with sessions() as s:
        # Seed the historical schema using SQL: current ORM metadata also
        # includes organization fields that did not exist in migration 0014.
        s.execute(
            text(
                "INSERT INTO matters (id, name, created_utc, is_demo) VALUES ('m', 'Synthetic migration', '2026-01-01', false)"
            )
        )
        s.execute(
            text(
                "INSERT INTO documents (id, matter_id, filename, sha256, bytes, storage_path, created_utc) VALUES ('d', 'm', 'sample.txt', :digest, 1, 'legacy/reference', '2026-01-01')"
            ),
            {"digest": "0" * 64},
        )
        s.commit()
    upgrade_head(cfg.db_url())
    long_reference = "s3v1:" + "v" * 1024 + ":" + "k" * 1024
    with sessions() as s:
        assert (
            s.execute(text("SELECT storage_path FROM documents WHERE id='d'")).scalar_one()
            == "legacy/reference"
        )
        s.execute(
            text("UPDATE documents SET storage_path=:ref WHERE id='d'"), {"ref": long_reference}
        )
        s.commit()
    with sessions() as s:
        assert (
            s.execute(text("SELECT storage_path FROM documents WHERE id='d'")).scalar_one()
            == long_reference
        )
    with pytest.raises(RuntimeError, match="cannot downgrade"):
        command.downgrade(migration, "0014")
    with sessions() as s:
        assert (
            s.execute(text("SELECT storage_path FROM documents WHERE id='d'")).scalar_one()
            == long_reference
        )
        s.execute(text("UPDATE documents SET storage_path='legacy/reference' WHERE id='d'"))
        s.commit()
    command.downgrade(migration, "0014")
    upgrade_head(cfg.db_url())
    with sessions() as s:
        assert (
            s.execute(text("SELECT storage_path FROM documents WHERE id='d'")).scalar_one()
            == "legacy/reference"
        )
    engine.dispose()
