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
from app.models import Document, Matter


def test_upgrade_preserves_reference_and_long_versions_cannot_be_truncated(tmp_path, queue_backend):
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    migration = AlembicConfig(str(_ALEMBIC_INI))
    migration.set_main_option("script_location", str(_ALEMBIC_DIR))
    migration.set_main_option("sqlalchemy.url", cfg.db_url())
    command.upgrade(migration, "0014")
    sessions = make_session_factory(engine)
    with sessions() as s:
        s.add(Matter(id="m", name="Synthetic migration"))
        s.flush()
        s.add(
            Document(
                id="d",
                matter_id="m",
                filename="sample.txt",
                sha256="0" * 64,
                bytes=1,
                storage_path="legacy/reference",
            )
        )
        s.commit()
    upgrade_head(cfg.db_url())
    long_reference = "s3v1:" + "v" * 1024 + ":" + "k" * 1024
    with sessions() as s:
        document = s.get(Document, "d")
        assert document.storage_path == "legacy/reference"
        document.storage_path = long_reference
        s.commit()
    with sessions() as s:
        assert s.get(Document, "d").storage_path == long_reference
    with pytest.raises(RuntimeError, match="cannot downgrade"):
        command.downgrade(migration, "0014")
    with sessions() as s:
        assert s.get(Document, "d").storage_path == long_reference
        s.get(Document, "d").storage_path = "legacy/reference"
        s.commit()
    command.downgrade(migration, "0014")
    upgrade_head(cfg.db_url())
    with sessions() as s:
        assert s.get(Document, "d").storage_path == "legacy/reference"
    engine.dispose()
