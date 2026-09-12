"""Upgrade legacy rows without rewriting storage references or hashes."""

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app.migrate import _ALEMBIC_DIR, _ALEMBIC_INI


def test_existing_documents_and_matters_get_neutral_metadata(tmp_path):
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    url = f"sqlite:///{tmp_path / 'legacy.sqlite3'}"
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "0017")
    engine = create_engine(url)
    with engine.begin() as con:
        con.execute(
            text(
                "INSERT INTO matters (id,name,created_utc,is_demo) VALUES ('m','Existing','2026-01-01',false)"
            )
        )
        con.execute(
            text(
                "INSERT INTO documents (id,matter_id,filename,sha256,bytes,storage_path,created_utc) VALUES ('d','m','old.docx',:hash,9,'/old/path','2026-01-01')"
            ),
            {"hash": "a" * 64},
        )
    command.upgrade(cfg, "head")
    command.upgrade(cfg, "head")
    with engine.connect() as con:
        assert tuple(
            con.execute(
                text("SELECT client_name,matter_number,status,organization_version FROM matters")
            ).one()
        ) == ("", "", "active", 0)
        assert tuple(
            con.execute(
                text(
                    "SELECT category,previous_revision_id,organization_version,sha256,storage_path FROM documents"
                )
            ).one()
        ) == ("", None, 0, "a" * 64, "/old/path")
    engine.dispose()
