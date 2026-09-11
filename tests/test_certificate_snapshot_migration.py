"""Certificate snapshot migration preserves legacy release records."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy.dialects import postgresql

SERVICE = Path(__file__).resolve().parents[1] / "service"
if str(SERVICE) not in sys.path:
    sys.path.insert(0, str(SERVICE))

from app.migrate import _ALEMBIC_DIR, _ALEMBIC_INI
from app.models import Release


@pytest.fixture
def legacy_database(tmp_path):
    url = f"sqlite:///{tmp_path / 'legacy.sqlite3'}"
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "0011")
    engine = sa.create_engine(url)
    metadata = sa.MetaData()
    metadata.reflect(bind=engine)
    at = "2026-09-10T12:00:00+00:00"
    job = {
        "id": "legacy-job",
        "matter_id": "legacy-matter",
        "document_id": "legacy-document",
        "batch_id": None,
        "kind": "sanitize",
        "policy_id": "production",
        "reason": "Legacy release",
        "attestation": False,
        "finding_decisions": {},
        "legal_justifications": {},
        "layer_b": None,
        "status": "done",
        "error": "",
        "result_json": {"legacy": True},
        "bundle_dir": "bundles/legacy-job",
        "worker_image": "legacy-image",
        "created_utc": at,
        "finished_utc": at,
    }
    release = {
        "id": "legacy-release",
        "matter_id": "legacy-matter",
        "document_id": "legacy-document",
        "batch_id": None,
        "job_id": "legacy-job",
        "policy_id": "production",
        "profile_id": "external",
        "recipient_type": "client",
        "recipient_name": "Legacy Client",
        "purpose": "Preserve existing release metadata",
        "intended_external": True,
        "requested_by": "legacy-operator",
        "predecessor_release_id": "prior-release",
        "status": "done",
        "created_utc": at,
        "finished_utc": at,
        "last_anchor_type": "ed25519-operator",
        "last_anchor_at": at,
        "last_anchor_digest": "a" * 64,
    }
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.execute(
                metadata.tables["matters"].insert(),
                {
                    "id": "legacy-matter",
                    "name": "Legacy matter",
                    "created_utc": at,
                    "is_demo": False,
                },
            )
            connection.execute(
                metadata.tables["documents"].insert(),
                {
                    "id": "legacy-document",
                    "matter_id": "legacy-matter",
                    "filename": "legacy.docx",
                    "sha256": "b" * 64,
                    "bytes": 123,
                    "storage_path": "originals/legacy.docx",
                    "created_utc": at,
                },
            )
            connection.execute(metadata.tables["jobs"].insert(), job)
            connection.execute(metadata.tables["releases"].insert(), release)
        yield cfg, engine, metadata, job, release
    finally:
        engine.dispose()


def test_upgrade_and_downgrade_preserve_legacy_release(legacy_database):
    cfg, engine, _, _, legacy_release = legacy_database
    command.upgrade(cfg, "head")
    columns = {column["name"]: column for column in sa.inspect(engine).get_columns("releases")}
    assert columns["certificate_snapshot"]["nullable"] is True
    assert columns["certificate_snapshot"]["default"] is None
    with engine.connect() as connection:
        row = dict(connection.execute(sa.select(Release.__table__)).mappings().one())
        assert row.pop("certificate_snapshot") is None
        assert row == legacy_release
        assert (
            connection.execute(
                sa.select(Release.id).where(Release.certificate_snapshot.is_(None))
            ).scalar_one()
            == legacy_release["id"]
        )

    command.downgrade(cfg, "0011")
    assert "certificate_snapshot" not in {
        column["name"] for column in sa.inspect(engine).get_columns("releases")
    }
    with engine.connect() as connection:
        row = dict(connection.exec_driver_sql("SELECT * FROM releases").mappings().one())
        assert row == legacy_release
        assert not connection.exec_driver_sql("PRAGMA foreign_key_check").all()

    command.upgrade(cfg, "head")
    with engine.connect() as connection:
        assert connection.execute(sa.select(Release.certificate_snapshot)).scalar_one() is None


def test_explicit_none_remains_claimable_with_sql_null(legacy_database):
    cfg, engine, metadata, legacy_job, legacy_release = legacy_database
    command.upgrade(cfg, "head")
    snapshot = {"html": "<html>Recorded certificate</html>", "sha256": "c" * 64}
    with engine.begin() as connection:
        connection.execute(metadata.tables["jobs"].insert(), {**legacy_job, "id": "new-job"})
        connection.execute(
            Release.__table__.insert(),
            {
                **legacy_release,
                "id": "new-release",
                "job_id": "new-job",
                "certificate_snapshot": None,
            },
        )
        claim = (
            sa.update(Release)
            .where(Release.id == "new-release", Release.certificate_snapshot.is_(None))
            .values(certificate_snapshot=snapshot)
        )
        assert connection.execute(claim).rowcount == 1
        assert connection.execute(claim).rowcount == 0
        assert (
            connection.execute(
                sa.select(Release.certificate_snapshot).where(Release.id == "new-release")
            ).scalar_one()
            == snapshot
        )


def test_postgres_snapshot_is_nullable_jsonb_with_sql_null_binding():
    output = io.StringIO()
    cfg = AlembicConfig(str(_ALEMBIC_INI), output_buffer=output)
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", "postgresql+psycopg://unused/unused")
    command.upgrade(cfg, "0011:head", sql=True)
    assert "ADD COLUMN certificate_snapshot JSONB;" in output.getvalue()
    column = Release.__table__.c.certificate_snapshot
    assert column.nullable is True
    assert column.default is None
    assert column.server_default is None
    dialect = postgresql.dialect()
    assert column.type.dialect_impl(dialect).bind_processor(dialect)(None) is None
