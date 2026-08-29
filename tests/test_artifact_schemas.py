"""Versioned JSON Schemas for CounselClear release artifacts.

The verifier remains stdlib-only, but the repo must publish and test the
machine contracts it emits: manifest.json, report.json, release_packet.json,
and release_result.json.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO / "service" / "scripts" / "schemas"
APP_DIR = REPO / "service" / "app"
SCRIPTS = REPO / "service" / "scripts"
for p in (str(SCRIPTS), str(APP_DIR.parent), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import counselclear_verify_release_packet as verifier
from app.config import Config
from app.db import make_engine
from app.main import create_app
from app.migrate import upgrade_head
from custody import emit_manifest

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"
PW = "schema-pw"


def _schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text())


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    cfg = Config(tmp_path / "data")
    make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    yield c
    c.app.state.batch_dispatcher.stop()
    c.close()


def _matter(c) -> str:
    r = c.post("/v1/matters", json={"name": "Schema Matter"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _upload(c, matter_id: str, name: str) -> str:
    data = (FIXTURES / name).read_bytes()
    r = c.post(
        f"/v1/matters/{matter_id}/documents",
        files={"file": (name, data, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _release(c, matter_id: str, document_id: str) -> dict:
    r = c.post(
        f"/v1/matters/{matter_id}/documents/{document_id}/releases",
        json={
            "profile_id": "counterparty_deal_room",
            "recipient_type": "opposing_counsel",
            "recipient_name": "Schema Reviewer",
            "purpose": "schema contract test",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_artifact_schemas_are_valid_draft_2020_12():
    for name in (
        "manifest.schema.json",
        "report.schema.json",
        "release_packet.schema.json",
        "release_result.schema.json",
    ):
        Draft202012Validator.check_schema(_schema(name))


def test_emit_manifest_matches_published_schema():
    manifest = emit_manifest(
        original_name="SPA.docx",
        original_sha256="a" * 64,
        original_bytes=123,
        derivative_name_="SPA.external.docx",
        derivative_sha256="b" * 64,
        derivative_bytes=100,
        policy_id="external_sharing",
        actions=["comments_and_notes:strip: removed comments"],
        processor={"git_sha": "unknown", "tools": {"qpdf": True}},
        findings_before=["docx-comments: 1 comment"],
        verification={"pass": True, "checks": []},
        operator_id="operator",
        matter_id="m1",
    )
    jsonschema.validate(manifest, _schema("manifest.schema.json"))


def test_real_release_artifacts_match_published_schemas(client):
    matter_id = _matter(client)
    document_id = _upload(client, matter_id, "spa.docx")
    body = _release(client, matter_id, document_id)
    release = body["release"]
    job = body["job"]
    release_result = body["release_result"]

    jsonschema.validate(release_result, _schema("release_result.schema.json"))

    result_download = client.get(f"/v1/matters/{matter_id}/releases/{release['id']}/result")
    assert result_download.status_code == 200
    jsonschema.validate(result_download.json(), _schema("release_result.schema.json"))

    bundle = client.get(f"/v1/matters/{matter_id}/jobs/{job['id']}/bundle")
    assert bundle.status_code == 200, bundle.text
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        report = json.loads(zf.read("report.json"))
        release_packet = json.loads(zf.read("release_packet.json"))

    jsonschema.validate(manifest, _schema("manifest.schema.json"))
    jsonschema.validate(report, _schema("report.schema.json"))
    jsonschema.validate(release_packet, _schema("release_packet.schema.json"))
    assert report["report_version"] == 1


def test_verifier_required_fields_track_published_schemas():
    assert set(verifier.REQUIRED_MANIFEST_FIELDS) == set(
        _schema("release_packet.schema.json")["required"]
    )
    assert set(verifier.REQUIRED_RELEASE_RESULT_FIELDS) == set(
        _schema("release_result.schema.json")["required"]
    )
