"""Versioned JSON Schemas for CounselClear release artifacts.

The verifier remains stdlib-only, but the repo must publish and test the
machine contracts it emits: manifest.json, report.json, release_packet.json,
and release_result.json.
"""

from __future__ import annotations

import hashlib
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
ENGINE_SCHEMA_DIR = REPO / "engine" / "schemas"
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
            "profile_id": "ediscovery_production",
            "recipient_type": "court",
            "recipient_name": "Schema Reviewer",
            "purpose": "schema contract test",
            "finding_decisions": {
                "comments_and_notes": "keep",
                "tracked_changes": "approve",
            },
            "legal_justifications": {
                "comments_and_notes": {
                    "basis": "work_product",
                    "note": "Counsel drafting comments withheld from production.",
                }
            },
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_artifact_schemas_are_valid_draft_2020_12():
    for name in (
        "finding.schema.json",
        "manifest.schema.json",
        "report.schema.json",
        "release_packet.schema.json",
        "release_result.schema.json",
    ):
        Draft202012Validator.check_schema(_schema(name))
    Draft202012Validator.check_schema(json.loads((ENGINE_SCHEMA_DIR / "finding.schema.json").read_text()))


def test_finding_schema_copies_accept_optional_legal_justification():
    finding = {
        "finding_id": "f_0123456789abcdef",
        "category": "revision_history",
        "subtype": "comments_and_notes",
        "format": "docx",
        "location": {"pane": "comment"},
        "action_recommended": "flag",
        "action_allowed_by_policy": ["keep", "strip", "flag"],
        "content_visible": True,
        "risk_level": "high",
        "confidence": "confirmed",
        "removal_changes_visible_content": False,
        "legal_justification": {"basis": "privilege", "note": "Attorney-client note."},
    }
    for schema_path in (
        SCHEMA_DIR / "finding.schema.json",
        ENGINE_SCHEMA_DIR / "finding.schema.json",
    ):
        jsonschema.validate(finding, json.loads(schema_path.read_text()))


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


def test_emit_manifest_carries_schema_pin():
    """PR 63: the manifest doesn't just match the published schema, it
    NAMES it -- schema_version + schema_sha256 stamped by the emitter,
    checked against the published file here independently (the same
    recomputation tools/counselclear_verify_release_packet.py performs
    offline)."""
    manifest = emit_manifest(
        original_name="SPA.docx",
        original_sha256="a" * 64,
        original_bytes=123,
        derivative_name_="SPA.external.docx",
        derivative_sha256="b" * 64,
        derivative_bytes=100,
        policy_id="external_sharing",
        actions=[],
        processor={"git_sha": "unknown", "tools": {}},
        findings_before=[],
        verification={"pass": True, "checks": []},
    )
    assert manifest["schema_version"] == 1
    assert manifest["schema_sha256"] == hashlib.sha256(
        (SCHEMA_DIR / "manifest.schema.json").read_bytes()
    ).hexdigest()


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
    # PR 63: every artifact in the bundle names the published contract
    # it was built against -- version + file hash, checked here against
    # the same published files the schemas above came from.
    assert manifest["schema_version"] == 1
    assert manifest["schema_sha256"] == hashlib.sha256(
        (SCHEMA_DIR / "manifest.schema.json").read_bytes()
    ).hexdigest()
    assert report["schema_version"] == 1
    assert report["schema_sha256"] == hashlib.sha256(
        (SCHEMA_DIR / "report.schema.json").read_bytes()
    ).hexdigest()
    assert release_packet["schema_version"] == 1
    assert release_packet["schema_sha256"] == hashlib.sha256(
        (SCHEMA_DIR / "release_packet.schema.json").read_bytes()
    ).hexdigest()
    expected = [
        {
            "subtype": "comments_and_notes",
            "action": "keep",
            "legal_justification": {
                "basis": "work_product",
                "note": "Counsel drafting comments withheld from production.",
            },
        }
    ]
    assert release_result["legal_justifications"] == expected
    assert release_packet["legal_justifications"] == expected
    action = next(
        r
        for r in manifest["action_records"]
        if r["subtype"] == "comments_and_notes" and "legal_justification" in r
    )
    assert action["legal_justification"] == expected[0]["legal_justification"]
    assert report["action_records"] == manifest["action_records"]


def test_verifier_required_fields_track_published_schemas():
    assert set(verifier.REQUIRED_MANIFEST_FIELDS) == set(
        _schema("release_packet.schema.json")["required"]
    )
    assert set(verifier.REQUIRED_RELEASE_RESULT_FIELDS) == set(
        _schema("release_result.schema.json")["required"]
    )
