"""Tests for GET /v1/matters/{matter_id}/privilege-log.

Verifies:
- Read-permission gate (403 for unauthorized users, 200 for read-authorized).
- Empty matter export (CSV headers with 0 rows, JSON with 0 records).
- Multi-document and multi-finding privilege log entries.
- Approved 9-term ballot vocabulary and operator justifications.
- RFC 4180 compliance for CSV escaping (commas, quotes, newlines in notes).
- JSON format parity with ?format=json.
- Handling of refused releases.
"""

from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import create_app
from app.migrate import upgrade_head
from app.security import issue_session

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"
PW = "pw-privilege-log"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    sf = make_session_factory(engine)
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    yield c, sf, cfg
    if hasattr(c.app.state, "batch_dispatcher"):
        c.app.state.batch_dispatcher.stop()
    c.close()


def _upload(c, mid: str, name: str, fixture: str = "spa.txt") -> str:
    data = (FIXTURES / fixture).read_bytes()
    r = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": (name, data, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_privilege_log_requires_read_permission(env):
    c, _, cfg = env
    mid = c.post("/v1/matters", json={"name": "Privilege Matter"}).json()["id"]
    unauth = "oidc:unauthorized_user"

    # User with no permissions
    c.cookies.set("cc_session", issue_session(cfg, unauth))
    r = c.get(f"/v1/matters/{mid}/privilege-log")
    assert r.status_code == 403

    # Grant read permission
    admin_session = issue_session(cfg, "operator")
    c.cookies.set("cc_session", admin_session)
    c.put(f"/v1/matters/{mid}/acl", json={"user_id": unauth, "perm": "read"})

    # Now read-authorized user succeeds
    c.cookies.set("cc_session", issue_session(cfg, unauth))
    r = c.get(f"/v1/matters/{mid}/privilege-log")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")


def test_privilege_log_empty_matter(env):
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "Empty Matter"}).json()["id"]

    # CSV default
    r = c.get(f"/v1/matters/{mid}/privilege-log")
    assert r.status_code == 200
    assert r.headers["X-Total-Records"] == "0"
    reader = csv.reader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 1  # header row only
    assert "release_id" in rows[0]
    assert "legal_basis" in rows[0]

    # JSON format
    r_json = c.get(f"/v1/matters/{mid}/privilege-log?format=json")
    assert r_json.status_code == 200
    data = r_json.json()
    assert data["matter_id"] == mid
    assert data["total_records"] == 0
    assert data["records"] == []


def test_privilege_log_with_dispositions_and_justifications(env):
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "Litigation Matter"}).json()["id"]
    doc_id = _upload(c, mid, "agreement.docx", fixture="spa.docx")

    # Create release with legal justifications using 9-term ballot vocabulary
    note_text = "Legal opinion regarding indemnification clause; attorney-client privileged."
    body = {
        "profile_id": "ediscovery_production",
        "recipient_type": "court",
        "recipient_name": "SDNY Clerk",
        "purpose": "Summary judgment motion exhibit",
        "finding_decisions": {
            "comments_and_notes": "keep",
        },
        "legal_justifications": {
            "comments_and_notes": {
                "basis": "attorney_client_privilege",
                "note": note_text,
            }
        },
    }
    rel_res = c.post(f"/v1/matters/{mid}/documents/{doc_id}/releases", json=body)
    assert rel_res.status_code == 200, rel_res.text
    release_id = rel_res.json()["release"]["id"]

    # Test CSV export
    r = c.get(f"/v1/matters/{mid}/privilege-log?format=csv")
    assert r.status_code == 200
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) >= 1

    # Find the row for this release
    rel_row = next((row for row in rows if row["release_id"] == release_id), None)
    assert rel_row is not None
    assert rel_row["document_filename"] == "agreement.docx"
    assert rel_row["recipient_type"] == "court"
    assert rel_row["recipient_name"] == "SDNY Clerk"
    assert rel_row["finding_subtype"] == "comments_and_notes"
    assert rel_row["legal_basis"] == "attorney_client_privilege"
    assert rel_row["operator_note"] == note_text
    assert rel_row["reviewer_id"] != ""

    # Test JSON export parity
    r_json = c.get(f"/v1/matters/{mid}/privilege-log?format=json")
    assert r_json.status_code == 200
    json_data = r_json.json()
    assert json_data["total_records"] == len(rows)
    json_rel = next((rec for rec in json_data["records"] if rec["release_id"] == release_id), None)
    assert json_rel is not None
    assert json_rel["legal_basis"] == "attorney_client_privilege"
    assert json_rel["operator_note"] == note_text


def test_privilege_log_rfc4180_escaping(env):
    """Ensure notes with commas, quotes, and newlines round-trip safely through CSV."""
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "Escaping Matter"}).json()["id"]
    doc_id = _upload(c, mid, "memo.docx", fixture="spa.docx")

    complex_note = (
        'Memo contains "confidential" communications,\n'
        'including work-product notes, settlement figures ($1,000,000),\n'
        'and privileged counsel "deliberations".'
    )
    body = {
        "profile_id": "counterparty_deal_room",
        "recipient_type": "opposing_counsel",
        "recipient_name": "Counsel Smith, Esq.",
        "purpose": "Discovery production",
        "legal_justifications": {
            "comments_and_notes": {
                "basis": "work_product_protection",
                "note": complex_note,
            }
        },
    }
    rel_res = c.post(f"/v1/matters/{mid}/documents/{doc_id}/releases", json=body)
    assert rel_res.status_code == 200, rel_res.text

    r = c.get(f"/v1/matters/{mid}/privilege-log?format=csv")
    assert r.status_code == 200

    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    row = next(r for r in rows if r["document_filename"] == "memo.docx" and r["finding_subtype"] == "comments_and_notes")
    assert row["operator_note"] == complex_note
    assert row["legal_basis"] == "work_product_protection"


def test_privilege_log_records_refused_release(env):
    """A refused release must appear in the privilege log with status and reason."""
    c, _, _ = env
    mid = c.post("/v1/matters", json={"name": "Refusal Matter"}).json()["id"]
    doc_id = _upload(c, mid, "macro.docm", fixture="macro.docm")

    # Mutating release on macro-bearing file without attestation is refused
    body = {
        "profile_id": "counterparty_deal_room",
        "recipient_type": "court",
        "recipient_name": "Judge",
        "purpose": "Filing",
    }
    rel_res = c.post(f"/v1/matters/{mid}/documents/{doc_id}/releases", json=body)
    assert rel_res.status_code == 200
    release_data = rel_res.json()["release"]
    assert release_data["status"] == "refused"

    r = c.get(f"/v1/matters/{mid}/privilege-log?format=json")
    assert r.status_code == 200
    records = r.json()["records"]
    assert len(records) >= 1
    refused_rec = next(rec for rec in records if rec["release_id"] == release_data["id"])
    assert refused_rec["release_status"] == "refused"
    assert refused_rec["document_filename"] == "macro.docm"
    assert refused_rec["action"] == "refuse"
