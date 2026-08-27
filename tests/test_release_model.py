"""POST .../releases -- the Release object (PR 39): the business/custody
event wrapping a Job. Job stays the execution mechanism, unchanged;
Release adds recipient/purpose/profile context and always terminates as
either a full release packet (done) or a structured refusal/failure
record (release_result.json) -- never neither. Covers single-document
release (done + refused), batch release (mixed outcome, each Release
completing independently of the others), the release-profile catalog,
and audit-chain placement (no parallel chain -- see
test_release_events_live_in_the_same_matter_audit_chain).

Existing /sanitize-jobs and /batches routes are untouched by this pass;
they're covered by test_app.py and test_batches.py respectively.
"""

from __future__ import annotations

import io
import json
import sys
import time
import zipfile
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
from app.models import AuditEvent, Release

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"
PW = "pw12345"


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
    c.close()


def _matter(c) -> str:
    return c.post("/v1/matters", json={"name": "Release Matter"}).json()["id"]


def _upload(c, mid: str, name: str) -> str:
    data = (FIXTURES / name).read_bytes()
    r = c.post(f"/v1/matters/{mid}/documents", files={"file": (name, data, "application/octet-stream")})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _create_release(c, mid, doc_id, **overrides):
    body = {
        "profile_id": "counterparty_deal_room",
        "recipient_type": "opposing_counsel",
        "recipient_name": "Jane Doe, Esq.",
        "purpose": "settlement negotiation",
        **overrides,
    }
    return c.post(f"/v1/matters/{mid}/documents/{doc_id}/releases", json=body)


def _wait_batch_done(c, mid, bid, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = c.get(f"/v1/matters/{mid}/batches/{bid}").json()
        if body["finished_utc"] is not None:
            return body
        time.sleep(0.05)
    raise TimeoutError("batch did not finish")


# --- release profiles catalog ---------------------------------------------------


def test_list_release_profiles(env):
    c, _sf, _cfg = env
    r = c.get("/v1/release-profiles")
    assert r.status_code == 200
    body = r.json()
    ids = {p["id"] for p in body["release_profiles"]}
    assert ids == {"counterparty_deal_room", "public_filing_anonymized", "ediscovery_production"}
    assert "opposing_counsel" in body["recipient_types"]


# --- single-document release: done -----------------------------------------------


def test_single_document_release_done(env):
    c, sf, _cfg = env
    mid = _matter(c)
    doc_id = _upload(c, mid, "spa.docx")
    r = _create_release(c, mid, doc_id)
    assert r.status_code == 200, r.text
    body = r.json()
    release, job, result = body["release"], body["job"], body["release_result"]

    assert release["status"] == "done"
    assert release["job_id"] == job["id"]
    assert release["policy_id"] == "external_sharing"
    assert release["profile_id"] == "counterparty_deal_room"
    assert release["recipient_type"] == "opposing_counsel"
    assert release["recipient_name"] == "Jane Doe, Esq."
    assert release["intended_external"] is True
    assert release["batch_id"] is None

    assert result["release_id"] == release["id"]
    assert result["status"] == "done"
    assert result["reason"] == ""
    assert result["original_sha256"]
    assert result["audit_refs"]["release_created_seq"] is not None
    assert result["audit_refs"]["release_terminal_seq"] is not None
    assert result["anchor"]["type"] == "none"

    with sf() as s:
        row = s.get(Release, release["id"])
        assert row is not None
        assert row.status == "done"
        assert row.finished_utc is not None

    # release_packet.json (job_bundle) picks up release_id + original_sha256,
    # additive to what it already carried (PR 37).
    bundle = c.get(f"/v1/matters/{mid}/jobs/{job['id']}/bundle")
    assert bundle.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(bundle.content))
    packet = json.loads(zf.read("release_packet.json"))
    assert packet["release_id"] == release["id"]
    assert packet["original_sha256"] == result["original_sha256"]


# --- single-document release: refused ---------------------------------------------


def test_single_document_release_refused(env):
    c, _sf, _cfg = env
    mid = _matter(c)
    doc_id = _upload(c, mid, "macro.docm")
    r = _create_release(c, mid, doc_id)
    assert r.status_code == 200, r.text
    body = r.json()
    release, result = body["release"], body["release_result"]

    assert release["status"] == "refused"
    assert result["status"] == "refused"
    assert result["reason"]
    assert "refused" in result["limitations"][0]

    # No packet exists for a refused release -- no derivative was produced.
    bundle = c.get(f"/v1/matters/{mid}/jobs/{release['job_id']}/bundle")
    assert bundle.status_code == 409

    # But release_result.json is still fetchable on its own -- "packet or
    # refusal" never collapses into "packet, or nothing machine-checkable".
    r2 = c.get(f"/v1/matters/{mid}/releases/{release['id']}/result")
    assert r2.status_code == 200
    fetched = r2.json()
    assert fetched["status"] == "refused"
    assert fetched["release_id"] == release["id"]


# --- validation --------------------------------------------------------------------


def test_unknown_profile_id_rejected(env):
    c, _sf, _cfg = env
    mid = _matter(c)
    doc_id = _upload(c, mid, "spa.docx")
    r = _create_release(c, mid, doc_id, profile_id="not_a_real_profile")
    assert r.status_code == 400


def test_unknown_recipient_type_rejected(env):
    c, _sf, _cfg = env
    mid = _matter(c)
    doc_id = _upload(c, mid, "spa.docx")
    r = _create_release(c, mid, doc_id, recipient_type="not_a_real_type")
    assert r.status_code == 400


# --- GET release detail -------------------------------------------------------------


def test_get_release_detail(env):
    c, _sf, _cfg = env
    mid = _matter(c)
    doc_id = _upload(c, mid, "spa.docx")
    created = _create_release(c, mid, doc_id).json()["release"]
    r = c.get(f"/v1/matters/{mid}/releases/{created['id']}")
    assert r.status_code == 200
    assert r.json() == created


def test_get_release_detail_404_for_other_matter(env):
    c, _sf, _cfg = env
    mid = _matter(c)
    other_mid = _matter(c)
    doc_id = _upload(c, mid, "spa.docx")
    created = _create_release(c, mid, doc_id).json()["release"]
    r = c.get(f"/v1/matters/{other_mid}/releases/{created['id']}")
    assert r.status_code == 404


# --- batch release: mixed outcome, independent per-release completion --------------


def test_batch_release_mixed_outcome(env):
    c, sf, _cfg = env
    mid = _matter(c)
    good_id = _upload(c, mid, "spa.docx")
    bad_id = _upload(c, mid, "macro.docm")
    r = c.post(
        f"/v1/matters/{mid}/releases",
        json={
            "document_ids": [good_id, bad_id],
            "profile_id": "counterparty_deal_room",
            "recipient_type": "client",
            "purpose": "quarterly production",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    batch_id = body["batch"]["id"]
    releases = body["releases"]
    assert len(releases) == 2
    assert all(rel["status"] == "queued" for rel in releases)
    assert all(rel["batch_id"] == batch_id for rel in releases)

    _wait_batch_done(c, mid, batch_id)

    with sf() as s:
        rows = {row.document_id: row for row in s.query(Release).filter(Release.batch_id == batch_id).all()}
        assert rows[good_id].status == "done"
        assert rows[bad_id].status == "refused"
        assert rows[good_id].finished_utc is not None
        assert rows[bad_id].finished_utc is not None

    # Each Release completed independently -- release_result is fetchable
    # per-release without needing the batch itself to have "finished" in
    # a business sense beyond BatchDispatcher's own job-level completion.
    good_release_id = next(rel["id"] for rel in releases if rel["document_id"] == good_id)
    result = c.get(f"/v1/matters/{mid}/releases/{good_release_id}/result").json()
    assert result["status"] == "done"


def test_batch_release_rejects_non_bulk_safe_profile(env):
    c, _sf, _cfg = env
    mid = _matter(c)
    doc_id = _upload(c, mid, "spa.docx")
    r = c.post(
        f"/v1/matters/{mid}/releases",
        json={"document_ids": [doc_id], "profile_id": "ediscovery_production", "recipient_type": "court"},
    )
    assert r.status_code == 400


def test_batch_release_rejects_empty_document_ids(env):
    c, _sf, _cfg = env
    mid = _matter(c)
    r = c.post(
        f"/v1/matters/{mid}/releases",
        json={"document_ids": [], "profile_id": "counterparty_deal_room", "recipient_type": "client"},
    )
    assert r.status_code == 400


# --- audit chain: no parallel chain, release events live in the matter chain -------


def test_release_events_live_in_the_same_matter_audit_chain(env):
    c, sf, _cfg = env
    mid = _matter(c)
    doc_id = _upload(c, mid, "spa.docx")
    release_id = _create_release(c, mid, doc_id).json()["release"]["id"]

    with sf() as s:
        events = s.query(AuditEvent).filter(AuditEvent.matter_id == mid).order_by(AuditEvent.seq).all()
        actions = [e.action for e in events]
        assert "release.created" in actions
        assert "release.terminal" in actions
        assert "job.sanitize" in actions
        # The business event brackets the execution event, never the
        # reverse: created before the job ran, terminal after it finished.
        assert actions.index("release.created") < actions.index("job.sanitize") < actions.index("release.terminal")
        # One gapless, hash-chained sequence -- no parallel chain for
        # Release's own events (document upload is also audited, so this
        # doesn't necessarily start at seq 1).
        seqs = [e.seq for e in events]
        assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))
        release_created = next(e for e in events if e.action == "release.created")
        assert release_created.payload["release_id"] == release_id


def test_batch_release_created_events_fire_per_release_not_once_per_batch(env):
    """Constraint: Batch is only the grouping/execution envelope; each
    Release gets its own release.created, distinct from the one shared
    batch.created -- "batch completed" and "each release completed" must
    never blur into one event."""
    c, sf, _cfg = env
    mid = _matter(c)
    doc_ids = [_upload(c, mid, "spa.docx"), _upload(c, mid, "spa.txt")]
    r = c.post(
        f"/v1/matters/{mid}/releases",
        json={"document_ids": doc_ids, "profile_id": "counterparty_deal_room", "recipient_type": "client"},
    )
    batch_id = r.json()["batch"]["id"]
    _wait_batch_done(c, mid, batch_id)

    with sf() as s:
        events = s.query(AuditEvent).filter(AuditEvent.matter_id == mid).all()
        created_events = [e for e in events if e.action == "release.created"]
        terminal_events = [e for e in events if e.action == "release.terminal"]
        batch_created = [e for e in events if e.action == "batch.created"]
        batch_completed = [e for e in events if e.action == "batch.completed"]
        assert len(created_events) == 2
        assert len(terminal_events) == 2
        assert len(batch_created) == 1
        assert len(batch_completed) == 1
