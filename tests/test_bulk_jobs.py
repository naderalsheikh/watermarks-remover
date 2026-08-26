"""POST /v1/matters/{id}/bulk-jobs — one job per document, audited per job.

The endpoint is deliberately narrow: inspect on any document, sanitize on
bulk_safe policies only (no approve-default subtype cells, so no per-finding
decisions are required), never Layer B. Request validation happens fully
before any job starts, and every job's outcome is returned and audited
individually — a refusal or failure can never hide behind a blanket
"bulk succeeded" (the trust rule this endpoint exists to keep).
"""

from __future__ import annotations

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
from app.main import NO_DECISION_MARKER, create_app
from app.migrate import upgrade_head
from app.models import MatterAcl
from app.security import issue_session

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
    return c.post("/v1/matters", json={"name": "Bulk Matter"}).json()["id"]


def _upload(c, mid: str, name: str) -> str:
    data = (FIXTURES / name).read_bytes()
    r = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": (name, data, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _bulk(c, mid, doc_ids, kind, policy_id="external_sharing", reason=""):
    return c.post(
        f"/v1/matters/{mid}/bulk-jobs",
        json={"document_ids": doc_ids, "kind": kind, "policy_id": policy_id, "reason": reason},
    )


def _audit_actions(c, mid) -> list[dict]:
    return c.get(f"/v1/matters/{mid}/audit").json()["events"]


# --- happy paths ---------------------------------------------------------------


def test_bulk_inspect_reports_each_document(env):
    c, _, _ = env
    mid = _matter(c)
    d1 = _upload(c, mid, "spa.docx")
    d2 = _upload(c, mid, "spa.txt")

    r = _bulk(c, mid, [d1, d2], "inspect")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"] == {"requested": 2, "done": 2, "refused": 0, "failed": 0, "queued": 0, "running": 0}
    assert [res["document_id"] for res in body["results"]] == [d1, d2]
    assert all(res["status"] == "done" for res in body["results"])
    assert all(res["job_id"] for res in body["results"])
    # Each document's job is audited individually, with its own job id.
    events = [e for e in _audit_actions(c, mid) if e["action"] == "job.inspect"]
    assert len(events) == 2
    assert len({e["payload"]["job_id"] for e in events}) == 2
    assert {e["payload"]["document_id"] for e in events} == {d1, d2}


def test_bulk_sanitize_mixed_outcomes_are_per_document(env):
    """One document sanitizes clean; the other two hit refusal classes
    (macro-enabled file, signed PDF without attestation). The response must
    show each status where it happened — never a blanket success."""
    c, _, _ = env
    mid = _matter(c)
    good = _upload(c, mid, "spa.docx")
    macro = _upload(c, mid, "macro.docm")
    signed = _upload(c, mid, "signed.pdf")

    r = _bulk(c, mid, [good, macro, signed], "sanitize", policy_id="external_sharing")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"] == {"requested": 3, "done": 1, "refused": 2, "failed": 0, "queued": 0, "running": 0}
    by_doc = {res["document_id"]: res for res in body["results"]}
    assert by_doc[good]["status"] == "done" and by_doc[good]["error"] == ""
    assert by_doc[macro]["status"] == "refused"
    assert "macro" in by_doc[macro]["error"].lower()
    assert by_doc[signed]["status"] == "refused"
    assert "signature" in by_doc[signed]["error"].lower()

    # Audit carries all three outcomes individually.
    events = [e for e in _audit_actions(c, mid) if e["action"] == "job.sanitize"]
    assert len(events) == 3
    assert len({e["payload"]["job_id"] for e in events}) == 3
    statuses = {e["payload"]["document_id"]: e["payload"]["status"] for e in events}
    assert statuses == {good: "done", macro: "refused", signed: "refused"}


def test_bulk_sanitize_privacy_only_leaves_no_no_decision_marker(env):
    """privacy_only is bulk-safe: it has no approve-default cells, so its
    keeps are policy-default keeps — the manifest must contain no
    NO_DECISION_MARKER (which would mean findings kept without review)."""
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    r = _bulk(c, mid, [d], "sanitize", policy_id="privacy_only")
    assert r.status_code == 200, r.text
    res = r.json()["results"][0]
    assert res["status"] == "done"
    assert res["policy_id"] == "privacy_only"

    manifest = c.get(f"/v1/matters/{mid}/jobs/{res['job_id']}/manifest").json()
    assert all(NO_DECISION_MARKER not in a for a in manifest["actions"])


# --- request validation: nothing starts on a bad request -----------------------


def test_bulk_rejects_non_bulk_safe_policies(env):
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    for policy_id in ("production", "evidence_preservation"):
        r = _bulk(c, mid, [d], "sanitize", policy_id=policy_id)
        assert r.status_code == 400, policy_id
        assert "per-finding decisions" in r.json()["detail"] or "no derivative" in r.json()["detail"]
    # Nothing ran: no jobs, no job audit events (only the seeding events:
    # matter.create / document.upload).
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0
    assert all(
        e["action"] not in ("job.inspect", "job.sanitize") for e in _audit_actions(c, mid)
    )


def test_bulk_rejects_unknown_documents_before_running_anything(env):
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    r = _bulk(c, mid, [d, "nope123"], "inspect")
    assert r.status_code == 400
    assert "not documents of this matter" in r.json()["detail"]
    assert "nope123" in r.json()["detail"]
    # The valid document must not have been processed either — the request
    # failed as a whole, no partial bulk.
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0


def test_bulk_rejects_empty_duplicates_unknown_kind_and_cap(env):
    c, _, _ = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")

    assert _bulk(c, mid, [], "inspect").status_code == 400
    assert _bulk(c, mid, [d, d], "inspect").status_code == 400
    assert _bulk(c, mid, [d], "frobnicate").status_code == 400
    too_many = [f"x{i}" for i in range(101)]
    assert _bulk(c, mid, too_many, "inspect").status_code == 400
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0


def test_bulk_requires_the_kind_perm(env):
    c, sf, cfg = env
    mid = _matter(c)
    d = _upload(c, mid, "spa.docx")
    alice = "oidc:alice"
    with sf() as s:
        s.add(MatterAcl(matter_id=mid, user_id=alice, perm="read"))
        s.commit()

    c.cookies.set("cc_session", issue_session(cfg, alice))
    r = _bulk(c, mid, [d], "sanitize")
    assert r.status_code == 403
    assert "sanitize" in r.json()["detail"]
    assert c.get(f"/v1/matters/{mid}/jobs").json()["total"] == 0


# --- bulk_safe flag stays honest against the engine ----------------------------


def test_bulk_safe_flags_match_policy_engine():
    """main.py's POLICIES literal (bulk_safe) must stay in sync with the
    engine's actual subtype table, the same way NO_DECISION_MARKER does:
    a bulk_safe policy must have NO approve-default subtype cells (a
    sanitize without per-finding decisions would silently keep them), and
    only the two decision-free derivative-producing policies are bulk-safe.
    """
    import policies as policies_mod
    from app.main import POLICIES as main_policies

    declared = {p["id"]: p["bulk_safe"] for p in main_policies}
    assert set(declared) == set(policies_mod.DEFAULT_POLICIES)
    for pid, bulk_safe in declared.items():
        # One-way implication: bulk-safe must be decision-free (an approve-
        # default cell without a per-finding decision silently keeps). The
        # converse does not hold — evidence_preservation has no approve
        # cells but produces no derivative, so it is pinned below instead.
        if bulk_safe:
            assert "approve" not in set(policies_mod.DEFAULT_POLICIES[pid].values()), pid
    assert declared["external_sharing"] is True
    assert declared["privacy_only"] is True
    assert declared["production"] is False
    assert declared["evidence_preservation"] is False
