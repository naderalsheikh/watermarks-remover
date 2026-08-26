"""GET /v1/matters/{id}/jobs/{job_id}/certificate — per-job custody
certificate (PR 33): a self-contained HTML artifact for one completed
transaction, distinct from the matter-level summary report (admin-gated,
whole-chain) and the raw manifest (JSON, no narrative/limitations).

Read-gated by design: every fact shown is already visible through the
existing read-gated job-detail and manifest routes, plus a narrow,
job-scoped custody assertion (this job's own audit rows, individually
hash-recomputed) rather than the matter's full audit chain.
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
from app.main import (
    APPROVED_BUT_NO_OP_MARKER,
    NO_DECISION_MARKER,
    OPERATOR_KEPT_MARKER,
    create_app,
)
from app.migrate import upgrade_head
from app.models import Job, MatterAcl
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


def _matter(c, name: str = "Certificate Matter") -> str:
    r = c.post("/v1/matters", json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _upload(c, mid: str, name: str) -> str:
    data = (FIXTURES / name).read_bytes()
    r = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": (name, data, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _sanitize(c, mid, doc_id, **body):
    r = c.post(f"/v1/matters/{mid}/documents/{doc_id}/sanitize-jobs", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _certificate(c, mid, jid):
    return c.get(f"/v1/matters/{mid}/jobs/{jid}/certificate")


def _audit_actions(c, mid) -> list[dict]:
    return c.get(f"/v1/matters/{mid}/audit").json()["events"]


# --- permission behavior ---------------------------------------------------------


def test_certificate_requires_read_perm(env):
    c, _sf, cfg = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    job = _sanitize(c, mid, doc)

    stranger = "oidc:stranger"
    c.cookies.set("cc_session", issue_session(cfg, stranger))
    r = _certificate(c, mid, job["id"])
    assert r.status_code == 403


def test_certificate_readable_by_read_only_principal(env):
    """A principal with only 'read' (no admin) can pull the certificate --
    unlike GET .../audit and GET .../summary, which require admin because
    they disclose the matter's full audit chain / other jobs' rows."""
    c, sf, cfg = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    job = _sanitize(c, mid, doc)

    reader = "oidc:reader"
    with sf() as s:
        s.add(MatterAcl(matter_id=mid, user_id=reader, perm="read"))
        s.commit()
    c.cookies.set("cc_session", issue_session(cfg, reader))
    r = _certificate(c, mid, job["id"])
    assert r.status_code == 200, r.text
    # Same reader is NOT an admin -- the admin-gated routes must still 403,
    # confirming the certificate's read-only gate is a real distinction,
    # not an accidental broadening of what read-only principals can see.
    assert c.get(f"/v1/matters/{mid}/audit").status_code == 403
    assert c.get(f"/v1/matters/{mid}/summary").status_code == 403


def test_certificate_404s_for_unknown_or_cross_matter_job(env):
    c, _, _ = env
    mid1 = _matter(c, "M1")
    mid2 = _matter(c, "M2")
    doc = _upload(c, mid1, "spa.docx")
    job = _sanitize(c, mid1, doc)

    assert _certificate(c, mid1, "nope").status_code == 404
    assert _certificate(c, mid2, job["id"]).status_code == 404


# --- content: completed sanitize job ----------------------------------------------


def test_certificate_content_for_completed_sanitize_job(env):
    c, _, _ = env
    mid = _matter(c, "Content Matter")
    doc = _upload(c, mid, "spa.docx")
    job = _sanitize(c, mid, doc, policy_id="external_sharing", reason="external review")
    assert job["status"] == "done", job["error"]

    r = _certificate(c, mid, job["id"])
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/html")
    body = r.text

    assert "Content Matter" in body
    assert mid in body
    assert "spa.docx" in body
    assert job["id"] in body
    assert "sanitize" in body
    assert "done" in body
    assert "external_sharing" in body

    manifest = c.get(f"/v1/matters/{mid}/jobs/{job['id']}/manifest").json()
    doc_detail = c.get(f"/v1/matters/{mid}/documents/{doc}").json()
    assert doc_detail["sha256"] in body
    assert manifest["derivative"]["sha256"] in body
    assert "passed" in body  # verification.pass True

    # Never claims cleanliness in bare terms -- doctrine point 5.
    assert "This document is clean" not in body
    assert "This document is safe" not in body

    # PR 35 UX pass: standalone-export banner with a real way back to the
    # job page this certificate belongs to.
    assert "STANDALONE EXPORT" in body
    assert f'href="/matters/job?matter={mid}&amp;job={job["id"]}"' in body


# --- no-decision / operator-kept limitations --------------------------------------


def test_certificate_shows_no_decision_limitation_prominently(env):
    """production policy, no finding_decisions -> comments_and_notes
    resolves to "keep" with reason "no_decision" -- NO_DECISION_MARKER
    must appear inside the certificate's own <div class="limitations">
    section, not just somewhere in the page."""
    c, _, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    job = _sanitize(c, mid, doc, policy_id="production")
    assert job["status"] == "done", job["error"]

    body = _certificate(c, mid, job["id"]).text
    assert NO_DECISION_MARKER in body
    limitations_block = body.split('class="limitations"')[1]
    assert NO_DECISION_MARKER in limitations_block


def test_certificate_shows_operator_kept_limitation(env):
    """finding_decisions={..., "keep"} -> reason "operator_kept" --
    OPERATOR_KEPT_MARKER, a *reviewed* keep, must be disclosed distinctly
    from an unreviewed one. spa.docx has two approve-default subtypes
    present (comments_and_notes, tracked_changes); both need an explicit
    decision or the undecided one would still show NO_DECISION_MARKER --
    that per-subtype distinction is itself correct behavior, not a test
    artifact to paper over."""
    c, _, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    job = _sanitize(
        c, mid, doc, policy_id="production",
        finding_decisions={"comments_and_notes": "keep", "tracked_changes": "keep"},
    )
    assert job["status"] == "done", job["error"]

    body = _certificate(c, mid, job["id"]).text
    assert OPERATOR_KEPT_MARKER in body
    assert NO_DECISION_MARKER not in body  # a decision *was* supplied for every subtype present


# The approved-but-no-op marker only fires for one specific subtype
# (layer_a_non_body — see policies.py's APPROVED_BUT_NO_OP_MARKER
# comment), which spa.docx's findings don't reach through the API.
# Exercised directly against a seeded Job row instead, same as the
# refused/failed test below -- the certificate route only ever reads
# job.result_json back, so seeding it directly still exercises the real
# rendering path end to end.
def test_certificate_shows_approved_but_no_op_limitation(env):
    c, sf, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    with sf() as s:
        job = Job(
            id="japnop",
            matter_id=mid,
            document_id=doc,
            kind="sanitize",
            policy_id="external_sharing",
            status="done",
            result_json={
                "derivative": "spa.docx",
                "verification_pass": True,
                "manifest": {
                    "policy": {"id": "external_sharing", "version": 1},
                    "derivative": {"sha256": "d" * 64},
                    "actions": [f"layer_a_non_body: {APPROVED_BUT_NO_OP_MARKER}"],
                    "findings_before": [],
                    "verification": {"pass": True, "checks": []},
                },
            },
        )
        s.add(job)
        s.commit()

    body = _certificate(c, mid, "japnop").text
    assert APPROVED_BUT_NO_OP_MARKER in body
    limitations_block = body.split('class="limitations"')[1]
    assert APPROVED_BUT_NO_OP_MARKER in limitations_block


# --- refused / failed jobs ---------------------------------------------------------


def test_certificate_for_refused_job_discloses_status_and_reason(env):
    c, _, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "macro.docm")
    job = _sanitize(c, mid, doc, policy_id="external_sharing")
    assert job["status"] == "refused"

    body = _certificate(c, mid, job["id"]).text
    assert "refused" in body
    assert "no derivative was produced" in body
    assert "macro" in body.lower()
    limitations_block = body.split('class="limitations"')[1]
    assert "refused" in limitations_block.lower()
    # No derivative hash to show for a refused job.
    assert "none — no derivative was produced for this job" in body


def test_certificate_for_failed_job_discloses_status_and_error(env):
    c, sf, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    with sf() as s:
        s.add(
            Job(
                id="jfailed",
                matter_id=mid,
                document_id=doc,
                kind="sanitize",
                policy_id="external_sharing",
                status="failed",
                error="worker exited rc=1: boom",
                result_json=None,
            )
        )
        s.commit()

    body = _certificate(c, mid, "jfailed").text
    assert "failed" in body
    assert "worker exited rc=1: boom" in body


# --- escaping ------------------------------------------------------------------------


def test_certificate_escapes_dynamic_values(env):
    c, sf, _ = env
    mid = _matter(c, "<script>alert(1)</script>")
    doc = _upload(c, mid, "spa.docx")
    with sf() as s:
        s.add(
            Job(
                id="jxss",
                matter_id=mid,
                document_id=doc,
                kind="sanitize",
                policy_id="external_sharing",
                status="failed",
                error="<img src=x onerror=alert(2)>",
                result_json=None,
            )
        )
        s.commit()

    body = _certificate(c, mid, "jxss").text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
    assert "<img src=x onerror=alert(2)>" not in body
    assert "&lt;img" in body


# --- certificate.issued on every pull, including repeats ---------------------------


def test_certificate_issued_event_appended_on_every_pull(env):
    c, _, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    job = _sanitize(c, mid, doc, policy_id="external_sharing")

    for _ in range(3):
        assert _certificate(c, mid, job["id"]).status_code == 200

    events = [e for e in _audit_actions(c, mid) if e["action"] == "certificate.issued"]
    assert len(events) == 3
    for e in events:
        assert e["payload"] == {
            "job_id": job["id"],
            "document_id": doc,
            "kind": "sanitize",
            "policy_id": "external_sharing",
            "status": "done",
        }


# --- no original bytes; no engine call ---------------------------------------------


def test_certificate_never_includes_original_bytes(env):
    c, _, _ = env
    mid = _matter(c)
    original_bytes = (FIXTURES / "spa.docx").read_bytes()
    doc = _upload(c, mid, "spa.docx")
    job = _sanitize(c, mid, doc, policy_id="external_sharing")

    r = _certificate(c, mid, job["id"])
    assert original_bytes not in r.content
    # A docx is a zip; its local-file-header magic bytes are a cheap,
    # format-independent tripwire for "raw binary content leaked in".
    assert b"PK\x03\x04" not in r.content


def test_certificate_route_never_imports_the_engine():
    """The certificate is built entirely from data already stored on the
    Job row (result_json/manifest) by the time it's requested -- it must
    never call back into the engine to (re-)compute anything. Belt-and-
    suspenders on top of test_worker_isolation.py::
    test_api_module_never_imports_parsers, which already statically bans
    engine_api/clean_to_bundle/inspect_bytes from all of main.py (so this
    route structurally cannot reference them even if someone tried) --
    this test names the certificate route specifically so the guarantee
    is discoverable from this file too."""
    src = (APP_DIR / "main.py").read_text()
    route_start = src.index('@app.get("/v1/matters/{matter_id}/jobs/{job_id}/certificate")')
    route_end = src.index("@app.get", route_start + 1)
    route_src = src[route_start:route_end]
    for banned in ("engine_api", "clean_to_bundle", "inspect_bytes", "import policies"):
        assert banned not in route_src
