"""One document, the whole chain, checked the way a recipient would.

Every other test in this suite proves one link. This proves they compose,
which is a different claim and the one a buyer actually cares about: a
document with real problems goes in, and what comes out the other end is a
packet whose every assertion survives an offline verifier that shares no
code with the thing that produced it.

The document is built to exercise the links that were added most recently
and therefore have the least combined mileage:

  concealed text        -> must be REMOVED (Lane B stripper), and the
                           removal proved by content, not by a detector
                           going quiet (verify.py hidden_text_removed)
  a comment             -> stripped
  tracked changes       -> accepted, deleted text proved absent
  authoring identity    -> scrubbed
  edit-session exhaust  -> RSIDs and docId removed, and the retention
                           decision for what stays recorded (Lane A4)
  hidden sheet analogue -> not present here; hidden_structure is XLSX-only

and then asserts the four artifacts a recipient holds agree with each other
and with the derivative's actual bytes.

If this test ever fails, something in the chain is claiming more than it
delivers, which is the only failure mode this product cannot absorb.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "service" / "scripts"), str(REPO / "service"), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import counselclear_verify_release_packet as verifier
from app.config import Config
from app.db import make_engine
from app.main import create_app
from app.migrate import upgrade_head
from test_custody_truthfulness import W_DECL, _document, _docx

PW = "pw12345"
CONCEALED = "ATTORNEY WORK PRODUCT DO NOT PRODUCE"
DELETED = "the struck-out indemnity clause"
VISIBLE = "The parties agree as set out herein."


def _loaded_document() -> bytes:
    body = (
        f"<w:p><w:r><w:t>{VISIBLE}</w:t></w:r></w:p>"
        # concealed text, split across two w:t the way Word writes it
        "<w:p><w:r><w:rPr><w:vanish/></w:rPr>"
        f"<w:t>{CONCEALED[:16]}</w:t><w:t>{CONCEALED[16:]}</w:t></w:r></w:p>"
        # tracked deletion whose text must not survive
        f"<w:p><w:del><w:r><w:delText>{DELETED}</w:delText></w:r></w:del></w:p>"
        # a comment anchor
        "<w:p><w:commentRangeStart/><w:r><w:t>anchored</w:t></w:r>"
        "<w:commentRangeEnd/><w:r><w:commentReference/></w:r></w:p>"
    )
    settings = (
        f'<?xml version="1.0"?><w:settings {W_DECL} '
        'xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml">'
        '<w:rsids><w:rsid w:val="00AB12CD"/></w:rsids>'
        '<w15:docId w15:val="{DEAD-BEEF}"/></w:settings>'
    ).encode()
    core = (
        b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="c" xmlns:dc="d" '
        b'xmlns:dcterms="t"><dc:title>Master Services Agreement</dc:title>'
        b"<dc:creator>Jane Counsel</dc:creator><cp:revision>7</cp:revision>"
        b"<dcterms:created>2026-01-01T00:00:00Z</dcterms:created>"
        b"</cp:coreProperties>"
    )
    comments = (
        f'<?xml version="1.0"?><w:comments {W_DECL}><w:comment>'
        "<w:p><w:r><w:t>privileged reviewer note</w:t></w:r></w:p>"
        "</w:comment></w:comments>"
    ).encode()
    return _docx(
        {
            "word/document.xml": _document(body),
            "word/settings.xml": settings,
            "word/comments.xml": comments,
            "docProps/core.xml": core,
        }
    )


@pytest.fixture()
def released(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    monkeypatch.setenv("COUNSELCLEAR_TSA_URL", "off")  # no network in tests
    cfg = Config(tmp_path / "data")
    make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    mid = c.post("/v1/matters", json={"name": "Full chain"}).json()["id"]
    doc = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("msa.docx", _loaded_document(), "application/octet-stream")},
    ).json()["id"]
    created = c.post(
        f"/v1/matters/{mid}/documents/{doc}/releases",
        json={
            "profile_id": "counterparty_deal_room",
            "recipient_type": "opposing_counsel",
            "recipient_name": "Jane Doe, Esq.",
            "purpose": "negotiation",
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["job"]["status"] == "done", body["job"].get("error")

    raw = c.get(f"/v1/matters/{mid}/jobs/{body['job']['id']}/bundle").content
    out = tmp_path / "packet"
    out.mkdir()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(out)
    return c, mid, body, out


def _derivative_text(packet_dir: Path) -> str:
    import container_meta

    (deriv,) = list((packet_dir / "derivative").iterdir())
    return container_meta.extract_ooxml_plaintext(deriv.read_bytes(), "docx")


def test_the_concealed_and_deleted_text_are_actually_gone(released):
    """The claim a recipient most needs to be true, checked against the
    derivative's own bytes rather than any record describing it."""
    _c, _mid, _body, out = released
    text = _derivative_text(out)
    assert VISIBLE in text, "visible content must survive"
    assert CONCEALED[:16] not in text, "concealed text must be removed, not hidden again"
    assert DELETED not in text, "tracked-deleted text must not survive Accept All"
    assert "privileged reviewer note" not in text, "comment content must be stripped"


def test_the_derivative_keeps_no_edit_session_correlators(released):
    _c, _mid, _body, out = released
    (deriv,) = list((out / "derivative").iterdir())
    with zipfile.ZipFile(deriv) as zf:
        names = set(zf.namelist())
        assert "word/comments.xml" not in names, "comment part must be dropped"
        settings = zf.read("word/settings.xml").decode() if "word/settings.xml" in names else ""
    assert "w:rsid" not in settings
    assert "docId" not in settings


def test_every_record_agrees_with_the_derivative(released):
    """Four artifacts describe one file. A recipient reading any of them must
    reach the same conclusion, or the record is worse than useless."""
    _c, _mid, _body, out = released
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    packet = json.loads((out / "release_packet.json").read_text(encoding="utf-8"))
    (deriv,) = list((out / "derivative").iterdir())

    import hashlib

    actual = hashlib.sha256(deriv.read_bytes()).hexdigest()
    assert manifest["derivative"]["sha256"] == actual
    assert packet["hashes"]["derivative"]["sha256"] == actual

    # The disposition ledger must account for every pre-sanitize finding,
    # and must not claim removal the verifier did not confirm.
    dispositions = {d["subtype"]: d for d in manifest["dispositions"]}
    assert dispositions, "a loaded document must produce a disposition ledger"
    assert dispositions["hidden_text"]["postcondition"] == "removed_confirmed"
    assert dispositions["comments_and_notes"]["postcondition"] == "removed_confirmed"
    for row in dispositions.values():
        assert row["present_before"] is True
        if row["action"] in ("strip", "sanitize", "accept_all", "rebuild"):
            assert row["postcondition"] == "removed_confirmed", row


def test_verification_proves_content_not_just_detector_silence(released):
    """`reinspect_targeted_gone` only re-runs a heuristic. These two checks
    read the actual words, and are the difference between "a detector went
    quiet" and "the text is not in the file"."""
    _c, _mid, _body, out = released
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    checks = {c["name"]: c for c in manifest["verification"]["checks"]}
    assert manifest["verification"]["pass"] is True
    assert checks["hidden_text_removed"]["pass"] is True
    assert checks["accept_all_deleted_text_absent"]["pass"] is True


def test_the_certificate_discloses_what_survived(released):
    """Nothing here is retained, so the limitations section must say that in
    scoped terms -- never a bare all-clear -- and the residual-metadata
    section must still state what the policy deliberately kept."""
    c, mid, body, _out = released
    html = c.get(f"/v1/matters/{mid}/jobs/{body['job']['id']}/certificate").text
    limitations = html.split('class="limitations"')[1]
    assert "REMAINS IN THE DERIVATIVE" not in limitations
    assert "No limitations flagged for this job" not in limitations
    assert "not that the document is free" in limitations
    # dc:title is deliberately retained; the certificate must say so.
    assert "Residual authoring metadata" in html
    assert "Deliberately retained" in html
    assert "Finding dispositions" in html


def test_an_offline_verifier_that_shares_no_code_agrees(released):
    """The recipient's own check. This tool imports nothing from service/,
    makes no network calls, and only reads the bytes it was handed."""
    _c, _mid, _body, out = released
    report = verifier.verify_release_packet(out)
    assert report.valid, report.to_text()
    text = report.to_text().lower()
    # It must never claim more than it checked. The bare words appear
    # legitimately inside DENIALS ("not independently timestamped or
    # unforgeable") -- that negation is the sanctioned pattern, and the
    # same one the certificate's disclaimer uses for "clean"/"safe". What
    # must never appear is the affirmative form.
    for banned in (
        "is unforgeable",
        "is court-proof",
        "is unimpeachable",
        "is independently timestamped",
        "packet is verified",
    ):
        assert banned not in text, banned
    assert "not externally anchored" in text


def test_tampering_with_the_derivative_fails_the_recipient_check(released):
    """The whole chain is worthless if it cannot detect this. Alter one byte
    of the derivative and every downstream assertion must stop agreeing."""
    _c, _mid, _body, out = released
    (deriv,) = list((out / "derivative").iterdir())
    deriv.write_bytes(deriv.read_bytes() + b"\x00")
    report = verifier.verify_release_packet(out)
    assert not report.valid, "a modified derivative must fail verification"
