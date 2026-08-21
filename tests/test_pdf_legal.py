#!/usr/bin/env python3
"""PR 5: PDF legal inspectors (Annots/JS/EmbeddedFiles/AcroForm/incrementals)
and the second qpdf --remove-info pass with the producer allowlist check."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import pdf_legal
import pytest
from container_meta import _pdf_structured_blob, clean_pdf, inspect_container
from findings import findings_for_report

NEED_PDF_TOOLS = pytest.mark.skipif(
    not (shutil.which("qpdf") and shutil.which("exiftool")),
    reason="exiftool and qpdf required",
)


def _pdf(*objects: bytes, info: bytes | None = None, extra_startxref: int = 0) -> bytes:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> >>",
        b"<< /Producer (Claude Opus) /Creator (Anthropic Claude) >>",
    ]
    if info is not None:
        objs[3] = info
    objs.extend(objects)
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\n" % (len(objs) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    for _ in range(extra_startxref):
        out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


# --- scanner ------------------------------------------------------------------


def test_scan_flags_all_legal_content():
    blob = _pdf_structured_blob(
        _pdf(
            b"<< /Type /Annots /Subtype /Square /Rect [0 0 1 1] >>",
            b"<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>",
            b"<< /Names << /EmbeddedFiles << /Names [(a) 9 0 R] >> >> >>",
            b"<< /Type /AcroForm /Fields [] >>",
            extra_startxref=2,
        )
    )
    scan = pdf_legal.scan_pdf_legal(blob)
    assert scan["annots"] >= 1
    assert scan["javascript"] is True
    assert scan["open_action"] is True
    assert scan["acroform"] is True
    assert scan["embedded_files"] >= 1
    assert scan["incremental_updates"] == 2


def test_clean_pdf_has_no_legal_hits():
    blob = _pdf_structured_blob(_pdf())
    scan = pdf_legal.scan_pdf_legal(blob)
    assert scan == {
        "annots": 0,
        "javascript": False,
        "open_action": False,
        "additional_actions": False,
        "embedded_files": 0,
        "acroform": False,
        "incremental_updates": 0,
        "info": {
            "author": None,
            "creator": "present (16 chars)",
            "producer": "Claude Opus",
            "title": None,
            "subject": None,
            "keywords": None,
        },
    }


def test_info_summary_redacts_but_keeps_producer():
    blob = _pdf_structured_blob(_pdf(info=b"<< /Author (Very Secret Name) /Producer (Claude Opus) >>"))
    info = pdf_legal.pdf_info_summary(blob)
    assert info["author"] == "present (16 chars)"
    assert info["producer"] == "Claude Opus"
    assert pdf_legal.producer_is_allowlisted(info) is False
    assert pdf_legal.producer_is_allowlisted({"producer": "qpdf 12.4.0"}) is True
    assert pdf_legal.producer_is_allowlisted({"producer": None}) is True


def test_inspect_container_surfaces_pdf_legal(tmp_path):
    p = tmp_path / "doc.pdf"
    p.write_bytes(
        _pdf(
            b"<< /Type /Annots /Subtype /Square /Rect [0 0 1 1] >>",
            b"<< /S /JavaScript /JS (x) >>",
            extra_startxref=1,
        )
    )
    rep = inspect_container(p).to_dict()
    legal = rep["details"]["pdf_legal"]
    assert legal["annots"] >= 1 and legal["javascript"] is True
    joined = "\n".join(rep["findings"])
    assert "pdf-annots:" in joined
    assert "pdf-js:" in joined
    assert "pdf-incremental-updates: 1" in joined


def test_findings_project_pdf_legal_signals(tmp_path):
    p = tmp_path / "doc.pdf"
    p.write_bytes(
        _pdf(
            b"<< /Type /Annots /Subtype /Square /Rect [0 0 1 1] >>",
            b"<< /S /JavaScript /JS (x) >>",
            b"<< /Type /AcroForm /Fields [] >>",
            b"<< /Names << /EmbeddedFiles << /Names [(a) 9 0 R] >> >> >>",
        )
    )
    rep = inspect_container(p).to_dict()
    found = findings_for_report("container", rep)
    by_subtype = {f.subtype: f for f in found}
    assert {"pdf_js_actions", "pdf_annots", "pdf_acroform", "pdf_attachments"} <= set(by_subtype)
    assert by_subtype["pdf_js_actions"].category == "active_content"
    assert by_subtype["pdf_annots"].location.pane == "comment"
    assert by_subtype["pdf_acroform"].action_recommended == "flag"
    assert by_subtype["pdf_acroform"].content_visible is True
    assert by_subtype["pdf_attachments"].risk_level == "high"


# --- clean flow: linearize + remove-info + allowlist ---------------------------


@NEED_PDF_TOOLS
def test_clean_runs_second_info_clear_and_allowlists_producer(tmp_path):
    src = tmp_path / "in.pdf"
    dest = tmp_path / "out.pdf"
    src.write_bytes(_pdf())
    actions, meta = clean_pdf(src, dest)
    assert meta["mode"] == "exiftool"
    assert meta["structural_rewrite"] is True
    assert meta["info_clear"] is True
    assert any("--remove-info" in a for a in actions)

    data = dest.read_bytes()
    info = pdf_legal.pdf_info_summary(_pdf_structured_blob(data))
    # Original producer gone entirely; only the qpdf stamp may remain.
    assert pdf_legal.producer_is_allowlisted(info)
    assert info["author"] is None
    assert info["creator"] is None
    if info["producer"] is not None:
        assert info["producer"].startswith("qpdf")


@NEED_PDF_TOOLS
def test_reinspect_of_cleaned_pdf_finds_no_identity(tmp_path):
    src = tmp_path / "in.pdf"
    dest = tmp_path / "out.pdf"
    src.write_bytes(_pdf())
    clean_pdf(src, dest)

    rep = inspect_container(dest).to_dict()
    info = rep["details"]["pdf_legal"]["info"]
    assert info["author"] is None
    assert "Anthropic" not in dest.read_text(errors="ignore")
