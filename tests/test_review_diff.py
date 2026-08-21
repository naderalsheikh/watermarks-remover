#!/usr/bin/env python3
"""PR 9: reviewer-facing Unicode diff + non-body Layer A switch.

- diff_entries(): human per-character diff derived from before/after texts.
- layer_a_scope="body": Layer A only touches body parts (document.xml,
  worksheets/sharedStrings, slides); headers/footers/footnotes/masters stay
  byte-identical. "all" restores the legacy whole-package sweep.
- ooxml_review_diff(): per-part diff with pane attribution and removed-part
  notes for parts dropped by the legal passes.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

from container_meta import (
    clean_docx,
    clean_xlsx,
    ooxml_review_diff,
)
from engine_api import clean_bytes
from text_unicode import diff_entries

ZWSP = "\u200b"


def _doc(parts: dict[str, str]) -> bytes:
    decl = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'

    def wrap(root: str, inner: str) -> str:
        return f'<?xml version="1.0"?><{root} {decl}>{inner}</{root}>'

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        ct = (
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            "</Types>"
        )
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
        )
        if "word/document.xml" in parts:
            zf.writestr("word/document.xml", wrap("w:document", f'<w:body>{parts["word/document.xml"]}</w:body>'))
        if "word/header1.xml" in parts:
            zf.writestr("word/header1.xml", wrap("w:hdr", parts["word/header1.xml"]))
        if "word/comments.xml" in parts:
            zf.writestr("word/comments.xml", wrap("w:comments", "<w:comment/>"))
    return buf.getvalue()


# --- diff_entries ---------------------------------------------------------------


def test_diff_entries_reports_strip_with_offset_and_label():
    before = f"Hello{ZWSP}World"
    after = "HelloWorld"
    d = diff_entries(before, after)
    assert d["changed_total"] == 1
    e = d["entries"][0]
    assert e["offset"] == 5
    assert e["codepoint"] == "U+200B"
    assert e["action"] == "strip"
    assert "ZERO WIDTH SPACE" in e["label"]
    assert d["truncated"] is False


def test_diff_entries_truncates():
    before = ZWSP * 30
    after = ""
    d = diff_entries(before, after, limit=10)
    assert d["changed_total"] == 30
    assert len(d["entries"]) == 10
    assert d["truncated"] is True


def test_diff_entries_no_changes():
    assert diff_entries("same", "same") == {"changed_total": 0, "truncated": False, "entries": []}


# --- non-body Layer A switch ------------------------------------------------------


def _body_with_zwsp() -> tuple[bytes, bytes]:
    """DOCX with a ZWSP in both the body and the header."""
    data = _doc(
        {
            "word/document.xml": f"<w:p><w:r><w:t>deal{ZWSP}terms</w:t></w:r></w:p>",
            "word/header1.xml": "<w:p><w:r><w:t>PRIVILEGED</w:t></w:r></w:p>",
        }
    )
    return data, b""


def test_body_scope_leaves_header_byte_identical():
    data = _doc(
        {
            "word/document.xml": f"<w:p><w:r><w:t>deal{ZWSP}terms</w:t></w:r></w:p>",
            "word/header1.xml": f"<w:p><w:r><w:t>PRIVILEGED{ZWSP}</w:t></w:r></w:p>",
        }
    )
    out, _actions = clean_docx(data)
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        assert b"PRIVILEGED" + ZWSP.encode() in zf.read("word/header1.xml")
        assert ZWSP.encode() not in zf.read("word/document.xml")


def test_all_scope_restores_legacy_whole_package_sweep():
    data = _doc(
        {
            "word/document.xml": f"<w:p><w:r><w:t>deal{ZWSP}terms</w:t></w:r></w:p>",
            "word/header1.xml": f"<w:p><w:r><w:t>PRIVILEGED{ZWSP}</w:t></w:r></w:p>",
        }
    )
    out, _actions = clean_docx(data, layer_a_scope="all")
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        hdr = zf.read("word/header1.xml")
    assert ZWSP.encode() not in hdr


def _xlsx_with_sharedstrings() -> bytes:
    ss = (
        '<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<si><t>a{ZWSP}b</t></si></sst>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("xl/workbook.xml", '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>')
        zf.writestr("xl/sharedStrings.xml", ss)
    return buf.getvalue()


def test_xlsx_body_scope_still_scrubs_shared_strings():
    out, actions = clean_xlsx(_xlsx_with_sharedstrings())
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        ss = zf.read("xl/sharedStrings.xml")
    assert ZWSP.encode() not in ss
    assert any("layer A text" in a for a in actions)


# --- ooxml_review_diff ------------------------------------------------------------


def test_ooxml_review_diff_attributes_parts_and_removed_parts():
    orig = _doc(
        {
            "word/document.xml": f"<w:p><w:r><w:t>deal{ZWSP}terms</w:t></w:r></w:p>",
            "word/comments.xml": "<w:comments/>",
        }
    )
    cleaned, _actions = clean_docx(orig)
    d = ooxml_review_diff(orig, cleaned, "docx")
    by_name = {p["part"]: p for p in d["parts"]}
    body = by_name["word/document.xml"]
    assert body["pane"] == "body"
    assert body["changed_total"] == 1
    assert body["entries"][0]["codepoint"] == "U+200B"
    comments = by_name.get("word/comments.xml")
    assert comments is not None and comments.get("removed_part") is True


def test_clean_bytes_text_report_includes_unicode_diff():
    data = f"Hello{ZWSP}World\n".encode()
    _cleaned, report = clean_bytes(data, "note.txt")
    d = report["unicode_diff"]
    assert d["changed_total"] == 1
    assert d["entries"][0]["action"] == "strip"


def test_clean_bytes_container_report_includes_unicode_diff(tmp_path):
    data = _doc(
        {"word/document.xml": f"<w:p><w:r><w:t>deal{ZWSP}terms</w:t></w:r></w:p>"}
    )
    _cleaned, report = clean_bytes(data, "letter.docx")
    d = report["unicode_diff"]
    assert d["format"] == "docx"
    assert d["parts_changed"] >= 1
