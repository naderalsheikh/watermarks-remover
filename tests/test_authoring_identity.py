"""authoring_identity.py — real (unredacted) identity extraction.

Deliberately separate from the main inspect pipeline; only exercised here
and by the counterparty-intake CLI path.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from authoring_identity import extract_identities, extract_ooxml_identities
from pdf_legal import pdf_info_summary

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_docx_extracts_real_author_and_company():
    values = extract_ooxml_identities(_load("spa.docx"))
    assert values["Author"] == "Jane Associate"
    assert values["Last modified by"] == "Jane Associate"
    assert values["Company"] == "Preston & Hale LLP"
    assert values["Manager"] == "R. Hale"


def test_extract_identities_dispatches_by_format():
    assert extract_identities(_load("spa.docx"), "docx") == extract_ooxml_identities(
        _load("spa.docx")
    )
    assert extract_identities(b"not a zip", "docx") == {}
    assert extract_identities(b"", "unknown") == {}


def test_pdf_dispatch_returns_real_author():
    values = extract_identities(_load("incremental.pdf"), "pdf")
    assert values == {"Author": "Attorney A"}


def test_ooxml_missing_docprops_returns_empty_not_error():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
    assert extract_ooxml_identities(buf.getvalue()) == {}


def test_ooxml_decodes_xml_entities_in_values():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "docProps/core.xml",
            '<cp:coreProperties xmlns:dc="x" xmlns:cp="y">'
            "<dc:creator>Smith &amp; Jones</dc:creator>"
            "</cp:coreProperties>",
        )
    assert extract_ooxml_identities(buf.getvalue()) == {"Author": "Smith & Jones"}


def test_pdf_info_summary_reveal_flag_is_opt_in():
    blob = b"/Author (Jane Associate) /Producer (qpdf 11.0)"
    redacted = pdf_info_summary(blob)
    assert redacted["author"] == "present (14 chars)"
    assert redacted["producer"] == "qpdf 11.0"  # Producer is always verbatim

    revealed = pdf_info_summary(blob, reveal=True)
    assert revealed["author"] == "Jane Associate"
    assert revealed["producer"] == "qpdf 11.0"


def test_pdf_info_summary_default_is_unchanged_redacted_behavior():
    # Regression guard: adding `reveal` must not change the default path.
    blob = b"/Author (Bob) /Creator (Word) /Title (Draft SPA)"
    assert pdf_info_summary(blob) == pdf_info_summary(blob, reveal=False)
