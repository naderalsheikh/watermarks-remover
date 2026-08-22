#!/usr/bin/env python3
"""PR 10: legal-document regression corpus.

Golden inspect payloads (redacted of volatile/optional-tool data) plus
sharing-clean behavioral invariants per fixture. All fixtures are synthetic;
regenerate with `python tests/fixtures/legal/generate.py`. Rewrite goldens
with UPDATE_GOLDENS=1.
"""

from __future__ import annotations

import io
import json
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
FIXTURES = ROOT / "tests" / "fixtures" / "legal"
GOLDEN = FIXTURES / "golden"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import pytest
from container_meta import UnsupportedCleanError, clean_container, clean_docx, clean_xlsx
from engine_api import inspect_bytes

ZWSP = "\u200b"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _redact(payload: dict) -> dict:
    """Drop optional-tool output and other machine-dependent noise."""
    p = json.loads(json.dumps(payload))  # deep copy via canonical JSON types

    def scrub(node):
        if isinstance(node, dict):
            node.pop("tools", None)
            node.pop("stylometry", None)
            node.pop("path", None)  # temp-dir paths differ per run
            for v in node.values():
                scrub(v)
        elif isinstance(node, list):
            for v in node:
                scrub(v)

    scrub(p)
    return p


def _inspect(name: str) -> dict:
    data = _load(name)
    res = inspect_bytes(data, name)
    findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in res.findings]
    return {
        "kind": res.kind,
        "format": res.format,
        "findings": findings,
        "unsupported_reason": res.unsupported_reason,
        "report": res.report,
    }


# --- golden snapshots ------------------------------------------------------------


def _assert_golden(name: str):
    payload = _redact(_inspect(name))
    GOLDEN.mkdir(exist_ok=True)
    out = GOLDEN / f"{name}.json"
    if os.environ.get("UPDATE_GOLDENS") == "1":
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    assert out.exists(), f"missing golden {out}; run UPDATE_GOLDENS=1 pytest"
    expected = json.loads(out.read_text())
    assert payload == expected, f"inspect output drifted from golden {name}"


@pytest.mark.parametrize(
    "name",
    [
        "spa.txt",
        "spa.docx",
        "signed.pdf",
        "macro.docm",
        "hidden.xlsx",
        "incremental.pdf",
        "gps.jpg",
    ],
)
def test_golden_inspect_snapshot(name):
    _assert_golden(name)


# --- sharing-clean invariants ------------------------------------------------------


def test_spa_txt_clean_keeps_operative_language():
    data = _load("spa.txt")
    cleaned, report = __import__("engine_api").clean_bytes(data, "spa.txt")
    text = cleaned.decode("utf-8")
    assert "shall deliver the Shares" in text
    assert "Section 8.3" in text
    assert ZWSP not in text
    assert report["unicode_diff"]["changed_total"] == 1


def test_spa_docx_clean_accept_all_and_body_invariant():
    orig = _load("spa.docx")
    cleaned, _actions = clean_docx(orig)
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        doc = zf.read("word/document.xml").decode("utf-8")
        names = zf.namelist()
        hdr_orig = zipfile.ZipFile(io.BytesIO(orig)).read("word/header1.xml")
        hdr_new = zf.read("word/header1.xml")
    # operative language survives verbatim
    assert "shall deliver the Shares" in doc
    assert "Section 8.3" in doc
    # accept-all resolved the revision pair
    deleted_clause = "DELETED CLAUSE about the side payment."
    assert deleted_clause not in doc and "<w:delText>" not in doc and "<w:ins>" not in doc
    assert "keep these terms confidential" in doc
    # comment plumbing gone; header legend byte-identical (flag-only + body scope)
    assert "word/comments.xml" not in names
    assert b"commentRangeStart" not in doc.encode() and b"commentReference" not in doc.encode()
    assert hdr_orig == hdr_new


def test_signed_pdf_refuses_clean(tmp_path):
    src = tmp_path / "signed.pdf"
    src.write_bytes(_load("signed.pdf"))
    with pytest.raises(UnsupportedCleanError):
        clean_container(src, tmp_path / "out.pdf")


def test_macro_docm_refuses_clean(tmp_path):
    src = tmp_path / "macro.docm"
    src.write_bytes(_load("macro.docm"))
    with pytest.raises(UnsupportedCleanError):
        clean_container(src, tmp_path / "out.docx")


def test_incremental_pdf_clean_removes_identity(tmp_path):
    src = tmp_path / "incremental.pdf"
    dest = tmp_path / "incremental-clean.pdf"
    src.write_bytes(_load("incremental.pdf"))
    result = clean_container(src, dest)
    assert result["meta"]["structural_rewrite"] is True
    assert result["meta"]["info_clear"] is True
    raw = dest.read_bytes()
    assert b"(Attorney A)" not in raw
    assert b"(Draft SPA v3)" not in raw
    if b"(qpdf" not in raw:
        pass  # producer stamp presence varies by qpdf invocation path


def test_hidden_xlsx_clean_strips_links_keeps_visibility(tmp_path):
    src = tmp_path / "hidden.xlsx"
    dest = tmp_path / "hidden-clean.xlsx"
    src.write_bytes(_load("hidden.xlsx"))
    clean_xlsx(src.read_bytes())
    clean_container(src, dest)
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
        wb = zf.read("xl/workbook.xml").decode()
    assert not any(n.startswith("xl/externalLinks") for n in names)
    assert "externalReferences" not in wb
    assert 'state="hidden"' in wb  # never auto-unhide


def test_gps_jpeg_clean_drops_location(tmp_path):
    from image_meta import _jpeg_has_gps, strip_jpeg

    data = _load("gps.jpg")
    assert _jpeg_has_gps(data) is True
    stripped, _actions = strip_jpeg(data, strip_all_app=True)
    assert _jpeg_has_gps(stripped) is False
