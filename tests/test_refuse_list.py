#!/usr/bin/env python3
"""PR 4: format refuse list — macros, signatures, encrypted packages."""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import pytest
from container_meta import (
    UnsupportedCleanError,
    clean_container,
    container_clean_refusal,
    detect_container_format,
    inspect_container,
    office_zip_risks,
)
from engine_api import classify_bytes, clean_bytes
from findings import findings_for_report


def _docx(extra: dict[str, str] | None = None, core_creator: str = "Attorney") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/></Types>',
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/></Relationships>',
        )
        z.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>',
        )
        z.writestr(
            "docProps/core.xml",
            f'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>{core_creator}</dc:creator></cp:coreProperties>',
        )
        for name, content in (extra or {}).items():
            z.writestr(name, content)
    return buf.getvalue()


def _pdf(extra_tail: bytes = b"") -> bytes:
    return b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + extra_tail + b"\n%%EOF\n"


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# --- detection ---------------------------------------------------------------


def test_docm_extension_never_sniffs_as_docx(tmp_path):
    p = _write(tmp_path, "contract.docm", _docx())
    assert detect_container_format(p, p.read_bytes()) == "docm"
    assert classify_bytes(p.read_bytes(), ".docm") == "container"


def test_macro_family_extensions_map_distinctly(tmp_path):
    assert detect_container_format(Path("b.xlsm")) == "xlsm"
    assert detect_container_format(Path("d.dotm")) == "docm"
    assert detect_container_format(Path("t.xltm")) == "xlsm"
    assert detect_container_format(Path("s.pptm")) == "pptm"


def test_encrypted_ooxml_detected_even_when_named_docx(tmp_path):
    enc = _docx({"EncryptedPackage": "\x00" * 16, "EncryptionInfo": "<x/>"})
    p = _write(tmp_path, "locked.docx", enc)
    assert detect_container_format(p, enc) == "encrypted_office"
    # extensionless: central-directory sniff must also catch it
    q = _write(tmp_path, "mystery", enc)
    assert classify_bytes(enc, "") == "container"
    assert detect_container_format(q, enc) == "encrypted_office"


def test_cfbf_legacy_office_detected(tmp_path):
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    p = _write(tmp_path, "old.doc", data)
    assert detect_container_format(p, data) == "cfbf"
    assert classify_bytes(data, ".doc") == "container"


def test_office_zip_risks_scans_names_only(tmp_path):
    risks = office_zip_risks(
        _docx({"word/vbaProject.bin": "MZ...", "_xmlsignatures/sig1.xml": "<x/>"})
    )
    assert risks["macros"] is True
    assert risks["signatures"] is True
    assert risks["macro_members"] == ["word/vbaProject.bin"]
    assert risks["signature_members"] == ["_xmlsignatures/sig1.xml"]
    assert office_zip_risks(_docx())["macros"] is False
    assert office_zip_risks(b"%PDF-nope") == {}


# --- inspection surfaces refusal ---------------------------------------------


def test_inspect_docm_reports_macros_and_refusal(tmp_path):
    p = _write(tmp_path, "c.docm", _docx())
    rep = inspect_container(p).to_dict()
    assert rep["format"] == "docm"
    assert rep["refuse_reason"]
    assert any(f.startswith("macros-office:") for f in rep["findings"])
    assert rep["details"]["unsupported"] is True


def test_inspect_plain_docx_with_vba_flags_active_content(tmp_path):
    p = _write(tmp_path, "c.docx", _docx({"vbaProject.bin": "x"}))
    rep = inspect_container(p).to_dict()
    assert rep["refuse_reason"] and "VBA macros" in rep["refuse_reason"]
    assert any(f.startswith("macros_vba: ") for f in rep["findings"])


def test_inspect_signed_docx_flags_signature(tmp_path):
    p = _write(tmp_path, "c.docx", _docx({"_xmlsignatures/origin.sxs": "<sig/>"}))
    rep = inspect_container(p).to_dict()
    assert rep["refuse_reason"] and "signature" in rep["refuse_reason"].lower()
    assert any(f.startswith("digital_signature: ") for f in rep["findings"])


def test_clean_docx_without_risk_is_still_allowed(tmp_path):
    src = _write(tmp_path, "ok.docx", _docx())
    dest = tmp_path / "ok.cleaned.docx"
    result = clean_container(src, dest)
    assert dest.exists()
    assert result["still_has_c2pa"] in (True, False)


def test_inspect_encrypted_and_signed_pdf(tmp_path):
    p = _write(tmp_path, "e.pdf", _pdf(b"/Encrypt 1 0 R"))
    rep = inspect_container(p).to_dict()
    assert rep["refuse_reason"] and "encrypt" in rep["refuse_reason"].lower()

    s = _write(tmp_path, "s.pdf", _pdf(b"/SigFlags 1"))
    reps = inspect_container(s).to_dict()
    assert reps["refuse_reason"] and "signature" in reps["refuse_reason"].lower()


# --- clean refuses ------------------------------------------------------------


@pytest.mark.parametrize(
    "name,data",
    [
        ("c.docm", _docx()),
        ("c.docx", _docx({"vbaProject.bin": "x"})),
        ("c.docx", _docx({"EncryptedPackage": "\x00" * 8, "EncryptionInfo": "x"})),
        ("legacy.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32),
        ("e.pdf", _pdf(b"/Encrypt 1 0 R")),
        ("s.pdf", _pdf(b"/SigFlags 3")),
    ],
)
def test_clean_bytes_refuses(tmp_path, name, data):
    with pytest.raises(ValueError, match="refusing"):
        clean_bytes(data, name, {})


def test_clean_container_raises_unsupported_clean_error(tmp_path):
    src = _write(tmp_path, "m.docm", _docx())
    with pytest.raises(UnsupportedCleanError):
        clean_container(src, tmp_path / "out.docx")
    assert not (tmp_path / "out.docx").exists()


def test_refusal_helper_is_the_single_source_of_truth(tmp_path):
    assert container_clean_refusal("docm", b"PK") is not None
    assert container_clean_refusal("cfbf", b"x") is not None
    assert container_clean_refusal("encrypted_office", b"x") is not None
    assert container_clean_refusal("pdf", _pdf()) is None
    assert container_clean_refusal("docx", _docx()) is None
    assert container_clean_refusal("markdown", b"# hi") is None


# --- canonical findings -------------------------------------------------------


def test_findings_project_macro_and_signature_signals(tmp_path):
    rep = inspect_container(
        _write(tmp_path, "c.docx", _docx({"vbaProject.bin": "x", "_xmlsignatures/a.xml": "<s/>"}))
    ).to_dict()
    found = findings_for_report("container", rep)
    subtypes = {f.subtype for f in found}
    assert {"macros_vba", "cms_or_xml_dsig"} <= subtypes
    for f in found:
        if f.subtype in ("macros_vba", "cms_or_xml_dsig"):
            assert f.action_recommended == "refuse"
            assert f.risk_level == "critical"
