#!/usr/bin/env python3
"""PR 3: canonical Finding model, adapters, and JPEG/TIFF GPS detection."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import jsonschema
import pytest
from engine_api import inspect_bytes
from findings import (
    ACTIONS,
    PANES,
    RISK_LEVELS,
    Finding,
    FindingLocation,
    findings_for_report,
    validate_finding_dict,
)
from image_meta import _jpeg_has_gps, detect_format, inspect_image

SCHEMA = json.loads((SCRIPTS / "schemas" / "finding.schema.json").read_text())


def _tiff_block(with_gps: bool) -> bytes:
    """Classic little-endian TIFF: IFD0 -> optional GPSInfo sub-IFD."""
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    n_entries = 1 if with_gps else 0
    gps_offset = 8 + 2 + n_entries * 12 + 4  # first byte after IFD0
    body = bytearray()
    body += struct.pack("<H", n_entries)
    if with_gps:
        body += struct.pack("<HHI", 34853, 4, 1)
        body += struct.pack("<I", gps_offset)
    body += struct.pack("<I", 0)  # next IFD
    if with_gps:
        body += struct.pack("<H", 1)  # GPS sub-IFD entries
        body += struct.pack("<HHI", 1, 2, 2)  # LatitudeRef, ASCII, count 2
        body += b"N\x00\x00\x00"  # inline value "N"
        body += struct.pack("<I", 0)  # next IFD
    return header + bytes(body)


def _jpeg(exif_tiff: bytes | None) -> bytes:
    out = bytearray(b"\xff\xd8")  # SOI
    out += b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # APP0 JFIF
    if exif_tiff is not None:
        payload = b"Exif\x00\x00" + exif_tiff
        out += b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    out += b"\xff\xda\x00\x02"  # SOS stub
    out += b"\x00\x00\xff\xd9"  # scan stub + EOI
    return bytes(out)


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# --- GPS detection ----------------------------------------------------------


def test_jpeg_with_exif_gps_is_detected(tmp_path):
    data = _jpeg(_tiff_block(with_gps=True))
    assert detect_format(data) == "jpeg"
    assert _jpeg_has_gps(data) is True
    rep = inspect_image(_write(tmp_path / "g.jpg", data)).to_dict()
    assert rep["has_gps"] is True
    assert any("GPS location data present" in f for f in rep["findings"])


def test_jpeg_exif_without_gps_is_not_flagged(tmp_path):
    data = _jpeg(_tiff_block(with_gps=False))
    rep = inspect_image(_write(tmp_path / "ng.jpg", data)).to_dict()
    assert rep["has_gps"] is False


def test_plain_jpeg_has_no_gps(tmp_path):
    data = _jpeg(None)
    rep = inspect_image(_write(tmp_path / "plain.jpg", data)).to_dict()
    assert rep["has_gps"] is False


def test_tiff_with_gps_is_detected(tmp_path):
    tiff = _tiff_block(with_gps=True)
    assert detect_format(tiff) == "tiff"
    rep = inspect_image(_write(tmp_path / "g.tif", tiff)).to_dict()
    assert rep["has_gps"] is True
    assert any("GPS location data present" in f for f in rep["findings"])


# --- Canonical findings -----------------------------------------------------


def _check_schema(d: dict) -> None:
    jsonschema.validate(d, SCHEMA)


def test_finding_id_is_deterministic_and_stable():
    f = Finding(
        category="provenance_metadata",
        subtype="c2pa",
        format="png",
        risk_level="high",
        confidence="confirmed",
    )
    d = f.to_dict()
    assert d["finding_id"] == f.to_dict()["finding_id"]
    assert d["finding_id"].startswith("f_") and len(d["finding_id"]) == 6
    other = Finding(category="file_metadata", subtype="ai_generator_metadata", format="png")
    assert other.to_dict()["finding_id"] != d["finding_id"]


def test_text_hits_map_to_layer_a_body_findings():
    report = {
        "hits": [
            {
                "codepoint": "U+200B",
                "label": "U+200B ZERO WIDTH SPACE (Cf)",
                "count": 2,
                "kind": "zwj_family",
                "confidence": "probable",
                "sample_offsets": [5],
            },
            {
                "codepoint": "U+00A0",
                "label": "U+00A0 NO-BREAK SPACE (Zs)",
                "count": 1,
                "kind": "space",
                "confidence": "informational",
                "sample_offsets": [9],
            },
        ]
    }
    found = findings_for_report("text", report)
    assert [f.subtype for f in found] == ["layer_a_body", "layer_a_body"]
    assert all(f.category == "invisible_text" for f in found)
    assert all(f.location.pane == "body" for f in found)
    assert found[0].risk_level == "high" and found[0].content_visible is False
    assert found[1].risk_level == "low" and found[1].confidence == "informational"
    assert "present (2x)" in found[0].value_redacted
    for f in found:
        _check_schema(f.to_dict())


def test_image_report_maps_c2pa_ai_and_gps():
    report = {"format": "jpeg", "has_c2pa": True, "has_ai_metadata": True, "has_gps": True}
    found = findings_for_report("image", report)
    subtypes = {f.subtype for f in found}
    assert subtypes == {"c2pa", "ai_generator_metadata", "jpeg_gps"}
    gps = next(f for f in found if f.subtype == "jpeg_gps")
    assert gps.category == "file_metadata"
    assert gps.location.pane == "metadata"
    assert gps.risk_level == "high" and gps.confidence == "confirmed"
    for f in found:
        _check_schema(f.to_dict())


def test_container_report_maps_layer_a_total():
    report = {"format": "docx", "suspicious_total": 7}
    found = findings_for_report("container", report)
    assert len(found) == 1
    assert found[0].subtype == "layer_a_body"
    assert "7 hits" in found[0].value_redacted
    _check_schema(found[0].to_dict())
    assert findings_for_report("container", {"format": "pdf"}) == []


def test_end_to_end_inspect_bytes_projects_findings(tmp_path):
    data = _jpeg(_tiff_block(with_gps=True))
    res = inspect_bytes(data, "photo.jpg")
    assert res.kind == "image"
    found = findings_for_report(res.kind, res.report)
    assert any(f.subtype == "jpeg_gps" for f in found)
    for f in found:
        _check_schema(f.to_dict())


def test_enum_validation_rejects_bad_values():
    with pytest.raises(ValueError, match="risk_level"):
        Finding(
            category="invisible_text",
            subtype="layer_a_body",
            format="txt",
            risk_level="extreme",
        )
    with pytest.raises(ValueError, match="pane"):
        Finding(
            category="invisible_text",
            subtype="layer_a_body",
            format="txt",
            location=FindingLocation(pane="sidebar"),
        )
    with pytest.raises(ValueError, match="category"):
        Finding(category="sorcery", subtype="x", format="txt")
    for r in RISK_LEVELS:
        assert r in ("critical", "high", "medium", "low", "info")
    assert all(p in PANES for p in ("body", "comment", "markup", "hidden"))
    assert "accept_all" in ACTIONS


def test_validate_finding_dict_roundtrip():
    d = Finding(
        category="file_metadata",
        subtype="authoring_props",
        format="docx",
        location=FindingLocation(part="docProps/core.xml", xpath_or_field="dc:creator"),
        field="dc:creator",
        value_redacted="present (12 chars)",
        risk_level="high",
        confidence="confirmed",
    ).to_dict()
    validate_finding_dict(d)
    bad = dict(d)
    bad["risk_level"] = "catastrophic"
    with pytest.raises(ValueError):
        validate_finding_dict(bad)
