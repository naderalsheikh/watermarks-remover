"""PDF deep-image metadata (docs/pdf-deep-image-metadata.md): detection of
EXIF/C2PA metadata living inside embedded JPEG image XObjects, which the
document-level exiftool/qpdf clean never touches.

Detection only — deliberately no removal pass. A Ghostscript re-encode was
built and then not shipped: it reliably dropped the embedded image entirely
in testing, not merely recompressed it, and root cause wasn't isolated. See
the module comment above container_meta.pdf_deep_image_scan and the design
note's "Status" section. The regression tests here exist specifically to
prove that stays true — sanitizing a PDF must never silently drop or
rewrite an embedded image while this mode is disabled."""

from __future__ import annotations

import shutil
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import pytest
from container_meta import (
    _iter_pdf_image_xobjects,
    clean_pdf,
    embedded_image_metadata_present,
    embedded_provenance_present,
    inspect_pdf,
    pdf_deep_image_scan,
)

NEED_EXIFTOOL_QPDF = pytest.mark.skipif(
    not (shutil.which("exiftool") and shutil.which("qpdf")), reason="exiftool and qpdf required"
)


def _jpeg_appn(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def _jpeg(*segments: bytes) -> bytes:
    """Minimal JPEG: SOI, caller-supplied APPn segments, a trivial SOS + one
    scan byte, EOI. Never decoded — only marker-walked — so the scan payload
    doesn't need to be a real coefficient stream."""
    sos = bytes([0xFF, 0xDA]) + struct.pack(">H", 8) + b"\x01\x00\x00\x3f\x00" + b"\x00"
    return b"\xff\xd8" + b"".join(segments) + sos + b"\xff\xd9"


def _pdf_with_image_xobject(jpeg: bytes) -> bytes:
    """One-page PDF whose page resources hold a single JPEG (DCTDecode)
    image XObject — the shape embedded_image_metadata_present /
    embedded_provenance_present / _iter_pdf_image_xobjects operate on."""
    content = b"q 200 0 0 200 0 0 cm /Im0 Do Q"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 "
        b"/ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode "
        b"/Length %d >>\nstream\n" % len(jpeg) + jpeg + b"\nendstream",
    ]
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
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objs) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


# --- marker-level detection (no external tools needed) -----------------------


def test_embedded_image_metadata_present_detects_exif_app1():
    jpeg = _jpeg(_jpeg_appn(0xE1, b"Exif\x00\x00fake tiff header"))
    assert embedded_image_metadata_present(jpeg)
    assert not embedded_provenance_present(jpeg)  # ordinary EXIF, no C2PA


def test_embedded_provenance_present_detects_c2pa_app11():
    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb box carrying c2pa manifest bytes"))
    assert embedded_image_metadata_present(jpeg)
    assert embedded_provenance_present(jpeg)


def test_app0_and_app2_are_not_metadata():
    """JFIF (APP0) and ICC profile (APP2) are structural/functional, never
    "metadata to strip"."""
    jpeg = _jpeg(
        _jpeg_appn(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"),
        _jpeg_appn(0xE2, b"ICC_PROFILE\x00" + b"\x00" * 20),
    )
    assert not embedded_image_metadata_present(jpeg)
    assert not embedded_provenance_present(jpeg)


def test_iter_pdf_image_xobjects_extracts_the_jpeg_stream_exactly():
    jpeg = _jpeg(_jpeg_appn(0xE1, b"Exif\x00\x00marker"))
    pdf = _pdf_with_image_xobject(jpeg)
    streams = list(_iter_pdf_image_xobjects(pdf))
    # The fixture (like many real PDF writers) puts a newline before
    # "endstream" — extraction correctly includes it as raw stream bytes;
    # the JPEG's own EOI marker, not "endstream", is what actually bounds
    # the image data, and the detectors only walk up to SOS/EOI regardless.
    assert streams == [jpeg + b"\n"]


def test_iter_pdf_image_xobjects_ignores_the_non_image_content_stream():
    jpeg = _jpeg(_jpeg_appn(0xE1, b"Exif\x00\x00x"))
    pdf = _pdf_with_image_xobject(jpeg)
    streams = list(_iter_pdf_image_xobjects(pdf))
    assert len(streams) == 1
    assert streams[0].startswith(b"\xff\xd8")  # only the real JPEG XObject, not the page content


def test_pdf_deep_image_scan_reports_both_flags_independently():
    exif_only = _pdf_with_image_xobject(_jpeg(_jpeg_appn(0xE1, b"Exif\x00\x00camera")))
    assert pdf_deep_image_scan(exif_only) == (True, False)

    provenance = _pdf_with_image_xobject(_jpeg(_jpeg_appn(0xEB, b"jumb c2pa")))
    assert pdf_deep_image_scan(provenance) == (True, True)

    clean = _pdf_with_image_xobject(_jpeg())
    assert pdf_deep_image_scan(clean) == (False, False)


# --- clean_pdf / inspect_pdf integration --------------------------------------


@NEED_EXIFTOOL_QPDF
def test_clean_pdf_reports_embedded_metadata_without_clearing_it(tmp_path):
    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(jpeg))
    dest = tmp_path / "out.pdf"
    actions, meta = clean_pdf(src, dest)
    d = meta["deep_images"]
    assert d["metadata_present"] is True
    assert d["provenance_present"] is True
    assert d["cleared"] is False
    assert any("detection only" in a for a in actions)


def test_clean_pdf_does_not_silently_drop_or_rewrite_the_embedded_image(tmp_path):
    """The regression this mode's absence must not regress into: sanitizing
    a PDF must leave an embedded image's own bytes completely untouched —
    not stripped, not recompressed, not dropped — while this detection-only
    mode is the only one that exists. clean_pdf's document-level pass
    (exiftool -all=, qpdf --linearize/--remove-info) operates on the PDF's
    /Info and XMP; this proves it never reaches into the image XObject."""
    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(jpeg))
    dest = tmp_path / "out.pdf"
    clean_pdf(src, dest)

    out_streams = list(_iter_pdf_image_xobjects(dest.read_bytes()))
    assert len(out_streams) == 1
    assert out_streams[0].rstrip(b"\n") == jpeg  # byte-identical: nothing touched it
    # The metadata is provably still there too — the honest counterpart of
    # "not silently dropped": clean_pdf must not claim or imply it's gone.
    assert embedded_provenance_present(out_streams[0])


def test_inspect_pdf_surfaces_embedded_provenance_as_a_finding(tmp_path):
    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    data = _pdf_with_image_xobject(jpeg)
    p = tmp_path / "in.pdf"
    p.write_bytes(data)
    has_c2pa, _has_ai, findings, _details = inspect_pdf(p, data)
    assert has_c2pa is True
    assert any("embedded-image provenance" in f for f in findings)


def test_inspect_pdf_surfaces_embedded_metadata_without_provenance(tmp_path):
    jpeg = _jpeg(_jpeg_appn(0xE1, b"Exif\x00\x00camera-only, no provenance"))
    data = _pdf_with_image_xobject(jpeg)
    p = tmp_path / "in.pdf"
    p.write_bytes(data)
    _has_c2pa, _has_ai, findings, _details = inspect_pdf(p, data)
    assert any("embedded-image metadata" in f for f in findings)
    assert not any("embedded-image provenance" in f for f in findings)
