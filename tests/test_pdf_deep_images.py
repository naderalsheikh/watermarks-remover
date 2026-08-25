"""PDF deep-image metadata (docs/pdf-deep-image-metadata.md): EXIF/C2PA
metadata living inside embedded JPEG image XObjects, which the document-
level exiftool/qpdf clean never touches on its own.

Removal is byte-preserving, not a re-render: strip_pdf_image_metadata
splices APPn segments out of the extracted JPEG stream directly and never
touches the SOS-to-EOI scan data. This is the safe alternative to a
Ghostscript pdfwrite re-encode that was built and deliberately not shipped
(it reliably dropped the embedded image entirely — see the module comment
above container_meta.strip_pdf_image_metadata and the design note's
"Status" section). The strongest tests here prove byte-identical scan data
before and after a real strip through a real qpdf rebuild — not "looks the
same," which was exactly the insufficient evidence that let the Ghostscript
approach look plausible before it was actually verified."""

from __future__ import annotations

import base64
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
    _pdf_direct_length,
    _strip_jpeg_appn,
    clean_pdf,
    embedded_image_metadata_present,
    embedded_provenance_present,
    inspect_pdf,
    pdf_deep_image_scan,
    strip_pdf_image_metadata,
)

NEED_EXIFTOOL_QPDF = pytest.mark.skipif(
    not (shutil.which("exiftool") and shutil.which("qpdf")), reason="exiftool and qpdf required"
)

# A real, valid, tiny (4x4 RGB) JPEG — generated once via
# `gs -sDEVICE=jpeg -g4x4 ...` and baked in here so the byte-identical-
# scan-data tests exercise genuine DCT-coded pixel data through a real qpdf
# rebuild, without requiring Ghostscript (or any image tool) at test time.
_REAL_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/4gogSUNDX1BST0ZJTEUAAQEAAAoQAAAAAAIQAABt"
    "bnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwQVBQTAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApkZXNjAAAA/AAAAHxjcHJ0"
    "AAABeAAAACh3dHB0AAABoAAAABRia3B0AAABtAAAABRyWFlaAAAByAAAABRnWFlaAAAB"
    "3AAAABRiWFlaAAAB8AAAABRyVFJDAAACBAAACAxnVFJDAAACBAAACAxiVFJDAAACBAAA"
    "CAxkZXNjAAAAAAAAACJBcnRpZmV4IFNvZnR3YXJlIHNSR0IgSUNDIFByb2ZpbGUAAAAA"
    "AAAAAAAAACJBcnRpZmV4IFNvZnR3YXJlIHNSR0IgSUNDIFByb2ZpbGUAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdGV4dAAAAABDb3B5cmlnaHQgQXJ0aWZl"
    "eCBTb2Z0d2FyZSAyMDExAFhZWiAAAAAAAADzUQABAAAAARbMWFlaIAAAAAAAAAAAAAAA"
    "AAAAAABYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAA"
    "AAAAACSgAAAPhAAAts9jdXJ2AAAAAAAABAAAAAAFAAoADwAUABkAHgAjACgALQAyADcA"
    "OwBAAEUASgBPAFQAWQBeAGMAaABtAHIAdwB8AIEAhgCLAJAAlQCaAJ8ApACpAK4AsgC3"
    "ALwAwQDGAMsA0ADVANsA4ADlAOsA8AD2APsBAQEHAQ0BEwEZAR8BJQErATIBOAE+AUUB"
    "TAFSAVkBYAFnAW4BdQF8AYMBiwGSAZoBoQGpAbEBuQHBAckB0QHZAeEB6QHyAfoCAwIM"
    "AhQCHQImAi8COAJBAksCVAJdAmcCcQJ6AoQCjgKYAqICrAK2AsECywLVAuAC6wL1AwAD"
    "CwMWAyEDLQM4A0MDTwNaA2YDcgN+A4oDlgOiA64DugPHA9MD4APsA/kEBgQTBCAELQQ7"
    "BEgEVQRjBHEEfgSMBJoEqAS2BMQE0wThBPAE/gUNBRwFKwU6BUkFWAVnBXcFhgWWBaYF"
    "tQXFBdUF5QX2BgYGFgYnBjcGSAZZBmoGewaMBp0GrwbABtEG4wb1BwcHGQcrBz0HTwdh"
    "B3QHhgeZB6wHvwfSB+UH+AgLCB8IMghGCFoIbgiCCJYIqgi+CNII5wj7CRAJJQk6CU8J"
    "ZAl5CY8JpAm6Cc8J5Qn7ChEKJwo9ClQKagqBCpgKrgrFCtwK8wsLCyILOQtRC2kLgAuY"
    "C7ALyAvhC/kMEgwqDEMMXAx1DI4MpwzADNkM8w0NDSYNQA1aDXQNjg2pDcMN3g34DhMO"
    "Lg5JDmQOfw6bDrYO0g7uDwkPJQ9BD14Peg+WD7MPzw/sEAkQJhBDEGEQfhCbELkQ1xD1"
    "ERMRMRFPEW0RjBGqEckR6BIHEiYSRRJkEoQSoxLDEuMTAxMjE0MTYxODE6QTxRPlFAYU"
    "JxRJFGoUixStFM4U8BUSFTQVVhV4FZsVvRXgFgMWJhZJFmwWjxayFtYW+hcdF0EXZReJ"
    "F64X0hf3GBsYQBhlGIoYrxjVGPoZIBlFGWsZkRm3Gd0aBBoqGlEadxqeGsUa7BsUGzsb"
    "Yxsg"
)


def _jpeg_appn(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def _jpeg(*segments: bytes) -> bytes:
    """Minimal fake JPEG for marker-level tests: SOI, caller-supplied APPn
    segments, a trivial SOS + one scan byte, EOI. Never decoded — only
    marker-walked — so the scan payload doesn't need to be real coefficient
    data. Not used for anything routed through qpdf/exiftool — use
    _tagged_real_jpeg for that."""
    sos = bytes([0xFF, 0xDA]) + struct.pack(">H", 8) + b"\x01\x00\x00\x3f\x00" + b"\x00"
    return b"\xff\xd8" + b"".join(segments) + sos + b"\xff\xd9"


def _inject_appn(jpeg: bytes, marker: int, payload: bytes) -> bytes:
    """Insert an APPn segment right after SOI, before whatever the real
    JPEG's encoder already put there (JFIF/ICC)."""
    return jpeg[:2] + _jpeg_appn(marker, payload) + jpeg[2:]


def _tagged_real_jpeg(marker: int, payload: bytes) -> bytes:
    return _inject_appn(_REAL_JPEG, marker, payload)


def _pdf_with_image_xobject(jpeg: bytes, *, w: int = 1, h: int = 1, indirect_length=False) -> bytes:
    """One-page PDF whose page resources hold a single JPEG (DCTDecode)
    image XObject. indirect_length=True writes `/Length 6 0 R` (a separate
    object) instead of a direct integer, matching common real-world PDF
    producer output and exercising strip_pdf_image_metadata's documented
    skip-rather-than-guess behavior for that case."""
    content = b"q 200 0 0 200 0 0 cm /Im0 Do Q"
    if indirect_length:
        img_obj = (
            b"<< /Type /XObject /Subtype /Image /Width %d /Height %d "
            b"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode "
            b"/Length 6 0 R >>\nstream\n" % (w, h) + jpeg + b"\nendstream"
        )
        objs = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            b"/Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>",
            b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
            img_obj,
            str(len(jpeg)).encode(),
        ]
    else:
        objs = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            b"/Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>",
            b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
            b"<< /Type /XObject /Subtype /Image /Width %d /Height %d "
            b"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode "
            b"/Length %d >>\nstream\n" % (w, h, len(jpeg)) + jpeg + b"\nendstream",
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


# --- byte-preserving strip primitives ------------------------------------------


def test_strip_jpeg_appn_removes_only_targeted_markers():
    jpeg = _jpeg(
        _jpeg_appn(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"),  # keep: structural
        _jpeg_appn(0xE1, b"Exif\x00\x00fake tiff"),  # strip
        _jpeg_appn(0xE2, b"ICC_PROFILE\x00" + b"\x00" * 10),  # keep: color-functional
        _jpeg_appn(0xEB, b"jumb c2pa manifest"),  # strip
    )
    from container_meta import _JPEG_METADATA_MARKERS

    stripped = _strip_jpeg_appn(jpeg, _JPEG_METADATA_MARKERS)
    assert not embedded_image_metadata_present(stripped)
    assert b"JFIF" in stripped
    assert b"ICC_PROFILE" in stripped
    assert b"Exif" not in stripped
    assert b"jumb" not in stripped


def test_strip_jpeg_appn_never_touches_scan_data():
    """The actual safety property: SOS through EOI is copied verbatim, byte
    for byte — this is what makes "no visual degradation" true by
    construction rather than by after-the-fact inspection."""
    from container_meta import _JPEG_METADATA_MARKERS

    tagged = _tagged_real_jpeg(0xEB, b"jumb c2pa manifest bytes")
    stripped = _strip_jpeg_appn(tagged, _JPEG_METADATA_MARKERS)
    orig_sos = _REAL_JPEG.find(b"\xff\xda")
    new_sos = stripped.find(b"\xff\xda")
    assert _REAL_JPEG[orig_sos:] == stripped[new_sos : new_sos + (len(_REAL_JPEG) - orig_sos)]


def test_strip_jpeg_appn_is_a_noop_when_nothing_to_strip():
    jpeg = _jpeg(_jpeg_appn(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"))
    from container_meta import _JPEG_METADATA_MARKERS

    assert _strip_jpeg_appn(jpeg, _JPEG_METADATA_MARKERS) == jpeg


def test_pdf_direct_length_parses_a_direct_integer():
    assert _pdf_direct_length(b"/Type /XObject /Length 43 /Filter /DCTDecode") == (
        43,
        23,
        25,
    )


def test_pdf_direct_length_returns_none_for_an_indirect_reference():
    # "/Length 6 0 R" — the value lives in object 6, not inline here.
    assert _pdf_direct_length(b"/Type /XObject /Length 6 0 R /Filter /DCTDecode") is None


def test_pdf_direct_length_returns_none_when_length_is_missing():
    assert _pdf_direct_length(b"/Type /XObject /Filter /DCTDecode") is None


def test_strip_pdf_image_metadata_updates_length_and_returns_count():
    from container_meta import _iter_pdf_image_xobject_spans

    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    pdf = _pdf_with_image_xobject(jpeg)
    new_pdf, count = strip_pdf_image_metadata(pdf)
    assert count == 1
    streams = list(_iter_pdf_image_xobjects(new_pdf))
    assert len(streams) == 1
    assert not embedded_provenance_present(streams[0])

    # /Length in the dict must match the new (shorter) stream exactly, or
    # any downstream reader — including qpdf's own rebuild — mis-frames it.
    (dict_open, dict_close, start, end), *_rest = _iter_pdf_image_xobject_spans(new_pdf)
    dict_content = new_pdf[dict_open + 2 : dict_close]
    value, _s, _e = _pdf_direct_length(dict_content)
    assert value == end - start


def test_strip_pdf_image_metadata_is_a_noop_when_nothing_to_strip():
    jpeg = _jpeg()
    pdf = _pdf_with_image_xobject(jpeg)
    new_pdf, count = strip_pdf_image_metadata(pdf)
    assert count == 0
    assert new_pdf == pdf


def test_strip_pdf_image_metadata_skips_indirect_length_rather_than_guessing():
    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    pdf = _pdf_with_image_xobject(jpeg, indirect_length=True)
    new_pdf, count = strip_pdf_image_metadata(pdf)
    assert count == 0
    assert new_pdf == pdf
    # Detection still sees it — this is "skip," not "silently pretend it's clean."
    assert pdf_deep_image_scan(pdf) == (True, True)


# --- clean_pdf / inspect_pdf integration --------------------------------------


@NEED_EXIFTOOL_QPDF
def test_clean_pdf_strips_embedded_provenance_and_reports_it(tmp_path):
    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(jpeg))
    dest = tmp_path / "out.pdf"
    actions, meta = clean_pdf(src, dest)
    d = meta["deep_images"]
    assert d["metadata_present_before"] is True
    assert d["provenance_present_before"] is True
    assert d["images_stripped"] == 1
    assert d["metadata_present"] is False
    assert d["provenance_present"] is False
    assert d["cleared"] is True
    assert any("stripped from 1 image" in a for a in actions)

    out_streams = list(_iter_pdf_image_xobjects(dest.read_bytes()))
    assert len(out_streams) == 1
    assert not embedded_provenance_present(out_streams[0])


@NEED_EXIFTOOL_QPDF
def test_clean_pdf_strip_preserves_real_jpeg_scan_data_byte_for_byte(tmp_path):
    """The actual regression this whole approach exists to prove: a real
    photographic JPEG's own compressed pixel data survives a full clean_pdf
    round trip — exiftool pass, qpdf structural rewrite, the metadata
    strip, and a second qpdf rebuild — byte-for-byte identical, not just
    "looks the same." This is the evidence the Ghostscript approach could
    never have produced even if it had worked."""
    tagged = _tagged_real_jpeg(0xEB, b"jumb c2pa manifest bytes")
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(tagged, w=4, h=4))
    dest = tmp_path / "out.pdf"
    _actions, meta = clean_pdf(src, dest)
    assert meta["deep_images"]["cleared"] is True

    out_streams = list(_iter_pdf_image_xobjects(dest.read_bytes()))
    assert len(out_streams) == 1
    orig_sos = _REAL_JPEG.find(b"\xff\xda")
    out_sos = out_streams[0].find(b"\xff\xda")
    assert (
        _REAL_JPEG[orig_sos:]
        == out_streams[0][out_sos : out_sos + (len(_REAL_JPEG) - orig_sos)]
    )


@NEED_EXIFTOOL_QPDF
def test_clean_pdf_leaves_a_clean_image_alone(tmp_path):
    jpeg = _jpeg(_jpeg_appn(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"))
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(jpeg))
    dest = tmp_path / "out.pdf"
    _actions, meta = clean_pdf(src, dest)
    d = meta["deep_images"]
    assert d["images_stripped"] == 0
    assert d["cleared"] is False  # nothing was there to clear


@NEED_EXIFTOOL_QPDF
def test_clean_pdf_reports_indirect_length_images_honestly(tmp_path, monkeypatch):
    """An indirect /Length is skipped rather than guessed at, and the
    manifest must say so, not claim a clean that didn't happen. This is
    reachable in practice specifically when qpdf is unavailable: when
    present, clean_pdf's own upstream structural rewrite (qpdf --linearize,
    already run for exiftool's incremental-edit cleanup) normalizes an
    indirect /Length to a direct integer as a side effect — confirmed by
    hand against a real qpdf invocation — so the strip step downstream
    almost never actually sees one. Simulate qpdf's absence to exercise the
    case where it's genuinely still indirect when strip_pdf_image_metadata
    runs."""
    import container_meta

    real_which = container_meta.which
    monkeypatch.setattr(
        container_meta, "which", lambda cmd: None if cmd == "qpdf" else real_which(cmd)
    )

    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(jpeg, indirect_length=True))
    dest = tmp_path / "out.pdf"
    actions, meta = clean_pdf(src, dest)
    d = meta["deep_images"]
    assert d["images_stripped"] == 0
    assert d["metadata_present"] is True
    assert d["cleared"] is False
    assert any("remains after strip attempt" in a for a in actions)


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


def test_embedded_image_findings_reach_the_structured_finding_list(tmp_path):
    """findings_for_report's container dispatch is a strict prefix match
    with no fallback — a raw finding string that doesn't match a known
    prefix is silently dropped, never reaching job.result["findings"] (what
    the product UI actually renders). Regression: "embedded-image
    metadata:"/"embedded-image provenance:" must have their own prefix
    branches, not just exist in the raw inspect_pdf string list."""
    from findings import findings_for_report

    jpeg = _jpeg(_jpeg_appn(0xE1, b"Exif\x00\x00camera-only, no provenance"))
    data = _pdf_with_image_xobject(jpeg)
    p = tmp_path / "in.pdf"
    p.write_bytes(data)
    has_c2pa, has_ai, raw_findings, _details = inspect_pdf(p, data)
    report = {
        "format": "pdf",
        "has_c2pa": has_c2pa,
        "has_ai_metadata": has_ai,
        "findings": raw_findings,
    }
    structured = findings_for_report("container", report)
    matches = [f for f in structured if f.subtype == "embedded_image_metadata"]
    assert len(matches) == 1
    assert matches[0].category == "file_metadata"
    assert not any(f.subtype == "embedded_image_provenance" for f in structured)


def test_embedded_image_provenance_finding_is_distinct_from_generic_c2pa(tmp_path):
    """A provenance marker inside an image must be identifiable as such —
    not indistinguishable from a document-level C2PA manifest — since only
    the embedded-image case has the indirect-/Length removal caveat."""
    from findings import findings_for_report

    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    data = _pdf_with_image_xobject(jpeg)
    p = tmp_path / "in.pdf"
    p.write_bytes(data)
    has_c2pa, has_ai, raw_findings, _details = inspect_pdf(p, data)
    report = {
        "format": "pdf",
        "has_c2pa": has_c2pa,
        "has_ai_metadata": has_ai,
        "findings": raw_findings,
    }
    structured = findings_for_report("container", report)
    embedded = [f for f in structured if f.subtype == "embedded_image_provenance"]
    assert len(embedded) == 1
    assert embedded[0].category == "provenance_metadata"
    assert "not the document's own manifest" in embedded[0].notes


# --- clean_to_bundle: the actual product sanitize-job pipeline ----------------
# apply_actions -> _apply_pdf calls clean_pdf (confirmed by reading
# service/scripts/policies.py) but used to filter its meta dict down to
# {mode, structural_rewrite, info_clear} before building the manifest's
# ActionRecords — deep_images was silently dropped, so the strip ran for
# real on every PDF sanitize job but was invisible in the manifest. These
# tests go through clean_to_bundle itself, not _apply_pdf in isolation, so
# a regression here would mean a real sanitize job stops reporting this.


@NEED_EXIFTOOL_QPDF
def test_clean_to_bundle_records_the_embedded_image_strip(tmp_path):
    from engine_api import clean_to_bundle

    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(jpeg))
    out = tmp_path / "bundle"
    result = clean_to_bundle(src, out, policy_id="external_sharing", matter_id="m1")
    actions = result["manifest_data"]["actions"]
    assert any(
        a.startswith("embedded_image_metadata:strip:") and "provenance" in a for a in actions
    )


@NEED_EXIFTOOL_QPDF
def test_clean_to_bundle_fails_closed_without_qpdf_rather_than_ship_unverified(
    tmp_path, monkeypatch
):
    """The indirect-/Length "flag, don't guess" path in clean_pdf turns out
    to be unreachable through clean_to_bundle for external_sharing/
    production specifically: both are in policies._PDF_STRICT_TOOLING_
    POLICIES, which requires clean_pdf's own structural_rewrite (qpdf
    --linearize) to have succeeded — and that same rewrite is what
    normalizes an indirect /Length to direct as a side effect (see
    container_meta.py's module comment), so by the time a strict-policy
    job would reach the strip step, there's no indirect reference left to
    skip. What's actually reachable, and what this asserts instead: qpdf
    genuinely absent means the whole job fails closed with a clear reason
    (unit-level indirect-/Length coverage lives in test_clean_pdf_
    reports_indirect_length_images_honestly)."""
    import container_meta
    from custody import CustodyError
    from engine_api import clean_to_bundle

    real_which = container_meta.which
    monkeypatch.setattr(
        container_meta, "which", lambda cmd: None if cmd == "qpdf" else real_which(cmd)
    )

    jpeg = _jpeg(_jpeg_appn(0xEB, b"jumb c2pa manifest bytes"))
    src = tmp_path / "in.pdf"
    src.write_bytes(_pdf_with_image_xobject(jpeg, indirect_length=True))
    out = tmp_path / "bundle"
    with pytest.raises(CustodyError, match="tooling bar"):
        clean_to_bundle(src, out, policy_id="external_sharing", matter_id="m1")
