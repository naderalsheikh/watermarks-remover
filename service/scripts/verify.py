"""Derivative verification (PR 13).

A derivative is not "clean" because a cleaner returned. ``verify_derivative``
re-inspects the derivative and gates on:

1. targeted subtypes (strip / accept_all / rebuild / sanitize in the plan)
   must be gone on re-inspect; new identity findings fail
2. format validation: magic bytes, zip integrity, Content_Types presence
3. structural invariants scoped by policy: privacy/evidence require an
   identical part inventory, matching page/sheet/slide counts and image
   dimensions; sharing records page-count deltas as expected when the plan
   contains accept_all/rebuild
4. body diff: under privacy_only the visible-text projection must be
   unchanged (Layer A only touches invisible codepoints)

The result dict matches schemas/verify_result.schema.json. PDF pixel
render-compare is deliberately absent in v1 (warn-only future work).
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
from typing import Any

from engine_api import inspect_bytes
from findings import findings_for_report
from policies import SUBTYPES, ActionPlan

VERIFY_VERSION = 1

_PASSIVE = {"keep", "flag", "inspect_only"}
_MUTATING = {"strip", "accept_all", "rebuild", "sanitize"}
# Dropped-part name fragments allowed under non-strict policies (external_sharing /
# production). Matched case-insensitively against the full part path.
_ALLOWED_DROP_TAGS = (
    "comment", "customxml", "embedding", "externallink", "notesslide", "people", "person",
)

_PDF_PAGE_RE = re.compile(rb"/Type\s*/Page(?![a-zA-Z])")


class VerifyError(RuntimeError):
    pass


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "pass": bool(passed), "detail": detail}


def _png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        w, h = struct.unpack(">II", data[16:24])
        return int(w), int(h)
    return None


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    if not data.startswith(b"\xff\xd8"):
        return None
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seg_len = struct.unpack(">H", data[i + 2 : i + 4])[0]
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", data[i + 5 : i + 9])
            return int(w), int(h)
        i += 2 + seg_len
    return None


def _gif_dimensions(data: bytes) -> tuple[int, int] | None:
    if data[:6] in (b"GIF87a", b"GIF89a"):
        w, h = struct.unpack("<HH", data[6:10])
        return int(w), int(h)
    return None


def _image_dimensions(data: bytes) -> tuple[int, int] | None:
    for fn in (_png_dimensions, _gif_dimensions):
        d = fn(data)
        if d:
            return d
    return _jpeg_dimensions(data)


def _pdf_page_count(data: bytes) -> int | None:
    if not data.startswith(b"%PDF-"):
        return None
    return len(_PDF_PAGE_RE.findall(data))


def _xlsx_visible_sheets(names: set[str], blobs: dict[str, bytes]) -> int | None:
    wb = None
    for n in names:
        if re.fullmatch(r"xl/workbook\.xml", n):
            wb = blobs[n]
            break
    if wb is None:
        return None
    text = wb.decode("utf-8", errors="replace")
    total = len(re.findall(r"<sheet\b", text))
    hidden = len(re.findall(r"<sheet\b[^>]*state=\"(?:hidden|veryHidden)\"", text))
    return total - hidden


def _pptx_slide_count(names: set[str]) -> int | None:
    slides = {n for n in names if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)}
    return len(slides) if slides else None


_INVISIBLE_RE = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u202a-\u202e\u2066-\u2069]"
)


def visible_projection(text: str) -> str:
    return _INVISIBLE_RE.sub("", text)


def _present_subtypes(kind: str, report: dict[str, Any]) -> set[str]:
    from policies import _FINDING_SUBTYPE_ALIASES  # single source mapping

    out: set[str] = set()
    try:
        found = findings_for_report(kind, report)
    except Exception:
        found = []
    for f in found:
        st = _FINDING_SUBTYPE_ALIASES.get(f.subtype, f.subtype)
        if st in SUBTYPES:
            out.add(st)
    return out


def verify_derivative(
    original: bytes,
    derivative: bytes,
    plan: ActionPlan,
    *,
    pre_present: set[str] | None = None,
    name: str = "",
) -> dict[str, Any]:
    """Gate a derivative against its plan. Returns a VerifyResult dict;
    ``pass`` is False when any check fails.

    ``name`` should be the original file's name (real extension included) so
    the re-inspect classifies formats like markdown/HTML correctly instead of
    falling back to ``unknown`` on an extensionless label — callers that omit
    it fall back to magic-byte-only classification.
    """
    checks: list[dict[str, Any]] = []
    counts: dict[str, Any] = {}
    # cms_or_xml_dsig resolves to rebuild-with-consent, not removal
    mutating = {
        st
        for st, eff in plan.actions.items()
        if eff["action"] in _MUTATING and st != "cms_or_xml_dsig"
    }

    # 1. re-inspect both sides
    label = name or "input"
    res_before = inspect_bytes(original, label)
    res_after = inspect_bytes(derivative, label)
    before = pre_present if pre_present is not None else _present_subtypes(
        res_before.kind, res_before.report
    )
    after = _present_subtypes(res_after.kind, res_after.report)
    still_there = sorted(mutating & after)
    new_identity = sorted((after - before) & {"authoring_props", "c2pa"})
    checks.append(
        _check(
            "reinspect_targeted_gone",
            not still_there,
            f"still present: {still_there}" if still_there else "targeted subtypes cleared",
        )
    )
    checks.append(
        _check(
            "no_new_identity_findings",
            not new_identity,
            f"new: {new_identity}" if new_identity else "none",
        )
    )

    # 2. format validator (sniff bytes first: PDFs classify as containers)
    fmt_ok = True
    fmt_detail = "unknown kind"
    kind = plan.kind or res_after.kind
    names: set[str] = set()
    blobs: dict[str, bytes] = {}
    if derivative.startswith(b"%PDF-"):
        fmt_ok, fmt_detail = True, "pdf magic"
    elif kind == "container":
        names: set[str] = set()
        blobs: dict[str, bytes] = {}
        try:
            with zipfile.ZipFile(io.BytesIO(derivative)) as zf:
                bad = zf.testzip()
                if bad:
                    fmt_ok, fmt_detail = False, f"corrupt member {bad}"
                else:
                    for info in zf.infolist():
                        names.add(info.filename)
                    for key in ("[Content_Types].xml",):
                        if key in names:
                            blobs[key] = zf.read(key)
                    fmt_detail = f"{len(names)} members"
        except zipfile.BadZipFile as e:
            fmt_ok, fmt_detail = False, f"bad zip: {e}"
    elif kind == "image":
        dims = _image_dimensions(derivative)
        fmt_ok, fmt_detail = dims is not None, f"dimensions parsed: {dims}"
        names, blobs = set(), {}
    elif kind == "text":
        try:
            derivative.decode("utf-8", errors="strict")
            fmt_ok, fmt_detail = True, "valid utf-8"
        except UnicodeDecodeError as e:
            fmt_ok, fmt_detail = False, f"invalid utf-8: {e}"
        names, blobs = set(), {}
    checks.append(_check("format_valid", fmt_ok, fmt_detail))

    strict = plan.policy_id in ("privacy_only", "evidence_preservation")

    # 3. structural invariants
    page_delta_expected = False
    if kind == "container":
        o_names: set[str] = set()
        d_names: set[str] = set()
        for _label, blob, sink in (("o", original, o_names), ("d", derivative, d_names)):
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                    sink.update(zf.namelist())
            except zipfile.BadZipFile:
                pass
        added = sorted(d_names - o_names)
        dropped = sorted(o_names - d_names)
        if strict:
            # privacy_only / evidence_preservation promise an identical part
            # inventory: no dropped part is allowed, not even an allowlisted one.
            inv_pass = not added and not dropped
        else:
            inv_pass = not added and all(
                any(tag in p.lower() for tag in _ALLOWED_DROP_TAGS) for p in dropped
            )
        checks.append(
            _check(
                "part_inventory",
                inv_pass,
                f"added={added} dropped={dropped[:8]}",
            )
        )
        pages_o = _pdf_page_count(original)
        pages_d = _pdf_page_count(derivative)
        if pages_o is not None and pages_d is not None:
            counts["page_count_original"] = pages_o
            counts["page_count_derivative"] = pages_d
            same = pages_o == pages_d
            page_delta_expected = not strict and (
                plan.actions.get("tracked_changes", {}).get("action") == "accept_all"
                or plan.actions.get("pdf_incremental", {}).get("action") == "rebuild"
            )
            checks.append(
                _check(
                    "page_count",
                    same or page_delta_expected,
                    f"{pages_o} -> {pages_d}"
                    + (" (delta expected)" if page_delta_expected and not same else ""),
                )
            )
        vis_sheets_o = _xlsx_visible_sheets(o_names, {})
        vis_sheets_d = _xlsx_visible_sheets(d_names, {})
        if vis_sheets_o is not None and vis_sheets_d is not None:
            counts["visible_sheet_count"] = [vis_sheets_o, vis_sheets_d]
            checks.append(
                _check(
                    "visible_sheet_count",
                    vis_sheets_o == vis_sheets_d,
                    f"{vis_sheets_o} -> {vis_sheets_d}",
                )
            )
        slides_o = _pptx_slide_count(o_names)
        slides_d = _pptx_slide_count(d_names)
        if slides_o is not None and slides_d is not None:
            counts["slide_count"] = [slides_o, slides_d]
            checks.append(
                _check("slide_count", slides_o == slides_d, f"{slides_o} -> {slides_d}")
            )

    if kind == "image":
        do = _image_dimensions(original)
        dd = _image_dimensions(derivative)
        if do is not None and dd is not None:
            counts["image_dimensions"] = [list(do), list(dd)]
            checks.append(
                _check("image_dimensions", do == dd, f"{do} -> {dd}")
            )

    # 4. body diff under privacy: only invisible codepoints may change
    if plan.policy_id == "privacy_only" and kind == "text":
        try:
            vo = visible_projection(original.decode("utf-8", errors="replace"))
            vd = visible_projection(derivative.decode("utf-8", errors="replace"))
            checks.append(
                _check(
                    "privacy_body_unchanged",
                    vo == vd,
                    "visible projection identical" if vo == vd else "visible text changed",
                )
            )
        except Exception as e:
            checks.append(_check("privacy_body_unchanged", False, f"error: {e}"))

    hashes = {
        "original_sha256": hashlib.sha256(original).hexdigest(),
        "derivative_sha256": hashlib.sha256(derivative).hexdigest(),
    }
    passed = all(c["pass"] for c in checks)
    return {
        "verify_version": VERIFY_VERSION,
        "policy_id": plan.policy_id,
        "kind": kind,
        "pass": passed,
        "checks": checks,
        "counts": counts,
        "page_count_delta_expected": page_delta_expected,
        "hashes": hashes,
    }
