"""XLSX legal-content inspectors (PR 7 groundwork).

Stdlib-only scans over the raw XLSX zip bytes (independent of
``container_meta``/``findings``): hidden and veryHidden sheets from
workbook.xml, legacy comment parts (xl/comments*.xml) with their
``<comment>`` element counts, threaded-comment parts, external workbook
links (xl/externalLinks/*.xml), defined names carrying ``hidden="1"``,
person metadata (xl/persons/person*.xml), and a redacted docProps/core.xml
identity summary mirroring ``pdf_legal.pdf_info_summary``.

Counts are heuristic regex counts over member bytes; they are for
flagging and policy decisions, not OOXML schema validation.
"""

from __future__ import annotations

import contextlib
import io
import re
import zipfile
from typing import Any

# Element tags; \b keeps containers (<sheets>, <definedNames>) from matching.
_SHEET_TAG_RE = re.compile(r"<(?:\w+:)?sheet\b[^>]*>", re.IGNORECASE)
_DEFINED_NAME_TAG_RE = re.compile(r"<(?:\w+:)?definedName\b[^>]*>", re.IGNORECASE)
_COMMENT_ELEMENT_RE = re.compile(r"<(?:\w+:)?comment(?=[\s/>])", re.IGNORECASE)
# Quote-tolerant (["'] backreference — sheet/definedName detection above
# already goes through the quote-tolerant _attr() helper; these two direct
# regexes didn't, so a row/col hidden with single-quoted hidden='1' (valid
# XML — e.g. LibreOffice output) went undetected by exactly the check this
# module exists to run.
_HIDDEN_ROW_RE = re.compile(
    r'<(?:\w+:)?row\b[^>]*\bhidden=(["\'])(?:1|true)\1', re.IGNORECASE
)
# Also fixed here: the old pattern only checked the attribute was *present*,
# not its value, so hidden="0" (explicitly NOT hidden) false-positived as a
# hidden column. Matches _HIDDEN_ROW_RE's value check now.
_HIDDEN_COL_RE = re.compile(
    r'<(?:\w+:)?col\b[^>]*\bhidden=(["\'])(?:1|true)\1', re.IGNORECASE
)

# Part-name patterns (zip entry paths).
_WORKBOOK_PART_RE = re.compile(r"^xl/workbook\.xml$", re.IGNORECASE)
_COMMENTS_PART_RE = re.compile(r"^xl/comments\d*\.xml$", re.IGNORECASE)
_THREADED_PART_RE = re.compile(r"^xl/threadedComments/[^/]+\.xml$", re.IGNORECASE)
_EXTERNAL_LINK_PART_RE = re.compile(r"^xl/externalLinks/[^/]+\.xml$", re.IGNORECASE)
# Real Excel writes numbered parts (person1.xml, person2.xml, ...); the
# unnumbered person.xml form was the only one matched before, so numbered
# commenter names/emails survived every scan and sharing clean unflagged.
_PERSONS_PART_RE = re.compile(r"^xl/persons/person\d*\.xml$", re.IGNORECASE)
_WORKSHEET_PART_RE = re.compile(r"^xl/worksheets/sheet\d+\.xml$", re.IGNORECASE)
_CORE_PART_RE = re.compile(r"^docProps/core\.xml$", re.IGNORECASE)

# Only these members are decompressed; sharedStrings can be huge.
_INTERESTING_PART_RES = (
    _WORKBOOK_PART_RE,
    _CORE_PART_RE,
    _COMMENTS_PART_RE,
    _THREADED_PART_RE,
    _EXTERNAL_LINK_PART_RE,
    _PERSONS_PART_RE,
    _WORKSHEET_PART_RE,
)

_HIDDEN_STATES = {"hidden", "veryhidden"}

_CORE_FIELD_RES = {
    "creator": re.compile(
        r"<(?:\w+:)?creator\b[^>]*>(.*?)</(?:\w+:)?creator\s*>", re.DOTALL | re.IGNORECASE
    ),
    "last_modified_by": re.compile(
        r"<(?:\w+:)?lastModifiedBy\b[^>]*>(.*?)</(?:\w+:)?lastModifiedBy\s*>",
        re.DOTALL | re.IGNORECASE,
    ),
}


def _attr(tag: str, name: str) -> str:
    """Attribute value from a raw XML tag string; order/quote insensitive."""
    m = re.search(rf'\b{re.escape(name)}\s*=\s*(?:"([^"]*)"|\'([^\']*)\')', tag, re.IGNORECASE)
    if m is None:
        return ""
    return m.group(1) if m.group(1) is not None else m.group(2)


def _redact(match: re.Match[str] | None) -> str | None:
    """Redact a captured field value to its length, like pdf_legal._redact."""
    if match is None:
        return None
    value = match.group(1).strip()
    return f"present ({len(value)} chars)" if value else None


def xlsx_core_info(core_xml: bytes) -> dict[str, str | None]:
    """Redacted docProps/core.xml identity fields (creator / lastModifiedBy)."""
    text = core_xml.decode("utf-8", errors="replace")
    return {key: _redact(rx.search(text)) for key, rx in _CORE_FIELD_RES.items()}


def scan_xlsx_legal(data: bytes) -> dict[str, Any]:
    """Scan raw XLSX zip bytes for legal-relevant content.

    Individual unreadable members are skipped, not fatal; only a blob that
    is not a zip at all raises ValueError("not a valid XLSX zip").
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, EOFError) as exc:
        raise ValueError("not a valid XLSX zip") from exc

    report: dict[str, Any] = {
        "hidden_sheets": [],
        "very_hidden_sheets": [],
        "visible_sheet_count": 0,
        "comment_part_count": 0,
        "comment_count": 0,
        "threaded_comment_parts": 0,
        "external_links": 0,
        "defined_name_count": 0,
        "defined_names_hidden": 0,
        "persons_part": False,
        "hidden_rows": 0,
        "hidden_cols": 0,
        "core_info": None,
    }

    members: dict[str, bytes] = {}
    with zf:
        for info in zf.infolist():
            if not any(rx.match(info.filename) for rx in _INTERESTING_PART_RES):
                continue
            with contextlib.suppress(Exception):
                members[info.filename] = zf.read(info)  # corrupt member: skipped

    workbook = next((blob for name, blob in members.items() if _WORKBOOK_PART_RE.match(name)), b"")
    if workbook:
        text = workbook.decode("utf-8", errors="replace")
        for tag in _SHEET_TAG_RE.findall(text):
            state = _attr(tag, "state").lower()
            if state not in _HIDDEN_STATES:
                report["visible_sheet_count"] += 1
            elif state == "hidden":
                report["hidden_sheets"].append(_attr(tag, "name"))
            else:
                report["very_hidden_sheets"].append(_attr(tag, "name"))
        name_tags = _DEFINED_NAME_TAG_RE.findall(text)
        report["defined_name_count"] = len(name_tags)
        report["defined_names_hidden"] = sum(
            _attr(tag, "hidden").lower() in ("1", "true") for tag in name_tags
        )

    comment_parts = sorted(name for name in members if _COMMENTS_PART_RE.match(name))
    report["comment_part_count"] = len(comment_parts)
    report["comment_count"] = sum(
        len(_COMMENT_ELEMENT_RE.findall(members[name].decode("utf-8", errors="replace")))
        for name in comment_parts
    )
    report["threaded_comment_parts"] = sum(1 for name in members if _THREADED_PART_RE.match(name))
    report["external_links"] = sum(1 for name in members if _EXTERNAL_LINK_PART_RE.match(name))
    report["persons_part"] = any(_PERSONS_PART_RE.match(name) for name in members)

    # Hidden rows/cols: flag-only on sharing (never auto-unhide).
    for name, blob in members.items():
        if not _WORKSHEET_PART_RE.match(name):
            continue
        text = blob.decode("utf-8", errors="replace")
        report["hidden_rows"] += len(_HIDDEN_ROW_RE.findall(text))
        report["hidden_cols"] += len(_HIDDEN_COL_RE.findall(text))

    core = next((blob for name, blob in members.items() if _CORE_PART_RE.match(name)), None)
    if core is not None:
        report["core_info"] = xlsx_core_info(core)
    return report


def legal_findings(scan: dict[str, Any]) -> list[str]:
    """Stable-prefixed finding strings; the canonical adapter keys on these."""
    out: list[str] = []
    n_hidden = len(scan["hidden_sheets"])
    n_very = len(scan["very_hidden_sheets"])
    if n_hidden or n_very:
        out.append(f"xlsx-hidden-sheets: {n_hidden} hidden ({n_very} veryHidden)")
    if scan["comment_count"]:
        out.append(f"xlsx-comments: {scan['comment_count']} comment(s)")
    if scan["threaded_comment_parts"]:
        out.append(f"xlsx-threaded-comments: {scan['threaded_comment_parts']} part(s)")
    if scan["external_links"]:
        out.append(f"xlsx-external-links: {scan['external_links']} part(s)")
    if scan["defined_names_hidden"]:
        out.append(f"xlsx-hidden-names: {scan['defined_names_hidden']} hidden defined name(s)")
    if scan["hidden_rows"] or scan["hidden_cols"]:
        out.append(
            f"xlsx-hidden-rows-cols: {scan['hidden_rows']} row(s) {scan['hidden_cols']} col(s)"
        )
    return out
