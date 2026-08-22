"""PDF legal-content inspectors (PR 5).

Stdlib-only scans over the stream-stripped structured blob produced by
``container_meta._pdf_structured_blob``: active content (/JS, /OpenAction,
/AA), attachments (/EmbeddedFiles), form fields (/AcroForm, flag-only in
v1), annotations (/Annots), incremental-update count, and the /Info
identity dictionary used by the post-clean allowlist check.

Counts are heuristic token counts on dictionary/structure bytes; they are
for flagging and policy decisions, not exact object enumeration.
"""

from __future__ import annotations

import re
from typing import Any

_PDF_TOKEN_RES = {
    "annots": re.compile(rb"/Annots\b"),
    "javascript": re.compile(rb"/JavaScript\b|/\bJS\b"),
    "open_action": re.compile(rb"/OpenAction\b"),
    "additional_actions": re.compile(rb"/AA\b"),
    "embedded_files": re.compile(rb"/EmbeddedFiles\b"),
    "acroform": re.compile(rb"/AcroForm\b"),
}

_IDENTITY_KEYS = ("Author", "Creator", "Producer", "Title", "Subject", "Keywords")

_PRODUCER_RE = re.compile(rb"/Producer\s*\(((?:[^()\\]|\\.)*)\)")
_QPDF_PRODUCER_RE = re.compile(r"^qpdf")


def _redact(value: bytes) -> str:
    v = value.strip()
    return f"present ({len(v)} chars)" if v else ""


def pdf_info_summary(blob: bytes, *, reveal: bool = False) -> dict[str, str | None]:
    """/Info identity fields. Producer is always kept verbatim (allowlist —
    it names the generating tool, not a person). The rest are redacted to a
    length-only placeholder by default; ``reveal=True`` decodes the real
    value instead, for the explicit-opt-in counterparty-intake report only
    (see authoring_identity.py) — never the default inspect/sanitize path.
    """
    out: dict[str, str | None] = {}
    for key in _IDENTITY_KEYS:
        m = re.search(rb"/%s\s*\(((?:[^()\\]|\\.)*)\)" % key.encode(), blob)
        if not m:
            out[key.lower()] = None
            continue
        if key == "Producer" or reveal:
            out[key.lower()] = m.group(1).decode("latin-1", errors="replace") or None
        else:
            out[key.lower()] = _redact(m.group(1)) or None
    return out


def scan_pdf_legal(blob: bytes) -> dict[str, Any]:
    """Scan a stream-stripped PDF blob for legal-relevant content."""
    report: dict[str, Any] = {
        "annots": len(_PDF_TOKEN_RES["annots"].findall(blob)),
        "javascript": bool(_PDF_TOKEN_RES["javascript"].search(blob)),
        "open_action": bool(_PDF_TOKEN_RES["open_action"].search(blob)),
        "additional_actions": bool(_PDF_TOKEN_RES["additional_actions"].search(blob)),
        "embedded_files": len(_PDF_TOKEN_RES["embedded_files"].findall(blob)),
        "acroform": bool(_PDF_TOKEN_RES["acroform"].search(blob)),
        "incremental_updates": max(0, blob.count(b"startxref") - 1),
        "info": pdf_info_summary(blob),
    }
    return report


def producer_is_allowlisted(info: dict[str, str | None]) -> bool:
    """True when the only producer identity is a qpdf stamp (or absent)."""
    producer = info.get("producer")
    return producer is None or bool(_QPDF_PRODUCER_RE.match(producer))


def legal_findings(scan: dict[str, Any]) -> list[str]:
    """Stable-prefixed finding strings; the canonical adapter keys on these."""
    out: list[str] = []
    if scan["annots"]:
        out.append(f"pdf-annots: {scan['annots']} annotation reference(s)")
    if scan["javascript"]:
        out.append("pdf-js: JavaScript action present")
    if scan["open_action"]:
        out.append("pdf-openaction: OpenAction present")
    if scan["additional_actions"]:
        out.append("pdf-aa: additional actions (/AA) present")
    if scan["embedded_files"]:
        out.append(f"pdf-embeddedfiles: {scan['embedded_files']} attachment reference(s)")
    if scan["acroform"]:
        out.append("pdf-acroform: interactive form present (flag-only in v1)")
    if scan["incremental_updates"]:
        out.append(f"pdf-incremental-updates: {scan['incremental_updates']} update section(s)")
    return out
