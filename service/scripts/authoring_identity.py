"""Real (unredacted) authoring-identity extraction.

Deliberately separate from the main inspect pipeline (``engine_api.inspect_bytes``
/ ``InspectResult.findings``), which always redacts identity values to
``"present (N chars)"`` — that redaction is the product's default privacy
posture for your *own* documents (see Security & Privacy Considerations in
docs/COUNSELCLEAR_DESIGN.md: "Privilege in logs / support: categories only").

This module exists for a narrower, explicit-opt-in case: the operator has
received a file from a counterparty and wants to know who actually produced
it (dc:creator / cp:lastModifiedBy / Company / Manager / PDF /Author). It is
only ever called from ``counselclear intake --reveal-identities`` — never
from the general inspect/sanitize path — so real values never reach a
manifest, an audit log, or a support bundle by default.
"""

from __future__ import annotations

import io
import re
import zipfile

# Same field set as the design doc's privacy_only PII allowlist
# (docs/COUNSELCLEAR_DESIGN.md: dc:creator, cp:lastModifiedBy, Company, Manager).
_CORE_FIELDS = (("dc:creator", "Author"), ("cp:lastModifiedBy", "Last modified by"))
_APP_FIELDS = (("Company", "Company"), ("Manager", "Manager"))

_ENTITY_RE = re.compile(r"&#(?:x([0-9A-Fa-f]+)|([0-9]+));|&(amp|lt|gt|quot|apos);")
_NAMED_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}


def _decode_entities(s: str) -> str:
    def _sub(m: re.Match[str]) -> str:
        hexd, dec, named = m.group(1), m.group(2), m.group(3)
        if named:
            return _NAMED_ENTITIES[named]
        codepoint = int(hexd, 16) if hexd else int(dec)
        try:
            return chr(codepoint)
        except (ValueError, OverflowError):
            return m.group(0)

    return _ENTITY_RE.sub(_sub, s)


def _extract_tag(text: str, tag: str) -> str | None:
    m = re.search(rf"<{re.escape(tag)}\b[^>]*>(.*?)</{re.escape(tag)}>", text, re.I | re.S)
    if not m:
        return None
    value = _decode_entities(m.group(1)).strip()
    return value or None


def extract_ooxml_identities(data: bytes) -> dict[str, str]:
    """Real identity field values from a DOCX/XLSX/PPTX's docProps.

    Returns only fields that are present and non-empty. Malformed/corrupt
    zips return an empty dict rather than raising — this is a best-effort
    reporting aid, not a gate.
    """
    out: dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "docProps/core.xml" in names:
                text = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                for tag, label in _CORE_FIELDS:
                    v = _extract_tag(text, tag)
                    if v:
                        out[label] = v
            if "docProps/app.xml" in names:
                text = zf.read("docProps/app.xml").decode("utf-8", errors="replace")
                for tag, label in _APP_FIELDS:
                    v = _extract_tag(text, tag)
                    if v:
                        out[label] = v
    except (zipfile.BadZipFile, OSError, KeyError):
        pass
    return out


def extract_identities(data: bytes, fmt: str) -> dict[str, str]:
    """Dispatch by format. PDF reuses pdf_legal's own /Info extraction
    (reveal=True) so there is one PDF string-decoding implementation, not two."""
    if fmt in ("docx", "xlsx", "pptx"):
        return extract_ooxml_identities(data)
    if fmt == "pdf":
        import pdf_legal
        from container_meta import _pdf_structured_blob

        blob = _pdf_structured_blob(data)
        info = pdf_legal.pdf_info_summary(blob, reveal=True)
        return {"Author": info["author"]} if info.get("author") else {}
    return {}


# Fields the *inspect* path reports on. Wider than the intake extractor's
# privacy_only list above: inspect answers "does this file still carry
# authoring identity?", which includes fields the sharing policy scrubs
# (title/subject/keywords) and not just the PII subset.
# Derived from the cleaner's own scrub list, deliberately, so inspect and
# clean cannot drift: reporting a field the cleaner does not scrub makes
# verify fail correct jobs, and reporting fewer makes the gate blind. Note
# what is NOT here: dc:title is a document's own name (content the recipient
# is meant to see), not authoring identity.
_CORE_PREFIXES = ("dc:", "cp:")


def _presence_fields() -> tuple[tuple[str, str], ...]:
    import container_meta

    return tuple(container_meta.DOCX_SCRUB_FIELDS)


def ooxml_identity_presence(data: bytes) -> dict[str, int]:
    """Redacted view of the same docProps fields: ``{field: value_length}``.

    The inspect/verify path must never carry real identity values (they end
    up in manifests and audit records), so this reports only *which* fields
    are populated and how long each value is. Same parser as
    ``extract_ooxml_identities`` so the two views cannot drift.
    """
    out: dict[str, int] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            fields = _presence_fields()
            for part in ("docProps/core.xml", "docProps/app.xml"):
                if part not in names:
                    continue
                text = zf.read(part).decode("utf-8", errors="replace")
                for tag, label in fields:
                    v = _extract_tag(text, tag)
                    if v:
                        out[label] = len(v)
    except (zipfile.BadZipFile, OSError, KeyError):
        pass
    return out
