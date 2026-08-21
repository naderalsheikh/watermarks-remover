"""Canonical Finding model + adapters from prototype reports (PR 3).

Contract: docs/COUNSELCLEAR_DESIGN.md "Structured findings". Reports keep
their ``findings: list[str]`` derived view; these structured findings are an
additional projection so later policy/custody PRs can key decisions by
``finding_id``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

RISK_LEVELS = ("critical", "high", "medium", "low", "info")
PANES = (
    "body",
    "comment",
    "note",
    "header",
    "footer",
    "footnote",
    "markup",
    "hidden",
    "metadata",
    "other",
)
ACTIONS = ("keep", "strip", "replace", "rebuild", "sanitize", "refuse", "accept_all", "flag")
CATEGORIES = (
    "file_metadata",
    "invisible_text",
    "provenance_metadata",
    "embedded_content",
    "revision_history",
    "active_content",
    "digital_signature",
)


@dataclass(frozen=True)
class FindingLocation:
    part: str | None = None
    xpath_or_field: str | None = None
    page: int | None = None
    sheet: int | None = None
    slide: int | None = None
    offset: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    pane: str = "metadata"


@dataclass(frozen=True)
class Finding:
    category: str
    subtype: str
    format: str
    location: FindingLocation = FindingLocation()
    field: str | None = None
    value_redacted: str | None = None
    action_recommended: str = "strip"
    action_allowed_by_policy: tuple[str, ...] = ("strip", "replace", "keep")
    content_visible: bool = False
    risk_level: str = "medium"
    confidence: str = "probable"
    removal_changes_visible_content: bool = False
    requires_approval: bool = False
    requires_attestation: bool = False
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category: {self.category}")
        if self.risk_level not in RISK_LEVELS:
            raise ValueError(f"unknown risk_level: {self.risk_level}")
        if self.confidence not in (
            "confirmed",
            "probable",
            "informational",
            "likely_false_positive",
        ):
            raise ValueError(f"unknown confidence: {self.confidence}")
        if self.location.pane not in PANES:
            raise ValueError(f"unknown pane: {self.location.pane}")
        if self.action_recommended not in ACTIONS:
            raise ValueError(f"unknown action_recommended: {self.action_recommended}")
        for a in self.action_allowed_by_policy:
            if a not in ACTIONS:
                raise ValueError(f"unknown allowed action: {a}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": _finding_id(self),
            "category": self.category,
            "subtype": self.subtype,
            "format": self.format,
            "location": {
                "part": self.location.part,
                "xpath_or_field": self.location.xpath_or_field,
                "page": self.location.page,
                "sheet": self.location.sheet,
                "slide": self.location.slide,
                "offset": self.location.offset,
                "bbox": list(self.location.bbox) if self.location.bbox else None,
                "pane": self.location.pane,
            },
            "field": self.field,
            "value_redacted": self.value_redacted,
            "action_recommended": self.action_recommended,
            "action_allowed_by_policy": list(self.action_allowed_by_policy),
            "content_visible": self.content_visible,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "removal_changes_visible_content": self.removal_changes_visible_content,
            "requires_approval": self.requires_approval,
            "requires_attestation": self.requires_attestation,
            "notes": self.notes,
        }


def validate_finding_dict(d: dict[str, Any]) -> None:
    """Structural check without a jsonschema dependency at runtime."""
    f = Finding(
        category=d["category"],
        subtype=d["subtype"],
        format=d["format"],
        location=FindingLocation(**{k: v for k, v in d["location"].items() if k != "bbox"}),
        field=d.get("field"),
        value_redacted=d.get("value_redacted"),
        action_recommended=d["action_recommended"],
        action_allowed_by_policy=tuple(d["action_allowed_by_policy"]),
        content_visible=d["content_visible"],
        risk_level=d["risk_level"],
        confidence=d["confidence"],
        removal_changes_visible_content=d["removal_changes_visible_content"],
        requires_approval=d.get("requires_approval", False),
        requires_attestation=d.get("requires_attestation", False),
        notes=d.get("notes"),
    )
    assert d["finding_id"] == _finding_id(f), "finding_id mismatch"


def _finding_id(f: Finding) -> str:
    identity = "|".join(
        str(x)
        for x in (
            f.category,
            f.subtype,
            f.format,
            f.location.part,
            f.location.xpath_or_field,
            f.location.page,
            f.location.sheet,
            f.location.slide,
            f.field,
        )
    )
    return "f_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:4]


# --- Adapters (prototype reports -> canonical findings) ---------------------


def finding_from_text_hit(hit: dict[str, Any], fmt: str) -> Finding:
    kind = hit.get("kind") or ""
    visible = kind in ("space", "confusable")
    return Finding(
        category="invisible_text",
        subtype="layer_a_body",
        format=fmt,
        location=FindingLocation(offset=(hit.get("sample_offsets") or [None])[0], pane="body"),
        field=hit.get("codepoint"),
        value_redacted=f"present ({int(hit.get('count') or 1)}x)",
        action_recommended="strip",
        action_allowed_by_policy=("strip", "keep"),
        content_visible=visible,
        risk_level="low" if kind == "space" else "high",
        confidence="informational" if kind == "space" else "probable",
        notes=hit.get("label"),
    )


def findings_from_text_report(report: dict[str, Any], fmt: str = "txt") -> list[Finding]:
    return [finding_from_text_hit(h, fmt) for h in report.get("hits") or []]


def findings_from_image_report(report: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    fmt = report.get("format") or "unknown"
    if report.get("has_c2pa"):
        out.append(
            Finding(
                category="provenance_metadata",
                subtype="c2pa",
                format=fmt,
                risk_level="high",
                confidence="confirmed",
                action_recommended="strip",
                notes="Content Credentials manifest present",
            )
        )
    if report.get("has_ai_metadata"):
        out.append(
            Finding(
                category="file_metadata",
                subtype="ai_generator_metadata",
                format=fmt,
                risk_level="high",
                confidence="confirmed",
                notes="AI generator metadata markers present",
            )
        )
    if report.get("has_gps"):
        out.append(
            Finding(
                category="file_metadata",
                subtype="jpeg_gps",
                format=fmt,
                risk_level="high",
                confidence="confirmed",
                action_recommended="strip",
                notes="EXIF GPS location data present",
            )
        )
    return out


def findings_from_container_report(report: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    fmt = report.get("format") or "unknown"
    if report.get("has_c2pa"):
        out.append(
            Finding(
                category="provenance_metadata",
                subtype="c2pa",
                format=fmt,
                risk_level="high",
                confidence="confirmed",
                notes="Content Credentials manifest present",
            )
        )
    if report.get("has_ai_metadata"):
        out.append(
            Finding(
                category="file_metadata",
                subtype="ai_generator_metadata",
                format=fmt,
                risk_level="high",
                confidence="confirmed",
                notes="AI generator metadata markers present",
            )
        )
    # Container Layer A totals are aggregated across parts until the per-part
    # inspectors (PR 6+) can split body vs comments/headers/notes; classify as
    # body conservatively.
    if int(report.get("suspicious_total") or 0):
        out.append(
            Finding(
                category="invisible_text",
                subtype="layer_a_body",
                format=fmt,
                risk_level="high",
                confidence="probable",
                value_redacted=f"present ({int(report['suspicious_total'])} hits)",
                notes="aggregated across parts; per-part split lands with part-aware inspectors",
            )
        )
    # PR 4 refuse-list signals surface as prefixed finding strings.
    for text in report.get("findings") or []:
        if text.startswith(("macros_vba: ", "macros-office:")):
            out.append(
                Finding(
                    category="active_content",
                    subtype="macros_vba",
                    format=fmt,
                    risk_level="critical",
                    confidence="confirmed",
                    action_recommended="refuse",
                    action_allowed_by_policy=("keep",),
                    value_redacted=text,
                    notes="clean is refused without written attestation (PR 11)",
                )
            )
        elif text.startswith("digital_signature: "):
            out.append(
                Finding(
                    category="digital_signature",
                    subtype="cms_or_xml_dsig",
                    format=fmt,
                    risk_level="critical",
                    confidence="confirmed",
                    action_recommended="refuse",
                    action_allowed_by_policy=("keep",),
                    value_redacted=text.removeprefix("digital_signature: "),
                    requires_attestation=True,
                    notes="a rebuilt copy would break the signature",
                )
            )
        elif text.startswith(("pdf-js:", "pdf-openaction:", "pdf-aa:")):
            out.append(
                Finding(
                    category="active_content",
                    subtype="pdf_js_actions",
                    format=fmt,
                    risk_level="high",
                    confidence="confirmed",
                    location=FindingLocation(pane="other"),
                    value_redacted=text,
                )
            )
        elif text.startswith("pdf-acroform:"):
            out.append(
                Finding(
                    category="embedded_content",
                    subtype="pdf_acroform",
                    format=fmt,
                    risk_level="medium",
                    confidence="confirmed",
                    location=FindingLocation(pane="body"),
                    content_visible=True,
                    action_recommended="flag",
                    action_allowed_by_policy=("flag", "keep"),
                    removal_changes_visible_content=True,
                    value_redacted=text,
                )
            )
        elif text.startswith("pdf-annots:"):
            out.append(
                Finding(
                    category="embedded_content",
                    subtype="pdf_annots",
                    format=fmt,
                    risk_level="medium",
                    confidence="confirmed",
                    location=FindingLocation(pane="comment"),
                    content_visible=True,
                    value_redacted=text,
                )
            )
        elif text.startswith("pdf-embeddedfiles:"):
            out.append(
                Finding(
                    category="embedded_content",
                    subtype="pdf_attachments",
                    format=fmt,
                    risk_level="high",
                    confidence="confirmed",
                    location=FindingLocation(pane="other"),
                    value_redacted=text,
                )
            )
        elif text.startswith("docx-comments:"):
            out.append(
                Finding(
                    category="embedded_content",
                    subtype="comments_and_notes",
                    format=fmt,
                    risk_level="high",
                    confidence="confirmed",
                    location=FindingLocation(pane="comment"),
                    action_recommended="strip",
                    value_redacted=text,
                )
            )
        elif text.startswith("docx-tracked-changes:"):
            out.append(
                Finding(
                    category="revision_history",
                    subtype="office_tracked_changes",
                    format=fmt,
                    risk_level="medium",
                    confidence="confirmed",
                    location=FindingLocation(pane="markup"),
                    content_visible=True,
                    action_recommended="accept_all",
                    action_allowed_by_policy=("accept_all", "keep"),
                    value_redacted=text,
                )
            )
        elif text.startswith("docx-hidden-text:"):
            out.append(
                Finding(
                    category="invisible_text",
                    subtype="hidden_text_formatting",
                    format=fmt,
                    risk_level="medium",
                    confidence="confirmed",
                    location=FindingLocation(pane="hidden"),
                    content_visible=False,
                    action_recommended="sanitize",
                    action_allowed_by_policy=("sanitize", "keep"),
                    value_redacted=text,
                )
            )
        elif text.startswith("docx-embeddings:"):
            out.append(
                Finding(
                    category="embedded_content",
                    subtype="embeddings_ole",
                    format=fmt,
                    risk_level="high",
                    confidence="confirmed",
                    location=FindingLocation(pane="other"),
                    action_recommended="strip",
                    value_redacted=text,
                )
            )
    return out


def findings_for_report(kind: str, report: dict[str, Any]) -> list[Finding]:
    """Dispatch on the payload ``kind`` returned by inspect_bytes."""
    if kind == "text":
        return findings_from_text_report(report)
    if kind == "image":
        return findings_from_image_report(report)
    if kind == "container":
        return findings_from_container_report(report)
    return []
