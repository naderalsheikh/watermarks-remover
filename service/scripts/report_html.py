"""Self-contained HTML report for inspect / sanitize results.

Renders the same structured Finding data the JSON API already returns
(category / subtype / risk_level / pane / action) into a single readable
page: no external assets, no JS, stdlib only — reuses the visual language
already established in ``ui.html`` so it reads as part of the same product
rather than a bolted-on export.

Two modes:
  - "inspect": findings only (what inspect_bytes / counselclear inspect found).
  - "sanitize": findings + actions taken + verification + custody hashes
    (what clean_to_bundle produced) — this is the report.json's sibling
    named in the design doc's default bundle contents.
"""

from __future__ import annotations

import html
from typing import Any

RISK_ORDER = ("critical", "high", "medium", "low", "info")

CATEGORY_LABELS = {
    "file_metadata": "File metadata",
    "embedded_content": "Embedded content",
    "revision_history": "Revision history",
    "digital_signature": "Digital signature",
    "active_content": "Active content",
    "visual_watermark": "Visual watermark",
    "provenance_metadata": "Provenance metadata",
    "invisible_text": "Invisible text",
    "statistical_watermark": "Statistical watermark",
    "hidden_structure": "Hidden structure",
}

SUBTYPE_LABELS = {
    "authoring_props": "Author & company identity",
    "jpeg_gps": "GPS location (EXIF)",
    "comments_and_notes": "Comments & speaker notes",
    "tracked_changes": "Tracked changes",
    "office_tracked_changes": "Tracked changes",
    "hidden_text": "Hidden / white-on-white text",
    "hidden_text_formatting": "Hidden / white-on-white text",
    "layer_a_body": "Hidden Unicode watermark (body text)",
    "layer_a_non_body": "Hidden Unicode watermark (comments/headers)",
    "c2pa": "C2PA / Content Credentials",
    "ai_generator_metadata": "AI generator metadata",
    "cms_or_xml_dsig": "Digital signature",
    "macros_vba": "Macros (VBA)",
    "pdf_js_actions": "Embedded JavaScript / auto-actions",
    "pdf_acroform": "Form field values",
    "pdf_annots": "Annotations / markup",
    "pdf_attachments": "Embedded file attachments",
    "pdf_incremental": "Incremental edit history",
    "custom_xml": "Custom XML data",
    "external_links": "External file/workbook links",
    "embeddings_ole": "Embedded objects (OLE)",
    "headers_footers": "Headers & footers",
    "defined_names_hidden_range": "Hidden named ranges",
}

ACTION_LABELS = {
    "strip": "Removed",
    "keep": "Kept",
    "flag": "Flagged for review",
    "replace": "Replaced",
    "rebuild": "Rebuilt",
    "sanitize": "Sanitized",
    "refuse": "Refused",
    "accept_all": "Finalized (Accept All)",
    "inspect_only": "Inspected only",
}

CHECK_LABELS = {
    "reinspect_targeted_gone": "Targeted findings are actually gone",
    "no_new_identity_findings": "No new identity leaked in the process",
    "format_valid": "Output file is well-formed",
    "part_inventory": "No unexpected content added or removed",
    "page_count": "Page count matches expectation",
    "privacy_body_unchanged": "Visible text is byte-for-byte unchanged",
}


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _label(mapping: dict[str, str], key: Any, fallback_prefix: str = "") -> str:
    key = str(key or "")
    if key in mapping:
        return mapping[key]
    pretty = key.replace("_", " ").strip()
    return (fallback_prefix + pretty) if pretty else "—"


def _risk_rank(level: str) -> int:
    try:
        return RISK_ORDER.index(level)
    except ValueError:
        return len(RISK_ORDER)


def _as_dict(f: Any) -> dict[str, Any]:
    return f.to_dict() if hasattr(f, "to_dict") else dict(f)


def _summary_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in RISK_ORDER}
    for f in findings:
        level = f.get("risk_level") or "info"
        if level in counts:
            counts[level] += 1
    return counts


def _findings_html(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<p class="empty">No structured findings — nothing to report.</p>'

    by_category: dict[str, list[dict[str, Any]]] = {}
    for f in sorted(findings, key=lambda f: (_risk_rank(f.get("risk_level") or "info"))):
        by_category.setdefault(f.get("category") or "other", []).append(f)

    parts: list[str] = []
    for category, items in by_category.items():
        parts.append(f'<div class="group"><h3>{_esc(_label(CATEGORY_LABELS, category))}'
                      f' &middot; {len(items)}</h3><div class="tablewrap"><table><thead><tr>'
                      "<th>Risk</th><th>What</th><th>Where</th><th>Action</th>"
                      "<th>Detail</th></tr></thead><tbody>")
        for f in items:
            risk = f.get("risk_level") or "info"
            what = _label(SUBTYPE_LABELS, f.get("subtype"))
            loc = f.get("location") or {}
            where = loc.get("pane") or loc.get("part") or "—"
            action = _label(ACTION_LABELS, f.get("action_recommended"))
            detail = f.get("notes") or f.get("value_redacted") or ""
            parts.append(
                f'<tr><td class="risk {_esc(risk)}">{_esc(risk)}</td>'
                f"<td>{_esc(what)}</td><td>{_esc(where)}</td>"
                f"<td>{_esc(action)}</td><td>{_esc(detail)}</td></tr>"
            )
        parts.append("</tbody></table></div></div>")
    return "".join(parts)


def _checks_html(checks: list[dict[str, Any]]) -> str:
    if not checks:
        return ""
    rows = []
    for c in checks:
        ok = bool(c.get("pass"))
        label = _label(CHECK_LABELS, c.get("name"))
        cls = "clear" if ok else "found"
        mark = "Pass" if ok else "Fail"
        rows.append(
            f'<tr><td class="risk {cls}">{mark}</td><td>{_esc(label)}</td>'
            f'<td class="mono">{_esc(c.get("detail") or "")}</td></tr>'
        )
    return (
        '<div class="group"><h3>Verification checks</h3><div class="tablewrap"><table><thead><tr>'
        "<th>Result</th><th>Check</th><th>Detail</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div></div>"
    )


_CSS = """
:root {
  --paper: #f6f5f1; --ink: #121212; --mute: #5c5a56; --rule: #121212;
  --found: #8b1e1e; --clear: #1f4d38; --skip: #6b675f; --fill: #fffdf8;
  --amber: #7a4a12;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--paper); color: var(--ink); }
body {
  font: 15px/1.45 "Iowan Old Style", Palatino, "Palatino Linotype", "Times New Roman", serif;
}
.wrap { max-width: 62rem; margin: 0 auto; padding: 1.5rem 1.25rem 4rem; }
header {
  display: flex; justify-content: space-between; align-items: baseline; gap: 1rem;
  border-bottom: 1px solid var(--rule); padding-bottom: 0.7rem; margin-bottom: 1.4rem;
}
.brand { font-size: 0.78rem; letter-spacing: 0.22em; text-transform: uppercase; font-weight: 700; }
.where { font: 12px/1.3 ui-sans-serif, system-ui, sans-serif; color: var(--mute); }
h1 { font-size: 1.5rem; font-weight: 500; letter-spacing: -0.02em; margin: 0 0 0.35rem; }
.lede { margin: 0 0 1.3rem; color: var(--mute); }
.summary {
  display: flex; flex-wrap: wrap; gap: 0.5rem 0.9rem; align-items: center;
  border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule);
  padding: 0.7rem 0; margin: 0 0 1.3rem;
  font: 13px/1.3 ui-sans-serif, system-ui, sans-serif;
}
.summary .verdict { font-size: 1.02rem; font-weight: 650; font-family: inherit; }
.summary .verdict.clear { color: var(--clear); }
.summary .verdict.found { color: var(--found); }
.chip {
  display: inline-block; font: 11.5px/1.2 ui-monospace, Menlo, monospace;
  border: 1px solid #ddd8ce; padding: 0.15rem 0.4rem;
}
.chip.critical, .chip.high { border-color: var(--found); color: var(--found); }
.chip.medium { border-color: var(--amber); color: var(--amber); }
.chip.low, .chip.info { color: var(--mute); }
h2 {
  font: 12px/1.3 ui-sans-serif, system-ui, sans-serif; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--mute); margin: 1.6rem 0 0.5rem;
  border-bottom: 1px solid #ddd8ce; padding-bottom: 0.3rem;
}
.group { margin: 1rem 0 0; }
.group h3 {
  font: 10.5px/1 ui-sans-serif, system-ui, sans-serif; letter-spacing: 0.1em;
  text-transform: uppercase; margin: 0 0 0.4rem; color: var(--mute);
}
.tablewrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font: 13px/1.35 ui-sans-serif, system-ui, sans-serif; min-width: 32rem; }
th {
  text-align: left; font-size: 10.5px; letter-spacing: 0.08em; text-transform: uppercase;
  font-weight: 650; color: var(--mute); border-bottom: 1px solid var(--rule);
  padding: 0 0.4rem 0.35rem 0;
}
td { vertical-align: top; padding: 0.5rem 0.5rem 0.5rem 0; border-bottom: 1px solid #ddd8ce; }
td.risk { font-weight: 650; white-space: nowrap; width: 5rem; text-transform: capitalize; }
td.risk.critical, td.risk.high, td.risk.found { color: var(--found); }
td.risk.medium { color: var(--amber); }
td.risk.low, td.risk.info { color: var(--mute); }
td.risk.clear { color: var(--clear); }
td.risk.skip { color: var(--skip); }
td.mono { font: 11.5px/1.4 ui-monospace, Menlo, monospace; color: var(--mute); }
.empty { color: var(--mute); font-size: 0.95rem; margin: 1rem 0; }
.foot {
  margin-top: 1.6rem; padding-top: 0.8rem; border-top: 1px solid var(--rule);
  font: 11.5px/1.5 ui-monospace, Menlo, monospace; color: var(--mute);
}
.foot div { margin: 0.15rem 0; }
@media (prefers-color-scheme: dark) {
  :root {
    --paper: #171613; --ink: #f3f2ee; --mute: #a39e93; --rule: #f3f2ee;
    --fill: #201f1b; --found: #e08585; --clear: #6fbf9a; --amber: #d3a35f;
  }
}
"""


def render_report_html(
    *,
    subject_name: str,
    kind: str,
    format: str,
    findings: list[Any],
    mode: str = "inspect",
    generated_at: str = "",
    policy_id: str | None = None,
    actions: list[str] | None = None,
    checks: list[dict[str, Any]] | None = None,
    verification_pass: bool | None = None,
    original_sha256: str | None = None,
    derivative_name: str | None = None,
    derivative_sha256: str | None = None,
    processor: dict[str, Any] | None = None,
) -> str:
    """Render a self-contained HTML report. ``mode`` is "inspect" (findings
    only) or "sanitize" (adds actions taken, verification, custody hashes)."""
    fdicts = [_as_dict(f) for f in findings]
    counts = _summary_counts(fdicts)
    total = sum(counts.values())

    chips = "".join(
        f'<span class="chip {level}">{counts[level]} {level}</span>'
        for level in RISK_ORDER
        if counts[level]
    )
    if mode == "sanitize" and verification_pass is not None:
        verdict_cls = "clear" if verification_pass else "found"
        verdict_txt = "Verification passed" if verification_pass else "Verification FAILED"
    elif total:
        verdict_cls, verdict_txt = "found", f"{total} finding(s)"
    else:
        verdict_cls, verdict_txt = "clear", "No findings"

    body = [
        "<header>",
        '<span class="brand">CounselClear</span>',
        f'<span class="where">{_esc(generated_at)}</span>',
        "</header>",
        f"<h1>{'Sanitization report' if mode == 'sanitize' else 'Inspection report'}"
        f"</h1>",
        f'<p class="lede">{_esc(subject_name)} &middot; {_esc(kind)}/{_esc(format)}'
        + (f" &middot; policy <code>{_esc(policy_id)}</code>" if policy_id else "")
        + "</p>",
        '<div class="summary">',
        f'<span class="verdict {verdict_cls}">{_esc(verdict_txt)}</span>',
        chips,
        "</div>",
        "<h2>Findings</h2>",
        _findings_html(fdicts),
    ]

    if mode == "sanitize":
        if actions:
            body.append("<h2>Actions taken</h2><ul>")
            body.extend(f"<li>{_esc(a)}</li>" for a in actions)
            body.append("</ul>")
        if checks:
            body.append(_checks_html(checks))
        foot = ["<h2>Custody</h2><div class=\"foot\">"]
        if original_sha256:
            foot.append(f"<div>original   sha256 {_esc(original_sha256)}</div>")
        if derivative_name:
            foot.append(f"<div>derivative {_esc(derivative_name)}</div>")
        if derivative_sha256:
            foot.append(f"<div>derivative sha256 {_esc(derivative_sha256)}</div>")
        if processor:
            tools = ", ".join(f"{k}={v}" for k, v in (processor.get("tools") or {}).items())
            foot.append(f"<div>processor  {_esc(processor.get('git_sha') or 'unknown')}"
                        f"{(' &middot; ' + _esc(tools)) if tools else ''}</div>")
        foot.append("</div>")
        body.extend(foot)

    return (
        "<!doctype html><meta charset=\"utf-8\">"
        f"<title>{_esc(subject_name)} — CounselClear report</title>"
        f"<style>{_CSS}</style>"
        f'<div class="wrap">{"".join(body)}</div>'
    )


def _top_finding(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not findings:
        return None
    return min(findings, key=lambda f: _risk_rank(f.get("risk_level") or "info"))


def _identity_rollup(records: list[dict[str, Any]]) -> list[tuple[str, str, int]]:
    """(field label, value, file count), most-common first — the "who shows
    up across this production" view, only populated when identities were
    revealed for each record."""
    counts: dict[tuple[str, str], int] = {}
    for rec in records:
        for label, value in (rec.get("identities") or {}).items():
            counts[(label, value)] = counts.get((label, value), 0) + 1
    rows = [(label, value, n) for (label, value), n in counts.items()]
    rows.sort(key=lambda r: (-r[2], r[0], r[1]))
    return rows


def render_intake_report(
    *,
    root_label: str,
    records: list[dict[str, Any]],
    reveal_identities: bool,
    generated_at: str = "",
    matter_label: str | None = None,
) -> str:
    """Aggregate HTML report over many files received from a counterparty.

    Each record: {"name", "kind", "format", "findings": [Finding-like, ...],
    "identities": dict[str, str] | None, "error": str | None}. Read-only —
    this never cleans anything, it only summarizes what inspect_bytes (plus,
    optionally, authoring_identity.extract_identities) already found.
    """
    scanned = [dict(r, _findings=[_as_dict(f) for f in (r.get("findings") or [])])
               for r in records if not r.get("error")]
    errored = [r for r in records if r.get("error")]

    all_findings = [f for r in scanned for f in r["_findings"]]
    counts = _summary_counts(all_findings)
    total = sum(counts.values())
    chips = "".join(
        f'<span class="chip {level}">{counts[level]} {level}</span>'
        for level in RISK_ORDER
        if counts[level]
    )

    body = [
        "<header>",
        '<span class="brand">CounselClear</span>',
        f'<span class="where">{_esc(generated_at)}</span>',
        "</header>",
        "<h1>Intake report</h1>",
        f'<p class="lede">{_esc(root_label)}'
        + (f" &middot; matter <code>{_esc(matter_label)}</code>" if matter_label else "")
        + f" &middot; {len(scanned)} file(s) scanned"
        + (f", {len(errored)} unreadable" if errored else "")
        + "</p>",
        '<div class="summary">',
        f'<span class="verdict {"found" if total else "clear"}">'
        f"{total} finding(s) across {len(scanned)} file(s)</span>",
        chips,
        "</div>",
    ]

    body.append("<h2>Identities found across this production</h2>")
    if reveal_identities:
        identity_rows = _identity_rollup(scanned)
        if identity_rows:
            body.append(
                '<div class="tablewrap"><table><thead><tr><th>Field</th><th>Value</th>'
                "<th>Files</th></tr></thead><tbody>"
            )
            for label, value, n in identity_rows:
                body.append(
                    f"<tr><td>{_esc(label)}</td><td>{_esc(value)}</td><td>{n}</td></tr>"
                )
            body.append("</tbody></table></div>")
        else:
            body.append('<p class="empty">No authoring identity fields found.</p>')
    else:
        body.append(
            '<p class="empty">Identity values are redacted by default '
            "(this product's default privacy posture). Re-run with "
            "--reveal-identities to see them for this intake.</p>"
        )

    body.append("<h2>Files</h2>")
    if not scanned and not errored:
        body.append('<p class="empty">No files found.</p>')
    else:
        body.append(
            '<div class="tablewrap"><table><thead><tr><th>Risk</th><th>File</th><th>Format</th>'
            "<th>Findings</th><th>Most severe</th></tr></thead><tbody>"
        )
        for r in sorted(
            scanned, key=lambda r: _risk_rank((_top_finding(r["_findings"]) or {}).get(
                "risk_level") or "info")
        ):
            top = _top_finding(r["_findings"])
            top_label = _label(SUBTYPE_LABELS, top.get("subtype")) if top else "—"
            top_risk = (top.get("risk_level") if top else "info") or "info"
            body.append(
                f'<tr><td class="risk {_esc(top_risk)}">{_esc(top_risk)}</td>'
                f"<td>{_esc(r['name'])}</td>"
                f"<td>{_esc(r.get('format') or r.get('kind'))}</td>"
                f"<td>{len(r['_findings'])}</td><td>{_esc(top_label)}</td></tr>"
            )
        for r in errored:
            body.append(
                f'<tr><td class="risk skip">skip</td><td>{_esc(r["name"])}</td>'
                f'<td colspan="3">{_esc(r.get("error"))}</td></tr>'
            )
        body.append("</tbody></table></div>")

    return (
        "<!doctype html><meta charset=\"utf-8\">"
        f"<title>{_esc(root_label)} — CounselClear intake report</title>"
        f"<style>{_CSS}</style>"
        f'<div class="wrap">{"".join(body)}</div>'
    )
