"""FastAPI application factory and /v1 routes (single-tenant profile)."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import logging
import os
import shutil
import time
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import custody as custody_mod  # WORM storage only — never parses documents
from common import MAX_INPUT_BYTES  # a size constant, not a parser
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# Imported as a module (not by name): tests stub IdP calls on the module
# object, and attribute access must resolve at call time for that to work.
from . import oidc as oidc_mod

# PR 17 doctrine: this module must NOT import engine_api / custody or call
# inspect_bytes/clean_to_bundle — untrusted bytes are parsed only inside
# isolated worker processes (see app.runner). A test enforces the ban.
from .acl import OPERATOR, bootstrap_operator, grant, has_perm, list_grants, perms_of, revoke
from .audit import append_event, event_hash, verify_chain
from .config import Config
from .db import make_engine, make_session_factory
from .dispatcher import BatchDispatcher, sync_release
from .malware import get_scanner
from .migrate import upgrade_head
from .models import (
    AttestationUse,
    AuditEvent,
    Batch,
    Document,
    Job,
    Matter,
    MatterAcl,
    Release,
    _now,
    _uuid,
)
from .oidc import OidcError
from .runner import run_job, sync_job
from .security import (
    ATTEST_STRENGTHS,
    LOCAL_SUBJECT,
    LoginThrottle,
    consume_attestation,
    ensure_local_password,
    issue_attestation,
    issue_session,
    revoke_all_sessions,
    session_subject,
    verify_attestation,
    verify_password,
)
from .storage import StorageError as StorageError_
from .storage import original_key, storage_from_config

# scripts.policies.NO_DECISION_MARKER, literal here for the same PR 17
# reason as POLICIES below: main.py must not import the engine. Used only
# to count how many kept-without-review findings an already-finished
# sanitize job's manifest reports, for the job.sanitize audit event —
# never to decide anything. Kept in sync by
# test_worker_isolation.py::test_no_decision_marker_stays_in_sync_with_policies.
NO_DECISION_MARKER = "no operator decision was supplied"
# scripts.policies.OPERATOR_KEPT_MARKER / APPROVED_BUT_NO_OP_MARKER, same
# PR 17 literal-not-imported reason and the same sync test. Used by the
# custody certificate (PR 33) to distinguish, in a manifest's actions[],
# an operator's own reviewed "keep" decision (OPERATOR_KEPT_MARKER) and an
# "approve" that this policy structurally resolves to a no-op keep anyway
# (APPROVED_BUT_NO_OP_MARKER) from an unreviewed keep (NO_DECISION_MARKER
# above) — the same string-distinction reason policies.py itself gives.
OPERATOR_KEPT_MARKER = "reviewed and kept by operator"
APPROVED_BUT_NO_OP_MARKER = "approved, but this subtype has no strip action under this policy"


def _escape_like(q: str) -> str:
    """Escape SQL LIKE/ILIKE wildcards in a user-supplied search string.

    Without this, a literal percent sign or underscore typed into a search
    box would act as a wildcard instead of matching itself -- e.g.
    searching a matter named "50% Settlement" would silently behave like a
    fuzzy search instead of an exact substring one. Callers pass a single
    backslash as the ilike() escape character to match this.
    """
    return q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


_ATTENTION_SECTION_TITLE = {
    "unreviewed_findings": "Unreviewed findings",
    "refused": "Refused jobs",
    "failed": "Failed jobs",
    "stale": "Stale matter",
}

# Shared CSS for the "you are looking at a standalone export, not the live
# app" banner every backend-rendered HTML report/certificate carries (UX
# coherence pass, PR 35) -- both _render_matter_summary_html and
# _render_job_certificate_html splice this in verbatim so the two reports
# can never drift into inconsistent banner styling.
_STANDALONE_BANNER_CSS = """
  .standalone-banner { display: flex; align-items: center; justify-content: space-between;
                       gap: 0.75rem; background: #eef2ff; border: 1px solid #4f46e5;
                       border-radius: 6px; padding: 0.5rem 0.9rem; margin-bottom: 1.25rem;
                       font-size: 0.85rem; }
  .standalone-banner .badge { font-weight: 700; letter-spacing: 0.02em; color: #4338ca; }
  .standalone-banner a { color: #4338ca; font-weight: 600; text-decoration: none; }
  .standalone-banner a:hover { text-decoration: underline; }
"""


def _standalone_banner_html(*, back_href: str, back_label: str) -> str:
    """Relative link back into the Next.js app: this HTML page is reached
    either through the app's own same-origin dev proxy (next.config.ts's
    rewrites -- so the browser's location origin is already the Next app,
    even though this content came from the API) or, in production, through
    nginx unifying both under one origin (docs/COUNSELCLEAR_PRODUCTION.md
    §1) -- a relative path resolves correctly in both cases without this
    backend needing to know the frontend's own URL."""
    e = html.escape
    return (
        '<div class="standalone-banner">'
        '<span><span class="badge">STANDALONE EXPORT</span> '
        "— not the live CounselClear app; nothing here refreshes automatically.</span>"
        f'<a href="{e(back_href)}">{e(back_label)}</a>'
        "</div>"
    )


def _render_matter_summary_html(
    *,
    matter_id: str,
    matter_name: str,
    generated_at: str,
    generated_by: str,
    total_documents: int,
    job_counts: dict[str, int],
    attention: list[dict],
    chain_ok: bool,
    chain_detail: str,
    total_events: int,
    recent_events: list[dict],
) -> str:
    """Self-contained HTML reviewer-handoff report -- no external CSS/JS,
    printable to PDF from any browser's own print dialog rather than this
    app taking on a PDF-generation dependency. Every dynamic value is
    html.escape()'d: matter names, filenames, and job error strings are
    all user/policy-supplied text that could otherwise inject markup into
    a document meant to be handed to someone outside the app.

    Deliberately NOT a certification: the disclaimer at both top and
    bottom is load-bearing, not boilerplate -- this restates only what
    the audit chain and manifests themselves already support (per-job
    verification, hash-chained events), not a claim that a matter is
    "clean" or that no risk remains.
    """
    e = html.escape

    def esc(v: object) -> str:
        return e(str(v))

    attention_html = ""
    if not attention:
        attention_html = "<p>No open attention items for this matter.</p>"
    else:
        by_type: dict[str, list[dict]] = {}
        for item in attention:
            by_type.setdefault(item["type"], []).append(item)
        for atype, items in by_type.items():
            title = _ATTENTION_SECTION_TITLE.get(atype, atype)
            attention_html += f"<h3>{esc(title)} ({len(items)})</h3><ul>"
            for item in items:
                ref_bits = []
                if item.get("document_name"):
                    ref_bits.append(f"document: {esc(item['document_name'])}")
                if item.get("job_id"):
                    ref_bits.append(f"job id: {esc(item['job_id'])}")
                ref = f" ({', '.join(ref_bits)})" if ref_bits else ""
                # Every attention item with a job_id belongs to *this*
                # matter (_attention_items was called with matter_ids=[this
                # matter] for the summary route, unlike the dashboard's
                # multi-matter call) -- safe to build the link from this
                # function's own matter_id param rather than trusting an
                # unscoped item['matter_id'].
                cert_link = (
                    f' <a href="/v1/matters/{esc(matter_id)}/jobs/{esc(item["job_id"])}/certificate">'
                    "certificate</a>"
                    if item.get("job_id")
                    else ""
                )
                attention_html += f"<li>{esc(item['detail'])}{ref}{cert_link}</li>"
            attention_html += "</ul>"

    job_status_html = "".join(
        f"<tr><td>{esc(status)}</td><td>{esc(count)}</td></tr>"
        for status, count in job_counts.items()
    )

    if not recent_events:
        recent_html = "<p>No audit events recorded.</p>"
    else:
        shown = len(recent_events)
        coverage_note = (
            f"Showing the most recent {shown} of {total_events} total event(s)."
            if shown < total_events
            else f"Showing all {total_events} event(s) -- this matter has no more."
        )
        rows = "".join(
            f"<tr><td>{esc(ev['seq'])}</td><td>{esc(ev['at'])}</td>"
            f"<td>{esc(ev['action'])}</td><td>{esc(ev['actor_id'])}</td></tr>"
            for ev in recent_events
        )
        recent_html = (
            f"<p>{coverage_note} The complete, hash-chain-verifiable audit "
            f"trail is available via the CSV export "
            f"(<code>/v1/matters/{esc(matter_id)}/audit/export</code>), not "
            "reproduced in full here.</p>"
            "<table><thead><tr><th>#</th><th>When (UTC)</th><th>Action</th>"
            f"<th>Actor</th></tr></thead><tbody>{rows}</tbody></table>"
        )

    disclaimer = (
        "This report summarizes CounselClear's own recorded state for this "
        "matter -- document and job counts, open attention items, and audit "
        "chain integrity -- as of the generation timestamp below. It is "
        "<strong>not</strong> a legal certification, attestation, or a "
        "claim that any document is fully “clean” beyond what the "
        "per-job manifest and the hash-chained audit trail themselves "
        "record. Consult the individual job manifests for exactly what was "
        "stripped, flagged, or kept in each derivative."
    )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Matter Summary — {esc(matter_name)}</title>
<style>
  body {{ font-family: -apple-system, Helvetica, Arial, sans-serif; max-width: 800px;
         margin: 2rem auto; padding: 0 1rem; color: #171717; line-height: 1.5; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.25rem; }}
  h3 {{ font-size: 0.95rem; margin-bottom: 0.25rem; }}
  .meta {{ color: #6b7280; font-size: 0.9rem; }}
  .disclaimer {{ background: #fef3c7; border: 1px solid #d97706; border-radius: 6px;
                padding: 0.75rem 1rem; font-size: 0.9rem; margin: 1rem 0; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; margin-top: 0.5rem; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 4px 8px; text-align: left; }}
  code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 3px; }}
  .chain-ok {{ color: #047857; font-weight: 600; }}
  .chain-broken {{ color: #b91c1c; font-weight: 600; }}
{_STANDALONE_BANNER_CSS}</style>
</head>
<body>
{_standalone_banner_html(back_href=f"/matters/view?id={matter_id}", back_label="← Back to matter")}
<h1>Matter Summary — {esc(matter_name)}</h1>
<p class="meta">Matter ID: <code>{esc(matter_id)}</code><br>
Generated: {esc(generated_at)} UTC by <code>{esc(generated_by)}</code></p>
<div class="disclaimer">{disclaimer}</div>

<h2>Totals</h2>
<p>Documents: {esc(total_documents)}</p>
<table><thead><tr><th>Job status</th><th>Count</th></tr></thead>
<tbody>{job_status_html}</tbody></table>

<h2>Attention items</h2>
{attention_html}

<h2>Audit chain</h2>
<p>Status: <span class="{"chain-ok" if chain_ok else "chain-broken"}">
{"Verified intact" if chain_ok else "BROKEN"}</span> — {esc(chain_detail)}</p>
{recent_html}

<div class="disclaimer">{disclaimer}</div>
</body>
</html>
"""


def _render_job_certificate_html(
    *,
    matter_id: str,
    matter_name: str,
    document_id: str,
    document_name: str,
    job_id: str,
    kind: str,
    status: str,
    error: str,
    created_utc: str,
    finished_utc: str | None,
    original_sha256: str,
    derivative_sha256: str | None,
    policy_id: str | None,
    policy_version: int | None,
    policy_description: str | None,
    actions: list[str],
    findings_before: list[str],
    inspect_findings: list[dict],
    verification: dict | None,
    limitations: list[str],
    audit_event_count: int,
    audit_integrity_ok: bool,
    generated_at: str,
    generated_by: str,
    release_context: dict | None = None,
) -> str:
    """Self-contained per-job custody/transaction certificate (PR 33).

    Same discipline as _render_matter_summary_html above: no external CSS/
    JS (printable to PDF from any browser's own print dialog), every
    dynamic value html.escape()'d, and the disclaimer is load-bearing —
    this certifies CounselClear's own recorded transaction (what ran,
    what the policy did, what was verified, what's disclosed as a
    limitation), never that the document is "clean" or "safe". No
    original bytes and no unrelated audit rows appear here — original_
    sha256/derivative_sha256 are hashes only, and audit_event_count/
    audit_integrity_ok are a narrow, job-scoped custody assertion (each
    of this job's own audit rows' stored hash recomputed and checked),
    not a walk of the matter's full chain (that's the admin-gated
    GET .../audit route's job).
    """
    e = html.escape

    def esc(v: object) -> str:
        return e(str(v))

    limitations_html = (
        "<p>No limitations flagged for this job.</p>"
        if not limitations
        else "<ul>" + "".join(f"<li>{esc(item)}</li>" for item in limitations) + "</ul>"
    )

    policy_html = ""
    if policy_id is not None:
        policy_html = (
            "<h2>Policy</h2>"
            f"<p><code>{esc(policy_id)}</code> (v{esc(policy_version)})"
            f"{f' — {esc(policy_description)}' if policy_description else ''}</p>"
        )

    # release_context is None for a legacy job with no Release wrapper --
    # this section is absent entirely then, same as policy_html is absent
    # for an inspect job. "Prepared for release" throughout, deliberately
    # never "sent"/"delivered": this certifies what CounselClear itself
    # did (produced this under a chosen profile, for a stated recipient
    # and purpose), never that the document actually reached anyone.
    release_html = ""
    if release_context is not None:
        recipient_label = RECIPIENT_TYPE_LABEL.get(
            release_context["recipient_type"], release_context["recipient_type"]
        )
        recipient_line = f"Recipient: {esc(recipient_label)}"
        if release_context.get("recipient_name"):
            recipient_line += f" — {esc(release_context['recipient_name'])}"
        purpose_line = (
            f"<br>Purpose: {esc(release_context['purpose'])}" if release_context.get("purpose") else ""
        )
        intent_line = (
            "Intended to leave the organization"
            if release_context["intended_external"]
            else "Intended to remain internal — not for external release"
        )
        release_html = (
            "<h2>Release</h2>"
            f"<p>Prepared for release under profile <code>{esc(release_context['profile_label'])}</code> "
            f"(<code>{esc(release_context['profile_id'])}</code>).<br>"
            f"{recipient_line}{purpose_line}<br>"
            f"{esc(intent_line)}.</p>"
        )

    hashes_html = f"<p>Original SHA-256: <code>{esc(original_sha256)}</code>"
    hashes_html += (
        f"<br>Derivative SHA-256: <code>{esc(derivative_sha256)}</code></p>"
        if derivative_sha256
        else "<br>Derivative SHA-256: <em>none — no derivative was produced for this job</em></p>"
    )

    actions_html = (
        "<p>No manifest actions recorded.</p>"
        if not actions
        else "<ul>" + "".join(f"<li>{esc(a)}</li>" for a in actions) + "</ul>"
    )
    findings_before_html = (
        "<p>None recorded.</p>"
        if not findings_before
        else "<ul>" + "".join(f"<li>{esc(f)}</li>" for f in findings_before) + "</ul>"
    )

    inspect_findings_html = ""
    if inspect_findings:
        rows = "".join(
            f"<tr><td>{esc(f.get('category', ''))}</td><td>{esc(f.get('subtype', ''))}</td>"
            f"<td>{esc(f.get('risk_level', ''))}</td><td>{esc(f.get('confidence', ''))}</td></tr>"
            for f in inspect_findings
        )
        inspect_findings_html = (
            "<h2>Findings</h2>"
            f"<p>{len(inspect_findings)} finding(s) reported. Inspection is read-only: no "
            "derivative was produced and the original was not modified.</p>"
            "<table><thead><tr><th>Category</th><th>Subtype</th><th>Risk</th>"
            f"<th>Confidence</th></tr></thead><tbody>{rows}</tbody></table>"
        )

    verification_html = "<p>No verification data recorded for this job.</p>"
    if verification:
        v_pass = verification.get("pass")
        checks = verification.get("checks") or []
        checks_html = (
            "".join(f"<li>{esc(c)}</li>" for c in checks) if checks else "<li>(no detail recorded)</li>"
        )
        verification_html = (
            f"<p>Result: <span class=\"{'chain-ok' if v_pass else 'chain-broken'}\">"
            f"{'passed' if v_pass else 'FAILED'}</span></p><ul>{checks_html}</ul>"
        )

    disclaimer = (
        "This certificate records CounselClear's own recorded state for this single "
        "job — what ran, what the applied policy did, what was verified, and what "
        "is explicitly disclosed as a limitation below — as of the generation "
        "timestamp. It is <strong>not</strong> a claim that this document is "
        "“clean,” “safe,” or free of risk beyond what is "
        "stated here, and it is <strong>not</strong> a legal opinion. Any "
        "limitation listed below is part of the certificate, not a defect in it."
    )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Custody Certificate — {esc(document_name)}</title>
<style>
  body {{ font-family: -apple-system, Helvetica, Arial, sans-serif; max-width: 800px;
         margin: 2rem auto; padding: 0 1rem; color: #171717; line-height: 1.5; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.25rem; }}
  .meta {{ color: #6b7280; font-size: 0.9rem; }}
  .disclaimer {{ background: #fef3c7; border: 1px solid #d97706; border-radius: 6px;
                padding: 0.75rem 1rem; font-size: 0.9rem; margin: 1rem 0; }}
  .limitations {{ background: #fee2e2; border: 2px solid #b91c1c; border-radius: 6px;
                  padding: 0.75rem 1rem; margin: 1rem 0; }}
  .limitations h2 {{ margin-top: 0; border-bottom: none; color: #b91c1c; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; margin-top: 0.5rem; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 4px 8px; text-align: left; }}
  code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 3px; word-break: break-all; }}
  .chain-ok {{ color: #047857; font-weight: 600; }}
  .chain-broken {{ color: #b91c1c; font-weight: 600; }}
  .status {{ font-weight: 600; }}
{_STANDALONE_BANNER_CSS}</style>
</head>
<body>
{_standalone_banner_html(back_href=f"/matters/job?matter={matter_id}&job={job_id}", back_label="← Back to job")}
<h1>Custody Certificate — {esc(document_name)}</h1>
<p class="meta">Matter: {esc(matter_name)} (<code>{esc(matter_id)}</code>)<br>
Document ID: <code>{esc(document_id)}</code><br>
Job ID: <code>{esc(job_id)}</code> · kind: {esc(kind)} · status:
<span class="status">{esc(status)}</span><br>
Created: {esc(created_utc)} UTC{f" · Finished: {esc(finished_utc)} UTC" if finished_utc else ""}<br>
Generated: {esc(generated_at)} UTC by <code>{esc(generated_by)}</code></p>
<div class="disclaimer">{disclaimer}</div>

<div class="limitations">
<h2>Limitations — read before relying on this certificate</h2>
{limitations_html}
</div>

{f'<div class="disclaimer"><strong>Error:</strong> {esc(error)}</div>' if error else ""}

<h2>Hashes</h2>
{hashes_html}

{policy_html}
{release_html}
{inspect_findings_html}

<h2>Manifest actions</h2>
{actions_html}

<h2>Findings before sanitization</h2>
{findings_before_html}

<h2>Verification</h2>
{verification_html}

<h2>Custody record</h2>
<p>{esc(audit_event_count)} audit event(s) recorded for this job in the matter's
hash-chained audit log; each recomputed and confirmed to match its stored hash:
<span class="{"chain-ok" if audit_integrity_ok else "chain-broken"}">
{"OK" if audit_integrity_ok else "MISMATCH"}</span>. This is a check of this
job's own recorded events only, not a walk of the matter's complete audit
chain — see the matter's audit log (admin access) for that.</p>

<div class="limitations">
<h2>Limitations — read before relying on this certificate</h2>
{limitations_html}
</div>
<div class="disclaimer">{disclaimer}</div>
</body>
</html>
"""


# Four frozen v1 default policies (docs/COUNSELCLEAR_DESIGN.md, "Key
# Decisions" #5, and the full subtype table under Policy Engine). Literal
# ids/labels here, not an import of scripts.policies: main.py stays out of
# the engine's import graph (PR 17 isolation) for what is, by design, a
# frozen list that only ever changes alongside this file.
POLICIES = [
    {
        "id": "external_sharing",
        "label": "External sharing",
        "description": (
            "For sending outside the firm: strips comments, external links, "
            "embedded objects, and custom XML; accepts all tracked changes; "
            "flags headers/footers and hidden content for review."
        ),
        # bulk_safe: the subtype table has NO approve-default cells, so a
        # sanitize needs no per-finding decisions (main.py stays out of the
        # engine's import graph; tests/test_batches.py keeps this flag in
        # sync with policies.py). Still refuses whole documents on macros /
        # digital signatures — disclosed pre-submit, refused per document.
        "bulk_safe": True,
    },
    {
        "id": "privacy_only",
        "label": "Privacy only",
        "description": (
            "Minimal, no-visible-change: strips only PII authoring fields "
            "and GPS location. Keeps comments, tracked changes, and C2PA "
            "provenance untouched."
        ),
        # Decision-free like external_sharing; its keeps are policy-default
        # keeps, never no-decision keeps, so no manifest marker is produced.
        "bulk_safe": True,
    },
    {
        "id": "production",
        "label": "Production",
        "description": (
            "Litigation production: most findings require an explicit "
            "per-finding approve/keep decision instead of an automatic strip."
        ),
        # Approve-default cells (comments, tracked changes, hidden content,
        # embedded objects, attachments, links, ...) demand a per-document
        # decision workflow — never bulk-run without one.
        "bulk_safe": False,
    },
    {
        "id": "evidence_preservation",
        "label": "Evidence preservation",
        "description": (
            "Inspect-only — never produces a derivative. Preserves the "
            "original for evidentiary integrity."
        ),
        # Not bulk-safe: sanitize under this policy produces no derivative,
        # so a "bulk sanitize" would silently mean "bulk inspect".
        "bulk_safe": False,
    },
]


# Display-facing selection for the Release routes (POST .../releases):
# the operator picks a use-case profile, not a low-level sanitizer
# policy_id -- policy_id stays the stable internal identifier every
# existing route (POLICIES above) already keys on, untouched by this.
# Each profile resolves to exactly one policy_id; nothing here changes
# what that policy actually does.
RELEASE_PROFILES = [
    {
        "id": "counterparty_deal_room",
        "label": "Counterparty / Deal Room Release",
        "policy_id": "external_sharing",
        "description": "Sending to the other side of a deal or matter: strips comments, "
        "external links, embedded objects, and custom XML.",
    },
    {
        "id": "public_filing_anonymized",
        "label": "Public Filing / Anonymized Release",
        "policy_id": "privacy_only",
        "description": "Minimal, no-visible-change strip of PII authoring fields and "
        "GPS location, for content that's otherwise going out as-is.",
    },
    {
        "id": "ediscovery_production",
        "label": "E-Discovery / Production Release",
        "policy_id": "production",
        "description": "Litigation production: most findings require an explicit "
        "per-finding decision instead of an automatic strip. Not available in "
        "batch mode -- see POLICIES[*].bulk_safe.",
    },
]

# Controlled vocabulary for Release.recipient_type -- deliberately narrow
# and structured (unlike recipient_name/purpose, both free text) so this
# is the one field a future learning-layer pass can safely aggregate on
# without touching anything that might carry privileged/sensitive detail.
RECIPIENT_TYPES = (
    "opposing_counsel",
    "court",
    "client",
    "regulator",
    "internal_reviewer",
    "other",
)

# Mirrors web/app/matters/view/page.tsx's RECIPIENT_TYPE_LABEL -- the one
# other place recipient_type's raw slug gets a human-readable label
# (PR 44: the certificate now shows it too). Kept as a second literal
# copy, not a shared import, for the same reason RECIPIENT_TYPES itself
# is a tuple literal here rather than sourced from the frontend: main.py
# has no dependency on web/, and shouldn't grow one for a label map.
RECIPIENT_TYPE_LABEL = {
    "opposing_counsel": "Opposing counsel",
    "court": "Court / tribunal",
    "client": "Client",
    "regulator": "Regulator",
    "internal_reviewer": "Internal reviewer",
    "other": "Other",
}

# --- PR 45: evaluation-flow demo fixtures --------------------------------
#
# Baked in here rather than read from tests/fixtures/legal/, the same way
# tools/seed_eval_matter.py already deliberately builds its own fixture
# inline: production images don't ship the tests/ tree (service/Dockerfile
# .counselclear only COPYs scripts/ and app/), so a runtime route can't
# depend on it existing on disk. The byte structure mirrors
# tests/fixtures/legal/generate.py's spa.docx/macro.docm/hidden.xlsx
# exactly (same clauses, same tracked-change/comment/header shape, same
# hidden-sheet/external-link/comment shape) -- those are the real,
# already-regression-tested fixtures this mirrors, not a fresh invention.
_DEMO_W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_DEMO_SPA_CLAUSES = [
    "1. The Seller shall deliver the Shares on Closing.",
    "2. The Buyer shall pay the Consideration under Section 8.3.",
    "3. This Agreement is governed by the laws of Delaware.",
]
_DEMO_SPA_DELETED = "4. DELETED CLAUSE about the side payment."
_DEMO_SPA_INSERTED = "4. The Parties shall keep these terms confidential."


def _demo_docx_bytes(parts: dict[str, str]) -> bytes:
    def decl(root: str, inner: str) -> str:
        return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><{root} {_DEMO_W_NS}>{inner}</{root}>'

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        ct = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            "<Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/>"
            "<Override PartName='/word/comments.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml'/>"
            "<Override PartName='/docProps/core.xml' ContentType='application/vnd.openxmlformats-package.core-properties+xml'/>"
            "<Override PartName='/docProps/app.xml' ContentType='application/vnd.openxmlformats-officedocument.extended-properties+xml'/>"
            "</Types>"
        )
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>",
        )
        zf.writestr(
            "docProps/core.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<dc:title>Sample Stock Purchase Agreement</dc:title>"
            "<dc:subject>Evaluation Sample</dc:subject>"
            "<dc:creator>Sample Associate</dc:creator>"
            "<cp:lastModifiedBy>Sample Associate</cp:lastModifiedBy>"
            "<cp:keywords>sample, evaluation</cp:keywords>"
            "</cp:coreProperties>",
        )
        zf.writestr(
            "docProps/app.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            "<Application>Microsoft Office Word</Application>"
            "<Company>Sample Firm LLP</Company>"
            "<Manager>Sample Manager</Manager>"
            "</Properties>",
        )
        zf.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdC" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>'
            "</Relationships>",
        )
        for name, xml in parts.items():
            if name == "word/document.xml":
                zf.writestr(name, decl("w:document", f"<w:body>{xml}</w:body>"))
            else:
                zf.writestr(name, decl(name.split("/")[-1].split(".")[0].capitalize(), xml))
    return buf.getvalue()


def _demo_xlsx_bytes(parts: dict[str, str], sheets_xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        ct = (
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            "</Types>"
        )
        zf.writestr("[Content_Types].xml", ct)
        rels = (
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdX" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink" Target="externalLinks/externalLink1.xml"/>'
            "</Relationships>"
        )
        zf.writestr("xl/_rels/workbook.xml.rels", rels)
        zf.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f"<sheets>{sheets_xml}</sheets>"
            '<externalReferences><externalReference r:id="rIdX"/></externalReferences></workbook>',
        )
        for name, xml in parts.items():
            zf.writestr(name, xml)
    return buf.getvalue()


def _demo_fixture_spa_docx() -> bytes:
    """Tracked-change insertion/deletion, a comment, and a hidden (w:vanish)
    "ATTORNEY WORK PRODUCT" paragraph -- under counterparty_deal_room/
    external_sharing the comment strips and tracked changes get
    Accept-All'd, but hidden_text is flag-only (policies.py) so the vanish
    text survives, listed under "What was found" but never "Actions
    taken". One document, both behaviors. (A bare word/header1.xml part
    was tried first and dropped: this engine's own docx inspector doesn't
    generate a finding for header/footer part presence by itself --
    confirmed against tests/fixtures/legal/golden/spa.docx.json, which has
    no headers_footers finding either -- so it demonstrated nothing.)"""
    body_parts = [f"<w:p><w:r><w:t>{clause}</w:t></w:r></w:p>" for clause in _DEMO_SPA_CLAUSES]
    body_parts.append(
        f"<w:p><w:ins><w:r><w:t>{_DEMO_SPA_INSERTED}</w:t></w:r></w:ins>"
        f"<w:del><w:r><w:delText>{_DEMO_SPA_DELETED}</w:delText></w:r></w:del></w:p>"
    )
    body_parts.append(
        "<w:p><w:r><w:t>Consideration</w:t></w:r>"
        "<w:commentRangeStart/><w:r><w:t>amounts</w:t></w:r><w:commentRangeEnd/>"
        "<w:r><w:commentReference/></w:r><w:r><w:t> are final.</w:t></w:r></w:p>"
    )
    body_parts.append(
        "<w:p><w:r><w:rPr><w:vanish/></w:rPr>"
        "<w:t>ATTORNEY WORK PRODUCT — PRIVILEGED AND CONFIDENTIAL</w:t></w:r></w:p>"
    )
    return _demo_docx_bytes(
        {
            "word/document.xml": "".join(body_parts),
            "word/comments.xml": "<w:comment/>",
        }
    )


def _demo_fixture_macro_docm() -> bytes:
    """A .docm carrying a VBA project -- macros_vba is refused
    unconditionally by every mutating policy (policies.py), so this hits a
    deterministic release refusal with no attestation ambiguity."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        zf.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?><w:document {_DEMO_W_NS}><w:body><w:p/></w:body></w:document>',
        )
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0VBA-STUB")
    return buf.getvalue()


def _demo_fixture_hidden_xlsx() -> bytes:
    """A hidden sheet alongside a visible one, plus a comment and an
    external link. Under counterparty_deal_room/external_sharing the
    comment and external link strip, but hidden_structure is flag-only
    (Key Decision 5) -- the release still succeeds, with a real, visible
    limitation recorded rather than silently stripped or ignored."""
    return _demo_xlsx_bytes(
        {
            "xl/worksheets/sheet1.xml": (
                '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>'
            ),
            "xl/comments1.xml": '<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><comment ref="A1"/></comments>',
            "xl/persons/person1.xml": '<persons xmlns="http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"><person/></persons>',
            "xl/externalLinks/externalLink1.xml": '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
        },
        sheets_xml=(
            '<sheet name="Deal" sheetId="1" r:id="rId1"/>'
            '<sheet name="SideTerms" sheetId="2" state="hidden" r:id="rId2"/>'
        ),
    )


# filename -> (fixture builder, release profile) for POST .../demo-seed.
# One profile (counterparty_deal_room) for all three so the walkthrough is
# "one profile, three real outcomes" rather than requiring the evaluator
# to also reason about profile choice.
_DEMO_SEED_DOCUMENTS = (
    ("Sample - Stock Purchase Agreement.docx", _demo_fixture_spa_docx),
    ("Sample - Macro-Enabled Draft.docm", _demo_fixture_macro_docm),
    ("Sample - Deal Terms Workbook.xlsx", _demo_fixture_hidden_xlsx),
)
_DEMO_MATTER_NAME = "Sample Matter — Release Gate Walkthrough"


class LoginBody(BaseModel):
    password: str


class MatterBody(BaseModel):
    name: str


class LegalJustificationBody(BaseModel):
    basis: str = "unspecified"
    note: str = ""


class LayerBBody(BaseModel):
    strength: str
    token: str


class SanitizeBody(BaseModel):
    policy_id: str = "external_sharing"
    reason: str = ""
    signature_break_attestation: bool = False
    # {subtype: "approve"|"keep"}, for policies with approve-default cells
    # (production's comments_and_notes and friends). Validated inside the
    # worker by plan_actions itself (an unknown subtype or action becomes a
    # failed job with a clear PolicyError message) — the same place
    # policy_id's own validity is checked, not pre-validated here.
    finding_decisions: dict[str, str] = {}
    # {subtype: {basis, note}}. Operator-supplied legal basis for findings
    # that survive the derivative; the worker validates basis/subtype and
    # records "unspecified" when a surviving finding has no supplied basis.
    legal_justifications: dict[str, LegalJustificationBody] = {}
    # PR 20: Layer B (statistical watermark) rewrite, gated by the signed
    # attestation token issued by POST /v1/attestations. Absent = Layer A
    # only. The token is verified server-side before the job is created.
    layer_b: LayerBBody | None = None


class BulkJobsBody(BaseModel):
    """One request, one job per document — each job audited individually.

    Deliberately narrow: inspect (any document) or sanitize (bulk_safe
    policies only — see POLICIES). No attestation, no finding_decisions,
    no layer_b: those are per-document workflows and bulk is never allowed
    to launder them into a blanket run.
    """

    document_ids: list[str]
    kind: str
    policy_id: str = "external_sharing"
    reason: str = ""


class ReleaseBody(BaseModel):
    """POST .../documents/{doc_id}/releases -- single-document.

    profile_id, not policy_id: the Release routes are profile-first (see
    RELEASE_PROFILES) precisely so a caller chooses a destination/use-case,
    not a low-level sanitizer policy. The raw policy_id-based
    /sanitize-jobs route is untouched and still exists for advanced/
    internal use.
    """

    profile_id: str
    recipient_type: str = "other"
    recipient_name: str = ""
    purpose: str = ""
    intended_external: bool = True
    reason: str = ""
    signature_break_attestation: bool = False
    finding_decisions: dict[str, str] = {}
    legal_justifications: dict[str, LegalJustificationBody] = {}
    layer_b: LayerBBody | None = None


class BatchReleaseBody(BaseModel):
    """POST .../matters/{id}/releases -- batch. Reuses the existing async
    Batch resource unchanged underneath (see create_batch); one Release
    row per document_id, each riding alongside its own child Job."""

    document_ids: list[str]
    profile_id: str
    recipient_type: str = "other"
    recipient_name: str = ""
    purpose: str = ""
    intended_external: bool = True
    reason: str = ""

class AttestationBody(BaseModel):
    matter_id: str
    document_id: str
    strength: str
    reason: str = ""


class AclBody(BaseModel):
    # Phase 3 (OIDC): user_id here is an arbitrary ACL principal — the local
    # "operator", or another principal's "oidc:<hash>" subject.
    user_id: str = OPERATOR
    perm: str
    # DELETE only: revoking your own admin/read grant is a self-lockout
    # risk (losing visibility into, or control over, a matter you may
    # still need). Not an outright block like the last-admin case in
    # acl.revoke -- an admin may legitimately want to step back after
    # handing off -- but it must be a deliberate act, not a stray click.
    confirm_self_revoke: bool = False


def _legal_justifications_payload(
    items: dict[str, LegalJustificationBody] | None,
) -> dict[str, dict[str, str]]:
    """Serialize request-model legal bases without duplicating policy validation.

    The worker/policy layer remains authoritative for subtype and basis
    validity. The app boundary only normalizes Pydantic request objects into
    plain JSON so the job row can carry operator-supplied legal context across
    the process boundary.
    """
    out: dict[str, dict[str, str]] = {}
    for subtype, item in (items or {}).items():
        note = item.note if item.note is not None else ""
        out[subtype] = {"basis": item.basis, "note": note[:1000]}
    return out


log = logging.getLogger("counselclear")


def _jlog(level: int, event: str, **fields) -> None:
    """Structured single-line JSON log record.

    The design doc's observability section requires machine-parsable logs
    (one JSON object per line, no basename/author/GPS/text payloads) — this
    is the one funnel for every app-level log line. Field order is stable
    via dict insertion; values are operator-safe by construction.
    """
    payload = {"event": event, **fields}
    log.log(level, json.dumps(payload, separators=(",", ":"), default=str))


def _sweep_orphaned_jobs(s: Session) -> tuple[int, list[str]]:
    """Fail jobs left running, or left queued with no dispatcher to resume
    them, by a previous process death.

    A "running" row can only exist while the process that flipped it to
    running is alive — for a single-document job that's the request that
    spawned it, and for a batch child it's the dispatcher's claim
    (service/app/dispatcher.py) — so at boot, before the app serves
    anything, any running row is by definition orphaned: its worker
    subprocess/container died with the old API process and sync_job will
    never run for it. Left alone it would sit "running" forever.

    "queued" is different for PR 31's batch children: a queued row is
    exactly the durable, restart-safe queue state (Job.batch_id IS NOT
    NULL) — BatchDispatcher picks it back up once the new process boots,
    same as it would have without a restart. Failing it here would be
    wrong, not just unnecessary. A plain queued job with no batch_id has
    no dispatcher that will ever claim it (the single-document routes
    execute inline, synchronously, within the request that created the
    row — the synchronous bulk-jobs route that used to share this
    property was retired in PR 31 commit 3) — that queued state is never
    reachable in
    steady state, so if one is ever found orphaned it must still be
    swept to failed, exactly as before, or it would sit stuck forever
    with nothing to notice.

    Returns the sweep count and the distinct batch_ids of any batch
    children this sweep just failed out of "running" — the caller must
    still check each one for completion (BatchDispatcher.
    check_batch_completion): failing a batch's last outstanding child
    here, on boot, is exactly as capable of finishing that batch as
    failing it mid-run is, and nothing else will ever check for it.
    Queued rows are excluded on purpose: they're untouched by this sweep
    (see above), so they can't be the trigger for a batch just finishing.
    """
    affected_batch_ids = [
        row[0]
        for row in s.query(Job.batch_id)
        .filter(Job.status == "running", Job.batch_id.isnot(None))
        .distinct()
        .all()
    ]
    # release_id/profile_id bugfix: a swept job's sibling Release (if
    # any) must be synced to "failed" too, same as a normally-completed
    # job already is (dispatcher.sync_release) -- otherwise it's stuck
    # "queued" forever with no release.terminal event. Collected up
    # front, before the bulk UPDATE, since the UPDATE itself can't hand
    # back which rows it touched the way an ORM save would.
    affected_job_ids = [
        row[0]
        for row in s.query(Job.id)
        .filter(
            (Job.status == "running")
            | ((Job.status == "queued") & (Job.batch_id.is_(None)))
        )
        .all()
    ]
    result = s.execute(
        update(Job)
        .where(Job.id.in_(affected_job_ids))
        .values(
            status="failed",
            error="interrupted by an application restart",
            finished_utc=_now(),
        )
    )
    s.commit()
    if affected_job_ids:
        s.expire_all()
        for job_id in affected_job_ids:
            sync_release(s, s.get(Job, job_id))
        s.commit()
    return result.rowcount or 0, affected_batch_ids


def _reconcile_stale_releases(s: Session) -> int:
    """Catches a narrower crash window the sweep above cannot: a Job that
    already reached a terminal status (done/refused/failed) through the
    normal path -- sync_job's own commit -- before the process died on
    the next line, mid-sync_release, leaving its sibling Release stuck
    queued/running forever with no release.terminal event. The sweep
    above only targets a Job still running/queued itself; a Job that's
    already terminal is untouched by it and by definition, so this is a
    separate check: any Release whose own status disagrees with its
    (already-terminal) Job's status, reconciled the same way a normal
    completion already would have.

    Safe to run every boot, not just after a crash: a Release and its
    Job are always expected to agree once the Job is terminal, so an
    empty result here is the normal case, not a special one.
    """
    stale = (
        s.query(Release, Job)
        .join(Job, Job.id == Release.job_id)
        .filter(
            Release.status.in_(("queued", "running")),
            Job.status.in_(("done", "refused", "failed")),
        )
        .all()
    )
    for _release, job in stale:
        sync_release(s, job)
    if stale:
        s.commit()
    return len(stale)


def _log_startup_posture(cfg: Config, swept: int, storage, *, reconciled_releases: int = 0) -> None:
    """One-time, non-secret operational summary at boot — this app shipped
    with zero logging until now, which meant an operator running it
    unisolated or with a no-op malware scanner had no way to notice short
    of reading the source. Never logs the password, hash, or cookie secret."""
    _jlog(
        logging.INFO,
        "startup",
        data_root=str(cfg.data_root),
        worker_mode=cfg.worker_mode,
        auth_mode="oidc" if cfg.oidc_enabled else "local_password",
        db_backend="postgres" if cfg.database_url else "sqlite",
        storage=storage.describe(),
        orphaned_jobs_failed=swept,
        stale_releases_reconciled=reconciled_releases,
    )
    if cfg.storage_mode == "s3" and cfg.retention_days <= 0:
        log.warning(
            "COUNSELCLEAR_STORAGE=s3 with COUNSELCLEAR_RETENTION_DAYS=0: "
            "Object Lock is off — overwrite/delete protection relies on "
            "If-None-Match only (and any Object-Lock-enabled bucket still "
            "enforces it)."
        )
    if cfg.oidc_enabled and not cfg.oidc_allowed:
        log.warning(
            "OIDC is enabled but COUNSELCLEAR_OIDC_ALLOWED is empty: the "
            "fail-closed allowlist denies every principal — nobody can sign "
            "in until it names at least one email or subject."
        )
    if cfg.worker_mode != "docker":
        log.warning(
            'worker_mode=%s: sanitize/inspect jobs run as a plain child '
            "process of this API, sharing its filesystem access — not "
            "isolated from a hostile file. Set COUNSELCLEAR_WORKER_MODE="
            "docker (see compose.yaml's legal profile) for real isolation.",
            cfg.worker_mode,
        )
    if shutil.which("clamscan") is None:
        log.warning(
            "clamscan not found on PATH: uploads are only checked for "
            "nested-archive depth, not scanned for malware. "
            "Dockerfile.counselclear installs clamav; a bare non-container "
            "run of this app does not."
        )


_unknown_client_state = {"warned": False}


def _client_host(request: Request) -> str:
    # Socket peer only — X-Forwarded-For is client-controlled and would let
    # an attacker rotate fake IPs past the throttle. Proxy deployments that
    # need real-IP accounting should rate-limit at the proxy.
    #
    # request.client is None only when the ASGI server exposes no peer
    # address at all (e.g. bound to a Unix domain socket) — every such
    # request collapses onto this one literal key, sharing one throttle
    # bucket and one access-log "client" value across every caller. That's
    # a real loss of the per-peer isolation this exists for, not a
    # theoretical one: it silently affects 100% of traffic on that
    # deployment shape. It isn't attacker-triggerable over a normal TCP
    # path (the ASGI server decides this, not the client), so it can't be
    # abused to dodge the throttle — but an operator deploying that way
    # needs to know the throttle is now effectively deployment-wide and
    # must rate-limit at the proxy, so warn once instead of failing silent.
    if request.client:
        return request.client.host
    if not _unknown_client_state["warned"]:
        _unknown_client_state["warned"] = True
        log.warning(
            "request.client is unavailable (no ASGI peer address, e.g. a "
            "Unix-socket bind): the login throttle and access log now "
            "share one bucket across every caller on this deployment — "
            "rate-limit at the proxy instead."
        )
    return "unknown"


async def _read_capped(file: UploadFile, cap: int | None = None) -> bytes:
    """Read an upload in bounded chunks, never buffering past ``cap`` bytes.

    ``await file.read()`` has no size limit of its own — a client that
    omits Content-Length (or lies about it) could otherwise make this
    process buffer an arbitrarily large body before the engine's own
    MAX_INPUT_BYTES check ever runs (which only happens later, inside the
    isolated worker). This is the same cap, enforced at the door instead.
    ``cap`` defaults to the module-level constant, looked up at call time
    (not bound as a default value) so tests can override it.
    """
    if cap is None:
        cap = MAX_INPUT_BYTES
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise HTTPException(413, f"upload exceeds {cap} byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(data_root: str | Path | None = None) -> FastAPI:
    cfg = Config(data_root)
    cfg.data_root.mkdir(parents=True, exist_ok=True)
    # With OIDC SSO enabled the shared-password credential is retired
    # entirely: no hash file is created or required, and /v1/auth/login is
    # disabled (below).
    if not cfg.oidc_enabled:
        ensure_local_password(cfg)
    engine = make_engine(cfg)
    upgrade_head(cfg.db_url())
    session_factory = make_session_factory(engine)
    throttle = LoginThrottle(
        max_failures=cfg.login_max_failures,
        window_s=cfg.login_window_s,
        lockout_s=cfg.login_lockout_s,
    )
    storage = storage_from_config(cfg)
    dispatcher = BatchDispatcher(
        cfg=cfg,
        session_factory=session_factory,
        storage=storage,
        max_concurrent=cfg.batch_max_concurrent,
        no_decision_marker=NO_DECISION_MARKER,
    )
    with session_factory() as s:
        swept, affected_batch_ids = _sweep_orphaned_jobs(s)
        # A batch whose last outstanding child was just failed by the
        # sweep above (its child was "running" when the old process
        # died) would otherwise never get marked complete or get its
        # batch.completed event -- nothing else ever re-checks it.
        for batch_id in affected_batch_ids:
            dispatcher.check_batch_completion(s, batch_id)
        # Separate from the sweep above: a Release whose Job already
        # reached a terminal status through the normal path, but whose
        # own sync_release never ran (process died in between) -- the
        # sweep's own job-status-based query can't see this case.
        reconciled_releases = _reconcile_stale_releases(s)
    _log_startup_posture(cfg, swept, storage, reconciled_releases=reconciled_releases)

    # Docs are fail-closed: /docs, /redoc and /openapi.json carry no auth
    # check, so they only exist when explicitly opted in with
    # COUNSELCLEAR_ENABLE_DOCS=1 (the legacy COUNSELCLEAR_DISABLE_DOCS=1
    # still force-disables, winning over the enable flag).
    docs_enabled = (
        os.environ.get("COUNSELCLEAR_ENABLE_DOCS", "").strip() == "1"
        and os.environ.get("COUNSELCLEAR_DISABLE_DOCS", "").strip() != "1"
    )
    app = FastAPI(
        title="CounselClear",
        version="product-mvp",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.batch_dispatcher = dispatcher

    @app.on_event("startup")
    def _start_dispatcher() -> None:
        dispatcher.start()

    @app.on_event("shutdown")
    def _stop_dispatcher() -> None:
        dispatcher.stop()

    access_log_enabled = os.environ.get("COUNSELCLEAR_ACCESS_LOG", "1").strip() != "0"

    @app.middleware("http")
    async def _request_logging(request: Request, call_next):
        """One JSON line per request: method, path (no query string —
        include_original etc. carry nothing sensitive but the path is what
        belongs in a request log), status, duration, correlation id. The
        X-Request-ID header lets an operator match a client-side failure to
        exactly one server-side log line."""
        rid = uuid.uuid4().hex[:12]
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.perf_counter() - start) * 1000)
            _jlog(
                logging.ERROR,
                "http_request",
                request_id=rid,
                method=request.method,
                path=request.url.path,
                status=500,
                duration_ms=duration_ms,
                client=_client_host(request),
            )
            raise
        response.headers["X-Request-ID"] = rid
        if access_log_enabled:
            _jlog(
                logging.INFO,
                "http_request",
                request_id=rid,
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=int((time.perf_counter() - start) * 1000),
                client=_client_host(request),
            )
        return response

    def db_session():
        s = session_factory()
        try:
            yield s
        finally:
            s.close()

    @app.get("/health")
    def health():
        """Liveness only: the process is up and serving HTTP. No DB, no
        dependencies — a probe wired to this should never restart the
        container over a transient database outage; use /health/ready for
        that instead (see docs/COUNSELCLEAR_PRODUCTION.md)."""
        return {"ok": True}

    @app.get("/health/ready")
    def health_ready(s: Session = Depends(db_session)):
        """Readiness: can this instance actually serve a request right
        now. 503 when the database is unreachable — an orchestrator should
        stop routing traffic here, not restart the process (restarting
        doesn't fix a downed database and just adds churn)."""
        try:
            s.execute(text("SELECT 1"))
        except Exception:
            raise HTTPException(503, "database unavailable") from None
        return {"ok": True}

    @app.get("/v1")
    def api_root():
        """`/v1` itself carries no resource -- unauthenticated by design
        (unlike everything under it) so a bare 404 with no context isn't
        the first thing anyone hitting the API root sees, whether that's
        an operator sanity-checking --base-url for tools/counselclear_airlock.py
        or someone poking at a deployment. Lists a few well-known
        unauthenticated routes as a starting point, not a full API index."""
        return {
            "product": "CounselClear",
            "message": "This is the CounselClear API root. Authenticated resources live under /v1/...",
            "unauthenticated_routes": ["/health", "/health/ready", "/v1/auth/login", "/v1/auth/config"],
            "docs": "docs/COUNSELCLEAR_DESIGN.md, docs/COUNSELCLEAR_PRODUCTION.md",
        }

    def principal(request: Request) -> str:
        """Auth dependency: validates the session cookie and returns the
        authenticated subject ("operator" for local-password logins, an
        "oidc:<hash>" identity for SSO). Every permission check and audit
        actor_id below is keyed on this, so OIDC principals are isolated
        from each other by the same matter ACL that scopes the operator."""
        subject = session_subject(cfg, request.cookies.get("cc_session"))
        if not subject:
            raise HTTPException(401, "authentication required")
        return subject

    def _require(matter_id: str, perm: str, s: Session, user: str) -> None:
        if not has_perm(s, matter_id, user, perm):
            raise HTTPException(403, f"missing permission: {perm}")

    def _cookie_secure(request: Request) -> bool:
        """Session-cookie Secure flag per COUNSELCLEAR_COOKIE_SECURE.

        auto (default): follow the request scheme — correct when uvicorn runs
        with --proxy-headers behind a TLS-terminating proxy (the documented
        topology; it then reflects X-Forwarded-Proto from the trusted proxy).
        true/false: explicit override for deployments where the proxy cannot
        forward the proto (e.g. TCP passthrough) or for loopback dev.
        """
        mode = cfg.cookie_secure
        if mode == "true":
            return True
        if mode == "false":
            return False
        return request.url.scheme == "https"

    # --- auth ---------------------------------------------------------------

    @app.get("/v1/auth/config")
    def auth_config():
        """Public, unauthenticated: tells the login page which flow to
        render. The static-export web UI has no server at request time to
        read an env var from, so this is the one thing it fetches before
        a session exists. No secrets — just the OIDC on/off bit.

        PR 45: demo_seed_enabled rides along the same way -- the matters
        page needs to know, before showing the "Load sample matter"
        button, whether POST .../demo-seed will actually work. It's the
        same bit as oidc_enabled's negation (see that route's own gate),
        not a second secret; exposing it costs nothing an unauthenticated
        caller couldn't already infer from oidc_enabled itself.
        """
        return {"oidc_enabled": cfg.oidc_enabled, "demo_seed_enabled": not cfg.oidc_enabled}

    @app.get("/v1/auth/me")
    def auth_me(user: str = Depends(principal)):
        """The caller's own authenticated principal -- "operator" for a
        local-password session, "oidc:<hash>" for SSO. Exists so a reviewer
        can discover and hand an admin the exact string an Access-panel
        grant needs (service/app/acl.py's user_id); the value itself is not
        new exposure, since it already appears in every audit event's
        actor_id and every ACL row this session can see."""
        return {"principal": user}

    @app.post("/v1/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        if cfg.oidc_enabled:
            # The shared password is retired when SSO is on — keeping a
            # second, phishable credential path alive would defeat the
            # point of federating identity.
            raise HTTPException(403, "local login disabled; use OIDC SSO")
        peer = _client_host(request)
        if not throttle.allow(peer):
            # Headers must ride on the exception itself — FastAPI's handler
            # builds a fresh response for HTTPException and drops anything
            # set on `response` beforehand.
            raise HTTPException(
                429,
                "too many failed logins; try again later",
                headers={"Retry-After": str(throttle.retry_after_s(peer))},
            )
        if not verify_password(cfg, body.password):
            throttle.record_failure(peer)
            raise HTTPException(403, "invalid credentials")
        throttle.record_success(peer)
        # Secure flag policy lives in _cookie_secure: "auto" follows the
        # request scheme (this app has no TLS termination of its own today —
        # loopback-bound plain HTTP is the documented v1 deployment — and a
        # hardcoded secure flag would just make the cookie never get sent at
        # all rather than add any real protection), with explicit
        # COUNSELCLEAR_COOKIE_SECURE=true/false overrides for proxy
        # deployments that cannot forward the proto.
        response.set_cookie(
            "cc_session", issue_session(cfg),
            httponly=True, samesite="strict", secure=_cookie_secure(request),
        )
        return {"ok": True}

    if cfg.oidc_enabled:

        @app.get("/v1/auth/oidc/login")
        def oidc_login(request: Request):
            try:
                return RedirectResponse(
                    oidc_mod.authorization_redirect(cfg, request), status_code=303
                )
            except OidcError as e:
                log.warning("oidc discovery failed for peer %s: %s", _client_host(request), e)
                raise HTTPException(502, "identity provider unavailable") from e

        @app.get("/v1/auth/oidc/callback")
        def oidc_callback(request: Request, code: str = "", state: str = ""):
            # Same per-peer sliding-window guard as local-password login:
            # this is the credential-establishing step (state/code/id_token
            # validation), so it deserves the same brute-force/DoS backstop
            # as /v1/auth/login rather than being reachable at unlimited
            # rate just because the password check happens to live at the
            # IdP instead of here.
            peer = _client_host(request)
            if not throttle.allow(peer):
                raise HTTPException(
                    429,
                    "too many failed sign-in attempts; try again later",
                    headers={"Retry-After": str(throttle.retry_after_s(peer))},
                )
            if not code or not state:
                throttle.record_failure(peer)
                raise HTTPException(400, "missing code/state")
            try:
                nonce = oidc_mod.parse_state(cfg, state)  # CSRF: signed + fresh
                id_token = oidc_mod.exchange_code(
                    cfg, oidc_mod.redirect_uri_for(cfg, request), code
                )
                claims = oidc_mod.validated_claims(cfg, id_token, nonce)
            except OidcError as e:
                throttle.record_failure(peer)
                # Never echo IdP/validation internals to the client — the
                # exception text can carry token endpoints, audience values,
                # and PyJWT internals. Log it server-side for the operator.
                log.warning("oidc sign-in refused for peer %s: %s", peer, e)
                raise HTTPException(401, "SSO sign-in failed") from e
            if not oidc_mod.allowed_principal(cfg, claims):
                # Fail closed: not on the allowlist. Same message shape for
                # all denials; no enumeration help.
                throttle.record_failure(peer)
                raise HTTPException(403, "principal not permitted")
            throttle.record_success(peer)
            sub = str(claims["sub"])
            redirect = RedirectResponse("/", status_code=303)
            redirect.set_cookie(
                "cc_session",
                issue_session(cfg, oidc_mod.principal_for(sub)),
                httponly=True,
                samesite="strict",
                secure=_cookie_secure(request),
            )
            # This is a top-level browser navigation (the IdP redirected the
            # user here), not a fetch() call from the web app — returning
            # JSON would leave the user staring at a JSON blob instead of
            # landing back in the UI. "/" is the web app's root in the
            # deployed topology (nginx serves it; see next.config.ts); this
            # route has no opinion on what's there in a bare API-only test.
            return redirect

    @app.post("/v1/auth/logout", dependencies=[Depends(principal)])
    def logout(response: Response):
        """Clear the session cookie client-side. The HMAC token itself stays
        valid until its TTL — use /v1/auth/revoke-sessions when a cookie may
        have leaked and must die server-side."""
        response.delete_cookie("cc_session", httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/v1/auth/revoke-sessions")
    def revoke_sessions(response: Response, user: str = Depends(principal)):
        """Rotate the cookie secret: every issued session token fails
        signature verification from now on (including this caller's).

        Restricted to the local operator identity. This product has no
        global-admin concept — permissions are per-matter ACL rows — so
        `Depends(principal)` alone (any authenticated session, including an
        OIDC principal scoped to a single matter) is not authorization for a
        deployment-wide action. Under OIDC, local login is disabled and no
        session can ever carry the operator subject, so this route is
        unreachable there by design; the equivalent action is deleting
        `{data_root}/auth/cookie.secret` on the host, which any operator with
        host access already has."""
        if user != LOCAL_SUBJECT:
            raise HTTPException(403, "session revocation is restricted to the local operator")
        revoke_all_sessions(cfg)
        response.delete_cookie("cc_session", httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/v1/attestations")
    def create_attestation(
        body: AttestationBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """PR 20: sign a Layer B (content-altering) attestation token for one
        document. The product gate: 403 unless watermark tools are enabled,
        the caller holds the sanitize permission, and the strength is one the
        product allows (KD 10 — code/backtranslate stay CLI-only). The token
        is HMAC-signed, doc-bound (sha256), 10-minute TTL, single-use; the
        resulting job records the jti so the audit chain can tie the rewrite
        back to this exact authorization."""
        if not cfg.watermark_tools_enabled:
            raise HTTPException(403, "watermark tools are disabled")
        if body.strength not in ATTEST_STRENGTHS:
            raise HTTPException(400, f"strength not product-allowed: {body.strength!r}")
        _require(body.matter_id, "sanitize", s, user)
        doc = _document(body.matter_id, body.document_id, s)
        token, jti, expires_utc = issue_attestation(
            cfg,
            subject=user,
            matter_id=body.matter_id,
            doc_sha256=doc.sha256,
            strength=body.strength,
        )
        append_event(
            s,
            matter_id=body.matter_id,
            actor_id=user,
            action="attest.issued",
            payload={
                "jti": jti,
                "document_id": doc.id,
                "sha256": doc.sha256,
                "strength": body.strength,
                "reason": body.reason[:500],
            },
        )
        s.commit()
        return {"token": token, "jti": jti, "expires_utc": expires_utc}

    @app.get("/v1/policies", dependencies=[Depends(principal)])
    def list_policies():
        return {"policies": POLICIES}

    @app.get("/v1/release-profiles", dependencies=[Depends(principal)])
    def list_release_profiles():
        return {"release_profiles": RELEASE_PROFILES, "recipient_types": list(RECIPIENT_TYPES)}

    # --- matters ------------------------------------------------------------

    @app.get("/v1/matters")
    def list_matters(
        user: str = Depends(principal),
        s: Session = Depends(db_session),
        limit: int = 100,
        offset: int = 0,
        q: str = "",
    ):
        limit = min(max(1, limit), 500)  # server-capped, never unbounded
        offset = max(0, offset)
        matter_ids = [
            r[0]
            for r in s.query(MatterAcl.matter_id).filter_by(user_id=user, perm="read").distinct()
        ]
        base = s.query(Matter).filter(Matter.id.in_(matter_ids))
        q = q.strip()
        if q:
            # Search runs against the same ACL-scoped set as everything
            # else here -- it can never surface a matter name the caller
            # couldn't otherwise list. ilike() compiles to a case-insensitive
            # LIKE on every backend this app supports (sqlite/Postgres).
            base = base.filter(Matter.name.ilike(f"%{_escape_like(q)}%", escape="\\"))
        total = base.count()
        matters = base.order_by(Matter.created_utc.desc()).offset(offset).limit(limit)
        return {
            "matters": [_matter_dict(m) for m in matters],
            "total": total,
            "offset": offset,
            "limit": limit,
            "q": q,
        }

    @app.post("/v1/matters")
    def create_matter(body: MatterBody, user: str = Depends(principal), s: Session = Depends(db_session)):
        matter = Matter(name=body.name)
        s.add(matter)
        s.flush()
        # The creating principal gets OWNER_PERMS (minus download_original,
        # which is always a deliberate grant). In local-password mode this
        # is exactly the historical bootstrap_operator(OPERATOR) behaviour.
        bootstrap_operator(s, matter.id, user_id=user)
        append_event(
            s,
            matter_id=matter.id,
            actor_id=user,
            action="matter.create",
            payload={"name": body.name},
        )
        s.commit()
        return _matter_dict(matter, perms_of(s, matter.id, user))

    @app.get("/v1/matters/{matter_id}")
    def get_matter(
        matter_id: str, user: str = Depends(principal), s: Session = Depends(db_session)
    ):
        # Permission check first (uniform 403 for both nonexistent and
        # unauthorized), matching every other matter-scoped route — the
        # old existence-first order leaked an ID-existence oracle.
        _require(matter_id, "read", s, user)
        return _matter_dict(_matter(matter_id, s), perms_of(s, matter_id, user))

    # --- documents ----------------------------------------------------------

    def _upload_document_bytes(matter_id: str, filename: str, data: bytes, user: str, s: Session) -> Document:
        """Shared body of upload_document, taking already-read bytes rather
        than an UploadFile -- lets a non-HTTP caller (POST .../demo-seed,
        PR 45) create a real Document through the exact same scan/storage/
        audit path a browser upload uses, instead of a second, divergent
        implementation."""
        name = Path(filename or "upload").name
        verdict = get_scanner().scan(data, name)
        if not verdict.clean:
            raise HTTPException(422, f"malware scanner flagged upload ({verdict.scanner})")
        doc = Document(
            id=_uuid(),
            matter_id=matter_id,
            filename=name,
            sha256=custody_mod.sha256_bytes(data),
            bytes=len(data),
            storage_path="",
        )
        key = original_key(cfg.org, matter_id, doc.id, name)
        try:
            doc.storage_path = storage.write_once(key, data)
        except StorageError_ as e:
            raise HTTPException(409, str(e)) from e
        s.add(doc)
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="document.upload",
            payload={
                "document_id": doc.id,
                "filename_ext": Path(name).suffix,
                "sha256": doc.sha256,
                "bytes": doc.bytes,
            },
        )
        s.commit()
        return doc

    @app.post("/v1/matters/{matter_id}/documents")
    async def upload_document(
        matter_id: str,
        file: UploadFile = File(...),
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "upload", s, user)
        _matter(matter_id, s)
        data = await _read_capped(file)
        doc = _upload_document_bytes(matter_id, file.filename or "upload", data, user, s)
        return _doc_dict(doc)

    @app.get("/v1/matters/{matter_id}/documents")
    def list_documents(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
        limit: int = 100,
        offset: int = 0,
        q: str = "",
    ):
        limit = min(max(1, limit), 500)  # server-capped, never unbounded
        offset = max(0, offset)
        _require(matter_id, "read", s, user)
        _matter(matter_id, s)
        base = s.query(Document).filter_by(matter_id=matter_id)
        q = q.strip()
        if q:
            base = base.filter(Document.filename.ilike(f"%{_escape_like(q)}%", escape="\\"))
        total = base.count()
        docs = base.order_by(Document.created_utc.desc()).offset(offset).limit(limit)
        return {
            "documents": [_doc_dict(d) for d in docs],
            "total": total,
            "offset": offset,
            "limit": limit,
            "q": q,
        }

    @app.get("/v1/matters/{matter_id}/documents/{doc_id}")
    def get_document(
        matter_id: str,
        doc_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        return _doc_dict(_document(matter_id, doc_id, s))

    # --- jobs ---------------------------------------------------------------

    def _create_job(matter_id: str, doc_id: str, kind: str, s: Session, **kw) -> Job:
        job = Job(matter_id=matter_id, document_id=doc_id, kind=kind, **kw)
        s.add(job)
        s.commit()
        return job

    def _execute_job(job_id: str, kind: str) -> None:
        """Run the queued job in an isolated worker process (PR 17).

        The worker performs all status transitions; sync_job() is the
        crash/timeout backstop that guarantees a terminal status.
        Timeout budget derives from engine Caps per kind (PR 18).
        """
        s = session_factory()
        try:
            res = run_job(cfg, s, job_id, kind=kind, storage=storage)
            sync_job(s, job_id, res)
        finally:
            s.close()

    @app.post("/v1/matters/{matter_id}/documents/{doc_id}/inspect-jobs")
    def inspect_job(
        matter_id: str,
        doc_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "inspect", s, user)
        doc = _document(matter_id, doc_id, s)
        job = _create_job(matter_id, doc.id, "inspect", s)
        _execute_job(job.id, kind="inspect")
        s.expire_all()
        finished = _job(matter_id, job.id, s)
        findings = (finished.result_json or {}).get("findings") or []
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="job.inspect",
            payload={
                "job_id": job.id,
                "document_id": doc.id,
                "status": finished.status,
                "findings_count": len(findings),
            },
        )
        return _job_dict(finished)

    @app.post("/v1/matters/{matter_id}/documents/{doc_id}/sanitize-jobs")
    def sanitize_job(
        matter_id: str,
        doc_id: str,
        body: SanitizeBody | None = None,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "sanitize", s, user)
        doc = _document(matter_id, doc_id, s)
        body = body or SanitizeBody()
        layer_b: dict | None = None
        attest_claims: dict | None = None
        jti: str | None = None
        if body.layer_b is not None:
            if not cfg.watermark_tools_enabled:
                raise HTTPException(403, "watermark tools are disabled")
            claims = verify_attestation(
                cfg,
                body.layer_b.token,
                matter_id=matter_id,
                doc_sha256=doc.sha256,
            )
            if claims is None:
                raise HTTPException(403, "invalid or expired attestation token")
            # The token binds a specific principal; only that principal may
            # consume it (otherwise any sanitize-perm holder could spend
            # someone else's authorization).
            if claims.get("sub") != user:
                raise HTTPException(403, "attestation token was issued to another principal")
            jti = claims["jti"]
            layer_b = {
                "strength": claims["strength"],
                "label": claims["label"],
                "subject": claims["sub"],
                "jti": jti,
            }
            attest_claims = claims
        job = Job(
            matter_id=matter_id,
            document_id=doc.id,
            kind="sanitize",
            policy_id=body.policy_id,
            reason=body.reason[:500],
            attestation=bool(body.signature_break_attestation),
            finding_decisions=dict(body.finding_decisions),
            legal_justifications=_legal_justifications_payload(body.legal_justifications),
            layer_b=layer_b,
        )
        s.add(job)
        s.flush()  # assigns job.id (Job.id's default is Python-side)
        if jti is not None:
            # Single-use, race-free: jti is the primary key of a dedicated
            # table (0005 migration), inserted in the *same transaction* as
            # the job row it authorizes. A concurrent duplicate use of the
            # same token — a second thread, a second gunicorn worker, or a
            # replay of a token whose in-memory record didn't survive a
            # restart — collides with the unique constraint here instead of
            # racing a read-then-write check. app.security's in-memory
            # _consumed_jtis set (checked inside verify_attestation above)
            # is only the fast path for the common single-attempt case;
            # this is the durable backstop.
            s.add(AttestationUse(jti=jti, job_id=job.id, matter_id=matter_id))
            try:
                s.flush()
            except IntegrityError as e:
                s.rollback()
                raise HTTPException(403, "attestation token already used") from e
        if layer_b is not None and attest_claims is not None:
            # Consume only once the job + attestation_uses rows are staged
            # in this (not-yet-committed) transaction: a rollback above must
            # not have already burned the token in-memory with no durable
            # record to show for it.
            consume_attestation(attest_claims)
            append_event(
                s,
                matter_id=matter_id,
                actor_id=user,
                action="attest.used",
                payload={"jti": jti, "job_id": job.id, "strength": layer_b["strength"]},
            )
        s.commit()
        _execute_job(job.id, kind="sanitize")
        s.expire_all()
        finished = _job(matter_id, job.id, s)
        result = finished.result_json or {}
        actions = (result.get("manifest") or {}).get("actions") or []
        no_decision_count = sum(1 for a in actions if NO_DECISION_MARKER in a)
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="job.sanitize",
            payload={
                "job_id": job.id,
                "document_id": doc.id,
                "policy_id": body.policy_id,
                "status": finished.status,
                "verification_pass": result.get("verification_pass"),
                "no_decision_count": no_decision_count,
            },
        )
        return _job_dict(finished)

    def _resolve_release_profile(profile_id: str) -> dict:
        profile = next((p for p in RELEASE_PROFILES if p["id"] == profile_id), None)
        if profile is None:
            raise HTTPException(400, f"unknown release profile: {profile_id!r}")
        return profile

    def _release_dict(r: Release) -> dict:
        return {
            "id": r.id,
            "matter_id": r.matter_id,
            "document_id": r.document_id,
            "batch_id": r.batch_id,
            "job_id": r.job_id,
            "policy_id": r.policy_id,
            "profile_id": r.profile_id,
            "recipient_type": r.recipient_type,
            "recipient_name": r.recipient_name,
            "purpose": r.purpose,
            "intended_external": r.intended_external,
            "requested_by": r.requested_by,
            "status": r.status,
            "created_utc": r.created_utc,
            "finished_utc": r.finished_utc,
        }

    def _legal_justifications_from_manifest(manifest: dict) -> list[dict[str, object]]:
        """Extract operator-facing legal bases from manifest action records.

        The manifest is the custody source of truth for what survived the
        derivative. Release artifacts repeat only the compact legal-basis view
        so a verifier/reviewer can find it without reverse-engineering every
        action string.
        """
        out: list[dict[str, object]] = []
        seen: set[tuple[str, str]] = set()
        for record in manifest.get("action_records") or []:
            if not isinstance(record, dict):
                continue
            legal = record.get("legal_justification")
            if not isinstance(legal, dict):
                continue
            subtype = str(record.get("subtype") or "")
            action = str(record.get("action") or "")
            key = (subtype, action)
            if not subtype or not action or key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "subtype": subtype,
                    "action": action,
                    "legal_justification": {
                        "basis": str(legal.get("basis") or "unspecified"),
                        "note": str(legal.get("note") or ""),
                    },
                }
            )
        return out

    def _build_release_result(
        s: Session, *, matter: Matter, release: Release, job: Job, doc: Document, audit_refs: dict
    ) -> dict:
        """release_result.json: the one artifact every terminal release
        produces, regardless of outcome. For a refused/failed release
        this is the ONLY structured record -- no derivative, no zip, so
        "packet or refusal" doesn't collapse into "packet, or nothing
        machine-checkable". For a done release it's a lightweight,
        always-available companion to the full release_packet.json
        (job_bundle, below), which additionally carries the derivative
        itself. Computing the certificate here (via _build_certificate_html,
        which is side-effect-free -- it does not itself append
        certificate.issued) lets this cite a real, hash-bindable
        certificate without forcing an extra issuance event on every
        release creation; a caller who wants the actual HTML bytes still
        fetches GET .../jobs/{job_id}/certificate, which logs its own
        pull exactly as it always has.

        Never claims more than "prepared for release" -- see
        Release.intended_external's own docstring in models.py. status
        here is release.status (Job's own vocabulary, synced 1:1), never
        a claim about what happened to the packet after this system
        produced it.
        """
        cert_html, _policy_id, limitations = _build_certificate_html(
            s, matter=matter, job=job, doc=doc, generated_by=release.requested_by
        )
        reason = ""
        if job.status in ("refused", "failed"):
            reason = job.error or "no further detail recorded"
        manifest = (job.result_json or {}).get("manifest") or {}
        return {
            "spec_version": "1.0",
            "release_id": release.id,
            "job_id": job.id,
            "document_id": doc.id,
            "matter_id": matter.id,
            "status": release.status,
            "policy_id": release.policy_id,
            "profile_id": release.profile_id,
            "recipient_type": release.recipient_type,
            "recipient_name": release.recipient_name,
            "purpose": release.purpose,
            "intended_external": release.intended_external,
            "reason": reason,
            "original_sha256": doc.sha256,
            "created_at": release.created_utc,
            "finished_at": release.finished_utc,
            "audit_refs": audit_refs,
            "legal_justifications": _legal_justifications_from_manifest(manifest),
            "limitations": limitations,
            "certificate_html_sha256": hashlib.sha256(cert_html.encode("utf-8")).hexdigest(),
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            # Same honest "none" as release_packet.json's own anchor field
            # (job_bundle, below) -- not yet implemented, not omitted.
            "anchor": {"type": "none", "digest": None, "reference": None},
        }

    @app.post("/v1/matters/{matter_id}/documents/{doc_id}/releases")
    def create_release(
        matter_id: str,
        doc_id: str,
        body: ReleaseBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """The Release-first entry point for a single document (PR 39):
        wraps the exact same job-creation/execution path sanitize_job
        (above) uses, plus a Release row carrying the recipient/purpose/
        profile context a Job was never meant to. /sanitize-jobs itself
        is untouched -- this is additive, not a replacement, kept so
        nothing that already calls it (the frontend, the Airlock CLI)
        breaks. inspect never gets a Release wrapper: it produces no
        derivative, so it can never resolve to "packet or refusal".
        """
        _require(matter_id, "sanitize", s, user)
        matter = _matter(matter_id, s)
        doc = _document(matter_id, doc_id, s)
        profile = _resolve_release_profile(body.profile_id)
        if body.recipient_type not in RECIPIENT_TYPES:
            raise HTTPException(400, f"unknown recipient_type: {body.recipient_type!r}")
        policy_id = profile["policy_id"]

        layer_b: dict | None = None
        attest_claims: dict | None = None
        jti: str | None = None
        if body.layer_b is not None:
            if not cfg.watermark_tools_enabled:
                raise HTTPException(403, "watermark tools are disabled")
            claims = verify_attestation(cfg, body.layer_b.token, matter_id=matter_id, doc_sha256=doc.sha256)
            if claims is None:
                raise HTTPException(403, "invalid or expired attestation token")
            if claims.get("sub") != user:
                raise HTTPException(403, "attestation token was issued to another principal")
            jti = claims["jti"]
            layer_b = {
                "strength": claims["strength"],
                "label": claims["label"],
                "subject": claims["sub"],
                "jti": jti,
            }
            attest_claims = claims

        job = Job(
            matter_id=matter_id,
            document_id=doc.id,
            kind="sanitize",
            policy_id=policy_id,
            reason=body.reason[:500],
            attestation=bool(body.signature_break_attestation),
            finding_decisions=dict(body.finding_decisions),
            legal_justifications=_legal_justifications_payload(body.legal_justifications),
            layer_b=layer_b,
        )
        s.add(job)
        s.flush()  # assigns job.id
        if jti is not None:
            s.add(AttestationUse(jti=jti, job_id=job.id, matter_id=matter_id))
            try:
                s.flush()
            except IntegrityError as e:
                s.rollback()
                raise HTTPException(403, "attestation token already used") from e
        if layer_b is not None and attest_claims is not None:
            consume_attestation(attest_claims)
            append_event(
                s,
                matter_id=matter_id,
                actor_id=user,
                action="attest.used",
                payload={"jti": jti, "job_id": job.id, "strength": layer_b["strength"]},
            )

        release = Release(
            matter_id=matter_id,
            document_id=doc.id,
            job_id=job.id,
            policy_id=policy_id,
            profile_id=body.profile_id,
            recipient_type=body.recipient_type,
            recipient_name=body.recipient_name[:200],
            purpose=body.purpose[:500],
            intended_external=body.intended_external,
            requested_by=user,
            status="queued",
        )
        s.add(release)
        s.flush()  # assigns release.id
        created_event = append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="release.created",
            payload={
                "release_id": release.id,
                "document_id": doc.id,
                "job_id": job.id,
                "policy_id": policy_id,
                "profile_id": body.profile_id,
                "recipient_type": body.recipient_type,
                "requested_by": user,
            },
        )
        s.commit()

        _execute_job(job.id, kind="sanitize")
        s.expire_all()
        finished = _job(matter_id, job.id, s)
        result = finished.result_json or {}
        actions = (result.get("manifest") or {}).get("actions") or []
        no_decision_count = sum(1 for a in actions if NO_DECISION_MARKER in a)
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="job.sanitize",
            payload={
                "job_id": job.id,
                "document_id": doc.id,
                "policy_id": policy_id,
                "status": finished.status,
                "verification_pass": result.get("verification_pass"),
                "no_decision_count": no_decision_count,
            },
        )

        release.status = finished.status
        release.finished_utc = finished.finished_utc
        terminal_event = append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="release.terminal",
            payload={"release_id": release.id, "job_id": job.id, "status": finished.status},
        )
        s.commit()

        audit_refs = {"release_created_seq": created_event.seq, "release_terminal_seq": terminal_event.seq}
        release_result = _build_release_result(
            s, matter=matter, release=release, job=finished, doc=doc, audit_refs=audit_refs
        )
        job_out = _job_dict(finished, release_id=release.id, profile_id=release.profile_id)
        return {"release": _release_dict(release), "job": job_out, "release_result": release_result}

    @app.post("/v1/matters/demo-seed")
    def demo_seed_matter(user: str = Depends(principal), s: Session = Depends(db_session)):
        """Evaluation-flow walkthrough (PR 45): creates or reuses one demo
        matter carrying three real fixtures, and runs a real release on
        each one whenever it hasn't already -- through the exact same
        _upload_document_bytes/create_release path a human clicking
        through the UI uses, not a mock or a special-cased demo pipeline.
        Idempotent by filename/document the same way tools/seed_eval_
        matter.py already is: a repeat click reuses the matter and skips
        whatever's already there rather than piling up duplicates.

        Local-password mode only. A multi-tenant OIDC deployment has no
        single "the operator" to hand a shared sample matter to, and this
        route deliberately bypasses the ordinary upload-form friction --
        not a posture to expose on a production multi-tenant instance.
        See auth_config's demo_seed_enabled, the same bit the frontend
        checks before ever showing the button.
        """
        if cfg.oidc_enabled:
            raise HTTPException(403, "sample-matter seeding is only available in local-password mode")

        matter = s.query(Matter).filter_by(name=_DEMO_MATTER_NAME, is_demo=True).first()
        if matter is None:
            matter = Matter(name=_DEMO_MATTER_NAME, is_demo=True)
            s.add(matter)
            s.flush()
            bootstrap_operator(s, matter.id, user_id=user)
            append_event(
                s,
                matter_id=matter.id,
                actor_id=user,
                action="matter.create",
                payload={"name": _DEMO_MATTER_NAME, "is_demo": True},
            )
            s.commit()

        existing_docs = {d.filename: d for d in s.query(Document).filter_by(matter_id=matter.id).all()}
        released_doc_ids = {
            r[0] for r in s.query(Release.document_id).filter_by(matter_id=matter.id).all()
        }

        for filename, build_fixture in _DEMO_SEED_DOCUMENTS:
            doc = existing_docs.get(filename)
            if doc is None:
                doc = _upload_document_bytes(matter.id, filename, build_fixture(), user, s)
            if doc.id not in released_doc_ids:
                release_body = ReleaseBody(
                    profile_id="counterparty_deal_room",
                    recipient_type="opposing_counsel",
                    recipient_name="Sample Counterparty",
                    purpose="Release Gate evaluation walkthrough",
                    intended_external=True,
                    reason="demo seed",
                )
                create_release(matter.id, doc.id, release_body, user=user, s=s)

        return _matter_dict(matter, perms_of(s, matter.id, user))

    @app.get("/v1/matters/{matter_id}/releases/{release_id}")
    def get_release(
        matter_id: str,
        release_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        release = _release(matter_id, release_id, s)
        return _release_dict(release)

    @app.get("/v1/matters/{matter_id}/releases/{release_id}/result")
    def get_release_result(
        matter_id: str,
        release_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """Raw release_result.json bytes -- the artifact a caller (the
        Airlock CLI, a future verifier) would save to disk as
        `release_result.json` and hash-check. Deliberately read-only and
        side-effect-free: a re-fetch of already-committed facts (Release +
        Job + Document rows), not a new issuance -- unlike
        job_certificate's own per-pull audit logging (a distinct, explicit
        product decision for that route), this is a deterministic
        projection with nothing new to attest to on repeat reads. Audit
        refs cite the release.created/release.terminal events recorded at
        creation time, which don't change on re-fetch either.
        """
        _require(matter_id, "read", s, user)
        matter = _matter(matter_id, s)
        release = _release(matter_id, release_id, s)
        job = _job(matter_id, release.job_id, s)
        doc = _document(matter_id, release.document_id, s)
        created_seq = _release_event_seq(s, matter_id, release.id, "release.created")
        terminal_seq = _release_event_seq(s, matter_id, release.id, "release.terminal")
        audit_refs = {"release_created_seq": created_seq, "release_terminal_seq": terminal_seq}
        release_result = _build_release_result(
            s, matter=matter, release=release, job=job, doc=doc, audit_refs=audit_refs
        )
        body = json.dumps(release_result, indent=2, sort_keys=True)
        # PR 45: named explicitly so a browser "Save As" (or the `target=
        # "_blank"` link's own save) lands on disk as exactly
        # release_result.json -- the literal filename
        # tools/counselclear_verify_release_packet.py's own auto-detection
        # requires (main()'s is_result check). Without this header the
        # saved name was whatever the browser inferred from the URL's last
        # path segment ("result"), which the verifier doesn't recognize --
        # the documented "download it and run the verifier on it" flow
        # didn't actually work before this.
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="release_result.json"'},
        )

    def _release_event_seq(s: Session, matter_id: str, release_id: str, action: str) -> int | None:
        ev = (
            s.query(AuditEvent)
            .filter(AuditEvent.matter_id == matter_id, AuditEvent.action == action)
            .order_by(AuditEvent.seq)
            .all()
        )
        match = next((e for e in ev if (e.payload or {}).get("release_id") == release_id), None)
        return match.seq if match else None

    def _batch_dict(b: Batch, s: Session) -> dict:
        jobs = s.query(Job).filter(Job.batch_id == b.id).order_by(Job.created_utc).all()
        doc_names = {
            d.id: d.filename
            for d in s.query(Document).filter(Document.id.in_([j.document_id for j in jobs])).all()
        }
        # release_id/profile_id (PR 40): nullable per result -- only jobs
        # created through POST .../releases (not the raw /batches route)
        # have a sibling Release. One batch-queried lookup, not N+1, same
        # pattern doc_names above already uses.
        releases_by_job = {
            r.job_id: r
            for r in s.query(Release).filter(Release.job_id.in_([j.id for j in jobs])).all()
        }
        results = [
            {
                "document_id": j.document_id,
                "document_name": doc_names.get(j.document_id, ""),
                "job_id": j.id,
                "kind": j.kind,
                "policy_id": j.policy_id,
                "status": j.status,
                "error": j.error,
                "release_id": releases_by_job[j.id].id if j.id in releases_by_job else None,
                "profile_id": releases_by_job[j.id].profile_id if j.id in releases_by_job else None,
            }
            for j in jobs
        ]
        summary = {"requested": b.total, "done": 0, "refused": 0, "failed": 0, "queued": 0, "running": 0}
        for r in results:
            summary[r["status"]] = summary.get(r["status"], 0) + 1
        return {
            "id": b.id,
            "matter_id": b.matter_id,
            "kind": b.kind,
            "policy_id": b.policy_id,
            "total": b.total,
            "created_utc": b.created_utc,
            "finished_utc": b.finished_utc,
            "results": results,
            "summary": summary,
        }

    @app.post("/v1/matters/{matter_id}/batches")
    def create_batch(
        matter_id: str,
        body: BulkJobsBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """Creates a Batch and its queued child Job rows, returning as soon
        as they're durably recorded instead of blocking the request for the
        full run. BatchDispatcher (PR 31) picks the children up in the
        background; poll GET .../batches/{id} for progress. Request shape
        is validated fully up front (kind, non-empty, cap, duplicates, ACL,
        policy bulk-safety, document membership) so a bad request creates
        nothing -- the same up-front-validation discipline the retired
        synchronous /bulk-jobs endpoint (PR 23) used.
        """
        if body.kind not in ("inspect", "sanitize"):
            raise HTTPException(400, f"unsupported job kind: {body.kind!r}")
        if not body.document_ids:
            raise HTTPException(400, "document_ids must not be empty")
        if len(body.document_ids) > 100:
            raise HTTPException(400, "at most 100 documents per bulk request")
        if len(set(body.document_ids)) != len(body.document_ids):
            raise HTTPException(400, "document_ids must not contain duplicates")
        _require(matter_id, body.kind, s, user)
        if body.kind == "sanitize":
            policy = next((p for p in POLICIES if p["id"] == body.policy_id), None)
            if policy is None:
                raise HTTPException(400, f"unknown policy: {body.policy_id!r}")
            if not policy["bulk_safe"]:
                raise HTTPException(
                    400,
                    f"policy {body.policy_id!r} cannot be bulk-run: it requires "
                    "per-finding decisions (or produces no derivative) — "
                    "sanitize those documents individually",
                )
        found = {
            d.id
            for d in s.query(Document)
            .filter(Document.matter_id == matter_id, Document.id.in_(body.document_ids))
            .all()
        }
        missing = [i for i in body.document_ids if i not in found]
        if missing:
            raise HTTPException(400, f"not documents of this matter: {', '.join(missing)}")

        batch = Batch(
            matter_id=matter_id,
            kind=body.kind,
            policy_id=body.policy_id if body.kind == "sanitize" else "",
            reason=body.reason[:500],
            requested_by=user,
            total=len(body.document_ids),
        )
        s.add(batch)
        s.flush()  # assigns batch.id
        job_kw = {"policy_id": body.policy_id, "reason": body.reason[:500]} if body.kind == "sanitize" else {}
        for doc_id in body.document_ids:
            s.add(Job(matter_id=matter_id, document_id=doc_id, kind=body.kind, batch_id=batch.id, **job_kw))
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="batch.created",
            payload={"batch_id": batch.id, "kind": body.kind, "total": batch.total},
        )
        s.commit()
        dispatcher.wake()
        return _batch_dict(batch, s)

    @app.post("/v1/matters/{matter_id}/releases")
    def create_batch_release(
        matter_id: str,
        body: BatchReleaseBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """Batch release (PR 39): reuses the existing async Batch resource
        (create_batch, above) completely unchanged underneath -- one
        Release row per document_id, each riding alongside its own child
        Job, each completing independently the moment ITS OWN Job
        finishes (BatchDispatcher._sync_release). Batch stays only the
        grouping/execution envelope; "batch completed" and "this one
        release completed" are never the same event -- see Release's own
        docstring in models.py. Not available for a non-bulk_safe profile
        (production/ediscovery_production), same restriction create_batch
        already enforces on the raw policy -- release those individually.
        """
        if not body.document_ids:
            raise HTTPException(400, "document_ids must not be empty")
        if len(body.document_ids) > 100:
            raise HTTPException(400, "at most 100 documents per bulk request")
        if len(set(body.document_ids)) != len(body.document_ids):
            raise HTTPException(400, "document_ids must not contain duplicates")
        _require(matter_id, "sanitize", s, user)
        profile = _resolve_release_profile(body.profile_id)
        policy_id = profile["policy_id"]
        policy = next((p for p in POLICIES if p["id"] == policy_id), None)
        if policy is None or not policy["bulk_safe"]:
            raise HTTPException(
                400,
                f"release profile {body.profile_id!r} (policy {policy_id!r}) cannot be "
                "batch-released: it requires per-finding decisions (or produces no "
                "derivative) — release those documents individually",
            )
        if body.recipient_type not in RECIPIENT_TYPES:
            raise HTTPException(400, f"unknown recipient_type: {body.recipient_type!r}")
        found = {
            d.id
            for d in s.query(Document)
            .filter(Document.matter_id == matter_id, Document.id.in_(body.document_ids))
            .all()
        }
        missing = [i for i in body.document_ids if i not in found]
        if missing:
            raise HTTPException(400, f"not documents of this matter: {', '.join(missing)}")

        batch = Batch(
            matter_id=matter_id,
            kind="sanitize",
            policy_id=policy_id,
            reason=body.reason[:500],
            requested_by=user,
            total=len(body.document_ids),
        )
        s.add(batch)
        s.flush()  # assigns batch.id
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="batch.created",
            payload={"batch_id": batch.id, "kind": "sanitize", "total": batch.total},
        )
        releases: list[Release] = []
        for doc_id in body.document_ids:
            job = Job(
                matter_id=matter_id,
                document_id=doc_id,
                kind="sanitize",
                batch_id=batch.id,
                policy_id=policy_id,
                reason=body.reason[:500],
            )
            s.add(job)
            s.flush()  # assigns job.id
            release = Release(
                matter_id=matter_id,
                document_id=doc_id,
                batch_id=batch.id,
                job_id=job.id,
                policy_id=policy_id,
                profile_id=body.profile_id,
                recipient_type=body.recipient_type,
                recipient_name=body.recipient_name[:200],
                purpose=body.purpose[:500],
                intended_external=body.intended_external,
                requested_by=user,
                status="queued",
            )
            s.add(release)
            s.flush()  # assigns release.id
            append_event(
                s,
                matter_id=matter_id,
                actor_id=user,
                action="release.created",
                payload={
                    "release_id": release.id,
                    "document_id": doc_id,
                    "job_id": job.id,
                    "batch_id": batch.id,
                    "policy_id": policy_id,
                    "profile_id": body.profile_id,
                    "recipient_type": body.recipient_type,
                    "requested_by": user,
                },
            )
            releases.append(release)
        s.commit()
        dispatcher.wake()
        return {"batch": _batch_dict(batch, s), "releases": [_release_dict(r) for r in releases]}

    @app.get("/v1/matters/{matter_id}/batches/{batch_id}")
    def get_batch(
        matter_id: str,
        batch_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        batch = s.get(Batch, batch_id)
        if not batch or batch.matter_id != matter_id:
            raise HTTPException(404, "batch not found")
        return _batch_dict(batch, s)

    @app.post("/v1/matters/{matter_id}/batches/{batch_id}/cancel")
    def cancel_batch(
        matter_id: str,
        batch_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """Cancels only children still queued -- v1 does not kill a running
        worker subprocess (out of scope per the approved proposal). Any
        child already running or terminal is left untouched; the response
        reports how many were actually cancelled."""
        batch = s.get(Batch, batch_id)
        if not batch or batch.matter_id != matter_id:
            raise HTTPException(404, "batch not found")
        # Same permission the batch was created under -- whoever could
        # start this kind of run may also stop its not-yet-started part.
        _require(matter_id, batch.kind, s, user)
        # Collected up front, before the bulk UPDATE, same reasoning as
        # _sweep_orphaned_jobs above: the UPDATE itself can't hand back
        # which rows it touched the way an ORM save would, and each
        # cancelled job's sibling Release (if any) needs syncing too.
        cancelled_ids = [
            row[0]
            for row in s.query(Job.id).filter(Job.batch_id == batch_id, Job.status == "queued").all()
        ]
        if cancelled_ids:
            s.execute(
                update(Job)
                .where(Job.id.in_(cancelled_ids))
                .values(status="failed", error="cancelled by operator", finished_utc=_now())
            )
        cancelled = len(cancelled_ids)
        if cancelled:
            append_event(
                s,
                matter_id=matter_id,
                actor_id=user,
                action="batch.cancelled",
                payload={"batch_id": batch_id, "cancelled": cancelled},
            )
        s.commit()
        if cancelled_ids:
            # release_id/profile_id bugfix: a cancelled child's sibling
            # Release (if any) is stuck "queued" forever, with no
            # release.terminal event, unless synced here explicitly --
            # cancel_batch bypasses the dispatcher's own normal per-job
            # completion path entirely.
            s.expire_all()
            for job_id in cancelled_ids:
                sync_release(s, s.get(Job, job_id))
            s.commit()
        # Cancelling every still-queued child can itself be what finishes
        # the batch (nothing was ever claimed by the dispatcher to trigger
        # its own completion check) -- most visibly when the whole batch
        # is cancelled before the dispatcher claims anything at all.
        dispatcher.check_batch_completion(s, batch_id)
        # check_batch_completion writes finished_utc via a raw UPDATE,
        # bypassing this session's identity map -- without a refresh the
        # `batch` object below (loaded before the check ran) would still
        # show finished_utc=None in the response even after a completing
        # cancel (expire_on_commit=False, see db.make_session_factory).
        s.refresh(batch)
        return _batch_dict(batch, s)

    @app.get("/v1/matters/{matter_id}/jobs")
    def list_jobs(
        matter_id: str,
        document_id: str = "",
        user: str = Depends(principal),
        s: Session = Depends(db_session),
        limit: int = 100,
        offset: int = 0,
    ):
        limit = min(max(1, limit), 500)  # server-capped, never unbounded
        offset = max(0, offset)
        _require(matter_id, "read", s, user)
        _matter(matter_id, s)
        q = s.query(Job).filter_by(matter_id=matter_id)
        if document_id:
            q = q.filter_by(document_id=document_id)
        total = q.count()
        jobs = q.order_by(Job.created_utc.desc()).offset(offset).limit(limit).all()
        # release_id/profile_id (PR 40): one batched lookup across this
        # page's jobs, not N+1 -- an unknown mix of inspect/legacy-
        # sanitize/release-wrapped jobs, unlike the single-job routes.
        releases_by_job = {
            r.job_id: r
            for r in s.query(Release).filter(Release.job_id.in_([j.id for j in jobs])).all()
        }
        # List view omits the full result payload (it can be large for
        # inspect jobs); the detail route carries it.
        return {
            "jobs": [
                _job_dict(
                    j,
                    include_result=False,
                    release_id=releases_by_job[j.id].id if j.id in releases_by_job else None,
                    profile_id=releases_by_job[j.id].profile_id if j.id in releases_by_job else None,
                )
                for j in jobs
            ],
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    @app.get("/v1/matters/{matter_id}/jobs/export")
    def export_jobs(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """The full, unpaginated job history as CSV -- one row per job, the
        same fields GET .../jobs already returns (minus the large `result`
        payload, same as the list route), never truncated to a page: an
        export is an explicit "give me everything" action, not a view.

        Registered before GET .../jobs/{job_id} below on purpose: FastAPI
        matches routes in registration order, and {job_id} would otherwise
        greedily swallow the literal path segment "export" as a job id.
        """
        _require(matter_id, "read", s, user)
        _matter(matter_id, s)
        jobs = (
            s.query(Job, Document.filename)
            .join(Document, Document.id == Job.document_id)
            .filter(Job.matter_id == matter_id)
            .order_by(Job.created_utc.desc())
            .all()
        )
        # release_id/profile_id: one batched lookup across this matter's
        # jobs, not per-row -- same pattern _attention_items/_batch_dict/
        # list_jobs already use. Null for an inspect job or one from the
        # legacy /sanitize-jobs route, same as everywhere else.
        releases_by_job = {
            r.job_id: r
            for r in s.query(Release).filter(Release.job_id.in_([j.id for j, _ in jobs])).all()
        }
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "job_id", "document_id", "document_filename", "kind", "policy_id",
                "status", "error", "verification_pass", "created_utc", "finished_utc",
                "release_id", "profile_id",
            ]
        )
        for job, filename in jobs:
            result = job.result_json or {}
            release = releases_by_job.get(job.id)
            writer.writerow(
                [
                    job.id, job.document_id, filename, job.kind, job.policy_id,
                    job.status, job.error, result.get("verification_pass", ""),
                    job.created_utc, job.finished_utc or "",
                    release.id if release else "", release.profile_id if release else "",
                ]
            )
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="jobs_{matter_id}.csv"',
                "X-Total-Jobs": str(len(jobs)),
            },
        )

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}")
    def get_job(
        matter_id: str,
        job_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        job = _job(matter_id, job_id, s)
        release = s.query(Release).filter(Release.job_id == job.id).one_or_none()
        return _job_dict(job, release_id=release.id if release else None, profile_id=release.profile_id if release else None)

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}/manifest")
    def job_manifest(
        matter_id: str,
        job_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        job = _job(matter_id, job_id, s)
        if job.kind != "sanitize" or not job.result_json:
            raise HTTPException(404, "no manifest for this job")
        return JSONResponse(job.result_json.get("manifest", {}))

    def _build_certificate_html(
        s: Session, *, matter: Matter, job: Job, doc: Document, generated_by: str
    ) -> tuple[str, str | None, list[str]]:
        """Shared by job_certificate (PR 33) and job_bundle (PR 36/37, the
        release packet): the exact same certificate content either way,
        so a certificate pulled standalone and one embedded in a release
        packet can never read differently for the same job. Returns
        (html_body, policy_id, limitations) -- callers append their own
        certificate.issued audit event (payload needs policy_id, job/doc
        ids callers already have) rather than this helper doing it, since
        job_bundle commits it alongside its own bundle.download event in
        one place.
        """
        result = job.result_json or {}
        manifest = result.get("manifest") or {} if job.kind == "sanitize" else {}
        derivative_sha256 = manifest.get("derivative", {}).get("sha256")
        actions: list[str] = manifest.get("actions") or []
        findings_before: list[str] = manifest.get("findings_before") or []
        inspect_findings: list[dict] = result.get("findings") or [] if job.kind == "inspect" else []
        verification: dict | None = manifest.get("verification") if job.kind == "sanitize" else None

        policy_id = policy_version = policy_description = None
        if job.kind == "sanitize":
            policy_id = manifest.get("policy", {}).get("id") or job.policy_id
            policy_version = manifest.get("policy", {}).get("version", 1)
            policy_meta = next((p for p in POLICIES if p["id"] == policy_id), None)
            policy_description = policy_meta["description"] if policy_meta else None

        limitations: list[str] = []
        no_decision = [a for a in actions if NO_DECISION_MARKER in a]
        if no_decision:
            limitations.append(
                f"{len(no_decision)} finding(s) kept WITHOUT operator review "
                f"({NO_DECISION_MARKER}): " + "; ".join(no_decision)
            )
        operator_kept = [a for a in actions if OPERATOR_KEPT_MARKER in a]
        if operator_kept:
            limitations.append(
                f"{len(operator_kept)} finding(s) reviewed and explicitly kept by "
                "the operator: " + "; ".join(operator_kept)
            )
        approved_no_op = [a for a in actions if APPROVED_BUT_NO_OP_MARKER in a]
        if approved_no_op:
            limitations.append(
                f"{len(approved_no_op)} finding(s) approved by the operator but "
                "structurally kept anyway (this policy has no strip action for "
                "that subtype): " + "; ".join(approved_no_op)
            )
        if job.status in ("refused", "failed"):
            limitations.append(
                f"Job {job.status}: no derivative was produced. "
                + (job.error or "no further detail recorded.")
            )
        if job.kind == "inspect":
            limitations.append(
                "This is an INSPECT-ONLY certificate: no derivative was produced "
                "and the original document was not modified."
            )
        elif job.status == "done" and not derivative_sha256:
            limitations.append(
                "Job is done but no derivative hash is recorded — out of scope "
                "for this certificate's custody claim."
            )

        # Narrow, job-scoped custody assertion: this job's own audit rows,
        # individually hash-recomputed — never the matter's full chain and
        # never another job's rows (see the route docstring above).
        job_events = [
            ev
            for ev in s.query(AuditEvent)
            .filter(AuditEvent.matter_id == matter.id, AuditEvent.action.in_(("job.inspect", "job.sanitize")))
            .all()
            if (ev.payload or {}).get("job_id") == job.id
        ]
        audit_integrity_ok = all(
            event_hash(ev.prev_hash, ev.seq, ev.actor_id, ev.action, ev.payload) == ev.row_hash
            for ev in job_events
        )

        # release_context (PR 44): None for a legacy job with no Release
        # wrapper -- _render_job_certificate_html renders nothing for
        # this section then, same as it already does for policy_html on
        # an inspect job.
        release = s.query(Release).filter(Release.job_id == job.id).one_or_none()
        release_context = None
        if release is not None:
            profile = next((p for p in RELEASE_PROFILES if p["id"] == release.profile_id), None)
            release_context = {
                "profile_id": release.profile_id,
                "profile_label": profile["label"] if profile else release.profile_id,
                "recipient_type": release.recipient_type,
                "recipient_name": release.recipient_name,
                "purpose": release.purpose,
                "intended_external": release.intended_external,
            }

        body = _render_job_certificate_html(
            matter_id=matter.id,
            matter_name=matter.name,
            document_id=doc.id,
            document_name=doc.filename,
            job_id=job.id,
            kind=job.kind,
            status=job.status,
            error=job.error,
            created_utc=job.created_utc,
            finished_utc=job.finished_utc,
            original_sha256=doc.sha256,
            derivative_sha256=derivative_sha256,
            policy_id=policy_id,
            policy_version=policy_version,
            policy_description=policy_description,
            actions=actions,
            findings_before=findings_before,
            inspect_findings=inspect_findings,
            verification=verification,
            limitations=limitations,
            audit_event_count=len(job_events),
            audit_integrity_ok=audit_integrity_ok,
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            generated_by=generated_by,
            release_context=release_context,
        )
        return body, policy_id, limitations

    def _append_certificate_issued(
        s: Session, *, matter_id: str, actor_id: str, job: Job, doc: Document, policy_id: str | None
    ) -> AuditEvent:
        # Mandatory on every pull, including repeats -- "who has pulled a
        # certificate for this document, and when" is itself part of the
        # custody record (approved product decision, 2026-08-26). A
        # release packet embedding the certificate (job_bundle, PR 36) is
        # just as much an issuance as the standalone route, so it fires
        # this too, alongside its own bundle.download event. Returns the
        # created row so job_bundle (PR 37) can cite its seq in
        # release_packet.json's audit_refs.
        return append_event(
            s,
            matter_id=matter_id,
            actor_id=actor_id,
            action="certificate.issued",
            payload={
                "job_id": job.id,
                "document_id": doc.id,
                "kind": job.kind,
                "policy_id": policy_id,
                "status": job.status,
            },
        )

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}/certificate")
    def job_certificate(
        matter_id: str,
        job_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """Self-contained per-job custody/transaction certificate (PR 33).

        Read-gated, same as job_manifest/job detail: every fact here is
        already visible through those two read-gated routes (job status/
        error/timestamps, the sanitize manifest, the document's own
        original hash). The "custody record" section is a narrow,
        job-scoped assertion (this job's own audit rows, hash-recomputed
        individually) — never the matter's full audit chain or any other
        job's rows, which is what keeps this at read rather than the
        admin gate GET .../audit and GET .../summary both use.

        Secondary discovery path since PR 36: the primary one is the
        release packet (job_bundle below), which embeds this same
        content. This route stays for direct/standalone access -- a
        link shared on its own, or opened without downloading the whole
        packet.
        """
        _require(matter_id, "read", s, user)
        matter = _matter(matter_id, s)
        job = _job(matter_id, job_id, s)
        doc = _document(matter_id, job.document_id, s)

        body, policy_id, _limitations = _build_certificate_html(
            s, matter=matter, job=job, doc=doc, generated_by=user
        )
        _append_certificate_issued(s, matter_id=matter_id, actor_id=user, job=job, doc=doc, policy_id=policy_id)
        s.commit()
        return Response(content=body, media_type="text/html")

    def _safe_download_stem(name: str) -> str:
        """A document's own filename, stripped to its stem and made safe as
        a Content-Disposition quoted-string value -- arbitrary user content
        (whatever the uploader named the file), so control characters and
        quote/backslash are replaced rather than passed through raw. Used
        so a downloaded release packet's own filename identifies which
        document it's for -- previously just "{job.id}-release-packet.zip",
        indistinguishable from any other job's download once saved.
        """
        stem = Path(name).stem or "document"
        safe = "".join(c if c.isprintable() and c not in '"\\' else "_" for c in stem)
        return safe[:80] or "document"

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}/bundle")
    def job_bundle(
        matter_id: str,
        job_id: str,
        include_original: bool = False,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """The release packet (PR 36): everything a recipient needs for one
        sanitize job's output travels together by default, the way a
        DocuSign certificate travels with the document it signs --
        derivative, manifest.json, report.json, the same custody
        certificate job_certificate serves standalone, and a README
        naming what each file is. Never alters the derivative itself to
        embed the certificate (see docs/release-packet-pdf-append.md for
        why a PDF-embedded certificate page was evaluated and deferred,
        not adopted) -- the certificate is a sibling file, not baked into
        the bytes under custody.
        """
        _require(matter_id, "read", s, user)
        matter = _matter(matter_id, s)
        job = _job(matter_id, job_id, s)
        doc = _document(matter_id, job.document_id, s)
        if job.status != "done" or not job.bundle_dir:
            raise HTTPException(409, f"job is {job.status}; no bundle")
        original_ref = None
        original_name = None
        if include_original:
            _require(matter_id, "download_original", s, user)
            original_ref = doc.storage_path
            original_name = doc.filename

        cert_html, policy_id, limitations = _build_certificate_html(
            s, matter=matter, job=job, doc=doc, generated_by=user
        )

        bundle = Path(job.bundle_dir)
        manifest_path = bundle / "manifest.json"
        manifest_bytes = manifest_path.read_bytes() if manifest_path.exists() else b"{}"
        deriv_dir = bundle / "derivative"
        # A truncated/failed worker output can lack the derivative tree
        # entirely — that's a 409 ("no bundle"), not an unhandled 500.
        if not deriv_dir.is_dir():
            raise HTTPException(409, f"job bundle is incomplete: {deriv_dir} missing")
        deriv_names = [p.name for p in sorted(deriv_dir.iterdir())]
        deriv_bytes_by_name = {name: (deriv_dir / name).read_bytes() for name in deriv_names}
        report = {
            "report_version": 1,
            "verification": (job.result_json or {}).get("manifest", {}).get("verification"),
            "findings_before": (job.result_json or {}).get("manifest", {}).get("findings_before"),
            "action_records": (job.result_json or {}).get("manifest", {}).get("action_records", []),
        }
        report_bytes = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
        cert_bytes = cert_html.encode("utf-8")
        readme_text = (
            "CounselClear release packet\n"
            "============================\n"
            f"Matter:   {matter.name} ({matter.id})\n"
            f"Document: {doc.filename} ({doc.id})\n"
            f"Job:      {job.id} ({job.kind}, {job.status})\n"
            f"Policy:   {policy_id or '(n/a)'}\n\n"
            "Files in this packet:\n"
            f"  derivative/{deriv_names[0] if deriv_names else '<name>'}"
            "   -- the sanitized document\n"
            "  manifest.json   -- full custody manifest: hashes, policy, actions taken\n"
            "  report.json     -- verification result and pre-sanitize findings summary\n"
            "  certificate.html -- the custody certificate; open in a browser for a\n"
            "                     human-readable summary, including any limitations\n"
            "  release_packet.json -- machine-readable manifest: content hashes of every\n"
            "                     file in this packet, audit references, and whether this\n"
            "                     packet is externally anchored (not yet -- see that file's\n"
            "                     own \"anchor\" field). Check it with\n"
            "                     tools/counselclear_verify_release_packet.py.\n"
            "  README.txt      -- this file\n\n"
            "certificate.html is the same certificate available on its own at\n"
            f"/v1/matters/{matter.id}/jobs/{job.id}/certificate -- read it before\n"
            "relying on this packet: it discloses anything kept without review,\n"
            "reviewed-and-kept findings, and any refusal/failure, not just a pass/fail.\n"
        )
        readme_bytes = readme_text.encode("utf-8")

        # Audit events first, not last: release_packet.json (built below)
        # cites their seq numbers, so this row must exist -- and be
        # committed, append_event's own responsibility -- before the
        # packet claiming to reference it is assembled.
        bundle_event = append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="bundle.download",
            payload={"job_id": job.id, "include_original": include_original},
        )
        cert_event = _append_certificate_issued(
            s, matter_id=matter_id, actor_id=user, job=job, doc=doc, policy_id=policy_id
        )

        def _sha256(data: bytes) -> str:
            return hashlib.sha256(data).hexdigest()

        policy_version = (job.result_json or {}).get("manifest", {}).get("policy", {}).get("version", 1)
        # Nullable: absent for a bundle pulled from a Job created via the
        # legacy, unwrapped /sanitize-jobs route (no Release exists for
        # it). release_id is additive, not a replacement for packet_id --
        # existing consumers keyed on packet_id (== job.id) are untouched.
        release = s.query(Release).filter(Release.job_id == job.id).one_or_none()
        release_packet = {
            "spec_version": "1.0",
            "packet_id": job.id,
            "release_id": release.id if release else None,
            # Nullable as a whole (mirrors release_id): absent for a
            # legacy, unwrapped job. Otherwise the same recipient/purpose/
            # intent context release_result.json already carries -- a
            # reviewer of the full packet shouldn't have to also fetch
            # the lighter companion JSON just to see who this was for.
            "release": (
                {
                    "profile_id": release.profile_id,
                    "recipient_type": release.recipient_type,
                    "recipient_name": release.recipient_name,
                    "purpose": release.purpose,
                    "intended_external": release.intended_external,
                }
                if release
                else None
            ),
            "matter_id": matter.id,
            "document_id": doc.id,
            "job_id": job.id,
            # Top-level, always the same doc.sha256 already visible via
            # GET .../documents -- so binding "this derivative came from
            # this original" never requires opening manifest.json's own
            # nested copy first.
            "original_sha256": doc.sha256,
            "kind": job.kind,
            "status": job.status,
            "policy": {
                "id": policy_id,
                "version": policy_version if policy_id else None,
                # Reserved, not implemented (docs/release-packet-verification-and-
                # anchoring-proposal.md §3): hash-pinning the actual policy rule
                # content, not just its id/version label, is separate design work.
                "digest": None,
            },
            "hashes": {
                "derivative": {
                    "filename": deriv_names[0] if deriv_names else None,
                    "sha256": _sha256(deriv_bytes_by_name[deriv_names[0]]) if deriv_names else None,
                },
                "manifest_json_sha256": _sha256(manifest_bytes),
                "report_json_sha256": _sha256(report_bytes),
                "certificate_html_sha256": _sha256(cert_bytes),
                "readme_txt_sha256": _sha256(readme_bytes),
            },
            "audit_refs": {
                "bundle_download_seq": bundle_event.seq,
                "certificate_issued_seq": cert_event.seq,
            },
            "legal_justifications": _legal_justifications_from_manifest(
                (job.result_json or {}).get("manifest") or {}
            ),
            "limitations": limitations,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "generated_by": user,
            # Not yet implemented -- see docs/release-packet-verification-and-
            # anchoring-proposal.md §5/§6. "none" is an honest statement, not
            # an omission: this packet's timestamp and content are currently
            # self-attested by this system only.
            "anchor": {"type": "none", "digest": None, "reference": None},
        }
        release_packet_bytes = json.dumps(release_packet, indent=2, sort_keys=True).encode("utf-8")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", manifest_bytes)
            for name, data in deriv_bytes_by_name.items():
                zf.writestr(f"derivative/{name}", data)
            zf.writestr("report.json", report_bytes)
            zf.writestr("certificate.html", cert_bytes)
            zf.writestr("release_packet.json", release_packet_bytes)
            zf.writestr("README.txt", readme_bytes)
            if original_ref and storage.exists(original_ref):
                zf.writestr(f"original/{original_name}", storage.read(original_ref))
        s.commit()
        download_name = f"{_safe_download_stem(doc.filename)}-release-packet-{job.id}.zip"
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{download_name}"'},
        )

    @app.get("/v1/matters/{matter_id}/acl")
    def get_acl(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "admin", s, user)
        _matter(matter_id, s)
        return {"grants": list_grants(s, matter_id)}

    @app.put("/v1/matters/{matter_id}/acl")
    def put_acl(
        matter_id: str,
        body: AclBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "admin", s, user)
        _matter(matter_id, s)
        try:
            grant(s, matter_id, body.user_id, body.perm)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="acl.grant",
            payload={"user_id": body.user_id, "perm": body.perm},
        )
        s.commit()
        return {"ok": True, "user_id": body.user_id, "perm": body.perm}

    @app.delete("/v1/matters/{matter_id}/acl")
    def delete_acl(
        matter_id: str,
        body: AclBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "admin", s, user)
        _matter(matter_id, s)
        if (
            body.user_id == user
            and body.perm in ("admin", "read")
            and not body.confirm_self_revoke
        ):
            raise HTTPException(
                400,
                f"revoking your own {body.perm!r} grant requires confirm_self_revoke=true "
                "(self-lockout guard)",
            )
        try:
            revoke(s, matter_id, body.user_id, body.perm)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="acl.revoke",
            payload={"user_id": body.user_id, "perm": body.perm},
        )
        s.commit()
        return {"ok": True, "revoked": {"user_id": body.user_id, "perm": body.perm}}

    @app.get("/v1/matters/{matter_id}/audit")
    def list_audit(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
        limit: int = 100,
        offset: int = 0,
    ):
        limit = min(max(1, limit), 500)  # server-capped, never unbounded
        offset = max(0, offset)
        _require(matter_id, "admin", s, user)
        # Chain verification is inherently sequential from genesis -- it
        # needs every row, not just the page being displayed, so it always
        # runs against the full set regardless of pagination. Already
        # fetched in full before this change too; paginating the *response*
        # doesn't need a second query, just a slice of what's already here.
        all_rows = (
            s.query(AuditEvent)
            .filter(AuditEvent.matter_id == matter_id)
            .order_by(AuditEvent.seq)
            .all()
        )
        ok, detail = verify_chain(all_rows)
        page_rows = all_rows[offset : offset + limit]
        return {
            "chain_ok": ok,
            "chain_detail": detail,
            "total": len(all_rows),
            "offset": offset,
            "limit": limit,
            "events": [
                {
                    "id": e.id,
                    "seq": e.seq,
                    "action": e.action,
                    "actor_id": e.actor_id,
                    "payload": e.payload,
                    "prev_hash": e.prev_hash,
                    "row_hash": e.row_hash,
                    "at": e.at,
                }
                for e in page_rows
            ],
        }

    @app.get("/v1/matters/{matter_id}/audit/export")
    def export_audit(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """The full, unpaginated audit chain as CSV -- a reviewer handoff
        artifact, not a UI list. Same "admin" perm and the same
        verify_chain() call as GET .../audit; deliberately ignores
        limit/offset entirely (there is no partial handoff of a chain of
        custody) and reports the verification verdict in response headers
        rather than folding it into the CSV body, so every row stays a
        real audit event and the file stays valid, parseable CSV.
        """
        _require(matter_id, "admin", s, user)
        _matter(matter_id, s)
        all_rows = (
            s.query(AuditEvent)
            .filter(AuditEvent.matter_id == matter_id)
            .order_by(AuditEvent.seq)
            .all()
        )
        ok, detail = verify_chain(all_rows)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            ["seq", "at", "action", "actor_id", "payload_json", "prev_hash", "row_hash"]
        )
        for e in all_rows:
            writer.writerow(
                [e.seq, e.at, e.action, e.actor_id, json.dumps(e.payload), e.prev_hash, e.row_hash]
            )
        # Header values must be a single line -- chain_detail is normally a
        # short fixed phrase, but never trust it not to contain one.
        safe_detail = detail.replace("\n", " ").replace("\r", " ")
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="audit_{matter_id}.csv"',
                "X-Chain-Ok": "true" if ok else "false",
                "X-Chain-Detail": safe_detail,
                "X-Total-Events": str(len(all_rows)),
            },
        )

    @app.get("/v1/matters/{matter_id}/summary")
    def matter_summary(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """Human-readable HTML reviewer-handoff report for one matter.

        Same "admin" perm as the audit routes: the report discloses audit
        chain verification status and refusal/failure reasons, the same
        class of operational detail those routes already gate. Served
        inline (not attachment) so it opens directly in a tab -- the
        recipient can read it there or use the browser's own print dialog
        to save a PDF, rather than this app taking on a PDF-generation
        dependency for a "prefer simple HTML" reviewer handoff artifact.
        """
        _require(matter_id, "admin", s, user)
        matter = _matter(matter_id, s)

        total_documents = s.query(Document).filter_by(matter_id=matter_id).count()
        job_counts = {st: 0 for st in ("queued", "running", "done", "failed", "refused")}
        for status, n in (
            s.query(Job.status, func.count(Job.id))
            .filter(Job.matter_id == matter_id)
            .group_by(Job.status)
            .all()
        ):
            if status in job_counts:
                job_counts[status] = n

        attention = _attention_items(s, [matter_id], {matter_id: matter.name})

        all_audit_rows = (
            s.query(AuditEvent)
            .filter(AuditEvent.matter_id == matter_id)
            .order_by(AuditEvent.seq)
            .all()
        )
        chain_ok, chain_detail = verify_chain(all_audit_rows)
        recent_events = [
            {"seq": ev.seq, "at": ev.at, "action": ev.action, "actor_id": ev.actor_id}
            for ev in reversed(all_audit_rows[-10:])
        ]

        body = _render_matter_summary_html(
            matter_id=matter_id,
            matter_name=matter.name,
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            generated_by=user,
            total_documents=total_documents,
            job_counts=job_counts,
            attention=attention,
            chain_ok=chain_ok,
            chain_detail=chain_detail,
            total_events=len(all_audit_rows),
            recent_events=recent_events,
        )
        return Response(content=body, media_type="text/html")

    @app.get("/v1/dashboard")
    def dashboard(
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """Operator overview across every matter this principal can read.

        Unlike list_matters (whose frontend honestly labels itself
        "loaded-so-far"), every number here is a server-computed total over
        the *full* ACL-visible set — no pagination, no accumulated pages —
        so the dashboard can present these as global truth for the
        principal's corpus.

        Disclosure is split by permission level, not just by readability
        (operator decision, 2026-08-25 — this dashboard previously showed
        every read-scoped matter's audit actor IDs and recent-event feed
        to any reader, while the near-identical content on GET .../audit
        and GET .../summary correctly required admin; that was an
        inconsistency this endpoint's own contract should never have had):

        - totals: read-scoped, as before -- server-computed counts over
          every readable matter, no per-matter admin requirement.
        - attention items whose detail is already visible through a
          read-gated per-job route (unreviewed_findings via the manifest
          route, refused/failed via the job detail route's `error` field)
          stay at read scope -- the dashboard isn't disclosing anything a
          read principal couldn't already fetch one document at a time.
        - "stale" attention items are audit-derived (they compare a
          matter's last AuditEvent timestamp, not just job/document
          activity, against a cutoff) and audit itself is admin-gated, so
          they're now scoped to matters this principal administers only.
        - recent[] (the cross-matter audit-event feed: action, actor_id,
          timestamp) is audit content the same way GET .../audit is, so
          it's now built only from matters this principal administers,
          not every readable one. Empty (not an error) when the principal
          administers none of their readable matters.
        """
        matter_ids = [
            r[0]
            for r in s.query(MatterAcl.matter_id).filter_by(user_id=user, perm="read").distinct()
        ]
        if matter_ids:
            # PR 45: a demo-seeded matter is real, fully functional data --
            # visible everywhere else (list_matters, matter view, audit) --
            # but it shouldn't inflate an operator's cross-matter attention/
            # activity totals here. Filtering matter_ids once, at the top,
            # means every query below (totals, attention, recent) that
            # already keys off this list is excluded for free, with no
            # second exclusion to keep in sync.
            demo_ids = {
                r[0]
                for r in s.query(Matter.id).filter(Matter.id.in_(matter_ids), Matter.is_demo.is_(True))
            }
            if demo_ids:
                matter_ids = [m for m in matter_ids if m not in demo_ids]
        empty = {
            "totals": {
                "matters": 0,
                "documents": 0,
                "jobs": {"queued": 0, "running": 0, "done": 0, "failed": 0, "refused": 0},
            },
            "attention": [],
            "recent": [],
            "admin_matters": 0,
        }
        if not matter_ids:
            return empty

        admin_matter_ids = {
            r[0]
            for r in s.query(MatterAcl.matter_id).filter_by(user_id=user, perm="admin").distinct()
            if r[0] in set(matter_ids)
        }

        total_matters = s.query(Matter).filter(Matter.id.in_(matter_ids)).count()
        total_documents = (
            s.query(Document).filter(Document.matter_id.in_(matter_ids)).count()
        )
        job_counts = {st: 0 for st in ("queued", "running", "done", "failed", "refused")}
        for status, n in (
            s.query(Job.status, func.count(Job.id))
            .filter(Job.matter_id.in_(matter_ids))
            .group_by(Job.status)
            .all()
        ):
            if status in job_counts:  # never KeyError on an unknown stored value
                job_counts[status] = n

        matter_names = dict(
            s.query(Matter.id, Matter.name).filter(Matter.id.in_(matter_ids)).all()
        )
        attention = [
            item
            for item in _attention_items(s, matter_ids, matter_names)
            if item["type"] != "stale" or item["matter_id"] in admin_matter_ids
        ]

        recent_rows = (
            s.query(AuditEvent, Matter.name)
            .join(Matter, Matter.id == AuditEvent.matter_id)
            .filter(AuditEvent.matter_id.in_(admin_matter_ids))
            .order_by(AuditEvent.at.desc(), AuditEvent.seq.desc())
            .limit(10)
            .all()
            if admin_matter_ids
            else []
        )
        return {
            "totals": {
                "matters": total_matters,
                "documents": total_documents,
                "jobs": job_counts,
            },
            "attention": attention,
            "recent": [
                {
                    "matter_id": e.matter_id,
                    "matter_name": name,
                    "action": e.action,
                    "actor_id": e.actor_id,
                    "at": e.at,
                }
                for e, name in recent_rows
            ],
            "admin_matters": len(admin_matter_ids),
        }

    # --- helpers ------------------------------------------------------------

    def _parse_ts(ts: str | None) -> datetime | None:
        """ISO timestamp -> UTC-aware datetime; None for missing/unparseable.

        Rows carry _now() strings ("2026-08-25T12:34:56+00:00"); tolerate
        legacy naive strings rather than crash the whole overview on one
        odd row.
        """
        if not ts:
            return None
        try:
            d = datetime.fromisoformat(ts)
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=UTC)
        return d.astimezone(UTC)

    def _attention_items(
        s: Session, matter_ids: list[str], matter_names: dict[str, str]
    ) -> list[dict]:
        """The four trust-critical queues (unreviewed_findings, refused,
        failed, stale), scoped to whichever matter_ids the caller passes.

        Shared by GET /v1/dashboard (every ACL-readable matter) and
        GET /v1/matters/{id}/summary (a single matter) so the two surfaces
        can never silently disagree about what counts as "needs attention"
        -- one computation, two callers, not two hand-maintained copies.
        """
        attention: list[dict] = []
        # release_id/profile_id: one batched lookup across every Release
        # in these matters, not per-item -- same pattern _batch_dict/
        # list_jobs already use. Fetched once, up front, since both
        # job-bearing queues below (unreviewed_findings, refused/failed)
        # need it.
        releases_by_job = {
            r.job_id: r for r in s.query(Release).filter(Release.matter_id.in_(matter_ids)).all()
        }

        # Trust-critical queue 1: done sanitize jobs whose manifest kept
        # findings without an operator decision. Every such job shipped a
        # derivative with unreviewed keeps, so it must surface even when
        # its status (done) looks benign. Detected the same way the
        # job.sanitize audit event counts them (NO_DECISION_MARKER inside
        # an action string).
        done_sanitize = (
            s.query(Job, Document.filename)
            .join(Document, Document.id == Job.document_id)
            .filter(
                Job.matter_id.in_(matter_ids),
                Job.kind == "sanitize",
                Job.status == "done",
                Job.result_json.isnot(None),
            )
            .order_by(Job.finished_utc.desc())
            .all()
        )
        for job, doc_name in done_sanitize:
            actions = ((job.result_json or {}).get("manifest") or {}).get("actions") or []
            kept_unreviewed = [a for a in actions if NO_DECISION_MARKER in a]
            if not kept_unreviewed:
                continue
            attention.append(
                {
                    "type": "unreviewed_findings",
                    "matter_id": job.matter_id,
                    "matter_name": matter_names.get(job.matter_id, job.matter_id),
                    "document_id": job.document_id,
                    "document_name": doc_name,
                    "job_id": job.id,
                    "release_id": releases_by_job[job.id].id if job.id in releases_by_job else None,
                    "profile_id": (
                        releases_by_job[job.id].profile_id if job.id in releases_by_job else None
                    ),
                    "detail": (
                        f"{len(kept_unreviewed)} finding(s) kept without operator review"
                    ),
                    "created_utc": job.finished_utc or job.created_utc,
                }
            )

        # Queues 2-3: refused and failed jobs — both are "correct" outcomes
        # in different senses (policy declined vs. something broke), but
        # either way the operator needs the list with the job's reason.
        for status, label in (("refused", "refused"), ("failed", "failed")):
            rows = (
                s.query(Job, Document.filename)
                .join(Document, Document.id == Job.document_id)
                .filter(Job.matter_id.in_(matter_ids), Job.status == status)
                .order_by(Job.created_utc.desc())
                .all()
            )
            for job, doc_name in rows:
                attention.append(
                    {
                        "type": status,  # "refused" | "failed"
                        "matter_id": job.matter_id,
                        "matter_name": matter_names.get(job.matter_id, job.matter_id),
                        "document_id": job.document_id,
                        "document_name": doc_name,
                        "job_id": job.id,
                        "kind": job.kind,
                        "release_id": (
                            releases_by_job[job.id].id if job.id in releases_by_job else None
                        ),
                        "profile_id": (
                            releases_by_job[job.id].profile_id if job.id in releases_by_job else None
                        ),
                        "detail": job.error[:300] or label,
                        "created_utc": job.created_utc,
                    }
                )

        # Queue 4: stale matters — no audit event and no job at all in the
        # last 7 days (matter creation counts as activity, so a fresh,
        # untouched matter is not stale).
        cutoff = datetime.now(UTC) - timedelta(days=7)
        last_audit_at = dict(
            s.query(AuditEvent.matter_id, func.max(AuditEvent.at))
            .filter(AuditEvent.matter_id.in_(matter_ids))
            .group_by(AuditEvent.matter_id)
            .all()
        )
        last_job_at = dict(
            s.query(Job.matter_id, func.max(Job.created_utc))
            .filter(Job.matter_id.in_(matter_ids))
            .group_by(Job.matter_id)
            .all()
        )
        for m in s.query(Matter).filter(Matter.id.in_(matter_ids)).all():
            latest: datetime | None = None
            for stamp in (m.created_utc, last_audit_at.get(m.id), last_job_at.get(m.id)):
                t = _parse_ts(stamp)
                if t is not None and (latest is None or t > latest):
                    latest = t
            if latest is not None and latest < cutoff:
                attention.append(
                    {
                        "type": "stale",
                        "matter_id": m.id,
                        "matter_name": m.name,
                        "detail": (
                            "no audit or job activity since "
                            f"{latest.isoformat(timespec='seconds')}"
                        ),
                        "created_utc": m.created_utc,
                    }
                )

        return attention

    def _matter(matter_id: str, s: Session) -> Matter:
        m = s.get(Matter, matter_id)
        if not m:
            raise HTTPException(404, "matter not found")
        return m

    def _document(matter_id: str, doc_id: str, s: Session) -> Document:
        d = s.get(Document, doc_id)
        if not d or d.matter_id != matter_id:
            raise HTTPException(404, "document not found")
        return d

    def _job(matter_id: str, job_id: str, s: Session) -> Job:
        j = s.get(Job, job_id)
        if not j or j.matter_id != matter_id:
            raise HTTPException(404, "job not found")
        return j

    def _release(matter_id: str, release_id: str, s: Session) -> Release:
        r = s.get(Release, release_id)
        if not r or r.matter_id != matter_id:
            raise HTTPException(404, "release not found")
        return r

    def _matter_dict(m: Matter, perms: list[str] | None = None) -> dict:
        d: dict = {"id": m.id, "name": m.name, "created_utc": m.created_utc, "is_demo": m.is_demo}
        # perms is the calling principal's OWN grants on this matter --
        # only computed by routes that already know who's asking (get_matter,
        # create_matter), not list_matters (would be an N+1 query per row
        # for a value the matters-list UI doesn't currently need). The
        # frontend uses this to hide or disable controls that would 403
        # rather than let a limited-permission reviewer hit dead ends.
        if perms is not None:
            d["perms"] = perms
        return d

    def _doc_dict(d: Document) -> dict:
        return {
            "id": d.id,
            "matter_id": d.matter_id,
            "filename": d.filename,
            "sha256": d.sha256,
            "bytes": d.bytes,
            "created_utc": d.created_utc,
        }

    def _job_dict(
        j: Job, *, include_result: bool = True, release_id: str | None = None, profile_id: str | None = None
    ) -> dict:
        """release_id/profile_id (PR 40): nullable, non-derived from a
        query inside this function on purpose -- an inspect job or a job
        from the legacy /sanitize-jobs route never has a Release wrapper
        at all (both None is correct there, no lookup needed), and a
        caller that just created or already loaded the Release already
        has it in hand. Only list_matter_jobs (many jobs, unknown mix)
        needs an actual batched lookup -- see its own call site."""
        out = {
            "id": j.id,
            "matter_id": j.matter_id,
            "document_id": j.document_id,
            "kind": j.kind,
            "policy_id": j.policy_id,
            "status": j.status,
            "error": j.error,
            "attestation": j.attestation,
            "layer_b": j.layer_b,
            "worker_image": j.worker_image,
            "created_utc": j.created_utc,
            "finished_utc": j.finished_utc,
            "release_id": release_id,
            "profile_id": profile_id,
        }
        if include_result and j.result_json:
            out["result"] = j.result_json
        return out

    return app
