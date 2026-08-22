"""report_html.py — self-contained HTML report rendering."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from findings import Finding
from report_html import render_intake_report, render_report_html


def _finding(**kw) -> Finding:
    base = dict(
        category="file_metadata",
        subtype="authoring_props",
        format="docx",
        risk_level="high",
        confidence="confirmed",
    )
    base.update(kw)
    return Finding(**base)


def test_empty_findings_renders_clear_verdict():
    out = render_report_html(
        subject_name="clean.txt", kind="text", format="txt", findings=[], mode="inspect",
    )
    assert "No findings" in out
    assert "clean.txt" in out
    assert out.startswith("<!doctype html>")


def test_findings_grouped_and_counted_by_risk():
    findings = [
        _finding(subtype="authoring_props", risk_level="high"),
        _finding(subtype="jpeg_gps", category="file_metadata", risk_level="high"),
        _finding(subtype="layer_a_body", category="invisible_text", risk_level="low",
                 confidence="informational"),
    ]
    out = render_report_html(
        subject_name="doc.docx", kind="container", format="docx", findings=findings,
        mode="inspect",
    )
    assert "2 high" in out
    assert "1 low" in out
    assert "Author &amp; company identity" in out or "Author & company identity" in out
    assert "GPS location" in out
    assert "found" in out  # non-empty findings -> found verdict class present


def test_notes_and_filenames_are_html_escaped():
    dangerous = _finding(notes="<script>alert(1)</script>")
    out = render_report_html(
        subject_name="<img src=x onerror=alert(1)>.docx",
        kind="container",
        format="docx",
        findings=[dangerous],
        mode="inspect",
    )
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "<img src=x onerror=alert(1)>" not in out


def test_sanitize_mode_includes_actions_checks_and_custody():
    findings = [_finding()]
    out = render_report_html(
        subject_name="SPA.docx",
        kind="container",
        format="docx",
        findings=findings,
        mode="sanitize",
        policy_id="external_sharing",
        actions=["authoring_props:strip: blanked dc:creator"],
        checks=[
            {"name": "reinspect_targeted_gone", "pass": True, "detail": "targeted subtypes cleared"},
            {"name": "part_inventory", "pass": False, "detail": "added=[] dropped=['x']"},
        ],
        verification_pass=False,
        original_sha256="a" * 64,
        derivative_name="SPA.external.docx",
        derivative_sha256="b" * 64,
        processor={"git_sha": "abc123", "tools": {"qpdf": "11.0"}},
    )
    assert "external_sharing" in out
    assert "blanked dc:creator" in out
    assert "Verification FAILED" in out
    assert "a" * 64 in out
    assert "SPA.external.docx" in out
    assert "qpdf" in out


def test_intake_report_without_reveal_hides_identities():
    records = [
        {"name": "a.docx", "kind": "container", "format": "docx",
         "findings": [_finding(subtype="authoring_props", risk_level="high")],
         "identities": {"Author": "Jane Associate"}},
    ]
    out = render_intake_report(root_label="/received", records=records, reveal_identities=False)
    assert "Jane Associate" not in out
    assert "redacted by default" in out
    assert "a.docx" in out


def test_intake_report_reveal_rolls_up_identities_across_files():
    common = {"Author": "Jane Associate", "Company": "Preston & Hale LLP"}
    records = [
        {"name": "a.docx", "kind": "container", "format": "docx",
         "findings": [_finding(subtype="authoring_props")], "identities": dict(common)},
        {"name": "b.docx", "kind": "container", "format": "docx",
         "findings": [_finding(subtype="authoring_props")], "identities": dict(common)},
        {"name": "c.docx", "kind": "container", "format": "docx",
         "findings": [], "identities": {"Author": "Bob Partner"}},
    ]
    out = render_intake_report(
        root_label="/received", records=records, reveal_identities=True, matter_label="M-42",
    )
    assert "M-42" in out
    # Jane Associate shows up in 2 files -> rolled up, not repeated per-row
    assert out.count("Jane Associate") == 1
    assert "<td>2</td>" in out
    assert "Bob Partner" in out
    assert "a.docx" in out and "b.docx" in out and "c.docx" in out


def test_intake_report_lists_unreadable_files_without_crashing():
    records = [
        {"name": "corrupt.docx", "error": "zip parse error"},
        {"name": "ok.txt", "kind": "text", "format": "txt", "findings": [], "identities": {}},
    ]
    out = render_intake_report(root_label="/received", records=records, reveal_identities=False)
    assert "corrupt.docx" in out
    assert "zip parse error" in out
    assert "1 unreadable" in out


def test_intake_report_empty_directory():
    out = render_intake_report(root_label="/empty", records=[], reveal_identities=False)
    assert "No files found" in out
    assert "0 finding(s) across 0 file(s)" in out


def test_mode_inspect_omits_custody_and_actions_sections():
    out = render_report_html(
        subject_name="x.txt", kind="text", format="txt", findings=[], mode="inspect",
        policy_id="external_sharing", actions=["should not appear"],
    )
    # actions/checks/custody are sanitize-only; inspect mode ignores them
    assert "should not appear" not in out
    assert "Custody" not in out
