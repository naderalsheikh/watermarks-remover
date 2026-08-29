"""PR 11 — policy engine: plan_actions / apply_actions."""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from engine_api import inspect_bytes
from policies import (
    DEFAULT_POLICIES,
    SUBTYPES,
    ActionPlan,
    PolicyError,
    apply_actions,
    plan_actions,
    validate_policy,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# --- table integrity ---------------------------------------------------------


def test_all_four_policies_cover_every_subtype():
    for pid, doc in DEFAULT_POLICIES.items():
        assert set(doc.keys()) == set(SUBTYPES), pid
    assert set(DEFAULT_POLICIES) == {
        "external_sharing",
        "privacy_only",
        "production",
        "evidence_preservation",
    }


def test_frozen_matrix_spot_checks():
    assert DEFAULT_POLICIES["external_sharing"]["tracked_changes"] == "accept_all"
    assert DEFAULT_POLICIES["external_sharing"]["headers_footers"] == "flag"
    assert DEFAULT_POLICIES["privacy_only"]["c2pa"] == "keep"
    assert DEFAULT_POLICIES["privacy_only"]["jpeg_gps"] == "strip"
    assert DEFAULT_POLICIES["privacy_only"]["comments_and_notes"] == "keep"
    assert DEFAULT_POLICIES["production"]["comments_and_notes"] == "approve"
    assert DEFAULT_POLICIES["evidence_preservation"]["macros_vba"] == "inspect_only"
    assert all(DEFAULT_POLICIES[p]["macros_vba"] == "refuse" for p in
               ("external_sharing", "privacy_only", "production"))


def test_prefix_subtypes_values_are_all_valid_policy_subtypes():
    from policies import _PREFIX_SUBTYPES

    for prefix, subtype in _PREFIX_SUBTYPES.items():
        assert subtype in SUBTYPES, f"{prefix!r} maps to unknown subtype {subtype!r}"


def test_prefix_subtypes_match_real_emitted_prefixes():
    # Legacy-string fallback path (_collect_subtypes): must recognize the
    # prefixes actually emitted by pdf_legal.py / xlsx_legal.py / the docx
    # legal scanners, not stale guesses. This table previously listed
    # "pdf-attachments:" (never emitted; real prefix is "pdf-embeddedfiles:")
    # and "hidden-sheet:"/"hidden-row:"/"hidden-col:" (never emitted; real
    # prefixes are "xlsx-hidden-sheets:"/"xlsx-hidden-rows-cols:") and was
    # missing "docx-tracked-changes:"/"xlsx-hidden-names:"/
    # "xlsx-threaded-comments:" entirely, so those subtypes silently fell
    # through to unmapped_findings on this fallback path.
    from policies import _collect_subtypes

    cases = {
        "pdf-embeddedfiles: 2 attachment(s)": "pdf_attachments",
        "pdf-incremental-updates: 3 update section(s)": "pdf_incremental",
        "xlsx-hidden-sheets: 1 hidden sheet(s)": "hidden_structure",
        "xlsx-hidden-rows-cols: 4 hidden row(s)/col(s)": "hidden_structure",
        "xlsx-hidden-names: 1 hidden defined name(s)": "hidden_structure",
        "xlsx-threaded-comments: 2 threaded comment(s)": "comments_and_notes",
        "docx-tracked-changes: 5 revision(s)": "tracked_changes",
    }
    for text, expected_subtype in cases.items():
        seen, unmapped = _collect_subtypes({"kind": None, "report": None, "findings": [text]})
        assert seen == [expected_subtype], f"{text!r}: got seen={seen} unmapped={unmapped}"


def test_policy_subtype_for_finding_matches_collect_subtypes():
    """policy_subtype_for_finding is the per-Finding primitive
    _collect_subtypes is now built from -- same alias table, so an
    aliased raw subtype (office_tracked_changes) resolves the same way
    whichever path calls it, and an unmapped one returns None rather than
    a bogus subtype string a caller could put in finding_decisions."""
    from findings import Finding, FindingLocation
    from policies import policy_subtype_for_finding

    aliased = Finding(
        category="revision_history",
        subtype="office_tracked_changes",
        format="docx",
        location=FindingLocation(pane="markup"),
    )
    assert policy_subtype_for_finding(aliased) == "tracked_changes"

    direct = Finding(category="revision_history", subtype="comments_and_notes", format="docx")
    assert policy_subtype_for_finding(direct) == "comments_and_notes"

    unmapped = Finding(category="file_metadata", subtype="totally_unknown_subtype", format="docx")
    assert policy_subtype_for_finding(unmapped) is None


def test_validate_overlay_rules():
    ok = validate_policy({"hidden_text": "strip"}, base_id="production")
    assert ok["hidden_text"] == "strip" and ok["tracked_changes"] == "approve"
    with pytest.raises(PolicyError, match="unknown policy subtype"):
        validate_policy({"nope": "strip"})
    with pytest.raises(PolicyError, match="unknown action"):
        validate_policy({"hidden_text": "nuke"})
    with pytest.raises(PolicyError, match="may not be weakened"):
        validate_policy({"macros_vba": "strip"})
    with pytest.raises(PolicyError, match="may not be weakened"):
        validate_policy({"cms_or_xml_dsig": "sanitize"})


# --- planning ----------------------------------------------------------------


def test_plan_sharing_on_docx_fixture():
    res = inspect_bytes(_load("spa.docx"), "spa.docx")
    plan = plan_actions(res, "external_sharing")
    assert isinstance(plan, ActionPlan)
    assert plan.actions["tracked_changes"] == {"action": "accept_all", "reason": "policy_default"}
    assert plan.requires_execution()
    assert plan.source_sha256 == res.source_sha256


def test_missing_decision_defaults_to_keep_and_is_recorded():
    res = inspect_bytes(b"clean text\n", "memo.txt")
    plan = plan_actions(res, "production")
    assert plan.actions["comments_and_notes"] == {"action": "keep", "reason": "no_decision"}


def test_operator_decisions_are_honored():
    res = inspect_bytes(b"clean text\n", "memo.txt")
    plan = plan_actions(
        res, "production", decisions={"comments_and_notes": "approve"}
    )
    assert plan.actions["comments_and_notes"]["action"] == "strip"
    assert plan.actions["comments_and_notes"]["reason"] == "operator_approved"
    keep_plan = plan_actions(res, "production", decisions={"tracked_changes": "keep"})
    assert keep_plan.actions["tracked_changes"] == {
        "action": "keep",
        "reason": "operator_kept",
    }
    with pytest.raises(PolicyError):
        plan_actions(res, "production", decisions={"comments_and_notes": "reject_all"})
    with pytest.raises(PolicyError):
        plan_actions(res, "production", decisions={"made_up_subtype": "approve"})


def test_operator_approved_subtype_that_resolves_to_keep_is_disclosed():
    """layer_a_non_body is the one approve-default subtype whose
    _APPROVE_RESOLVES_TO value is itself "keep" (external_sharing's own
    row keeps it -- confirmed by checking every _APPROVE_RESOLVES_TO
    value directly, not assumed). An operator who explicitly approves it
    -- choosing strip, not keep -- still ends up with action "keep": a
    structural no-op the operator didn't ask for and wouldn't expect from
    clicking "Approve". Before this test's fix, that combination (reason
    "operator_approved", action "keep") produced no ActionRecord at all
    -- neither the no_decision nor operator_kept branches of the old
    approve-default keep disclosure matched it, so it was invisible in the
    manifest exactly like the other two silent-omission cases this file
    already covers."""
    from findings import Finding, FindingLocation
    from policies import _surviving_finding_records

    finding = Finding(
        category="invisible_text",
        subtype="layer_a_non_body",
        format="docx",
        location=FindingLocation(pane="other"),
        risk_level="high",
        confidence="probable",
        action_recommended="flag",
    )
    result = {"kind": "container", "report": None, "findings": [finding]}
    plan = plan_actions(
        result,
        "production",
        decisions={"layer_a_non_body": "approve"},
        source_sha256="0" * 64,
    )
    assert plan.actions["layer_a_non_body"] == {
        "action": "keep",
        "reason": "operator_approved",
        "legal_justification": {"basis": "unspecified", "note": ""},
    }

    records = _surviving_finding_records(plan, set())
    assert len(records) == 1
    assert records[0].subtype == "layer_a_non_body"
    assert records[0].action == "keep"
    assert "approved, but this subtype has no strip action" in records[0].detail
    assert records[0].legal_justification == {"basis": "unspecified", "note": ""}


def test_signed_pdf_requires_attestation():
    res = inspect_bytes(_load("signed.pdf"), "signed.pdf")
    with pytest.raises(PolicyError, match="attestation"):
        plan_actions(res, "external_sharing")
    attested = plan_actions(res, "external_sharing", signature_break_attestation=True)
    assert attested.signature_break_attestation is True
    assert attested.actions["cms_or_xml_dsig"]["reason"] == "attested_signature_break"


def test_macro_files_refused_by_mutating_policies():
    res = inspect_bytes(_load("macro.docm"), "macro.docm")
    for pid in ("external_sharing", "privacy_only", "production"):
        with pytest.raises(PolicyError, match="macro"):
            plan_actions(res, pid)
    # evidence_preservation inspects only
    evd = plan_actions(res, "evidence_preservation")
    assert evd.actions["macros_vba"] == {
        "action": "inspect_only",
        "reason": "policy_default",
        "legal_justification": {"basis": "unspecified", "note": ""},
    }


def test_evidence_preservation_is_all_keep_and_apply_raises():
    res = inspect_bytes(_load("spa.docx"), "spa.docx")
    plan = plan_actions(res, "evidence_preservation")
    passive = {"keep", "flag", "inspect_only"}
    assert all(eff["action"] in passive for eff in plan.actions.values())
    assert not plan.requires_execution()
    with pytest.raises(PolicyError, match="never produces derivatives"):
        apply_actions(_load("spa.docx"), plan)


def test_overlay_policy_planning():
    res = inspect_bytes(b"text\n", "t.txt")
    overlay = {"id": "firm_strict", "base": "privacy_only", "hidden_text": "strip"}
    plan = plan_actions(res, overlay)
    assert plan.policy_id == "firm_strict"
    assert plan.actions["hidden_text"]["action"] == "strip"
    assert plan.actions["comments_and_notes"]["action"] == "keep"


def test_unknown_policy_or_bad_sha_raises():
    res = inspect_bytes(b"x\n", "x.txt")
    with pytest.raises(PolicyError, match="unknown policy"):
        plan_actions(res, "not_a_policy")
    plan = plan_actions(res, "external_sharing")
    with pytest.raises(PolicyError, match="sha256 mismatch"):
        apply_actions(b"different bytes entirely", plan)


# --- execution ---------------------------------------------------------------


def test_apply_privacy_docx_keeps_markup_and_comments_blanks_listed_props():
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(res, "privacy_only")
    cleaned, _records = apply_actions(data, plan)
    assert cleaned != data

    def parts(blob):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            return zf.namelist(), zf.read("word/document.xml").decode("utf-8")

    orig_names, orig_doc = parts(data)
    new_names, new_doc = parts(cleaned)
    assert new_names == orig_names  # nothing dropped under privacy
    assert "<w:delText>" in orig_doc and "<w:delText>" in new_doc  # markup kept

    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        core = zf.read("docProps/core.xml").decode("utf-8")
    assert "<dc:creator></dc:creator>" in core or "<dc:creator/>" in core
    if "<dc:title>" in core:
        assert "Draft" in core or "SPA" in core  # non-listed field survives


def test_apply_production_docx_discloses_findings_kept_without_a_decision():
    """production's comments_and_notes/tracked_changes default to "approve",
    which resolves to "keep" (not strip) when no operator decision is
    supplied. Before this test's fix (policies.py's surviving-finding records),
    apply_actions produced *no* record at all for those kept, present
    findings -- so a caller reading only manifest.actions had no way to
    tell "reviewed and kept" apart from "never looked at". This asserts
    the derivative is unchanged for the two present approve-default
    findings, and that the records list says so explicitly rather than
    staying silent."""
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(res, "production")
    cleaned, records = apply_actions(data, plan)

    by_subtype = {r.subtype: r for r in records}
    for subtype in ("comments_and_notes", "tracked_changes"):
        assert subtype in by_subtype, f"no record at all for kept-but-present {subtype}"
        assert by_subtype[subtype].action == "keep"
        assert "no operator decision was supplied" in by_subtype[subtype].detail

    def parts(blob):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            return zf.read("word/document.xml"), zf.namelist()

    orig_doc_xml, _ = parts(data)
    new_doc_xml, _ = parts(cleaned)
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        assert "word/comments.xml" in zf.namelist(), "comments part dropped despite 'keep'"
    assert orig_doc_xml == new_doc_xml, "kept subtype's markup was altered anyway"


def test_apply_production_docx_with_decisions_records_no_gap():
    """The counterpart to the test above: once every present approve-default
    subtype has an explicit operator decision, the no-decision disclosure has
    nothing left to add -- no "no operator decision" record appears."""
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(
        res,
        "production",
        decisions={"comments_and_notes": "approve", "tracked_changes": "approve"},
    )
    _cleaned, records = apply_actions(data, plan)
    assert not any("no operator decision was supplied" in r.detail for r in records)


def test_apply_production_docx_explicit_keep_is_visible_and_distinct_from_no_decision():
    """An operator who reviews a finding and chooses "keep" made a
    deliberate call -- that must not look, in the manifest, like the
    no_decision case (never reviewed at all). Both currently resolve to
    the same "keep" action, so the only thing that can tell them apart is
    the record's detail string; assert the two are actually distinct and
    that the reviewed one doesn't trip the no-decision marker the job
    page's NoDecisionWarning keys off of."""
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(
        res,
        "production",
        decisions={"comments_and_notes": "keep", "tracked_changes": "approve"},
    )
    _cleaned, records = apply_actions(data, plan)

    by_subtype = {r.subtype: r for r in records}
    assert by_subtype["comments_and_notes"].action == "keep"
    assert "reviewed and kept by operator" in by_subtype["comments_and_notes"].detail
    assert "no operator decision was supplied" not in by_subtype["comments_and_notes"].detail
    assert by_subtype["comments_and_notes"].legal_justification == {
        "basis": "unspecified",
        "note": "",
    }
    # approved subtypes still resolve to a real action, not a keep record
    assert by_subtype["tracked_changes"].action != "keep"


def test_operator_keep_records_structured_legal_justification():
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(
        res,
        "production",
        decisions={"comments_and_notes": "keep", "tracked_changes": "approve"},
        legal_justifications={
            "comments_and_notes": {
                "basis": "privilege",
                "note": "Attorney-client negotiation comments withheld.",
            }
        },
    )
    assert plan.actions["comments_and_notes"]["legal_justification"] == {
        "basis": "privilege",
        "note": "Attorney-client negotiation comments withheld.",
    }

    _cleaned, records = apply_actions(data, plan)
    record = next(
        r for r in records
        if r.subtype == "comments_and_notes" and r.legal_justification is not None
    )
    assert record.to_dict()["legal_justification"] == {
        "basis": "privilege",
        "note": "Attorney-client negotiation comments withheld.",
    }


def test_policy_rejects_invalid_legal_justification_payloads():
    res = inspect_bytes(_load("spa.docx"), "spa.docx")
    with pytest.raises(PolicyError, match="unknown subtype"):
        plan_actions(
            res,
            "production",
            legal_justifications={"made_up": {"basis": "privilege"}},
        )
    with pytest.raises(PolicyError, match="must be one of"):
        plan_actions(
            res,
            "production",
            legal_justifications={"comments_and_notes": {"basis": "because_i_said_so"}},
        )


def test_apply_sharing_docx_strips_everything():
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(res, "external_sharing")
    cleaned, _records = apply_actions(data, plan)

    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        names = zf.namelist()
        doc = zf.read("word/document.xml").decode("utf-8")
    assert "word/comments.xml" not in names
    assert "<w:delText>" not in doc and "<w:ins>" not in doc
    deleted_clause = "DELETED CLAUSE about the side payment."
    assert deleted_clause not in doc


def test_apply_text_privacy_equals_layer_a():
    raw = "Invoice\u200b total: see attachment\n"
    res = inspect_bytes(raw.encode(), "invoice.txt")
    plan = plan_actions(res, "privacy_only")
    cleaned, records = apply_actions(raw.encode(), plan)
    assert b"\xe2\x80\x8b" not in cleaned
    assert "Invoice total" in cleaned.decode()
    assert any(r.subtype == "layer_a_body" for r in records)


def test_apply_signed_pdf_still_refuses_without_attest_then_executes_with():
    data = _load("signed.pdf")
    res = inspect_bytes(data, "signed.pdf")
    with pytest.raises(PolicyError):
        plan_actions(res, "external_sharing")
    plan = plan_actions(res, "external_sharing", signature_break_attestation=True)
    cleaned, _records = apply_actions(data, plan)
    assert b"(Attorney A)" not in cleaned


def test_apply_incremental_pdf_under_sharing_rebuilds():
    data = _load("incremental.pdf")
    res = inspect_bytes(data, "incremental.pdf")
    plan = plan_actions(res, "external_sharing")
    cleaned, _records = apply_actions(data, plan)
    assert b"(Attorney A)" not in cleaned
    assert b"/Author (Attorney A)" not in cleaned


def test_apply_jpeg_privacy_gps_only_keeps_rest():
    data = _load("gps.jpg")
    res = inspect_bytes(data, "gps.jpg")
    plan = plan_actions(res, "privacy_only")
    cleaned, records = apply_actions(data, plan)
    assert cleaned.startswith(b"\xff\xd8")
    gps_gone = b"\x88\x25" not in cleaned and b"Trolltinden" not in cleaned
    assert gps_gone
    assert any(r.action == "strip" for r in records)
