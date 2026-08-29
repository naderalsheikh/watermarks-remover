"""tools/counselclear_verify_release_packet.py -- the offline release-
packet verifier (PR 37). Unit tests build synthetic packets directly
(no live server needed to exercise the verifier's own logic); a
separate end-to-end check lives in tests/test_app.py, confirming the
real job_bundle route actually produces a release_packet.json a real
run of this verifier accepts.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import counselclear_verify_release_packet as verifier


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _packet_files(
    *,
    matter_id: str = "MAT1",
    document_id: str = "DOC1",
    job_id: str = "JOB1",
    policy_id: str = "external_sharing",
    status: str = "done",
    derivative_bytes: bytes = b"fake derivative bytes",
    derivative_filename: str = "out.docx",
    anchor_type: str = "none",
    release_id: str | None = None,
    original_sha256: str = "0" * 64,
) -> dict[str, bytes]:
    """A self-consistent set of packet files, hashes computed for real --
    the same shape job_bundle produces, built independently here so the
    test isn't just checking the verifier agrees with itself."""
    manifest_json = json.dumps(
        {
            "policy": {"id": policy_id, "version": 1},
            "derivative": {"sha256": _sha256(derivative_bytes), "filename": derivative_filename},
        },
        sort_keys=True,
    ).encode()
    report_json = json.dumps({"verification": {"pass": True, "checks": []}}, sort_keys=True).encode()
    cert_html = (
        f"<!doctype html><html><body>Job ID: <code>{job_id}</code> "
        f"Matter: X (<code>{matter_id}</code>) "
        f"Document ID: <code>{document_id}</code> "
        f"status: <span class=\"status\">{status}</span></body></html>"
    ).encode()
    readme_txt = b"CounselClear release packet\n"

    release_packet = {
        "spec_version": "1.0",
        "packet_id": job_id,
        "release_id": release_id,
        "matter_id": matter_id,
        "document_id": document_id,
        "job_id": job_id,
        "original_sha256": original_sha256,
        "kind": "sanitize",
        "status": status,
        "policy": {"id": policy_id, "version": 1, "digest": None},
        "hashes": {
            "derivative": {"filename": derivative_filename, "sha256": _sha256(derivative_bytes)},
            "manifest_json_sha256": _sha256(manifest_json),
            "report_json_sha256": _sha256(report_json),
            "certificate_html_sha256": _sha256(cert_html),
            "readme_txt_sha256": _sha256(readme_txt),
        },
        "audit_refs": {"bundle_download_seq": 1, "certificate_issued_seq": 2},
        "limitations": [],
        "generated_at": "2026-08-27T00:00:00+00:00",
        "generated_by": "operator",
        "anchor": {"type": anchor_type, "digest": None, "reference": None},
    }
    return {
        "manifest.json": manifest_json,
        "report.json": report_json,
        "certificate.html": cert_html,
        "README.txt": readme_txt,
        f"derivative/{derivative_filename}": derivative_bytes,
        "release_packet.json": json.dumps(release_packet, indent=2, sort_keys=True).encode(),
    }


def _write_zip(tmp_path: Path, files: dict[str, bytes], name: str = "packet.zip") -> Path:
    out = tmp_path / name
    with zipfile.ZipFile(out, "w") as zf:
        for arcname, data in files.items():
            zf.writestr(arcname, data)
    return out


def _write_dir(tmp_path: Path, files: dict[str, bytes], name: str = "packet") -> Path:
    out = tmp_path / name
    for arcname, data in files.items():
        p = out / arcname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return out


# --- valid packet ------------------------------------------------------------


def test_valid_packet_verifies_from_zip(tmp_path):
    zip_path = _write_zip(tmp_path, _packet_files())
    report = verifier.verify_release_packet(zip_path)
    assert report.valid, report.to_text()
    assert report.schema_ok
    assert all(fc.status == "match" for fc in report.file_checks)
    # original_sha256 is declared but no original/ member is included in
    # this fixture (include_original wasn't used) -- "unavailable" is the
    # correct, non-failing status for that, not "match".
    assert all(cc.status in ("match", "unavailable") for cc in report.cross_checks)
    original_check = next(cc for cc in report.cross_checks if cc.name.startswith("original_sha256"))
    assert original_check.status == "unavailable"


def test_valid_packet_verifies_from_extracted_directory(tmp_path):
    dir_path = _write_dir(tmp_path, _packet_files())
    report = verifier.verify_release_packet(dir_path)
    assert report.valid, report.to_text()


# --- derivative layout: nested / flat / ambiguous ------------------------------


def test_valid_nested_derivative_passes(tmp_path):
    """derivative/<name> -- the canonical layout every zip (and any
    directory someone extracted a zip into with a tool that preserves
    its structure) uses."""
    files = _packet_files()  # _packet_files already keys the derivative as "derivative/<name>"
    assert "derivative/out.docx" in files
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert report.valid, report.to_text()
    deriv_check = next(fc for fc in report.file_checks if fc.name == "derivative")
    assert deriv_check.status == "match"


def test_valid_flat_derivative_passes(tmp_path):
    """<name> at the top level -- the Airlock CLI's own deliberate
    output convention (PR 34/37): easy to grab, not nested."""
    files = _packet_files()
    derivative_bytes = files.pop("derivative/out.docx")
    files["out.docx"] = derivative_bytes
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert report.valid, report.to_text()
    deriv_check = next(fc for fc in report.file_checks if fc.name == "derivative")
    assert deriv_check.status == "match"


def test_both_nested_and_flat_derivative_present_fails_as_ambiguous(tmp_path):
    """Both layouts present at once must never be silently resolved by
    preferring one -- even when the first candidate found happens to
    match the declared hash, which is exactly the case that would let a
    second, unexplained copy slip past a verifier that just took the
    first match."""
    files = _packet_files()
    nested_bytes = files["derivative/out.docx"]
    # The flat copy matches the declared hash too (identical bytes) --
    # proving the failure is the ambiguity itself, not a hash mismatch
    # that would fail for an unrelated reason anyway.
    files["out.docx"] = nested_bytes
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    deriv_check = next(fc for fc in report.file_checks if fc.name == "derivative")
    assert deriv_check.status == "ambiguous"
    assert "derivative/out.docx" in deriv_check.detail
    assert "out.docx" in deriv_check.detail
    assert "ambiguous" in deriv_check.detail.lower()


def test_missing_derivative_still_fails(tmp_path):
    files = _packet_files()
    del files["derivative/out.docx"]
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    deriv_check = next(fc for fc in report.file_checks if fc.name == "derivative")
    assert deriv_check.status == "missing"


def test_tampered_derivative_still_fails(tmp_path):
    files = _packet_files()
    files["derivative/out.docx"] = files["derivative/out.docx"] + b"tampered"
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    deriv_check = next(fc for fc in report.file_checks if fc.name == "derivative")
    assert deriv_check.status == "mismatch"


# --- missing / modified file --------------------------------------------------


def test_missing_file_fails(tmp_path):
    files = _packet_files()
    del files["report.json"]
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    report_check = next(fc for fc in report.file_checks if fc.name == "report.json")
    assert report_check.status == "missing"


def test_modified_file_fails_with_hash_mismatch(tmp_path):
    files = _packet_files()
    files["certificate.html"] = files["certificate.html"] + b"<script>tampered</script>"
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    cert_check = next(fc for fc in report.file_checks if fc.name == "certificate.html")
    assert cert_check.status == "mismatch"
    # Everything else must still be reported independently as ok -- one
    # tampered file shouldn't make the report vague about which one.
    other_checks = [fc for fc in report.file_checks if fc.name != "certificate.html"]
    assert all(fc.status == "match" for fc in other_checks)


def test_missing_release_packet_json_fails_cleanly(tmp_path):
    files = _packet_files()
    del files["release_packet.json"]
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    assert not report.schema_ok
    assert any("release_packet.json" in e for e in report.errors)


# --- mismatched ids where cross-checkable -------------------------------------


def test_mismatched_policy_id_between_release_packet_and_manifest_fails(tmp_path):
    files = _packet_files()
    # Swap in a manifest.json whose policy.id disagrees with
    # release_packet.json's -- same derivative hash (so only the policy
    # cross-check trips, isolating what's being tested), rebuilding the
    # manifest hash so the file-level hash check still passes and the
    # failure is specifically the cross-check, not a hash mismatch.
    outer = json.loads(files["release_packet.json"])
    derivative_bytes = b"fake derivative bytes"
    bad_manifest = json.dumps(
        {
            "policy": {"id": "privacy_only", "version": 1},
            "derivative": {"sha256": _sha256(derivative_bytes), "filename": "out.docx"},
        },
        sort_keys=True,
    ).encode()
    files["manifest.json"] = bad_manifest
    outer["hashes"]["manifest_json_sha256"] = _sha256(bad_manifest)
    files["release_packet.json"] = json.dumps(outer, indent=2, sort_keys=True).encode()

    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    policy_check = next(cc for cc in report.cross_checks if cc.name.startswith("policy.id"))
    assert policy_check.status == "mismatch"


def test_certificate_content_no_longer_semantically_cross_checked(tmp_path):
    """PR 39: certificate.html is verified for integrity (its bytes match
    the declared hash) only -- never re-parsed for meaning. A certificate
    whose *content* is unrelated to this job (as if swapped in from a
    different one) but whose declared hash was updated to match that
    content -- i.e. it's internally self-consistent, just wrong -- still
    passes the certificate.html FILE check, since that check only proves
    "these bytes are what was declared", nothing about what the bytes
    say. This is the deliberate, documented tradeoff (see the module
    docstring's "Certificate verification" section): release_packet.json
    is the authoritative source of facts, not a grep over rendered HTML.
    """
    files = _packet_files(job_id="JOB1")
    files["certificate.html"] = b"<!doctype html><html><body>unrelated content</body></html>"
    outer = json.loads(files["release_packet.json"])
    outer["hashes"]["certificate_html_sha256"] = _sha256(files["certificate.html"])
    files["release_packet.json"] = json.dumps(outer, indent=2, sort_keys=True).encode()

    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    cert_check = next(fc for fc in report.file_checks if fc.name == "certificate.html")
    assert cert_check.status == "match"
    assert not any(cc.name.startswith("job_id") for cc in report.cross_checks)
    assert not any(cc.name.startswith("matter_id") for cc in report.cross_checks)


def test_missing_original_sha256_field_fails_schema(tmp_path):
    files = _packet_files()
    outer = json.loads(files["release_packet.json"])
    del outer["original_sha256"]
    files["release_packet.json"] = json.dumps(outer, indent=2, sort_keys=True).encode()
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    assert not report.schema_ok
    assert any("original_sha256" in e for e in report.errors)


def test_original_sha256_checked_against_included_original_file(tmp_path):
    original_bytes = b"the untouched original document bytes"
    files = _packet_files(original_sha256=_sha256(original_bytes))
    files["original/input.docx"] = original_bytes
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert report.valid, report.to_text()
    original_check = next(cc for cc in report.cross_checks if cc.name.startswith("original_sha256"))
    assert original_check.status == "match"


def test_tampered_included_original_file_fails(tmp_path):
    original_bytes = b"the untouched original document bytes"
    files = _packet_files(original_sha256=_sha256(original_bytes))
    files["original/input.docx"] = original_bytes + b"tampered"
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    original_check = next(cc for cc in report.cross_checks if cc.name.startswith("original_sha256"))
    assert original_check.status == "mismatch"


# --- top-line wording: legacy VALID/INVALID vs. Release-aware ------------------


def test_legacy_packet_with_no_release_id_keeps_valid_invalid_wording(tmp_path):
    dir_path = _write_dir(tmp_path, _packet_files(release_id=None))
    report = verifier.verify_release_packet(dir_path)
    assert report.release_id is None
    text = report.to_text()
    assert text.splitlines()[0] == "VALID"
    assert "INTERNALLY CONSISTENT" not in text


def test_release_aware_packet_uses_internally_consistent_wording_not_valid(tmp_path):
    """PR 39: a packet carrying release_id must never say VALID -- that
    reads too easily as "verified authentic", which this tool never
    claims. INTERNALLY CONSISTENT is the honest, narrower claim."""
    dir_path = _write_dir(tmp_path, _packet_files(release_id="REL1"))
    report = verifier.verify_release_packet(dir_path)
    assert report.release_id == "REL1"
    assert report.valid
    text = report.to_text()
    assert text.splitlines()[0] == "INTERNALLY CONSISTENT"
    assert "VALID" not in text.split("\n\n")[0]  # the top line itself, not e.g. "INVALID" as a substring


def test_release_aware_packet_reports_internally_inconsistent_when_invalid(tmp_path):
    files = _packet_files(release_id="REL1")
    files["certificate.html"] += b"tampered"
    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    assert report.to_text().splitlines()[0] == "INTERNALLY INCONSISTENT"


# --- unanchored notice ---------------------------------------------------------


def test_unanchored_packet_reports_the_limitation_explicitly(tmp_path):
    dir_path = _write_dir(tmp_path, _packet_files(anchor_type="none"))
    report = verifier.verify_release_packet(dir_path)
    assert report.valid
    assert report.anchor_type == "none"
    text = report.to_text()
    assert "NOT EXTERNALLY ANCHORED" in text
    assert "Externally anchored: no" in text
    # Forbidden-claims coverage lives in its own dedicated test below.


def test_forbidden_claim_words_never_appear_as_affirmative_claims(tmp_path):
    """Separate, unambiguous test for the forbidden-claims discipline
    (docs/release-packet-verification-and-anchoring-proposal.md §7):
    the verifier's own unanchored notice legitimately *names* these
    words to explicitly deny them ("not independently timestamped or
    unforgeable") -- the same negation pattern the certificate's own
    disclaimer already uses for "clean"/"safe" (PR 33). What must never
    appear is the affirmative claim -- "is unforgeable", "is court-proof"
    -- not the bare word inside a denial of it. Checks both a valid and
    an invalid report."""
    valid_report = verifier.verify_release_packet(_write_dir(tmp_path / "a", _packet_files()))
    files = _packet_files()
    files["certificate.html"] += b"x"
    invalid_report = verifier.verify_release_packet(_write_dir(tmp_path / "b", files))

    for report in (valid_report, invalid_report):
        text = report.to_text().lower()
        for claim in (
            "is unforgeable", "this is unforgeable",
            "is independently timestamped", "this is independently timestamped",
            "is court-proof", "this is court-proof",
            "is unimpeachable", "this is unimpeachable",
        ):
            assert claim not in text, f"affirmative claim {claim!r} must never appear in verifier output"
        # "verified" as a bare claim ("This packet is verified") must not
        # appear; "what was verified" (a section heading describing what
        # was *checked*, not an assertion of trust) is fine and expected.
        assert "this packet is verified" not in text
        assert "packet is verified" not in text


# --- verify_release_result(): the refused/failed-release artifact (PR 39) ------


def _release_result(
    *,
    release_id: str = "REL1",
    job_id: str = "JOB1",
    document_id: str = "DOC1",
    matter_id: str = "MAT1",
    status: str = "refused",
    policy_id: str = "external_sharing",
    reason: str = "plan refused: macro-enabled file",
    original_sha256: str = "0" * 64,
    cert_html: bytes = b"<!doctype html><html><body>certificate</body></html>",
    anchor_type: str = "none",
) -> dict:
    return {
        "spec_version": "1.0",
        "release_id": release_id,
        "job_id": job_id,
        "document_id": document_id,
        "matter_id": matter_id,
        "status": status,
        "policy_id": policy_id,
        "profile_id": "counterparty_deal_room",
        "recipient_type": "opposing_counsel",
        "recipient_name": "Jane Doe, Esq.",
        "purpose": "settlement negotiation",
        "intended_external": True,
        "reason": reason,
        "original_sha256": original_sha256,
        "created_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:00:05+00:00",
        "audit_refs": {"release_created_seq": 1, "release_terminal_seq": 2},
        "limitations": [f"job {status}: {reason}"],
        "certificate_html_sha256": _sha256(cert_html),
        "generated_at": "2026-08-27T00:00:05+00:00",
        "anchor": {"type": anchor_type, "digest": None, "reference": None},
    }


def test_release_result_verifies_standalone_with_no_certificate(tmp_path):
    """The minimum case: just release_result.json on its own, no sibling
    certificate.html saved next to it -- still verifies, since the
    certificate is optional to include (fetched separately)."""
    result_path = tmp_path / "release_result.json"
    result_path.write_text(json.dumps(_release_result(), indent=2, sort_keys=True))
    report = verifier.verify_release_result(result_path)
    assert report.valid, report.to_text()
    assert report.to_text().splitlines()[0] == "INTERNALLY CONSISTENT"
    cert_check = next((fc for fc in report.file_checks if fc.name == "certificate.html"), None)
    assert cert_check.status == "missing"  # informational, not a validity failure
    assert report.valid


def test_release_result_verifies_with_sibling_certificate(tmp_path):
    cert_html = b"<!doctype html><html><body>refusal certificate</body></html>"
    out = tmp_path / "out"
    out.mkdir()
    (out / "release_result.json").write_text(
        json.dumps(_release_result(cert_html=cert_html), indent=2, sort_keys=True)
    )
    (out / "certificate.html").write_bytes(cert_html)
    report = verifier.verify_release_result(out)
    assert report.valid, report.to_text()
    cert_check = next(fc for fc in report.file_checks if fc.name == "certificate.html")
    assert cert_check.status == "match"


def test_release_result_tampered_sibling_certificate_fails(tmp_path):
    cert_html = b"<!doctype html><html><body>refusal certificate</body></html>"
    out = tmp_path / "out"
    out.mkdir()
    (out / "release_result.json").write_text(
        json.dumps(_release_result(cert_html=cert_html), indent=2, sort_keys=True)
    )
    (out / "certificate.html").write_bytes(cert_html + b"tampered")
    report = verifier.verify_release_result(out)
    assert not report.valid
    cert_check = next(fc for fc in report.file_checks if fc.name == "certificate.html")
    assert cert_check.status == "mismatch"


def test_release_result_missing_required_field_fails_schema(tmp_path):
    result = _release_result()
    del result["reason"]
    result_path = tmp_path / "release_result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True))
    report = verifier.verify_release_result(result_path)
    assert not report.valid
    assert not report.schema_ok
    assert any("reason" in e for e in report.errors)


def test_release_result_always_reports_not_externally_anchored():
    text = verifier.ReleaseResultReport(
        valid=True, schema_ok=True, anchor_type="none",
    ).to_text()
    assert "NOT EXTERNALLY ANCHORED" in text
    assert text.splitlines()[0] == "INTERNALLY CONSISTENT"


def test_audit_refs_note_appears_for_both_report_types(tmp_path):
    """audit_refs' seq numbers are declared, not independently checkable
    offline -- this tool has no database access. Both report types must
    say so explicitly, not just the anchor status."""
    packet_report = verifier.verify_release_packet(_write_dir(tmp_path / "pkt", _packet_files()))
    assert "audit_refs cites seq numbers" in packet_report.to_text()
    assert "GET /v1/matters/{id}/audit" in packet_report.to_text()

    result_report = verifier.ReleaseResultReport(valid=True, schema_ok=True, anchor_type="none")
    assert "audit_refs cites seq numbers" in result_report.to_text()


def test_main_auto_detects_release_result_vs_release_packet(tmp_path, capsys):
    result_dir = tmp_path / "refused"
    result_dir.mkdir()
    (result_dir / "release_result.json").write_text(json.dumps(_release_result(), indent=2, sort_keys=True))
    rc = verifier.main([str(result_dir)])
    assert rc == 0
    assert "INTERNALLY CONSISTENT" in capsys.readouterr().out

    packet_dir = _write_dir(tmp_path / "done", _packet_files(release_id="REL2"))
    rc = verifier.main([str(packet_dir)])
    assert rc == 0
    assert "INTERNALLY CONSISTENT" in capsys.readouterr().out


# --- verify_release_packet_and_result(): both artifacts present, cross-checked --


def _matching_result_for(packet: dict, files: dict) -> dict:
    """A release_result.json built to agree with `packet` on every field
    verify_release_packet_and_result compares -- used as the "agree"
    baseline; individual tests below mutate one field to force a
    disagreement."""
    return {
        "spec_version": "1.0",
        "release_id": packet["release_id"],
        "job_id": packet["job_id"],
        "document_id": packet["document_id"],
        "matter_id": packet["matter_id"],
        "status": packet["status"],
        "policy_id": packet["policy"]["id"],
        "profile_id": "counterparty_deal_room",
        "recipient_type": "opposing_counsel",
        "recipient_name": "",
        "purpose": "",
        "intended_external": True,
        "reason": "",
        "original_sha256": packet["original_sha256"],
        "created_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:00:05+00:00",
        "audit_refs": {"release_created_seq": 1, "release_terminal_seq": 2},
        "limitations": packet["limitations"],
        "certificate_html_sha256": _sha256(files["certificate.html"]),
        "generated_at": "2026-08-27T00:00:05+00:00",
        "anchor": {"type": "none", "digest": None, "reference": None},
    }


def test_verify_both_artifacts_agree_when_consistent(tmp_path):
    files = _packet_files(
        release_id="REL1", job_id="JOB1", document_id="DOC1", matter_id="MAT1",
        status="done", policy_id="external_sharing",
    )
    out = _write_dir(tmp_path, files)
    packet = json.loads((out / "release_packet.json").read_text())
    result = _matching_result_for(packet, files)
    (out / "release_result.json").write_text(json.dumps(result, indent=2, sort_keys=True))

    report = verifier.verify_release_packet_and_result(out)
    assert report.valid, report.to_text()
    assert report.packet.valid
    assert report.result.valid
    assert all(cc.status != "mismatch" for cc in report.agreement)
    matched = {cc.name for cc in report.agreement if cc.status == "match"}
    for field_name in ("release_id", "job_id", "document_id", "matter_id", "status", "original_sha256", "limitations"):
        assert f"{field_name} (packet vs result)" in matched, f"{field_name} should have matched, not been skipped"
    assert "policy_id (packet vs result)" in matched
    text = report.to_text()
    assert "INTERNALLY CONSISTENT" in text.splitlines()[0]
    assert "release_packet.json" in text
    assert "release_result.json" in text


def test_verify_both_artifacts_fails_loudly_on_status_disagreement(tmp_path):
    files = _packet_files(
        release_id="REL1", job_id="JOB1", document_id="DOC1", matter_id="MAT1",
        status="done", policy_id="external_sharing",
    )
    out = _write_dir(tmp_path, files)
    packet = json.loads((out / "release_packet.json").read_text())
    result = _matching_result_for(packet, files)
    result["status"] = "refused"  # disagrees with the packet's "done"
    (out / "release_result.json").write_text(json.dumps(result, indent=2, sort_keys=True))

    report = verifier.verify_release_packet_and_result(out)
    assert not report.valid
    status_check = next(cc for cc in report.agreement if cc.name == "status (packet vs result)")
    assert status_check.status == "mismatch"
    assert "done" in status_check.detail
    assert "refused" in status_check.detail
    assert "INTERNALLY INCONSISTENT" in report.to_text().splitlines()[0]


def test_verify_both_artifacts_fails_loudly_on_release_id_disagreement(tmp_path):
    """The most consequential disagreement -- release_result.json
    describing a DIFFERENT release than the packet it's sitting next to
    (e.g. two files accidentally mixed from different runs)."""
    files = _packet_files(
        release_id="REL1", job_id="JOB1", document_id="DOC1", matter_id="MAT1", status="done",
    )
    out = _write_dir(tmp_path, files)
    packet = json.loads((out / "release_packet.json").read_text())
    result = _matching_result_for(packet, files)
    result["release_id"] = "REL-DIFFERENT"
    (out / "release_result.json").write_text(json.dumps(result, indent=2, sort_keys=True))

    report = verifier.verify_release_packet_and_result(out)
    assert not report.valid
    release_id_check = next(cc for cc in report.agreement if cc.name == "release_id (packet vs result)")
    assert release_id_check.status == "mismatch"


def test_verify_both_artifacts_profile_id_unavailable_for_legacy_packet(tmp_path):
    """_packet_files() builds a legacy-shaped packet with no "release"
    sub-object -- profile_id has nothing to compare against, which must
    report "unavailable", not "mismatch", and must not fail the whole
    report on its own."""
    files = _packet_files(release_id="REL1", status="done")
    out = _write_dir(tmp_path, files)
    packet = json.loads((out / "release_packet.json").read_text())
    assert "release" not in packet  # confirms the fixture really is legacy-shaped here
    result = _matching_result_for(packet, files)
    (out / "release_result.json").write_text(json.dumps(result, indent=2, sort_keys=True))

    report = verifier.verify_release_packet_and_result(out)
    assert report.valid, report.to_text()
    profile_check = next(cc for cc in report.agreement if cc.name == "profile_id (packet vs result)")
    assert profile_check.status == "unavailable"


def test_main_verifies_both_artifacts_when_both_present(tmp_path, capsys):
    files = _packet_files(release_id="REL1", status="done")
    out = _write_dir(tmp_path, files)
    packet = json.loads((out / "release_packet.json").read_text())
    result = _matching_result_for(packet, files)
    (out / "release_result.json").write_text(json.dumps(result, indent=2, sort_keys=True))

    rc = verifier.main([str(out)])
    assert rc == 0
    text = capsys.readouterr().out
    assert "Both release_packet.json and release_result.json are present" in text
    assert "Agreement between release_packet.json and release_result.json" in text


# --- doctrine guard: no engine/app dependency -----------------------------------


def test_verifier_never_imports_the_engine_or_app_internals():
    src = (TOOLS / "counselclear_verify_release_packet.py").read_text()
    code = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
    for banned in (
        "engine_api", "clean_to_bundle", "inspect_bytes", "import policies",
        "import sqlalchemy", "from sqlalchemy", "import fastapi", "from fastapi",
        "from app.", "import app.", "from app import",
        "import requests", "import urllib", "import socket", "import http.client",
    ):
        assert banned not in code, f"counselclear_verify_release_packet.py must not reference {banned}"
