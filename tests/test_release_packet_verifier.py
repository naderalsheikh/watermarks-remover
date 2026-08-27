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
        "matter_id": matter_id,
        "document_id": document_id,
        "job_id": job_id,
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
    assert all(cc.status == "match" for cc in report.cross_checks)


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


def test_certificate_not_mentioning_job_id_fails_cross_check(tmp_path):
    files = _packet_files(job_id="JOB1")
    # A certificate that doesn't actually mention this job's id -- as if
    # it were swapped in from a different job's packet.
    files["certificate.html"] = b"<!doctype html><html><body>unrelated content</body></html>"
    outer = json.loads(files["release_packet.json"])
    outer["hashes"]["certificate_html_sha256"] = _sha256(files["certificate.html"])
    files["release_packet.json"] = json.dumps(outer, indent=2, sort_keys=True).encode()

    dir_path = _write_dir(tmp_path, files)
    report = verifier.verify_release_packet(dir_path)
    assert not report.valid
    job_id_check = next(cc for cc in report.cross_checks if cc.name.startswith("job_id"))
    assert job_id_check.status == "mismatch"


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
