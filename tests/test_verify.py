"""PR 13 — verify_derivative gates and the verify_file CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from engine_api import inspect_bytes
from policies import apply_actions, plan_actions
from verify import verify_derivative, visible_projection

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _plan_and_apply(data: bytes, name: str, policy: str):
    res = inspect_bytes(data, name)
    plan = plan_actions(res, policy)
    cleaned, _records = apply_actions(data, plan)
    return plan, cleaned


def test_privacy_text_passes_gate():
    data = "Invoice\u200b total\n".encode()
    plan, cleaned = _plan_and_apply(data, "invoice.txt", "privacy_only")
    report = verify_derivative(data, cleaned, plan)
    assert report["pass"] is True
    names = {c["name"] for c in report["checks"]}
    assert "privacy_body_unchanged" in names
    assert report["hashes"]["derivative_sha256"] is not None


def test_tampered_visible_text_fails_body_check():
    data = "Invoice\u200b total\n".encode()
    res = inspect_bytes(data, "invoice.txt")
    plan = plan_actions(res, "privacy_only")
    # attacker edits visible text and keeps the ZWSP stripped to fake hygiene
    tampered = b"Invoice total CHANGED\n"
    report = verify_derivative(data, tampered, plan)
    body = [c for c in report["checks"] if c["name"] == "privacy_body_unchanged"]
    assert body and body[0]["pass"] is False
    assert report["pass"] is False


def test_visible_projection_strips_invisible_only():
    assert visible_projection("a\u200b\u2060b\ufeffc") == "abc"
    assert visible_projection("plain") == "plain"


def test_sharing_docx_comments_gone_and_inventory_ok():
    data = _load("spa.docx")
    plan, cleaned = _plan_and_apply(data, "spa.docx", "external_sharing")
    report = verify_derivative(data, cleaned, plan)
    gone = next(c for c in report["checks"] if c["name"] == "reinspect_targeted_gone")
    assert gone["pass"] is True
    inv = next(c for c in report["checks"] if c["name"] == "part_inventory")
    assert inv["pass"] is True
    assert "comments" in inv["detail"]
    assert report["pass"] is True


def test_added_part_fails_inventory():
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(res, "external_sharing")
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(
        buf, "w", zipfile.ZIP_DEFLATED
    ) as zout:
        for info in zin.infolist():
            zout.writestr(info, zin.read(info.filename))
        zout.writestr("word/surprise.xml", "<x/>")
    report = verify_derivative(data, buf.getvalue(), plan)
    inv = next(c for c in report["checks"] if c["name"] == "part_inventory")
    assert inv["pass"] is False
    assert "surprise.xml" in inv["detail"]


def test_pdf_page_counts_recorded_with_delta_expected():
    data = _load("incremental.pdf")
    plan, cleaned = _plan_and_apply(data, "incremental.pdf", "external_sharing")
    report = verify_derivative(data, cleaned, plan)
    if report["counts"].get("page_count_original") is not None:
        assert report["page_count_delta_expected"] is True
        assert report["pass"] is True


def _zip(names: dict[str, str]) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, content in names.items():
            zf.writestr(n, content)
    return buf.getvalue()


def test_evidence_preservation_fails_on_any_dropped_part():
    from policies import ActionPlan

    original = _zip({"word/document.xml": "<a/>", "word/comments.xml": "<c/>"})
    derivative = _zip({"word/document.xml": "<a/>"})  # comments.xml dropped

    # A comments.xml drop is allowlisted under external_sharing, but
    # evidence_preservation/privacy_only promise an IDENTICAL part inventory
    # — no drop is acceptable, allowlisted or not.
    plan = ActionPlan(
        policy_id="evidence_preservation", source_sha256="0" * 64, kind="container", actions={}
    )
    report = verify_derivative(original, derivative, plan, name="input.docx")
    inv = next(c for c in report["checks"] if c["name"] == "part_inventory")
    assert inv["pass"] is False, inv["detail"]
    assert report["pass"] is False


def test_part_inventory_allowlist_is_case_insensitive_and_covers_identity_parts():
    from policies import ActionPlan

    # Real comment-identity parts container_meta drops alongside comments.xml
    # under external_sharing — mixed-case (threadedComments) and without the
    # literal substring "comments" at all (people.xml, commentAuthors.xml).
    original = _zip({
        "word/document.xml": "<a/>",
        "word/comments.xml": "<c/>",
        "word/people.xml": "<p/>",
        "xl/threadedComments/threadedComment1.xml": "<t/>",
        "ppt/commentAuthors.xml": "<ca/>",
    })
    derivative = _zip({"word/document.xml": "<a/>"})

    plan = ActionPlan(
        policy_id="external_sharing", source_sha256="0" * 64, kind="container", actions={}
    )
    report = verify_derivative(original, derivative, plan, name="input.docx")
    inv = next(c for c in report["checks"] if c["name"] == "part_inventory")
    assert inv["pass"] is True, inv["detail"]


def test_part_inventory_still_rejects_non_allowlisted_drop():
    from policies import ActionPlan

    original = _zip({"word/document.xml": "<a/>", "word/settings.xml": "<s/>"})
    derivative = _zip({"word/document.xml": "<a/>"})  # settings.xml: not allowlisted

    plan = ActionPlan(
        policy_id="external_sharing", source_sha256="0" * 64, kind="container", actions={}
    )
    report = verify_derivative(original, derivative, plan, name="input.docx")
    inv = next(c for c in report["checks"] if c["name"] == "part_inventory")
    assert inv["pass"] is False


def test_markdown_reinspect_uses_name_to_catch_residual_watermark():
    # Without threading a real name/extension through, the re-inspect used
    # to classify markdown as "unknown" (no magic-byte fallback), so a
    # cleaner that failed to strip the mark would still pass verification.
    zwsp = chr(0x200B)
    original = f"Hello{zwsp}World\n".encode()
    broken_derivative = original  # simulated: cleaner did nothing

    res = inspect_bytes(original, "notes.md")
    plan = plan_actions(res, "external_sharing")
    report = verify_derivative(original, broken_derivative, plan, name="notes.md")
    gone = next(c for c in report["checks"] if c["name"] == "reinspect_targeted_gone")
    assert gone["pass"] is False, gone["detail"]
    assert report["pass"] is False


def test_corrupt_zip_fails_format_check():
    data = _load("spa.docx")
    res = inspect_bytes(data, "spa.docx")
    plan = plan_actions(res, "external_sharing")
    report = verify_derivative(data, b"PK\x03\x04garbage", plan)
    fmt = next(c for c in report["checks"] if c["name"] == "format_valid")
    assert fmt["pass"] is False
    assert report["pass"] is False


def test_cli_exit_codes(tmp_path):
    src = FIXTURES / "spa.txt"
    out_dir = tmp_path / "b"
    from engine_api import clean_to_bundle

    result = clean_to_bundle(src, out_dir)
    deriv = Path(result["derivative"])

    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "verify_file.py"), str(src), str(deriv),
         "--policy", "external_sharing"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["pass"] is True

    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"totally unrelated bytes\n")
    proc2 = subprocess.run(
        [sys.executable, str(SCRIPTS / "verify_file.py"), str(src), str(bad),
         "--policy", "privacy_only"],
        capture_output=True, text=True, check=False,
    )
    assert proc2.returncode == 1

    missing = tmp_path / "missing.bin"
    proc3 = subprocess.run(
        [sys.executable, str(SCRIPTS / "verify_file.py"), str(missing), str(deriv)],
        capture_output=True, text=True, check=False,
    )
    assert proc3.returncode == 2
