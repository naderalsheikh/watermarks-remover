"""PR 13 — verify_derivative gates and the verify_file CLI."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import zipfile
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


def test_docprops_custom_xml_drop_passes_inventory_under_external_sharing():
    """Regression: a real DOCX carrying docProps/custom.xml (custom document
    properties -- e.g. a firm's "Matter Number" field, distinct from the
    customXml/*.xml *data storage* tree) used to fail part_inventory under
    external_sharing/production. container_meta.py's drop_custom_xml flag
    (set from policy custom_xml == "strip") deliberately drops this part
    the same way it drops customXml/ trees -- but verify.py's allowlist
    fragment "customxml" doesn't match "docprops/custom.xml" (the literal
    "." between "custom" and "xml" breaks the substring match), so the
    drop was flagged as an unexplained part loss and the release failed
    with "verification failed: part_inventory" for a document doing
    exactly what the policy intended."""
    content_types = (
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        "<Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/>"
        "<Override PartName='/docProps/custom.xml' ContentType='application/vnd.openxmlformats-officedocument.custom-properties+xml'/>"
        "</Types>"
    )
    custom_props = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
        '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Matter Number">'
        "<vt:lpwstr>2026-CV-00456</vt:lpwstr></property></Properties>"
    )
    data = _zip(
        {
            "[Content_Types].xml": content_types,
            "word/document.xml": (
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>Trust terms.</w:t></w:r></w:p></w:body></w:document>"
            ),
            "docProps/custom.xml": custom_props,
        }
    )
    res = inspect_bytes(data, "trust.docx")
    plan = plan_actions(res, "external_sharing")
    cleaned, _records = apply_actions(data, plan)

    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        names = set(zf.namelist())
    assert "docProps/custom.xml" not in names  # the drop this policy intends

    report = verify_derivative(data, cleaned, plan, name="trust.docx")
    inv = next(c for c in report["checks"] if c["name"] == "part_inventory")
    assert inv["pass"] is True, inv["detail"]
    assert "docProps/custom.xml" in inv["detail"]
    assert report["pass"] is True


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


# --- Layer A body / non-body split -------------------------------------------

def _docx_with_zwsp(*, header: bool = False, body: bool = False) -> bytes:
    """spa.docx plus a zero-width space in the chosen part(s)."""
    src = (FIXTURES / "spa.docx").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(src)) as zin, zipfile.ZipFile(
        buf, "w", zipfile.ZIP_DEFLATED
    ) as zout:
        for info in zin.infolist():
            if info.filename == "word/header1.xml":
                continue
            raw = zin.read(info.filename)
            if body and info.filename == "word/document.xml":
                raw = raw.replace(b"</w:t>", "​</w:t>".encode(), 1)
            zout.writestr(info, raw)
        if header:
            zout.writestr(
                "word/header1.xml",
                '<?xml version="1.0"?><w:hdr xmlns:w="http://schemas.openxmlformats.org'
                '/wordprocessingml/2006/main"><w:p><w:r><w:t>PRIVILEGED​</w:t>'
                "</w:r></w:p></w:hdr>",
            )
    return buf.getvalue()


def test_layer_a_hits_carry_part_scope():
    data = _docx_with_zwsp(header=True)
    hits = inspect_bytes(data, "h.docx").report["layer_a_hits"]
    assert hits, "expected a Layer A hit in the header"
    assert all("body" in h and "part" in h for h in hits)
    assert any(h["part"] == "word/header1.xml" and h["body"] is False for h in hits)


def test_header_only_invisible_is_non_body_and_does_not_fail_the_gate():
    """The composition rule deliberately leaves kept headers alone under
    external_sharing. Classifying that hit as layer_a_body made verify fail a
    job that behaved exactly as designed."""
    data = _docx_with_zwsp(header=True)
    res = inspect_bytes(data, "h.docx")
    subs = {f.subtype for f in res.findings if f.subtype.startswith("layer_a")}
    assert subs == {"layer_a_non_body"}

    plan = plan_actions(res, "external_sharing")
    cleaned, _ = apply_actions(data, plan)
    report = verify_derivative(data, cleaned, plan, name="h.docx")
    assert report["pass"] is True, [c for c in report["checks"] if not c["pass"]]


def test_body_and_header_invisibles_split_into_both_subtypes():
    data = _docx_with_zwsp(header=True, body=True)
    res = inspect_bytes(data, "hb.docx")
    subs = {f.subtype for f in res.findings if f.subtype.startswith("layer_a")}
    assert subs == {"layer_a_body", "layer_a_non_body"}

    plan = plan_actions(res, "external_sharing")
    cleaned, _ = apply_actions(data, plan)
    assert verify_derivative(data, cleaned, plan, name="hb.docx")["pass"] is True


def test_unsanitized_body_invisible_still_fails_the_gate():
    """The split must not blunt the gate: real body residue still fails."""
    data = _docx_with_zwsp(body=True)
    res = inspect_bytes(data, "b.docx")
    plan = plan_actions(res, "external_sharing")
    # a "derivative" that sanitized nothing
    report = verify_derivative(data, data, plan, name="b.docx")
    assert report["pass"] is False
    gone = next(c for c in report["checks"] if c["name"] == "reinspect_targeted_gone")
    assert "layer_a_body" in gone["detail"]


def test_qpdf_check_rejects_a_damaged_pdf():
    """format_valid on a PDF is structural now, not just magic bytes."""
    from verify import _qpdf_check

    good = (FIXTURES / "incremental.pdf").read_bytes()
    ok, detail = _qpdf_check(good)
    assert ok is True, detail
    bad_ok, bad_detail = _qpdf_check(good[:120])
    # degrades to True only when qpdf is absent; otherwise it must reject
    import shutil as _shutil

    if _shutil.which("qpdf"):
        assert bad_ok is False and "qpdf --check failed" in bad_detail


# --- Accept All deleted-text oracle ------------------------------------------


def test_accept_all_deleted_text_confirmed_absent_on_a_real_clean():
    data = _load("spa.docx")
    plan, cleaned = _plan_and_apply(data, "spa.docx", "external_sharing")
    report = verify_derivative(data, cleaned, plan, name="spa.docx")
    oracle = next(c for c in report["checks"] if c["name"] == "accept_all_deleted_text_absent")
    assert oracle["pass"] is True
    assert report["pass"] is True


def test_accept_all_deleted_text_oracle_catches_leaked_deleted_content():
    """The real failure mode this oracle exists for: deleted content that
    ends up mislabeled as ordinary visible text (e.g. a cleaner bug turning
    w:delText into w:t) looks structurally clean to a tag-based check —
    reinspect_targeted_gone would not necessarily notice — but the actual
    deleted words are still there for anyone reading the document."""
    import container_meta

    data = _load("spa.docx")
    deleted = container_meta.extract_docx_deleted_text(data)
    assert deleted, "fixture must carry a real deleted-text run for this test to mean anything"

    plan, cleaned = _plan_and_apply(data, "spa.docx", "external_sharing")
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zin, zipfile.ZipFile(
        buf, "w", zipfile.ZIP_DEFLATED
    ) as zout:
        for info in zin.infolist():
            zout.writestr(info, zin.read(info.filename))
        zout.writestr(
            "word/injected.xml",
            '<?xml version="1.0"?><w:sneaky '
            'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:t>{deleted[0]}</w:t></w:sneaky>",
        )
    report = verify_derivative(data, buf.getvalue(), plan, name="spa.docx")
    oracle = next(c for c in report["checks"] if c["name"] == "accept_all_deleted_text_absent")
    assert oracle["pass"] is False
    assert report["pass"] is False
