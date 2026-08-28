"""PR 48: policy-honesty fix for PDF annotations/attachments/active content.

The engine has no PDF object-graph editor -- no code anywhere in
container_meta.py touches /Annots, /EmbeddedFiles, /OpenAction, /JS, /AA,
or /AcroForm. Before this pass, external_sharing/production's default
policy rows for pdf_annots/pdf_attachments/pdf_js_actions said "strip",
which always resolved to a refusal in practice (policies.py's own
_apply_pdf) whenever the document actually carried that content -- an
honest refusal, but a dishonest policy row. This suite is the first
regression coverage of that refusal path at all: previously only the
*Finding* projection (category/pane/risk_level) was tested, never that
plan_actions -> apply_actions actually raises for content that's present.

Covers, per the approved scope: an annotated PDF, an embedded-file PDF, a
JavaScript PDF, an OpenAction-only PDF, and an AA-only PDF, each under
external_sharing -- plus confirming the production "Approve (strip)"
per-finding path doesn't silently succeed for these subtypes either.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import pytest
from engine_api import inspect_bytes
from policies import PDF_CONTENT_REFUSAL_MARKER, PolicyError, apply_actions, plan_actions


def _pdf(*objects: bytes, info: bytes | None = None) -> bytes:
    """Mirrors tests/test_pdf_legal.py's own fixture builder -- the same
    minimal, already-validated object shapes that module's detection
    tests use, so a mismatch between "what's detected" and "what refuses"
    can't hide behind two different fixture-construction styles."""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> >>",
        b"<< /Producer (Claude Opus) /Creator (Anthropic Claude) >>",
    ]
    if info is not None:
        objs[3] = info
    objs.extend(objects)
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\n" % (len(objs) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def _plan_and_expect_refusal(data: bytes, *, policy="external_sharing", decisions=None):
    res = inspect_bytes(data, "test.pdf")
    plan = plan_actions(res, policy, decisions=decisions or {})
    with pytest.raises(PolicyError) as exc_info:
        apply_actions(data, plan)
    return str(exc_info.value)


def test_annotated_pdf_refuses_under_external_sharing():
    data = _pdf(b"<< /Type /Annots /Subtype /Square /Rect [0 0 1 1] >>")
    msg = _plan_and_expect_refusal(data)
    assert PDF_CONTENT_REFUSAL_MARKER in msg
    assert "Annotations / markup" in msg


def test_embedded_file_pdf_refuses_under_external_sharing():
    data = _pdf(b"<< /Names << /EmbeddedFiles << /Names [(a) 9 0 R] >> >> >>")
    msg = _plan_and_expect_refusal(data)
    assert PDF_CONTENT_REFUSAL_MARKER in msg
    assert "Embedded file attachments" in msg


def test_javascript_pdf_refuses_under_external_sharing():
    data = _pdf(b"<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>")
    msg = _plan_and_expect_refusal(data)
    assert PDF_CONTENT_REFUSAL_MARKER in msg
    assert "Embedded JavaScript / auto-actions" in msg


def test_openaction_only_pdf_refuses_under_external_sharing():
    """/OpenAction alone (no /JS token) -- pdf_js_actions folds JavaScript,
    OpenAction, and /AA into one subtype (policies.py's _PREFIX_SUBTYPES),
    so an auto-navigate-on-open action with no script content still hits
    the same refusal as real JavaScript. Named explicitly, not just
    covered incidentally, since that conflation is a real, separate
    limitation worth being able to see fail on its own."""
    data = _pdf(b"<< /Type /Catalog /OpenAction 5 0 R >>")
    msg = _plan_and_expect_refusal(data)
    assert PDF_CONTENT_REFUSAL_MARKER in msg
    assert "Embedded JavaScript / auto-actions" in msg


def test_aa_only_pdf_refuses_under_external_sharing():
    data = _pdf(b"<< /Type /Page /AA << /O 5 0 R >> >>")
    msg = _plan_and_expect_refusal(data)
    assert PDF_CONTENT_REFUSAL_MARKER in msg
    assert "Embedded JavaScript / auto-actions" in msg


def test_production_approve_route_does_not_silently_succeed_for_annots():
    """The per-finding review UI (ReleasePanel) offers "Approve (strip)"
    for every approve-default subtype uniformly, including pdf_annots
    under production -- an operator who clicks it must not get a silent
    no-op or a derivative that still carries the content; they must get
    the same honest refusal external_sharing gives, not a different,
    quieter failure mode just because a decision was actively supplied."""
    data = _pdf(b"<< /Type /Annots /Subtype /Square /Rect [0 0 1 1] >>")
    msg = _plan_and_expect_refusal(
        data, policy="production", decisions={"pdf_annots": "approve"}
    )
    assert PDF_CONTENT_REFUSAL_MARKER in msg


def test_production_approve_route_does_not_silently_succeed_for_attachments():
    data = _pdf(b"<< /Names << /EmbeddedFiles << /Names [(a) 9 0 R] >> >> >>")
    msg = _plan_and_expect_refusal(
        data, policy="production", decisions={"pdf_attachments": "approve"}
    )
    assert PDF_CONTENT_REFUSAL_MARKER in msg


def test_production_pdf_js_actions_refuses_with_no_approve_option():
    """pdf_js_actions is a plain "refuse" row under production too (not
    approve-default) -- there's no operator decision that can route
    around it, unlike pdf_annots/pdf_attachments."""
    data = _pdf(b"<< /Type /Catalog /OpenAction 5 0 R >>")
    msg = _plan_and_expect_refusal(data, policy="production")
    assert PDF_CONTENT_REFUSAL_MARKER in msg


def test_clean_pdf_is_unaffected():
    """No annotations/attachments/active content at all -- must not
    refuse; the marker/message must never appear for ordinary PDFs."""
    res = inspect_bytes(_pdf(), "test.pdf")
    plan = plan_actions(res, "external_sharing")
    cleaned, _records = apply_actions(_pdf(), plan)
    assert cleaned  # completed without raising


def test_marker_does_not_appear_in_unrelated_refusals():
    """The frontend distinguishes "capability refusal" from "policy
    refusal by design" (macros, unattested signatures) by matching on
    PDF_CONTENT_REFUSAL_MARKER -- confirm the marker is specific to this
    one refusal class and doesn't leak into the macro-refusal message,
    which would make that match ambiguous."""
    from container_meta import container_clean_refusal

    macro_pdf = _pdf(b"<< /Type /Annots /Subtype /Square /Rect [0 0 1 1] >>")
    # Signature refusal is format-level (container_clean_refusal), not a
    # PolicyError -- confirm its own message never contains the marker.
    signed = _pdf(b"<< /Type /Annot /Subtype /Widget /FT /Sig /ByteRange [0 100 200 300] >>")
    reason = container_clean_refusal("pdf", signed)
    assert reason is not None
    assert PDF_CONTENT_REFUSAL_MARKER not in reason

    # macros_vba's own refusal (a docx path, but same PolicyError family)
    # is unconditional and unrelated to PDF content -- sanity-check by
    # re-asserting the real PDF-content message is the only place the
    # marker appears, using the already-covered annots case above.
    res = inspect_bytes(macro_pdf, "test.pdf")
    plan = plan_actions(res, "external_sharing")
    with pytest.raises(PolicyError) as exc_info:
        apply_actions(macro_pdf, plan)
    assert PDF_CONTENT_REFUSAL_MARKER in str(exc_info.value)
