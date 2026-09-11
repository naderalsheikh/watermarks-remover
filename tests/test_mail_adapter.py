"""Mail attachment adapter (M1) with the synthetic test-double processor.

Every test here uses ``SyntheticDeterministicProcessor``; none of them
establishes anything about the document engine. Engine-backed cases live in
``test_mail_adapter_engine.py``.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import io
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
SERVICE = ROOT / "service"
for p in (str(SCRIPTS), str(SERVICE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.mail import (
    AdapterLimits,
    AdapterRequest,
    ContractError,
    Envelope,
    MailAdapter,
    PolicyReference,
    TrustedCallerContext,
)
from app.mail.fixtures import (
    FAKE_PNG,
    AttachmentSpec,
    build_message,
    synthetic_docx,
    synthetic_pdf,
)
from app.mail.synthetic import SyntheticDeterministicProcessor, synthetic_derivative

DOCX_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
BCC = "hidden@example.test"
MARKER = ("X-CounselClear-Processed", "transport-supplied-value")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def caller(**overrides) -> TrustedCallerContext:
    values = {
        "tenant_id": "tenant-a",
        "transport": "test-harness",
        "provenance_verified": True,
        "request_id": "req-1",
        "peer_identity": "test",
    }
    values.update(overrides)
    return TrustedCallerContext(**values)


def envelope() -> Envelope:
    return Envelope(
        mail_from="sender@example.test",
        rcpt_to=("recipient@example.test", "cc@example.test", BCC),
    )


def request(raw: bytes, **overrides) -> AdapterRequest:
    values = {
        "raw_message": raw,
        "envelope": envelope(),
        "caller": caller(),
        "policy": PolicyReference("external_sharing", 1),
        "outbound_marker": MARKER,
    }
    values.update(overrides)
    return AdapterRequest(**values)


def adapter(mode: str = "replace", **kwargs) -> tuple[MailAdapter, SyntheticDeterministicProcessor]:
    processor = SyntheticDeterministicProcessor(mode=mode)
    kwargs.setdefault("allow_synthetic", True)
    return MailAdapter(processor, **kwargs), processor


def docx_attachment(name: str = "Agreement.docx", body: str = "Draft") -> AttachmentSpec:
    return AttachmentSpec(name, synthetic_docx(body), DOCX_CT)


def standard_message(**overrides) -> bytes:
    values = {
        "to": ("recipient@example.test",),
        "cc": ("cc@example.test",),
        "subject": "Draft agreement",
        "text": "Please see the attached.",
        "html": '<p>Please see the attached.</p><img src="cid:logo@x">',
        "inline_images": (("logo@x", FAKE_PNG),),
        "attachments": (docx_attachment(),),
    }
    values.update(overrides)
    return build_message(**values)


def parse(raw: bytes):
    return email.message_from_bytes(raw, policy=email.policy.SMTP)


def leaves(raw: bytes):
    return [p for p in parse(raw).walk() if not p.is_multipart()]


# --- successful replacement -------------------------------------------------


def test_release_replaces_attachment_and_preserves_everything_else():
    raw = standard_message()
    adp, proc = adapter()
    result = adp.process(request(raw))

    assert result.decision == "release", result.reasons
    assert result.releasable and result.outbound is not None and result.outbound.rewritten
    assert [o.disposition for o in result.attachments] == ["replaced"]
    outcome = result.attachments[0]
    assert outcome.verification == "synthetic"
    assert outcome.part_id == "2"

    original = leaves(raw)
    rewritten = leaves(result.outbound.raw)
    assert [p.get_content_type() for p in original] == [p.get_content_type() for p in rewritten]

    # Byte comparison: the new attachment is exactly the processor's output
    # for exactly the original bytes, and its digest is what the outcome says.
    original_docx = original[3].get_payload(decode=True)
    new_docx = rewritten[3].get_payload(decode=True)
    assert new_docx == synthetic_derivative(original_docx)
    assert sha256(new_docx) == outcome.output_sha256
    assert outcome.source_sha256 == sha256(original_docx)
    assert proc.calls[0].content == original_docx
    assert rewritten[3].get_filename() == "Agreement.docx"

    # Body, alternative HTML, and inline image are untouched.
    for index in (0, 1, 2):
        assert original[index].get_payload(decode=True) == rewritten[index].get_payload(decode=True)
    assert rewritten[2].get("Content-ID") == "<logo@x>"

    # Unrelated headers and recipients survive; the marker is the transport's.
    before = parse(raw)
    after = parse(result.outbound.raw)
    for name in ("From", "To", "Cc", "Subject", "Message-ID", "Date"):
        assert after[name] == before[name]
    assert after["X-CounselClear-Processed"] == MARKER[1]
    assert result.outbound.envelope == envelope()
    assert result.evidence["output_sha256"] == sha256(result.outbound.raw)


def test_duplicate_filenames_are_matched_by_part_identity():
    raw = standard_message(
        attachments=(
            docx_attachment("Agreement.docx", "one"),
            docx_attachment("Agreement.docx", "two"),
        )
    )
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release"
    assert [o.part_id for o in result.attachments] == ["2", "3"]
    assert len({o.source_sha256 for o in result.attachments}) == 2
    originals = leaves(raw)[3:]
    rewritten = leaves(result.outbound.raw)[3:]
    for src, dst, outcome in zip(originals, rewritten, result.attachments, strict=True):
        assert dst.get_payload(decode=True) == synthetic_derivative(src.get_payload(decode=True))
        assert sha256(dst.get_payload(decode=True)) == outcome.output_sha256
    assert [c.part_id for c in proc.calls] == ["2", "3"]


def test_pdf_and_docx_selected_inline_png_is_not():
    raw = standard_message(
        attachments=(
            docx_attachment(),
            AttachmentSpec("scan.pdf", synthetic_pdf(), "application/pdf"),
        )
    )
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release"
    assert {o.detected_format for o in result.attachments} == {"docx", "pdf"}
    assert [c.engine_name for c in proc.calls] == ["Agreement.docx", "scan.pdf"]
    roles = {leaf["part_id"]: leaf["role"] for leaf in result.evidence["leaves"]}
    assert roles["1.2.2"] == "inline_image"
    assert roles["1.1"] == "body" and roles["1.2.1"] == "body"


def test_lf_line_endings_round_trip():
    raw = standard_message(linesep="\n")
    adp, _ = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release", result.evidence.get("verification_problems")
    assert result.evidence["line_separator"] == "LF"
    assert b"\r\n" not in result.outbound.raw


def test_encoded_word_subject_survives():
    raw = standard_message(subject="Entwurf – Vertrag über Aktien")
    adp, _ = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release"
    assert parse(result.outbound.raw)["Subject"] == "Entwurf – Vertrag über Aktien"


def test_no_attachments_and_nothing_to_strip_is_verbatim():
    raw = build_message(text="No attachments here.")
    adp, proc = adapter()
    result = adp.process(request(raw, outbound_marker=None))
    assert result.decision == "release"
    assert result.outbound.raw == raw
    assert result.outbound.rewritten is False
    assert result.attachments == ()
    assert proc.calls == []


def test_filenames_are_display_names_never_paths():
    from app.mail.mime import sanitize_display_name

    assert sanitize_display_name("../../etc/passwd.docx") == "passwd.docx"
    assert sanitize_display_name("C:\\Users\\x\\Agreement.docx") == "Agreement.docx"
    assert sanitize_display_name("bad\x00name\r\n.pdf") == "badname.pdf"
    assert sanitize_display_name('a<b>:"c|d?e*.docx') == "a_b___c_d_e_.docx"
    assert sanitize_display_name("..") is None
    assert sanitize_display_name("") is None
    long_name = "x" * 400 + ".docx"
    assert len(sanitize_display_name(long_name)) <= 150
    assert sanitize_display_name(long_name).endswith(".docx")

    raw = standard_message(attachments=(docx_attachment("../../escape.docx", "e"),))
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release"
    assert result.attachments[0].display_name == "escape.docx"
    assert proc.calls[0].engine_name == "escape.docx"


# --- envelope and Bcc ---------------------------------------------------------


def test_bcc_recipient_stays_in_envelope_and_out_of_headers():
    raw = standard_message(extra_headers=(("Bcc", BCC),))
    assert BCC.encode() in raw
    adp, _ = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release"
    assert BCC in result.outbound.envelope.rcpt_to
    assert result.outbound.envelope.rcpt_to == envelope().rcpt_to
    assert parse(result.outbound.raw).get_all("Bcc") is None
    assert BCC.encode() not in result.outbound.raw
    assert result.evidence["bcc_headers_removed"] == 1


def test_envelope_rejects_injection_and_emptiness():
    with pytest.raises(ContractError):
        Envelope("a@example.test", ("b@example.test\r\nRCPT TO:<x@evil.test>",))
    with pytest.raises(ContractError):
        Envelope("a@example.test", ())
    with pytest.raises(ContractError):
        PolicyReference("", 1)
    with pytest.raises(ContractError):
        PolicyReference("external_sharing", 0)
    with pytest.raises(ContractError):
        AdapterLimits(max_parts=0)


# --- trust boundary -----------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"provenance_verified": False},
        {"tenant_id": ""},
        {"transport": " "},
        {"request_id": ""},
    ],
)
def test_untrusted_submission_is_refused_before_parsing(overrides):
    raw = standard_message()
    adp, proc = adapter()
    result = adp.process(request(raw, caller=caller(**overrides)))
    assert result.decision == "refuse"
    assert result.reasons == ("untrusted_submission",)
    assert result.outbound is None
    assert proc.calls == []


def test_inbound_marker_never_suppresses_processing():
    # A sender-set marker, plus one copied verbatim from an earlier delivery.
    raw = standard_message(
        extra_headers=(
            ("X-CounselClear-Processed", "true"),
            ("X-CounselClear-Processed", MARKER[1]),
            ("X-CounselClear-Job", "job-123"),
        )
    )
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release"
    assert len(proc.calls) == 1
    assert result.evidence["stripped_marker_headers"] == [
        "X-CounselClear-Processed",
        "X-CounselClear-Processed",
        "X-CounselClear-Job",
    ]
    after = parse(result.outbound.raw)
    assert after.get_all("X-CounselClear-Processed") == [MARKER[1]]
    assert after.get_all("X-CounselClear-Job") is None


def test_inbound_marker_is_stripped_even_without_an_outbound_marker():
    raw = standard_message(extra_headers=(("X-CounselClear-Processed", "true"),))
    adp, _ = adapter()
    result = adp.process(request(raw, outbound_marker=None))
    assert result.decision == "release"
    after = parse(result.outbound.raw)
    assert not [k for k in after if k.lower().startswith("x-counselclear-")]


def test_marker_configuration_is_validated():
    raw = standard_message()
    adp, _ = adapter()
    for marker in (
        ("X-Other", "v"),
        ("X-CounselClear-Processed", "a\r\nInjected: yes"),
        ("X-CounselClear-P", ""),
    ):
        result = adp.process(request(raw, outbound_marker=marker))
        assert result.decision == "refuse"
        assert result.reasons[0].startswith("invalid_marker_")


# --- structural refusals and holds -------------------------------------------


def test_malformed_mime_is_refused():
    raw = (
        b"From: a@example.test\r\nTo: b@example.test\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="never-appears"\r\n\r\n'
        b"body without any boundary\r\n"
    )
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "refuse"
    assert result.reasons == ("malformed_mime",)
    assert any("StartBoundaryNotFoundDefect" in d for d in result.evidence["defects"])
    assert proc.calls == []


def test_undecodable_attachment_is_refused():
    raw = standard_message()
    # Corrupt the base64 of the DOCX part with characters outside the alphabet.
    header_at = raw.index(b'filename="Agreement.docx"')
    body_start = raw.index(b"\r\n\r\n", header_at) + 4
    corrupted = raw[:body_start] + b"@@@@" + raw[body_start + 4 :]
    adp, _ = adapter()
    result = adp.process(request(corrupted))
    assert result.decision == "refuse"
    assert result.reasons == ("undecodable:2",)
    assert result.outbound is None


@pytest.mark.parametrize(
    "content_type",
    [
        "multipart/signed",
        "application/pkcs7-mime",
        "multipart/encrypted",
        "application/pgp-encrypted",
    ],
)
def test_signed_or_encrypted_messages_are_held_untouched(content_type):
    if content_type.startswith("multipart/"):
        raw = (
            b"From: a@example.test\r\nTo: b@example.test\r\nMIME-Version: 1.0\r\n"
            + f'Content-Type: {content_type}; boundary="sig"; protocol="application/pkcs7-signature"\r\n\r\n'.encode()
            + b"--sig\r\nContent-Type: text/plain\r\n\r\nsigned body\r\n"
            b"--sig\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--sig--\r\n"
        )
    else:
        raw = (
            b"From: a@example.test\r\nTo: b@example.test\r\nMIME-Version: 1.0\r\n"
            + f"Content-Type: {content_type}; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n".encode()
        )
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "hold"
    assert result.reasons == ("signed_or_encrypted_message",)
    assert result.retryable is False
    assert result.outbound is None
    assert proc.calls == []


def test_unsupported_part_holds_by_default_and_passes_through_on_request():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("inner.txt", "nested")
    raw = standard_message(
        attachments=(
            docx_attachment(),
            AttachmentSpec("bundle.zip", archive.getvalue(), "application/zip"),
        )
    )
    adp, _ = adapter()
    held = adp.process(request(raw))
    assert held.decision == "hold"
    assert held.reasons == ("unsupported:3",)
    assert held.retryable is False
    assert held.outbound is None
    assert held.attachments[1].reason == "format_unknown"

    passed = adp.process(request(raw, unsupported_parts="pass_through"))
    assert passed.decision == "release"
    assert [o.disposition for o in passed.attachments] == ["replaced", "unsupported"]
    original_zip = leaves(raw)[4].get_payload(decode=True)
    assert leaves(passed.outbound.raw)[4].get_payload(decode=True) == original_zip


@pytest.mark.parametrize(
    ("name", "content_type", "content", "expected"),
    [
        ("looks-like.pdf", "application/pdf", synthetic_docx("x"), "ambiguous"),
        ("claims.docx", DOCX_CT, b"\x00\x01random bytes", "ambiguous"),
        ("untyped", "application/octet-stream", synthetic_docx("x"), "replaced"),
        ("attached.txt", "text/plain", b"plain text attachment", "unsupported"),
        (
            "legacy.doc",
            "application/msword",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64,
            "unsupported",
        ),
        (
            "macro.docm",
            "application/vnd.ms-word.document.macroenabled.12",
            synthetic_docx("m"),
            "ambiguous",
        ),
    ],
)
def test_declared_versus_detected_format_dispositions(name, content_type, content, expected):
    raw = standard_message(attachments=(AttachmentSpec(name, content, content_type),))
    adp, proc = adapter()
    result = adp.process(request(raw))
    outcome = result.attachments[0]
    assert outcome.disposition == expected, outcome
    if expected == "replaced":
        assert result.decision == "release"
        assert proc.calls[0].engine_name == "attachment-2.docx"
    else:
        assert result.decision == "hold"
        assert proc.calls == []


def test_password_protected_office_is_unsupported():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("EncryptedPackage", b"\x00" * 32)
        zf.writestr("EncryptionInfo", b"\x00" * 16)
    raw = standard_message(attachments=(AttachmentSpec("secret.docx", buf.getvalue(), DOCX_CT),))
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "hold"
    assert result.attachments[0].disposition == "unsupported"
    assert result.attachments[0].reason == "password_protected_office"
    assert proc.calls == []


def test_attached_message_is_unsupported():
    inner = build_message(text="inner", attachments=(docx_attachment(),))
    raw = (
        b"From: a@example.test\r\nTo: b@example.test\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="outer"\r\n\r\n'
        b"--outer\r\nContent-Type: text/plain\r\n\r\nforwarding\r\n"
        b"--outer\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n"
        + inner
        + b"\r\n--outer--\r\n"
    )
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "hold"
    assert result.attachments[0].disposition == "unsupported"
    assert result.attachments[0].reason == "attached_message"
    assert proc.calls == []


# --- processor outcomes ------------------------------------------------------


def test_policy_refusal_refuses_the_message():
    adp, _ = adapter("refuse")
    result = adp.process(request(standard_message()))
    assert result.decision == "refuse"
    assert result.reasons == ("refused:2",)
    assert result.retryable is False
    assert result.outbound is None
    assert result.attachments[0].reason.startswith("plan refused")


@pytest.mark.parametrize("mode", ["unavailable", "raise_unavailable", "fail", "crash"])
def test_processor_problems_hold_as_retryable(mode):
    adp, _ = adapter(mode)
    result = adp.process(request(standard_message()))
    assert result.decision == "hold"
    assert result.retryable is True
    assert result.outbound is None
    assert result.attachments[0].disposition in ("unavailable", "failed")


@pytest.mark.parametrize(
    ("mode", "reason_fragment"),
    [
        ("wrong_source_digest", "source digest"),
        ("wrong_output_digest", "output digest"),
        ("wrong_policy", "policy id or version"),
        ("no_verification", "no verification evidence"),
    ],
)
def test_inconsistent_processor_evidence_is_refused(mode, reason_fragment):
    adp, _ = adapter(mode)
    result = adp.process(request(standard_message()))
    assert result.decision == "refuse"
    assert result.reasons == ("inconsistent:2",)
    assert reason_fragment in result.attachments[0].reason
    assert result.attachments[0].verification == "none"
    assert result.outbound is None


def test_synthetic_results_are_refused_unless_explicitly_allowed():
    adp, _ = adapter(allow_synthetic=False)
    result = adp.process(request(standard_message()))
    assert result.decision == "refuse"
    assert result.reasons == ("inconsistent:2",)
    assert "synthetic" in result.attachments[0].reason
    assert result.evidence["synthetic_results_allowed"] is False


def test_partial_success_never_releases():
    class HalfProcessor(SyntheticDeterministicProcessor):
        def process(self, req):
            self.mode = "replace" if req.part_id == "2" else "refuse"
            return super().process(req)

    processor = HalfProcessor()
    adp = MailAdapter(processor, allow_synthetic=True)
    raw = standard_message(
        attachments=(docx_attachment("a.docx", "a"), docx_attachment("b.docx", "b"))
    )
    result = adp.process(request(raw))
    assert result.decision == "refuse"
    assert [o.disposition for o in result.attachments] == ["replaced", "refused"]
    assert result.outbound is None


# --- bounds -------------------------------------------------------------------


def test_message_size_limit_refuses_before_parsing():
    raw = standard_message()
    adp, proc = adapter()
    result = adp.process(request(raw, limits=AdapterLimits(max_message_bytes=len(raw) - 1)))
    assert result.decision == "refuse"
    assert result.reasons == ("message_exceeds_limit",)
    assert proc.calls == []


def test_part_count_and_depth_bounds():
    raw = standard_message()
    adp, _ = adapter()
    result = adp.process(request(raw, limits=AdapterLimits(max_parts=3)))
    assert result.decision == "refuse"
    assert result.reasons == ("mime_bounds_exceeded",)
    assert "MIME parts" in result.evidence["bound"]
    result = adp.process(request(raw, limits=AdapterLimits(max_depth=1)))
    assert result.decision == "refuse"
    assert "nesting" in result.evidence["bound"]


def test_attachment_count_and_size_bounds():
    raw = standard_message(
        attachments=(docx_attachment("a.docx", "a"), docx_attachment("b.docx", "b"))
    )
    adp, proc = adapter()
    result = adp.process(request(raw, limits=AdapterLimits(max_attachments=1)))
    assert result.decision == "refuse"
    assert result.reasons == ("too_many_attachments",)
    assert proc.calls == []

    result = adp.process(request(raw, limits=AdapterLimits(max_attachment_bytes=200)))
    assert result.decision == "hold"
    assert result.reasons == ("oversize:2", "oversize:3")
    assert result.retryable is False
    assert proc.calls == []


def test_output_growth_beyond_limit_is_held():
    raw = standard_message()
    adp, _ = adapter("grow")
    result = adp.process(request(raw, limits=AdapterLimits(max_output_bytes=len(raw) + 1024)))
    assert result.decision == "hold"
    assert result.reasons == ("output_exceeds_limit",)
    assert result.retryable is False
    assert result.outbound is None
    assert result.evidence["output_bytes"] > len(raw) + 1024
    assert result.attachments[0].disposition == "replaced"


# --- acceptance-review regressions (Codex, 2026-09-11) -------------------------


def raw_part_message(part_headers: list[tuple[str, str]], content: bytes) -> bytes:
    """A multipart/mixed message whose second part has exactly the headers
    given, so tests can omit Content-Disposition or filename entirely."""
    import base64

    head = (
        b"From: sender@example.test\r\nTo: recipient@example.test\r\n"
        b"Subject: raw part\r\nMessage-ID: <raw-0001@example.test>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="rawb"\r\n\r\n'
        b"--rawb\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSee attached.\r\n--rawb\r\n"
    )
    headers = b"".join(f"{k}: {v}\r\n".encode() for k, v in part_headers)
    body = base64.encodebytes(content).replace(b"\n", b"\r\n")
    return head + headers + b"Content-Transfer-Encoding: base64\r\n\r\n" + body + b"--rawb--\r\n"


@pytest.mark.parametrize(
    "spec",
    [
        AttachmentSpec("Agreement.docx", synthetic_docx("inline"), DOCX_CT, "inline", "doc@x"),
        AttachmentSpec(None, synthetic_docx("inline"), DOCX_CT, "inline"),
        AttachmentSpec(None, synthetic_docx("inline"), DOCX_CT, "inline", "doc@x"),
        AttachmentSpec(None, synthetic_docx("inline"), "application/octet-stream", "inline", "b@x"),
    ],
    ids=["inline+filename+cid", "inline-no-filename", "inline+cid-no-filename", "octet-stream+cid"],
)
def test_inline_document_parts_are_processed_regardless_of_disposition_or_cid(spec):
    raw = standard_message(attachments=(spec,))
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release", result.reasons
    assert len(proc.calls) == 1
    assert [o.disposition for o in result.attachments] == ["replaced"]
    docx_part = leaves(result.outbound.raw)[3]
    assert docx_part.get_payload(decode=True) == synthetic_derivative(spec.content)
    assert docx_part.get_payload(decode=True) != spec.content


def test_document_without_disposition_or_filename_is_processed():
    content = synthetic_docx("bare")
    raw = raw_part_message([("Content-Type", DOCX_CT), ("Content-ID", "<bare@x>")], content)
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release", result.reasons
    assert len(proc.calls) == 1
    assert proc.calls[0].engine_name == "attachment-2.docx"
    assert leaves(result.outbound.raw)[1].get_payload(decode=True) == synthetic_derivative(content)
    role = next(leaf for leaf in result.evidence["leaves"] if leaf["part_id"] == "2")
    assert role["role"] == "attachment" and role["why"] == "binary_without_filename"


@pytest.mark.parametrize(
    ("headers", "content", "expected", "reason_fragment"),
    [
        (
            [
                ("Content-Type", "image/png"),
                ("Content-Disposition", "inline"),
                ("Content-ID", "<a@x>"),
            ],
            synthetic_docx("as image"),
            "ambiguous",
            "declared_image",
        ),
        (
            [("Content-Type", "text/plain; charset=utf-8"), ("Content-Disposition", "inline")],
            synthetic_docx("as text"),
            "ambiguous",
            "declared_text",
        ),
        (
            [
                ("Content-Type", "application/pdf"),
                ("Content-Disposition", "inline"),
                ("Content-ID", "<b@x>"),
            ],
            FAKE_PNG,
            "ambiguous",
            "declared_pdf",
        ),
        (
            [
                ("Content-Type", "image/png"),
                ("Content-Disposition", "inline"),
                ("Content-ID", "<c@x>"),
            ],
            b"\x00" * 64,
            "unsupported",
            "format_image",
        ),
        (
            [
                ("Content-Type", "image/png"),
                ("Content-Disposition", 'inline; filename="x.docx"'),
                ("Content-ID", "<d@x>"),
            ],
            FAKE_PNG,
            "ambiguous",
            "declared_docx_extension",
        ),
    ],
    ids=["docx-as-image", "docx-as-text", "png-as-pdf", "unknown-as-image", "png-named-docx"],
)
def test_misleading_inline_declarations_never_pass_untouched(
    headers, content, expected, reason_fragment
):
    raw = raw_part_message(headers, content)
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "hold", result.reasons
    assert result.outbound is None
    assert proc.calls == []
    outcome = result.attachments[0]
    assert outcome.disposition == expected
    assert reason_fragment in outcome.reason


def test_unknown_inline_binary_passes_through_only_when_permitted():
    raw = raw_part_message(
        [("Content-Type", "image/png"), ("Content-Disposition", "inline"), ("Content-ID", "<c@x>")],
        b"\x00" * 64,
    )
    adp, proc = adapter()
    assert adp.process(request(raw)).decision == "hold"
    passed = adp.process(request(raw, unsupported_parts="pass_through"))
    assert passed.decision == "release"
    assert passed.attachments[0].disposition == "unsupported"
    assert leaves(passed.outbound.raw)[1].get_payload(decode=True) == b"\x00" * 64
    assert proc.calls == []


@pytest.mark.parametrize(
    "headers",
    [
        [
            ("Content-Type", "image/png"),
            ("Content-Disposition", "inline"),
            ("Content-ID", "<img@x>"),
        ],
        [
            ("Content-Type", "image/png"),
            ("Content-Disposition", 'inline; filename="image001.png"'),
            ("Content-ID", "<img@x>"),
        ],
        [("Content-Type", "image/jpeg"), ("Content-ID", "<img@x>")],
        [("Content-Type", "image/png"), ("Content-Disposition", "inline")],
    ],
    ids=["png+cid", "outlook-style-filename", "jpeg-no-disposition", "png-no-cid"],
)
def test_ordinary_inline_raster_images_stay_untouched(headers):
    image = FAKE_PNG if "png" in headers[0][1] else b"\xff\xd8\xff\xe0" + b"\x00" * 32
    raw = raw_part_message(headers, image)
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "release", result.reasons
    assert result.attachments == ()
    assert proc.calls == []
    assert leaves(result.outbound.raw)[1].get_payload(decode=True) == image
    role = next(leaf for leaf in result.evidence["leaves"] if leaf["part_id"] == "2")
    assert role["role"] == "inline_image"


def test_raster_image_sent_as_attachment_is_not_exempt():
    raw = standard_message(
        attachments=(docx_attachment(), AttachmentSpec("photo.png", FAKE_PNG, "image/png"))
    )
    adp, proc = adapter()
    result = adp.process(request(raw))
    assert result.decision == "hold"
    assert [o.disposition for o in result.attachments] == ["replaced", "unsupported"]
    assert proc.calls[0].part_id == "2"


@pytest.mark.parametrize(
    ("name", "content_type", "content", "expected", "reason_fragment"),
    [
        (
            "Agreement.docx",
            "application/pdf",
            synthetic_docx("c"),
            "ambiguous",
            "declared_pdf_content_type_bytes_docx",
        ),
        ("scan.pdf", DOCX_CT, synthetic_pdf(), "ambiguous", "declared_docx_content_type_bytes_pdf"),
        (
            "file.pdf",
            DOCX_CT,
            synthetic_docx("c"),
            "ambiguous",
            "declared_pdf_extension_bytes_docx",
        ),
        (
            "file.docx",
            "application/pdf",
            synthetic_pdf(),
            "ambiguous",
            "declared_docx_extension_bytes_pdf",
        ),
        ("Agreement.docx", "application/octet-stream", synthetic_docx("c"), "replaced", "replaced"),
        (None, "application/octet-stream", synthetic_docx("c"), "replaced", "replaced"),
        (None, "application/pdf", synthetic_pdf(), "replaced", "replaced"),
        ("scan.pdf", "application/x-pdf", synthetic_pdf(), "replaced", "replaced"),
    ],
    ids=[
        "docx-ext-pdf-type",
        "pdf-ext-docx-type",
        "pdf-ext-docx-bytes",
        "docx-ext-pdf-bytes",
        "docx-octet-stream",
        "docx-no-name",
        "pdf-no-name",
        "pdf-alt-type",
    ],
)
def test_extension_and_media_type_are_checked_independently(
    name, content_type, content, expected, reason_fragment
):
    raw = standard_message(attachments=(AttachmentSpec(name, content, content_type),))
    adp, proc = adapter()
    result = adp.process(request(raw))
    outcome = result.attachments[0]
    assert outcome.disposition == expected, outcome
    assert reason_fragment in outcome.reason
    if expected == "replaced":
        assert result.decision == "release"
        assert len(proc.calls) == 1
    else:
        assert result.decision == "hold"
        assert result.outbound is None
        assert proc.calls == []


def _zip_attachment() -> AttachmentSpec:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.txt", "nested")
    return AttachmentSpec("bundle.zip", buf.getvalue(), "application/zip")


@pytest.mark.parametrize(
    ("attachments", "marker", "pass_through"),
    [
        ((), None, False),
        ((), MARKER, False),
        ((_zip_attachment(),), None, True),
        ((_zip_attachment(),), MARKER, True),
    ],
    ids=["plain-verbatim", "plain-rewritten", "passthrough-verbatim", "passthrough-rewritten"],
)
def test_output_limit_applies_on_every_release_path(attachments, marker, pass_through):
    raw = build_message(text="Short body.", attachments=attachments)
    adp, proc = adapter()
    mode = "pass_through" if pass_through else "hold"
    tight = AdapterLimits(max_message_bytes=len(raw) + 4096, max_output_bytes=100)
    held = adp.process(request(raw, outbound_marker=marker, unsupported_parts=mode, limits=tight))
    assert held.decision == "hold", held.reasons
    assert held.reasons == ("output_exceeds_limit",)
    assert held.retryable is False
    assert held.outbound is None
    assert held.evidence["output_bytes"] > 100
    assert held.evidence["rewritten"] is bool(marker)

    roomy = AdapterLimits(max_message_bytes=len(raw) + 4096, max_output_bytes=len(raw) + 4096)
    released = adp.process(
        request(raw, outbound_marker=marker, unsupported_parts=mode, limits=roomy)
    )
    assert released.decision == "release", released.reasons
    assert released.outbound.rewritten is bool(marker)
    assert len(released.outbound.raw) == released.evidence["output_bytes"]
    assert proc.calls == []


# --- determinism and harness -------------------------------------------------


def test_repeated_runs_are_consistent():
    raw = standard_message(
        attachments=(docx_attachment("a.docx", "a"), docx_attachment("b.docx", "b"))
    )
    adp, _ = adapter()
    first = adp.process(request(raw))
    second = adp.process(request(raw))
    assert first.decision == second.decision == "release"
    assert first.outbound.raw == second.outbound.raw
    assert first.to_dict() == second.to_dict()


def test_result_to_dict_is_json_serializable():
    import json

    adp, _ = adapter()
    result = adp.process(request(standard_message()))
    text = json.dumps(result.to_dict(), sort_keys=True)
    assert '"decision": "release"' in text


def test_demo_harness_runs_with_the_labeled_test_double(tmp_path):
    out = tmp_path / "out.eml"
    completed = subprocess.run(
        [sys.executable, "-m", "app.mail.demo", "--out", str(out)],
        cwd=SERVICE,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "TEST DOUBLE" in completed.stdout
    assert "verification=synthetic" in completed.stdout
    assert "decision: release" in completed.stdout
    message = parse(out.read_bytes())
    assert message.get_all("Bcc") is None
    assert message["X-CounselClear-Processed"] == "demo-transport-value"
