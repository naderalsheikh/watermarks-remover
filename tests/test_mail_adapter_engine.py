"""Mail attachment adapter (M1) with the real engine, in-process.

These tests run ``engine_api.clean_to_bundle`` through
``LocalEngineProcessor``. They establish that the adapter's processor
contract maps onto the engine's custody manifest and that a real policy
refusal reaches the adapter as a refusal. They do *not* exercise the
isolated worker/runner path the API uses in production, and they say
nothing about Microsoft 365 routing.
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

from app.mail import AdapterRequest, Envelope, MailAdapter, PolicyReference, TrustedCallerContext
from app.mail.engine_processor import LocalEngineProcessor
from app.mail.fixtures import AttachmentSpec, build_message, synthetic_docx, synthetic_pdf

FIXTURES = ROOT / "tests" / "fixtures" / "legal"
DOCX_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def request(raw: bytes, policy_id: str = "external_sharing") -> AdapterRequest:
    return AdapterRequest(
        raw_message=raw,
        envelope=Envelope("sender@example.test", ("recipient@example.test",)),
        caller=TrustedCallerContext("tenant-a", "test-harness", True, "req-engine"),
        policy=PolicyReference(policy_id, 1),
        outbound_marker=("X-CounselClear-Processed", "test"),
    )


def leaves(raw: bytes):
    return [
        p
        for p in email.message_from_bytes(raw, policy=email.policy.SMTP).walk()
        if not p.is_multipart()
    ]


def test_engine_releases_synthetic_docx_with_authoring_metadata_removed():
    source = synthetic_docx("Draft body text", creator="Jane Associate")
    raw = build_message(attachments=(AttachmentSpec("Agreement.docx", source, DOCX_CT),))
    adapter = MailAdapter(LocalEngineProcessor())
    result = adapter.process(request(raw))

    assert result.decision == "release", (result.reasons, result.attachments)
    outcome = result.attachments[0]
    assert outcome.verification == "engine_verified"
    assert outcome.evidence_ref and outcome.evidence_ref.startswith("manifest:sha256:")
    assert outcome.output_name == "Agreement.external.docx"
    assert outcome.processor == "local-engine-in-process"

    derivative = leaves(result.outbound.raw)[1].get_payload(decode=True)
    assert hashlib.sha256(derivative).hexdigest() == outcome.output_sha256
    assert derivative != source
    with zipfile.ZipFile(io.BytesIO(derivative)) as zf:
        assert b"Jane Associate" not in zf.read("docProps/core.xml")
        assert b"Draft body text" in zf.read("word/document.xml")
    # The recipient-visible filename is unchanged; the engine's derivative
    # name is recorded in the outcome only.
    assert leaves(result.outbound.raw)[1].get_filename() == "Agreement.docx"


def test_engine_releases_repository_fixture_and_pdf():
    raw = build_message(
        attachments=(
            AttachmentSpec("spa.docx", (FIXTURES / "spa.docx").read_bytes(), DOCX_CT),
            AttachmentSpec("scan.pdf", synthetic_pdf("Synthetic"), "application/pdf"),
        )
    )
    result = MailAdapter(LocalEngineProcessor()).process(request(raw))
    assert result.decision == "release", (result.reasons, result.attachments)
    assert [o.output_name for o in result.attachments] == ["spa.external.docx", "scan.external.pdf"]
    assert all(o.verification == "engine_verified" for o in result.attachments)


def test_engine_policy_refusal_reaches_the_adapter_as_a_refusal():
    # A .docx package that carries a VBA project: the external_sharing policy
    # refuses macro-enabled content with no derivative path.
    clean = synthetic_docx("macro", creator=None)
    with zipfile.ZipFile(io.BytesIO(clean)) as zin:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as zout:
            for name in zin.namelist():
                zout.writestr(name, zin.read(name))
            zout.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"\x00" * 32)
    raw = build_message(attachments=(AttachmentSpec("macro.docx", out.getvalue(), DOCX_CT),))
    result = MailAdapter(LocalEngineProcessor()).process(request(raw))
    assert result.decision == "refuse"
    assert result.reasons == ("refused:2",)
    assert result.retryable is False
    assert result.outbound is None
    assert "macro" in result.attachments[0].reason


def test_engine_refusal_for_unacknowledged_findings():
    raw = build_message(
        attachments=(
            AttachmentSpec(
                "hidden.xlsx",
                (FIXTURES / "hidden.xlsx").read_bytes(),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
        )
    )
    result = MailAdapter(LocalEngineProcessor()).process(request(raw))
    assert result.decision == "refuse"
    assert result.attachments[0].disposition == "refused"
    assert "not acknowledged" in result.attachments[0].reason


def test_engine_results_are_stable_across_runs():
    raw = build_message(
        attachments=(AttachmentSpec("Agreement.docx", synthetic_docx("x"), DOCX_CT),)
    )
    adapter = MailAdapter(LocalEngineProcessor())
    first = adapter.process(request(raw))
    second = adapter.process(request(raw))
    assert first.decision == second.decision == "release"
    assert first.attachments[0].output_sha256 == second.attachments[0].output_sha256
    assert first.outbound.raw == second.outbound.raw


@pytest.mark.parametrize(
    "spec",
    [
        AttachmentSpec(
            "Agreement.docx",
            synthetic_docx("inline", creator="Jane Associate"),
            DOCX_CT,
            "inline",
            "doc@x",
        ),
        AttachmentSpec(None, synthetic_docx("inline", creator="Jane Associate"), DOCX_CT, "inline"),
    ],
    ids=["inline+filename+cid", "inline-no-filename"],
)
def test_engine_cleans_inline_document_parts(spec):
    raw = build_message(attachments=(spec,))
    result = MailAdapter(LocalEngineProcessor()).process(request(raw))
    assert result.decision == "release", (result.reasons, result.attachments)
    outcome = result.attachments[0]
    assert outcome.disposition == "replaced" and outcome.verification == "engine_verified"
    derivative = leaves(result.outbound.raw)[1].get_payload(decode=True)
    assert derivative != spec.content
    assert hashlib.sha256(derivative).hexdigest() == outcome.output_sha256
    with zipfile.ZipFile(io.BytesIO(derivative)) as zf:
        assert b"Jane Associate" not in zf.read("docProps/core.xml")
        assert b"inline" in zf.read("word/document.xml")


def test_engine_never_sees_a_conflicting_declaration():
    raw = build_message(
        attachments=(AttachmentSpec("Agreement.docx", synthetic_docx("c"), "application/pdf"),)
    )
    result = MailAdapter(LocalEngineProcessor()).process(request(raw))
    assert result.decision == "hold"
    assert result.attachments[0].disposition == "ambiguous"
    assert result.outbound is None


def test_demo_harness_engine_mode(tmp_path):
    out = tmp_path / "out.eml"
    completed = subprocess.run(
        [sys.executable, "-m", "app.mail.demo", "--engine", "--out", str(out)],
        cwd=SERVICE,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "verification=engine_verified" in completed.stdout
    assert "not the isolated worker path" in completed.stdout
    parsed = [p for p in leaves(out.read_bytes()) if p.get_filename() == "Agreement.docx"]
    assert len(parsed) == 2
