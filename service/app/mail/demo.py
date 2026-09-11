"""Runnable local fixture harness for the mail adapter.

    cd service
    python -m app.mail.demo                # synthetic processor (TEST DOUBLE)
    python -m app.mail.demo --engine       # real engine, in-process
    python -m app.mail.demo --out /tmp/out.eml --json

The default run uses ``SyntheticDeterministicProcessor``. Its output is a
synthetic byte string, not a cleaned document, and the printed evidence says
``"verification": "synthetic"`` on every replaced part. ``--engine`` runs
``engine_api.clean_to_bundle`` in this process instead (see
``app.mail.engine_processor`` for why that is not the production isolation
path). Neither mode touches a mailbox, a tenant, or the network.

Exit status: 0 released, 2 held, 3 refused.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapter import MailAdapter
from .contract import AdapterLimits, AdapterRequest, Envelope, PolicyReference, TrustedCallerContext
from .fixtures import FAKE_PNG, AttachmentSpec, build_message, synthetic_docx

DEMO_TENANT = "tenant-synthetic"
DEMO_BCC = "hidden-recipient@example.test"


def demo_message() -> bytes:
    """Two DOCX attachments with the same filename, an HTML body with an
    inline image, a copied 'processed' marker, and a leaked Bcc header."""
    return build_message(
        sender="associate@firm.example.test",
        to=("counterparty@other.example.test",),
        cc=("partner@firm.example.test",),
        subject="Draft agreement",
        text="Please see the attached drafts.",
        html='<p>Please see the attached drafts.</p><img src="cid:logo@firm">',
        inline_images=(("logo@firm", FAKE_PNG),),
        attachments=(
            AttachmentSpec(
                "Agreement.docx",
                synthetic_docx("Draft 1", creator="Jane Associate"),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            AttachmentSpec(
                "Agreement.docx",
                synthetic_docx("Draft 2", creator="Jane Associate"),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
        ),
        extra_headers=(
            ("X-CounselClear-Processed", "true"),
            ("Bcc", DEMO_BCC),
        ),
    )


def demo_request(raw: bytes, *, policy_id: str = "external_sharing") -> AdapterRequest:
    return AdapterRequest(
        raw_message=raw,
        envelope=Envelope(
            mail_from="associate@firm.example.test",
            rcpt_to=(
                "counterparty@other.example.test",
                "partner@firm.example.test",
                DEMO_BCC,
            ),
        ),
        caller=TrustedCallerContext(
            tenant_id=DEMO_TENANT,
            transport="local-demo-harness",
            provenance_verified=True,
            request_id="demo-0001",
            peer_identity="demo: no transport authentication performed",
        ),
        policy=PolicyReference(policy_id, 1),
        limits=AdapterLimits(),
        outbound_marker=("X-CounselClear-Processed", "demo-transport-value"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--engine", action="store_true", help="use the real engine in-process")
    parser.add_argument("--policy", default="external_sharing")
    parser.add_argument("--out", type=Path, help="write the outbound message here on release")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = parser.parse_args(argv)

    if args.engine:
        from .engine_processor import LocalEngineProcessor

        adapter = MailAdapter(LocalEngineProcessor())
        label = "LocalEngineProcessor (real engine, in-process; not the isolated worker path)"
    else:
        from .synthetic import SyntheticDeterministicProcessor

        adapter = MailAdapter(SyntheticDeterministicProcessor(), allow_synthetic=True)
        label = "SyntheticDeterministicProcessor (TEST DOUBLE: no cleaning, no verification)"

    raw = demo_message()
    result = adapter.process(demo_request(raw, policy_id=args.policy))

    print(f"processor: {label}")
    print(
        f"decision: {result.decision}  retryable={result.retryable}  reasons={list(result.reasons)}"
    )
    for outcome in result.attachments:
        print(
            f"  part {outcome.part_id} {outcome.display_name!r} {outcome.detected_format}: "
            f"{outcome.disposition} ({outcome.reason}) verification={outcome.verification}"
        )
    print(
        "  stripped inbound markers:",
        result.evidence.get("stripped_marker_headers"),
        " bcc headers removed:",
        result.evidence.get("bcc_headers_removed"),
    )
    if result.outbound is not None:
        print(
            f"outbound: {len(result.outbound.raw)} bytes sha256={result.outbound.sha256} "
            f"rewritten={result.outbound.rewritten} envelope_rcpt={len(result.outbound.envelope.rcpt_to)}"
        )
        if args.out:
            args.out.write_bytes(result.outbound.raw)
            print(f"wrote {args.out}")
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return {"release": 0, "hold": 2, "refuse": 3}[result.decision]


if __name__ == "__main__":
    sys.exit(main())
