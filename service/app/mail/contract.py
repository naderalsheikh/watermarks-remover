"""Input/output contract for the CounselClear mail attachment adapter (M1).

The adapter sits between a trusted mail transport and the CounselClear
processing engine. It receives one raw RFC 822 message plus the facts only
the transport can vouch for (SMTP envelope, authenticated caller context,
the policy to apply) and returns a decision: a releasable outbound message,
or an explicit hold/refusal with no outbound message at all.

Trust boundary, stated once here and relied on everywhere else:

- Everything *inside* the message is untrusted: headers, filenames,
  Message-ID, content types, any "already processed" marker. None of it can
  change what the adapter does except by describing the MIME structure.
- Everything in :class:`Envelope`, :class:`TrustedCallerContext` and
  :class:`PolicyReference` must come from the transport process that
  authenticated the connection (for example an inbound SMTP listener that
  verified the tenant's TLS client certificate). A boolean or a
  secret-looking header copied out of the message never substitutes for
  that context; the adapter refuses submissions whose caller context is not
  marked as verified.
- Envelope recipients (including Bcc recipients) stay in the envelope. They
  are never written into message headers, and the outbound envelope is the
  inbound envelope unchanged.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Decision = Literal["release", "hold", "refuse"]

# Per-attachment dispositions. ``replaced`` is the only one that yields a
# rewritten part; every other value either holds or refuses the whole
# message (see adapter.MailAdapter for the mapping).
Disposition = Literal[
    "replaced",
    "refused",
    "failed",
    "unavailable",
    "inconsistent",
    "unsupported",
    "ambiguous",
    "password_protected",
    "oversize",
    "undecodable",
]

Verification = Literal["engine_verified", "synthetic", "none"]

_ADDRESS_FORBIDDEN = frozenset("\r\n\x00 \t")


class ContractError(ValueError):
    """A request violates the adapter contract before any message parsing."""


def _check_address(value: object, what: str, *, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{what} must be a string")
    if not value and not allow_empty:
        raise ContractError(f"{what} must not be empty")
    if any(ch in _ADDRESS_FORBIDDEN for ch in value):
        raise ContractError(f"{what} contains forbidden characters")
    if len(value) > 320:
        raise ContractError(f"{what} is longer than an SMTP path allows")
    return value


@dataclass(frozen=True)
class Envelope:
    """SMTP envelope as the transport received it.

    ``rcpt_to`` is the complete recipient list, including recipients that
    appear only as Bcc. An empty ``mail_from`` is the SMTP null sender.
    """

    mail_from: str
    rcpt_to: tuple[str, ...]

    def __post_init__(self) -> None:
        _check_address(self.mail_from, "envelope sender", allow_empty=True)
        recipients = tuple(self.rcpt_to)
        if not recipients:
            raise ContractError("envelope has no recipients")
        for recipient in recipients:
            _check_address(recipient, "envelope recipient", allow_empty=False)
        object.__setattr__(self, "rcpt_to", recipients)


@dataclass(frozen=True)
class TrustedCallerContext:
    """What the transport process asserts about the submission.

    ``provenance_verified`` must only be set by code that authenticated the
    peer (certificate domain, connector identity, or an equivalent trusted
    channel). ``peer_identity`` records what was authenticated, for evidence.
    """

    tenant_id: str
    transport: str
    provenance_verified: bool
    request_id: str
    peer_identity: str | None = None

    def is_trusted(self) -> bool:
        return (
            isinstance(self.tenant_id, str)
            and bool(self.tenant_id.strip())
            and isinstance(self.transport, str)
            and bool(self.transport.strip())
            and self.provenance_verified is True
            and isinstance(self.request_id, str)
            and bool(self.request_id.strip())
        )


@dataclass(frozen=True)
class PolicyReference:
    """The engine policy the transport selected for this tenant/message.

    Mirrors the ``policy`` object of the custody manifest
    (``{"id": ..., "version": ...}``) so processing evidence can be checked
    against the request without a second policy vocabulary.
    """

    policy_id: str
    version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise ContractError("policy id must be a non-empty string")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise ContractError("policy version must be a positive integer")


@dataclass(frozen=True)
class AdapterLimits:
    """Explicit resource bounds. Every bound produces a refusal or hold, never
    partial processing."""

    max_message_bytes: int = 50 * 1024 * 1024
    max_output_bytes: int | None = None
    max_parts: int = 200
    max_depth: int = 10
    max_attachments: int = 25
    max_attachment_bytes: int = 25 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_message_bytes",
            "max_parts",
            "max_depth",
            "max_attachments",
            "max_attachment_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ContractError(f"{name} must be a positive integer")
        if self.max_output_bytes is not None and (
            not isinstance(self.max_output_bytes, int) or self.max_output_bytes < 1
        ):
            raise ContractError("max_output_bytes must be a positive integer or None")

    @property
    def output_limit(self) -> int:
        return self.max_output_bytes or self.max_message_bytes


@dataclass(frozen=True)
class AdapterRequest:
    """One message to process.

    ``unsupported_parts`` decides what happens to file attachments the engine
    does not handle (archives, images, legacy binary Office, and so on).
    ``hold`` is the mandatory-cleaning default: the message waits for an
    operator. ``pass_through`` leaves such parts untouched and still replaces
    the supported ones. Ambiguous, password-protected, oversize, or
    undecodable parts are never passed through.

    ``outbound_marker`` is the header the *transport* wants stamped on a
    released message (the routing exception in Microsoft's add-on topology).
    The adapter strips any inbound copy of it before deciding anything; it
    never treats an inbound marker as evidence of prior processing.
    """

    raw_message: bytes
    envelope: Envelope
    caller: TrustedCallerContext
    policy: PolicyReference
    limits: AdapterLimits = field(default_factory=AdapterLimits)
    unsupported_parts: Literal["hold", "pass_through"] = "hold"
    outbound_marker: tuple[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.raw_message, bytes | bytearray):
            raise ContractError("raw_message must be bytes")
        object.__setattr__(self, "raw_message", bytes(self.raw_message))
        if self.unsupported_parts not in ("hold", "pass_through"):
            raise ContractError("unsupported_parts must be 'hold' or 'pass_through'")


@dataclass(frozen=True)
class AttachmentOutcome:
    """What happened to one selected attachment, keyed by stable part id."""

    part_id: str
    display_name: str | None
    declared_type: str
    detected_format: str
    disposition: Disposition
    reason: str
    source_sha256: str | None = None
    source_bytes: int | None = None
    output_sha256: str | None = None
    output_bytes: int | None = None
    output_name: str | None = None
    verification: Verification = "none"
    evidence_ref: str | None = None
    processor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OutboundMessage:
    raw: bytes
    envelope: Envelope
    sha256: str
    rewritten: bool


@dataclass(frozen=True)
class AdapterResult:
    decision: Decision
    reasons: tuple[str, ...]
    retryable: bool
    attachments: tuple[AttachmentOutcome, ...]
    outbound: OutboundMessage | None
    evidence: dict[str, Any]

    @property
    def releasable(self) -> bool:
        return self.decision == "release" and self.outbound is not None

    def to_dict(self) -> dict[str, Any]:
        outbound: dict[str, Any] | None = None
        if self.outbound is not None:
            outbound = {
                "sha256": self.outbound.sha256,
                "bytes": len(self.outbound.raw),
                "rewritten": self.outbound.rewritten,
                "envelope": {
                    "mail_from": self.outbound.envelope.mail_from,
                    "rcpt_to": list(self.outbound.envelope.rcpt_to),
                },
            }
        return {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "retryable": self.retryable,
            "attachments": [a.to_dict() for a in self.attachments],
            "outbound": outbound,
            "evidence": self.evidence,
        }
