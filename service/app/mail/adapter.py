"""The mail attachment adapter: parse, select, process, replace, verify.

Decision rules (mandatory-cleaning semantics, the only mode M1 implements):

- ``release`` only when every selected attachment was replaced by a
  processor result that passed :func:`released_result_problem`, the
  rewritten message serialized within the output limit, and parsing that
  serialization back reproduced the expected structure, digests, recipients
  and unrelated headers. ``pass_through`` additionally lets parts the engine
  does not handle at all travel untouched.
- ``hold`` when something needs an operator or a retry: the processor was
  unavailable or failed, a part is unsupported/ambiguous/oversize, the
  message is signed or encrypted, or the rewritten message grew past the
  limit. ``retryable`` is ``True`` only for processor unavailability/failure.
- ``refuse`` for definitive failures: untrusted submission, malformed MIME,
  structural bounds exceeded, a policy refusal, a processor result that
  contradicts the request, an undecodable part, or a rewritten message that
  fails re-verification.

A hold or refusal never carries an outbound message, and no message is ever
released with some attachments replaced and others still pending.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .contract import (
    AdapterLimits,
    AdapterRequest,
    AdapterResult,
    AttachmentOutcome,
    Decision,
    Envelope,
    OutboundMessage,
)
from .mime import (
    MARKER_HEADER_PREFIX,
    Leaf,
    MessageStructure,
    MimeBoundsError,
    decode_leaf,
    header_items,
    line_separator,
    parse_message,
    remove_bcc_header,
    strip_marker_headers,
    walk,
)
from .processor import (
    AttachmentProcessor,
    ProcessorUnavailable,
    ProcessRequest,
    ProcessResult,
    released_result_problem,
    sha256_hex,
)

# Formats the M1 adapter submits to the engine. Everything else is either
# "unsupported" (clearly not one of these) or "ambiguous" (claims to be one
# of these but the bytes disagree). The set is deliberately narrower than
# what engine_api can clean: mail M1 covers ordinary document attachments.
SUPPORTED_FORMATS = frozenset({"docx", "xlsx", "pptx", "pdf"})

EXTENSION_FORMATS = {
    ".docx": "docx",
    ".xlsx": "xlsx",
    ".pptx": "pptx",
    ".pdf": "pdf",
    ".docm": "docm",
    ".dotm": "docm",
    ".xlsm": "xlsm",
    ".xltm": "xlsm",
    ".pptm": "pptm",
    ".doc": "doc",
    ".xls": "xls",
    ".ppt": "ppt",
    ".odt": "odt",
}

CONTENT_TYPE_FORMATS = {
    "application/pdf": "pdf",
    "application/x-pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.ms-word.document.macroenabled.12": "docm",
    "application/vnd.ms-excel.sheet.macroenabled.12": "xlsm",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": "pptm",
    "application/msword": "doc",
    "application/vnd.ms-excel": "xls",
    "application/vnd.ms-powerpoint": "ppt",
    "application/vnd.oasis.opendocument.text": "odt",
}

# Byte-level formats that mean "this is a document container", whatever the
# sender declared. A text or image declaration over these bytes is a conflict.
DOCUMENT_LIKE_FORMATS = SUPPORTED_FORMATS | frozenset(
    {"encrypted_office", "cfbf", "odt", "epub", "docm", "xlsm", "pptm"}
)

# Raster formats the engine's image detector recognises. Only bytes that
# sniff as one of these qualify for the inline-image exemption.
RASTER_IMAGE_FORMATS = frozenset({"png", "jpeg", "webp", "avif", "heic", "bmp", "gif", "tiff"})

_TEXT_MAINTYPE = "text"
_IMAGE_MAINTYPE = "image"

_REFUSING_DISPOSITIONS = frozenset({"refused", "inconsistent", "undecodable"})
_RETRYABLE_DISPOSITIONS = frozenset({"failed", "unavailable"})

Sniffer = Callable[[bytes], str]


def engine_sniff(data: bytes) -> str:
    """Classify attachment bytes with the engine's own container detector,
    deliberately without an extension so the sender's filename cannot steer
    the answer."""
    from container_meta import detect_container_format

    return detect_container_format(Path("input"), data)


def engine_image_sniff(data: bytes) -> str:
    """Raster image format by magic bytes, using the engine's detector."""
    from image_meta import detect_format

    return detect_format(data)


@dataclass(frozen=True)
class _Classified:
    """One leaf after byte-level classification.

    ``role`` is ``body`` (text the recipient reads), ``inline_image`` (raster
    bytes referenced from a body), ``attachment`` (everything that must go
    through format checks and the processor), or ``attached_message``.
    ``data`` is the decoded payload when it was needed for the decision;
    ``None`` means it could not be decoded.
    """

    leaf: Leaf
    role: str
    reason: str
    data: bytes | None = None
    detected: str = ""


def _declared_formats(leaf: Leaf) -> dict[str, str]:
    """Every format assertion the sender made, keyed by where it was made.

    The extension and the media type are checked *independently* against the
    bytes: a recognised filename must not hide a conflicting Content-Type,
    and vice versa. ``text``/``image`` media types are recorded as category
    assertions so a document declared as text or image is a conflict too.
    """
    declared: dict[str, str] = {}
    if leaf.filename:
        ext = Path(leaf.filename).suffix.lower()
        if ext in EXTENSION_FORMATS:
            declared["extension"] = EXTENSION_FORMATS[ext]
    if leaf.content_type in CONTENT_TYPE_FORMATS:
        declared["content_type"] = CONTENT_TYPE_FORMATS[leaf.content_type]
    else:
        maintype = leaf.part.get_content_maintype()
        if maintype in (_TEXT_MAINTYPE, _IMAGE_MAINTYPE):
            declared["content_type"] = maintype
    return declared


# Declared formats the byte sniffer cannot name more precisely: legacy binary
# Office files are all OLE compound files ("cfbf") to the detector.
_COMPATIBLE_DETECTIONS = {"doc": {"cfbf"}, "xls": {"cfbf"}, "ppt": {"cfbf"}}


def _declaration_conflict(declared: dict[str, str], detected: str) -> str | None:
    """Reason text when any sender assertion contradicts the sniffed bytes."""
    for source, claimed in sorted(declared.items()):
        if claimed in (_TEXT_MAINTYPE, _IMAGE_MAINTYPE):
            if detected in DOCUMENT_LIKE_FORMATS:
                return f"declared_{claimed}_{source}_bytes_{detected}"
            continue
        if claimed != detected and detected not in _COMPATIBLE_DETECTIONS.get(claimed, ()):
            return f"declared_{claimed}_{source}_bytes_{detected}"
    return None


def _engine_name(leaf: Leaf, detected: str) -> str:
    if leaf.filename and EXTENSION_FORMATS.get(Path(leaf.filename).suffix.lower()) == detected:
        return leaf.filename
    return f"attachment-{leaf.part_id.replace('.', '-')}.{detected}"


def _normalize_text(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


class MailAdapter:
    """Process messages with an injected :class:`AttachmentProcessor`.

    ``allow_synthetic`` must stay ``False`` outside tests and the labeled
    demo; it is the only way a ``verification="synthetic"`` result can lead
    to a release.
    """

    def __init__(
        self,
        processor: AttachmentProcessor,
        *,
        sniff: Sniffer | None = None,
        image_sniff: Sniffer | None = None,
        allow_synthetic: bool = False,
    ) -> None:
        self._processor = processor
        self._sniff = sniff or engine_sniff
        self._image_sniff = image_sniff or engine_image_sniff
        self._allow_synthetic = allow_synthetic

    # -- classification ---------------------------------------------------

    def _classify(self, leaf: Leaf) -> _Classified:
        """Decide a leaf's role from its bytes, not from what the sender said.

        Only two kinds of part are left untouched: readable body text
        (``text/*`` without a filename whose bytes are not a document
        container) and inline raster images (``image/*`` not sent as an
        attachment, whose bytes sniff as a raster format, and whose filename,
        if any, does not claim a document type). A Content-ID, an ``inline``
        disposition, or a missing filename never exempts a part by itself:
        those are sender-controlled and cost nothing to fabricate.
        """
        if leaf.content_type.startswith("message/"):
            return _Classified(leaf, "attached_message", "attached_message")
        if leaf.disposition == "attachment":
            return _Classified(leaf, "attachment", "disposition_attachment")

        data = decode_leaf(leaf)
        if data is None:
            return _Classified(leaf, "attachment", "payload_not_decodable")
        maintype = leaf.part.get_content_maintype()
        detected = self._sniff(data) if data else "unknown"

        if maintype == _TEXT_MAINTYPE and not leaf.filename_declared:
            if detected in DOCUMENT_LIKE_FORMATS:
                return _Classified(
                    leaf, "attachment", f"declared_text_bytes_{detected}", data, detected
                )
            return _Classified(leaf, "body", "text_body", data, detected)

        if maintype == _IMAGE_MAINTYPE:
            extension_claim = None
            if leaf.filename:
                extension_claim = EXTENSION_FORMATS.get(Path(leaf.filename).suffix.lower())
            raster = self._image_sniff(data) if data else "unknown"
            if raster in RASTER_IMAGE_FORMATS and extension_claim is None:
                return _Classified(leaf, "inline_image", f"raster_{raster}", data, detected)
            return _Classified(leaf, "attachment", f"image_declared_bytes_{raster}", data, detected)

        reason = "filename_declared" if leaf.filename_declared else "binary_without_filename"
        return _Classified(leaf, "attachment", reason, data, detected)

    # -- public -----------------------------------------------------------

    def process(self, request: AdapterRequest) -> AdapterResult:
        limits = request.limits
        evidence: dict[str, Any] = {
            "request_id": request.caller.request_id,
            "tenant_id": request.caller.tenant_id,
            "transport": request.caller.transport,
            "peer_identity": request.caller.peer_identity,
            "policy": {"id": request.policy.policy_id, "version": request.policy.version},
            "processor": getattr(self._processor, "name", type(self._processor).__name__),
            "synthetic_results_allowed": self._allow_synthetic,
            "unsupported_parts": request.unsupported_parts,
            "input_sha256": sha256_hex(request.raw_message),
            "input_bytes": len(request.raw_message),
            "envelope_recipients": len(request.envelope.rcpt_to),
            "limits": {
                "max_message_bytes": limits.max_message_bytes,
                "max_output_bytes": limits.output_limit,
                "max_parts": limits.max_parts,
                "max_depth": limits.max_depth,
                "max_attachments": limits.max_attachments,
                "max_attachment_bytes": limits.max_attachment_bytes,
            },
        }

        if not request.caller.is_trusted():
            return self._terminal("refuse", ["untrusted_submission"], evidence)
        raw = request.raw_message
        if not raw:
            return self._terminal("refuse", ["empty_message"], evidence)
        if len(raw) > limits.max_message_bytes:
            return self._terminal("refuse", ["message_exceeds_limit"], evidence)
        marker_problem = _marker_problem(request.outbound_marker)
        if marker_problem:
            return self._terminal("refuse", [marker_problem], evidence)

        linesep = line_separator(raw)
        evidence["line_separator"] = "CRLF" if linesep == b"\r\n" else "LF"
        msg = parse_message(raw, linesep)
        try:
            structure = walk(msg, limits)
        except MimeBoundsError as exc:
            evidence["bound"] = str(exc)
            return self._terminal("refuse", ["mime_bounds_exceeded"], evidence)
        evidence["part_count"] = structure.part_count
        evidence["depth"] = structure.depth
        if structure.defects:
            evidence["defects"] = list(structure.defects)
            return self._terminal("refuse", ["malformed_mime"], evidence)

        original_root_headers = header_items(msg)
        stripped = strip_marker_headers(msg)
        bcc_removed = remove_bcc_header(msg)
        evidence["stripped_marker_headers"] = stripped
        evidence["bcc_headers_removed"] = bcc_removed

        if structure.signed_or_encrypted:
            evidence["signed_or_encrypted"] = list(structure.signed_or_encrypted)
            return self._terminal("hold", ["signed_or_encrypted_message"], evidence)

        classified = [self._classify(leaf) for leaf in structure.leaves]
        candidates = [c for c in classified if c.role in ("attachment", "attached_message")]
        evidence["leaves"] = [
            {
                "part_id": c.leaf.part_id,
                "content_type": c.leaf.content_type,
                "disposition": c.leaf.disposition,
                "role": c.role,
                "why": c.reason,
                "display_name": c.leaf.filename,
            }
            for c in classified
        ]
        if len(candidates) > limits.max_attachments:
            evidence["attachment_count"] = len(candidates)
            return self._terminal("refuse", ["too_many_attachments"], evidence)

        outcomes: list[AttachmentOutcome] = []
        replacements: dict[str, bytes] = {}
        for candidate in candidates:
            outcome, output = self._handle_attachment(candidate, request)
            outcomes.append(outcome)
            if output is not None:
                replacements[candidate.leaf.part_id] = output

        blocking = [
            o
            for o in outcomes
            if o.disposition != "replaced"
            and not (o.disposition == "unsupported" and request.unsupported_parts == "pass_through")
        ]
        if blocking:
            decision = (
                "refuse"
                if any(o.disposition in _REFUSING_DISPOSITIONS for o in blocking)
                else "hold"
            )
            retryable = decision == "hold" and all(
                o.disposition in _RETRYABLE_DISPOSITIONS for o in blocking
            )
            reasons = [f"{o.disposition}:{o.part_id}" for o in blocking]
            return AdapterResult(
                decision=decision,
                reasons=tuple(reasons),
                retryable=retryable,
                attachments=tuple(outcomes),
                outbound=None,
                evidence=evidence,
            )

        needs_rewrite = bool(replacements or stripped or bcc_removed or request.outbound_marker)
        evidence["rewritten"] = needs_rewrite
        if not needs_rewrite:
            # The output limit applies to every release, including a message
            # that goes out byte-for-byte as it came in.
            evidence["output_bytes"] = len(raw)
            if len(raw) > limits.output_limit:
                return self._terminal(
                    "hold", ["output_exceeds_limit"], evidence, attachments=tuple(outcomes)
                )
            outbound = OutboundMessage(
                raw=raw, envelope=request.envelope, sha256=evidence["input_sha256"], rewritten=False
            )
            evidence["output_sha256"] = outbound.sha256
            return AdapterResult(
                decision="release",
                reasons=(),
                retryable=False,
                attachments=tuple(outcomes),
                outbound=outbound,
                evidence=evidence,
            )

        expected_root_headers = _expected_root_headers(
            original_root_headers, stripped, bcc_removed, request.outbound_marker
        )
        for leaf in structure.leaves:
            if leaf.part_id in replacements:
                _replace_payload(leaf, replacements[leaf.part_id])
        if request.outbound_marker is not None:
            name, value = request.outbound_marker
            msg[name] = value

        out_raw = msg.as_bytes()
        evidence["output_bytes"] = len(out_raw)
        if len(out_raw) > limits.output_limit:
            return self._terminal(
                "hold", ["output_exceeds_limit"], evidence, attachments=tuple(outcomes)
            )

        problems = _verify_serialized(
            out_raw,
            linesep,
            limits,
            structure,
            replacements,
            {o.part_id: o for o in outcomes},
            expected_root_headers,
            request.outbound_marker,
        )
        if problems:
            evidence["verification_problems"] = problems
            return self._terminal(
                "refuse", ["output_verification_failed"], evidence, attachments=tuple(outcomes)
            )

        outbound = OutboundMessage(
            raw=out_raw, envelope=request.envelope, sha256=sha256_hex(out_raw), rewritten=True
        )
        evidence["output_sha256"] = outbound.sha256
        return AdapterResult(
            decision="release",
            reasons=(),
            retryable=False,
            attachments=tuple(outcomes),
            outbound=outbound,
            evidence=evidence,
        )

    # -- internals --------------------------------------------------------

    @staticmethod
    def _terminal(
        decision: Decision,
        reasons: list[str],
        evidence: dict[str, Any],
        *,
        attachments: tuple[AttachmentOutcome, ...] = (),
    ) -> AdapterResult:
        return AdapterResult(
            decision=decision,
            reasons=tuple(reasons),
            retryable=False,
            attachments=attachments,
            outbound=None,
            evidence=evidence,
        )

    def _handle_attachment(
        self, candidate: _Classified, request: AdapterRequest
    ) -> tuple[AttachmentOutcome, bytes | None]:
        leaf = candidate.leaf
        base = AttachmentOutcome(
            part_id=leaf.part_id,
            display_name=leaf.filename,
            declared_type=leaf.content_type,
            detected_format="",
            disposition="unsupported",
            reason="",
        )
        if candidate.role == "attached_message":
            return replace(base, reason="attached_message"), None

        data = candidate.data if candidate.data is not None else decode_leaf(leaf)
        if data is None:
            return replace(base, disposition="undecodable", reason="payload_not_decodable"), None
        source_sha = sha256_hex(data)
        base = replace(base, source_sha256=source_sha, source_bytes=len(data))
        if len(data) > request.limits.max_attachment_bytes:
            return replace(base, disposition="oversize", reason="attachment_exceeds_limit"), None

        detected = candidate.detected or (self._sniff(data) if data else "unknown")
        declared = _declared_formats(leaf)
        base = replace(base, detected_format=detected)
        if detected == "encrypted_office":
            return replace(base, reason="password_protected_office"), None
        conflict = _declaration_conflict(declared, detected)
        if conflict:
            return replace(base, disposition="ambiguous", reason=conflict), None
        if detected not in SUPPORTED_FORMATS:
            # No declaration contradicted the bytes, so whatever was declared
            # agrees that this is not a supported document.
            label = (
                detected if detected != "unknown" else (declared.get("content_type") or "unknown")
            )
            return replace(base, reason=f"format_{label}"), None

        process_request = ProcessRequest(
            part_id=leaf.part_id,
            display_name=leaf.filename,
            engine_name=_engine_name(leaf, detected),
            content=data,
            source_sha256=source_sha,
            detected_format=detected,
            policy=request.policy,
            caller=request.caller,
        )
        try:
            result = self._processor.process(process_request)
        except ProcessorUnavailable as exc:
            return replace(
                base, disposition="unavailable", reason=f"processor_unavailable:{exc}"[:200]
            ), None
        except Exception as exc:
            # Any processor crash is a failed part: the message holds, the
            # original is never released in its place.
            return replace(
                base, disposition="failed", reason=f"processor_error:{type(exc).__name__}"
            ), None
        return self._outcome_from_result(base, process_request, result)

    def _outcome_from_result(
        self, base: AttachmentOutcome, request: ProcessRequest, result: ProcessResult
    ) -> tuple[AttachmentOutcome, bytes | None]:
        if not isinstance(result, ProcessResult):
            return replace(
                base, disposition="inconsistent", reason="processor_returned_wrong_type"
            ), None
        base = replace(
            base,
            processor=result.processor or None,
            evidence_ref=result.evidence_ref,
            verification=result.verification,
        )
        if result.status == "refused":
            return replace(
                base, disposition="refused", reason=result.detail[:200] or "refused"
            ), None
        if result.status == "unavailable":
            return replace(
                base, disposition="unavailable", reason=result.detail[:200] or "unavailable"
            ), None
        if result.status == "failed":
            return replace(base, disposition="failed", reason=result.detail[:200] or "failed"), None
        problem = released_result_problem(request, result, allow_synthetic=self._allow_synthetic)
        if problem:
            return replace(
                base, disposition="inconsistent", reason=problem, verification="none"
            ), None
        assert result.output is not None  # released_result_problem checked this
        return (
            replace(
                base,
                disposition="replaced",
                reason="replaced",
                output_sha256=result.output_sha256,
                output_bytes=result.output_bytes,
                output_name=result.output_name,
            ),
            result.output,
        )


# -- helpers --------------------------------------------------------------


def _marker_problem(marker: tuple[str, str] | None) -> str | None:
    if marker is None:
        return None
    name, value = marker
    if not isinstance(name, str) or not name.lower().startswith(MARKER_HEADER_PREFIX):
        return "invalid_marker_name"
    if not all(ch.isalnum() or ch == "-" for ch in name):
        return "invalid_marker_name"
    if not isinstance(value, str) or not value or any(ch in "\r\n\x00" for ch in value):
        return "invalid_marker_value"
    if len(value) > 998 or not value.isascii():
        return "invalid_marker_value"
    return None


def _expected_root_headers(
    original: list[tuple[str, str]],
    stripped: list[str],
    bcc_removed: int,
    marker: tuple[str, str] | None,
) -> list[tuple[str, str]]:
    expected = [
        (name, value)
        for name, value in original
        if not name.startswith(MARKER_HEADER_PREFIX) and name != "bcc"
    ]
    if marker is not None:
        expected.append((marker[0].lower(), marker[1]))
    return expected


def _replace_payload(leaf: Leaf, output: bytes) -> None:
    part = leaf.part
    del part["Content-Transfer-Encoding"]
    # A digest of the old body would now be wrong; Content-MD5 is obsolete
    # anyway and nothing downstream should rely on it.
    del part["Content-MD5"]
    part["Content-Transfer-Encoding"] = "base64"
    part.set_payload(base64.encodebytes(output).decode("ascii"))


def _verify_serialized(
    out_raw: bytes,
    linesep: bytes,
    limits: AdapterLimits,
    before: MessageStructure,
    replacements: dict[str, bytes],
    outcomes: dict[str, AttachmentOutcome],
    expected_root_headers: list[tuple[str, str]],
    marker: tuple[str, str] | None,
) -> list[str]:
    """Parse the rewritten bytes again and compare with what was intended."""
    problems: list[str] = []
    msg = parse_message(out_raw, linesep)
    try:
        after = walk(msg, limits)
    except MimeBoundsError as exc:
        return [f"rewritten message exceeds bounds: {exc}"]
    if after.defects:
        problems.append(f"rewritten message has defects: {', '.join(after.defects)}")

    if header_items(msg) != expected_root_headers:
        problems.append("top-level headers differ from the expected header set")
    if msg.get_all("Bcc"):
        problems.append("Bcc header present in rewritten message")
    marker_name = marker[0].lower() if marker else None
    for name in msg:
        if name.lower().startswith(MARKER_HEADER_PREFIX) and name.lower() != marker_name:
            problems.append(f"unexpected marker header {name}")

    before_ids = [leaf.part_id for leaf in before.leaves]
    after_ids = [leaf.part_id for leaf in after.leaves]
    if before_ids != after_ids:
        problems.append("MIME leaf structure changed")
        return problems

    for old, new in zip(before.leaves, after.leaves, strict=True):
        if (old.content_type, old.disposition, old.filename) != (
            new.content_type,
            new.disposition,
            new.filename,
        ):
            problems.append(f"part {old.part_id}: content type, disposition or filename changed")
        if old.part_id in replacements:
            expected_sha = outcomes[old.part_id].output_sha256
            payload = decode_leaf(new)
            if payload is None or sha256_hex(payload) != expected_sha:
                problems.append(f"part {old.part_id}: replaced payload digest mismatch")
            if str(new.part.get("Content-Transfer-Encoding", "")).lower() != "base64":
                problems.append(f"part {old.part_id}: replaced payload is not base64")
            old_headers = [
                h
                for h in header_items(old.part)
                if h[0] not in ("content-transfer-encoding", "content-md5")
            ]
            new_headers = [
                h
                for h in header_items(new.part)
                if h[0] not in ("content-transfer-encoding", "content-md5")
            ]
            if old_headers != new_headers:
                problems.append(f"part {old.part_id}: unrelated headers changed")
            continue
        if header_items(old.part) != header_items(new.part):
            problems.append(f"part {old.part_id}: headers changed")
        old_payload = _leaf_bytes(old)
        new_payload = _leaf_bytes(new)
        if old.part.get_content_maintype() == _TEXT_MAINTYPE:
            same = _normalize_text(old_payload) == _normalize_text(new_payload)
        else:
            same = old_payload == new_payload
        if not same:
            problems.append(f"part {old.part_id}: payload changed")
    return problems


def _leaf_bytes(leaf: Leaf) -> bytes:
    if leaf.content_type.startswith("message/"):
        return leaf.part.as_bytes()
    payload = leaf.part.get_payload(decode=True)
    return bytes(payload) if isinstance(payload, bytes | bytearray) else b""


__all__ = [
    "CONTENT_TYPE_FORMATS",
    "EXTENSION_FORMATS",
    "SUPPORTED_FORMATS",
    "Envelope",
    "MailAdapter",
    "engine_sniff",
]
