"""Bounded, defect-aware MIME walking for the mail adapter.

Parts are identified by their position in the MIME tree (``"2"``,
``"2.3"``, ... in IMAP section style; a single-part message is ``"1"``).
That identity is stable across re-serialization, which is what lets the
adapter match a processor's result back to the part it came from and verify
the rewritten message by parsing it again. Filenames are decoded only for
display and classification; they are never used as paths.
"""

from __future__ import annotations

import email.policy
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from pathlib import PurePosixPath, PureWindowsPath

from .contract import AdapterLimits

SIGNED_OR_ENCRYPTED_CONTENT_TYPES = frozenset(
    {
        "multipart/signed",
        "multipart/encrypted",
        "application/pkcs7-mime",
        "application/x-pkcs7-mime",
        "application/pkcs7-signature",
        "application/x-pkcs7-signature",
        "application/pgp-encrypted",
        "application/pgp-signature",
    }
)

MARKER_HEADER_PREFIX = "x-counselclear-"

_CONTROL_CHARS = frozenset(chr(c) for c in range(32)) | {chr(127)}
# Characters no supported filesystem accepts in a name. They are replaced,
# not stripped, so "a<b>.docx" and "ab.docx" stay distinguishable.
_RESERVED_NAME_CHARS = frozenset('<>:"|?*')
_MAX_DISPLAY_NAME = 150


class MimeBoundsError(ValueError):
    """The message exceeds a configured structural bound."""


def line_separator(raw: bytes) -> bytes:
    """CRLF when the first line ends that way, else LF. Used to serialize the
    rewritten message with the line ending the sender's transport used."""
    first, _, _ = raw.partition(b"\n")
    return b"\r\n" if first.endswith(b"\r") else b"\n"


def message_policy(linesep: bytes) -> email.policy.EmailPolicy:
    # refold_source="none": headers that came from the source are emitted
    # with their original folding, so unrelated headers survive byte-for-byte
    # in the common case. Headers the adapter sets itself are folded by the
    # policy. raise_on_defect stays False so defects are *collected* and the
    # adapter can refuse the message with a list instead of an exception.
    return email.policy.SMTP.clone(refold_source="none", linesep=linesep.decode("ascii"))


def parse_message(raw: bytes, linesep: bytes) -> Message:
    return BytesParser(policy=message_policy(linesep)).parsebytes(raw)


def sanitize_display_name(raw: str | None) -> str | None:
    """A filename suitable for display and extension lookup: last path
    component only, no control or filesystem-reserved characters, bounded
    length. Never a path: the engine processor writes it under a private
    temporary directory it created itself."""
    if raw is None:
        return None
    text = str(raw)
    text = PureWindowsPath(text.replace("\\", "/")).name
    text = PurePosixPath(text).name
    text = "".join(ch for ch in text if ch not in _CONTROL_CHARS)
    text = "".join("_" if ch in _RESERVED_NAME_CHARS else ch for ch in text).strip()
    if text in ("", ".", ".."):
        return None
    if len(text) > _MAX_DISPLAY_NAME:
        stem, dot, ext = text.rpartition(".")
        if dot and 0 < len(ext) <= 12:
            text = stem[: _MAX_DISPLAY_NAME - len(ext) - 1] + "." + ext
        else:
            text = text[:_MAX_DISPLAY_NAME]
    return text


@dataclass(frozen=True)
class Leaf:
    part_id: str
    part: Message
    depth: int
    content_type: str
    disposition: str | None
    filename: str | None
    filename_declared: bool
    content_id: str | None
    ancestors: tuple[str, ...]


@dataclass(frozen=True)
class MessageStructure:
    leaves: tuple[Leaf, ...]
    part_count: int
    depth: int
    defects: tuple[str, ...]
    signed_or_encrypted: tuple[str, ...]


def _header_defects(part: Message, part_id: str) -> list[str]:
    found: list[str] = []
    for name in ("Content-Type", "Content-Disposition", "Content-Transfer-Encoding"):
        header = part.get(name)
        for defect in getattr(header, "defects", ()):
            found.append(f"{part_id or 'root'}:{name}:{type(defect).__name__}")
    return found


def walk(msg: Message, limits: AdapterLimits) -> MessageStructure:
    """Enumerate leaves depth-first, enforcing part-count and depth bounds.

    Raises :class:`MimeBoundsError` as soon as a bound is exceeded so a
    hostile message cannot make the adapter enumerate an unbounded tree.
    """
    leaves: list[Leaf] = []
    defects: list[str] = []
    signed: list[str] = []
    count = 0
    max_depth = 0

    def visit(part: Message, part_id: str, depth: int, ancestors: tuple[str, ...]) -> None:
        nonlocal count, max_depth
        count += 1
        if count > limits.max_parts:
            raise MimeBoundsError(f"more than {limits.max_parts} MIME parts")
        if depth > limits.max_depth:
            raise MimeBoundsError(f"MIME nesting deeper than {limits.max_depth}")
        max_depth = max(max_depth, depth)
        label = part_id or "root"
        defects.extend(f"{label}:{type(d).__name__}" for d in part.defects)
        defects.extend(_header_defects(part, part_id))

        content_type = part.get_content_type()
        if content_type in SIGNED_OR_ENCRYPTED_CONTENT_TYPES:
            signed.append(f"{label}:{content_type}")

        leaf_id = part_id or "1"
        if part.get_content_maintype() == "message":
            # An attached message is reported as a leaf and never descended:
            # its inner attachments would need their own custody story.
            leaves.append(_leaf(part, leaf_id, depth, content_type, ancestors))
            return
        if part.is_multipart():
            children = part.get_payload()
            if not isinstance(children, list):
                defects.append(f"{label}:MultipartWithoutSubparts")
                return
            for index, child in enumerate(children, 1):
                child_id = f"{part_id}.{index}" if part_id else str(index)
                visit(child, child_id, depth + 1, (*ancestors, content_type))
            return
        leaves.append(_leaf(part, leaf_id, depth, content_type, ancestors))

    visit(msg, "", 0, ())
    return MessageStructure(
        leaves=tuple(leaves),
        part_count=count,
        depth=max_depth,
        defects=tuple(defects),
        signed_or_encrypted=tuple(signed),
    )


def _leaf(
    part: Message, part_id: str, depth: int, content_type: str, ancestors: tuple[str, ...]
) -> Leaf:
    try:
        raw_name = part.get_filename()
    except (ValueError, TypeError, LookupError):
        raw_name = None
    content_id = part.get("Content-ID")
    return Leaf(
        part_id=part_id,
        part=part,
        depth=depth,
        content_type=content_type,
        disposition=part.get_content_disposition(),
        filename=sanitize_display_name(raw_name),
        filename_declared=raw_name is not None,
        content_id=str(content_id) if content_id is not None else None,
        ancestors=ancestors,
    )


def decode_leaf(leaf: Leaf) -> bytes | None:
    """Decoded payload bytes, or ``None`` when the part cannot be decoded.

    ``get_payload(decode=True)`` records base64/quoted-printable defects on
    the part; callers re-check ``leaf.part.defects`` afterwards.
    """
    before = len(leaf.part.defects)
    try:
        payload = leaf.part.get_payload(decode=True)
    except (ValueError, TypeError, LookupError):
        return None
    if len(leaf.part.defects) > before or not isinstance(payload, bytes | bytearray):
        return None
    return bytes(payload)


def header_items(part: Message) -> list[tuple[str, str]]:
    """Header names and unfolded values in order, for before/after comparison."""
    return [(name.lower(), str(value)) for name, value in part.items()]


def strip_marker_headers(msg: Message) -> list[str]:
    """Remove every ``X-CounselClear-*`` header from the top-level message.

    Any such header on an inbound message is sender-controlled (or copied
    from an earlier delivery) and carries no evidence. Removing it also
    keeps a spoofed marker from surviving into the delivered copy.
    """
    removed: list[str] = []
    for name in list(msg.keys()):
        if name.lower().startswith(MARKER_HEADER_PREFIX):
            removed.append(name)
            del msg[name]
    return removed


def remove_bcc_header(msg: Message) -> int:
    """Drop any ``Bcc`` header. Bcc recipients live in the envelope only."""
    count = len(msg.get_all("Bcc", []))
    if count:
        del msg["Bcc"]
    return count
