"""RFC 3161 TSA anchor client (spec: docs/rfc3161-anchor-implementation-proposal.md §2-§4).

Stdlib-only by choice, not necessity: the whole client surface is one
HTTP POST of a fixed-shape DER query and a strict read of the reply, so
a purpose-built RFC 3161 package would add a dependency for two dozen
lines (§4.6 asked for the maintenance check to happen at implementation
time -- it did: rfc3161-client brings a transitive tree and no retry
semantics this path needs). The VERIFIER's hand-roll is a different,
stronger constraint (§5: recipients must not need to pip-install to
trust a packet); the client lives in the control plane where
cryptography is already pinned, but urllib is enough here.

The non-blocking contract (§4.5) is the whole point of this module:
request_anchor() NEVER raises into the release path. Any failure --
timeout, HTTP error, TSA refusal, malformed reply, unreachable host --
returns the exact today-shaped unanchored dict after one retry, so a
TSA outage can neither fail nor delay a release. Anchoring is an
enhancement layered on an already-complete, already-signed packet.
"""

from __future__ import annotations

import base64
import hashlib
import os
import urllib.error
import urllib.request

DEFAULT_TSA_URL = "http://timestamp.digicert.com"
# §6: "not vetted for production reliability; operators should configure
# their own TSA relationship." Configurable, never hardcoded at call sites.
DEFAULT_TIMEOUT_S = 5.0
RETRIES = 1  # §4.5: "a single retry" then fall through

UNANCHORED = {"type": "ed25519-operator", "digest": None, "reference": None}

# OID 2.16.840.1.101.3.4.2.1 (SHA-256) in DER. The query carries explicit
# NULL AlgorithmIdentifier parameters: the default DigiCert TSA rejects
# the absent-parameters form with HTTP 400 (confirmed live while
# capturing the fixtures; asn1crypto's default encoder also omits them,
# so this is a real-world variance, not a theoretical one).
_SHA256_OID_DER = bytes.fromhex("0609608648016503040201")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_bool_true() -> bytes:
    # DER encodes BOOLEAN TRUE as exactly 0xFF, never 0x01 or any other nonzero.
    return b"\x01\x01\xff"


def build_timestamp_query(digest: bytes) -> bytes:
    """TimeStampReq ::= SEQUENCE { version 1, messageImprint, certReq TRUE }

    Minimal and nonce-less: the caller is not verifying the reply against
    a remembered nonce (that check happens offline via the pinned cert and
    the imprint itself), so a nonce would only narrow the reply's freedom
    without adding a check this path performs.
    """
    assert len(digest) == 32
    alg = _tlv(0x30, _SHA256_OID_DER + b"\x05\x00")  # SEQUENCE { OID, NULL }
    message_imprint = _tlv(0x30, alg + _tlv(0x04, digest))
    return _tlv(0x30, _tlv(0x02, b"\x01") + message_imprint + _der_bool_true())


def _extract_token(reply: bytes) -> bytes | None:
    """Return the DER TimeStampToken (a ContentInfo) from a TimeStampResp,
    or None if the reply is not a granted response carrying one.

    Strict shape, shallow depth -- this is the CLIENT, whose failure mode
    is "degrade to unanchored", not the verifier's fail-closed parsing;
    the verifier re-parses the token strictly and independently, so a
    lenient read here cannot make a bad token verify (the anchor dict it
    produces is still checked byte-for-byte by the offline verifier).
    """
    try:
        top = _read_tlv(reply)
        if top is None or top[0] != 0x30:
            return None
        fields = _read_children(top[1])
        if len(fields) < 2:
            return None
        status, token = fields[0], fields[1]
        # PKIStatusInfo ::= SEQUENCE { status INTEGER (0 == granted), ... }
        st = _read_children(status[1])
        if not st or st[0][0] != 0x02 or st[0][1] != b"\x00":
            return None
        if token[0] != 0x30:
            return None
        # ContentInfo ::= SEQUENCE { contentType OID (signedData), content [0] }
        ci = _read_children(token[1])
        if len(ci) != 2 or ci[0][0] != 0x06 or ci[1][0] != 0xA0:
            return None
        # The token is the full ContentInfo TLV (header included) -- what
        # "reference" carries and the offline verifier re-parses. Re-slice
        # from the reply: token[1] is the ContentInfo's value, so its DER
        # is (reply, offset-by-header) for exactly len(header)+len(value)
        # bytes. Simpler and unambiguous: recompute from the fields.
        tag_tok = 0x30
        value = token[1]
        if len(value) < 0x80:
            return bytes((tag_tok, len(value))) + value
        raw = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        return bytes((tag_tok, 0x80 | len(raw))) + raw + value
    except Exception:
        return None


def _read_tlv(buf: bytes) -> tuple[int, bytes, int] | None:
    """Strict-ish single TLV read (client-side). Returns (tag, value,
    total_bytes_consumed) or None. Lengths must be definite; indefinite
    (0x80) and reserved (0xFF) forms are rejected."""
    if len(buf) < 2:
        return None
    tag, first = buf[0], buf[1]
    if first < 0x80:
        length, header = first, 2
    elif first in (0x80, 0xFF):
        return None  # indefinite / reserved
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or len(buf) < 2 + n:
            return None
        length = int.from_bytes(buf[2 : 2 + n], "big")
        header = 2 + n
    if length > len(buf) - header:
        return None
    return tag, buf[header : header + length], header + length


def _read_children(buf: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    i = 0
    while i < len(buf):
        tlv = _read_tlv(buf[i:])
        if tlv is None:
            raise ValueError("unparseable element")
        out.append((tlv[0], tlv[1]))
        i += tlv[2]
    return out


def request_anchor(
    signature_bytes: bytes,
    *,
    tsa_url: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict:
    """Timestamp the packet's own Ed25519 signature bytes (§2).

    Returns {"type": "rfc3161-tsa", "digest": <sha256 hex of the signature
    bytes>, "reference": <base64 DER token>} on success, and the exact
    today-shaped UNANCHORED dict on any failure after one retry. Never
    raises: the caller is the release path (§4.5).
    """
    url = tsa_url or os.environ.get("COUNSELCLEAR_TSA_URL") or DEFAULT_TSA_URL
    digest = hashlib.sha256(signature_bytes).digest()
    query = build_timestamp_query(digest)
    token: bytes | None = None
    for attempt in range(1 + RETRIES):
        try:
            req = urllib.request.Request(
                url,
                data=query,
                headers={"Content-Type": "application/timestamp-query"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                if resp.status != 200:
                    continue
                token = _extract_token(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            token = None
        if token is not None:
            return {
                "type": "rfc3161-tsa",
                "digest": digest.hex(),
                "reference": base64.b64encode(token).decode("ascii"),
            }
    return dict(UNANCHORED)
