#!/usr/bin/env python3
"""CounselClear release-packet / release-result verifier (PR 37, PR 39).

Offline, stdlib-only, no engine/app dependency: recomputes every content
hash a manifest declares against the bytes actually present, checks
required fields, cross-checks a few identifiers between JSON documents
where practical, and reports plainly what it could and could not verify
-- most importantly, what binds a packet beyond its own claims: an
exported audit chain (--audit-csv) and an Ed25519 custody signature
(--public-key), both optional, both reported honestly when absent.

Two artifact shapes, three entry points:

- `verify_release_packet()` -- a full release packet (.zip or extracted
  directory): derivative + manifest.json + report.json + certificate.html
  + release_packet.json + README.txt. Only exists for a `done` release.
  Also schema-pin-checks every member that declares schema_version +
  schema_sha256 (PR 63; see "Schema pins" below).
- `verify_release_result()` -- `release_result.json` on its own (a bare
  file, or a directory containing it and optionally a sibling
  certificate.html): the lightweight artifact PR 39's Release object
  produces for EVERY terminal release, including a refused or failed one
  that never gets a full packet.
- `verify_release_packet_and_result()` (PR 44) -- when a directory
  contains BOTH artifacts (e.g. the Airlock CLI's own done-release
  output since PR 43), verifies each independently AND cross-checks
  that they agree on release_id/job_id/document_id/matter_id/status/
  policy or profile/original_sha256/limitations. Never silently picks
  one artifact and ignores the other; a disagreement fails loudly.
  `main()` below auto-detects which of the three shapes it was handed.

This tool makes NO network calls, imports NOTHING from service/app or
service/scripts, and never touches a database. It only ever reads bytes
handed to it on the local filesystem. See
docs/release-packet-verification-and-anchoring-proposal.md for the design
this implements, and docs/counselclear-strategy.md point 4 for why a
verifier -- which sits outside the engine/control-plane boundary
entirely, on the client side of both -- still holds to the same
no-hidden-dependency discipline.

Usage::

    python3 tools/counselclear_verify_release_packet.py <path>

<path> is a release-packet .zip, a directory it was extracted into, a
bare release_result.json file, or a directory containing one.

Two optional cross-checks bind the packet to something beyond itself:

- ``--audit-csv <export.csv>`` (MUST-1): a matter's exported audit chain
  (GET /v1/matters/{id}/audit/export). Every chain row's hash is
  independently recomputed and the declared manifest/derivative hashes
  are checked against the chain-committed values -- so a manifest
  altered before packet assembly fails instead of re-hashing clean.
- ``--public-key <key.pem>`` (MUST-2, repeatable): the deployment's
  custody public key (GET /v1/custody-public-key, or 64-char hex).
  Verifies the packet's Ed25519 signature over its canonical bytes.
  ``--verify-signature`` escalates signature downgrades (unsigned, no
  key, unknown key) to failures, for when a signature is required.

Exit code 0: every check that could run, passed (still prints the
"NOT EXTERNALLY ANCHORED" notice -- that's not a failure, it's an honest
statement about what this release does not yet do). Exit code 1: at
least one check failed (a missing file, a hash mismatch, a schema
problem, or a cross-check disagreement).

Schema pins (PR 63): every artifact an emitter stamps with
schema_version + schema_sha256 names the published contract it was
built against. When present, the pin's hash is recomputed against the
schema file shipped alongside this verifier and a disagreement fails
the packet -- a bundle built against a different contract can never
re-hash clean against the published one. An artifact with no pin
predates pinning: reported as "unavailable", never a failure, so
pre-PR-63 packets keep verifying.

Top-line wording: a packet or result carrying a `release_id` (PR 39's
Release-aware artifacts -- which is every one this tool now produces)
is reported as INTERNALLY CONSISTENT / INTERNALLY INCONSISTENT, never
VALID/INVALID -- "valid" reads too easily as "verified authentic", which
this tool never claims. A legacy packet with no release_id (produced by
the unwrapped /sanitize-jobs route, pre-Release) keeps the older
VALID/INVALID wording it always had, unchanged.

Certificate verification: this tool hash-checks certificate.html's bytes
against the declared certificate_html_sha256 and stops there -- it does
NOT grep the certificate's rendered HTML for substrings that happen to
match a manifest field (a prior version of this tool did; that was
removed, since a hash match already proves the HTML is byte-identical to
what was declared, and a substring match proves nothing a hash check
doesn't already prove more strongly). release_packet.json /
release_result.json are the authoritative source of facts; certificate.html
is verified for integrity, not re-parsed for meaning.

Anchor status: a packet's anchor.type is "none" only for legacy packets
(pre-PR 57); new packets carry "ed25519-operator" -- the deployment's
custody key's signature over the packet's canonical bytes, checkable
offline with --public-key. That is an OPERATOR signature (the producing
system vouching for its own output). When RFC 3161 TSA anchoring
succeeded at creation time (docs/rfc3161-anchor-implementation-
proposal.md), the anchor is "rfc3161-tsa": a TimeStampToken whose
messageImprint covers the sha256 of the packet's own Ed25519 signature
bytes, verified offline against the TSA signing certificate pinned in
this tool (--tsa-cert adds pins). A TSA token attests WHEN a digest
existed, by the TSA's own clock -- it is not a transparency log and it
does not make content unforgeable. This tool will never print
"unforgeable", "independently timestamped", "court-proof", or
"unimpeachable", and never the bare word "VALID" for a Release-aware
artifact -- see that proposal's §7. The only claims it makes are the
narrower ones that are actually true: internal hash consistency,
recomputed independently of the system that produced it, plus -- with
--public-key -- that the packet's Ed25519 signature checks out under
the key the operator handed you, which authenticates the packet's
ORIGIN, not its timestamp.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "service" / "scripts" / "schemas"

_FALLBACK_RELEASE_PACKET_FIELDS = (
    "spec_version",
    "packet_id",
    "release_id",
    "matter_id",
    "document_id",
    "job_id",
    "kind",
    "status",
    "policy",
    "hashes",
    "audit_refs",
    "legal_justifications",
    "limitations",
    "generated_at",
    "generated_by",
    "anchor",
    # PR 39: original_sha256 travels at the top level -- binding original
    # to derivative never requires opening manifest.json's own nested
    # copy first. release_id is required but nullable (null for a legacy
    # packet with no Release wrapper) -- see verify_release_packet.
    "original_sha256",
)

REQUIRED_SIBLING_FILES = ("manifest.json", "report.json", "certificate.html", "README.txt")


def _published_schema_sha256(schema_name: str) -> str | None:
    """sha256 of the shipped schema file's bytes, or None when the
    schema file isn't deployed alongside this verifier. The pin's whole
    meaning is 'the artifact was built against THIS published contract',
    so the comparison target is the file shipped here, recomputed -- never
    a hash hardcoded in this tool, which could drift from the file it
    claims to describe. Stdlib-only, same as the rest of this module."""
    try:
        return _sha256((SCHEMA_DIR / schema_name).read_bytes())
    except OSError:
        return None


# Which artifact members get a schema-pin cross-check, and against which
# published schema. Keys are packet member names; the artifact json is
# parsed from those members. report.json is only produced for a done
# release's packet, and manifest.json likewise only exists for a
# sanitize job with a bundle -- an absent member is "unavailable", not
# a failure, mirroring how the packet-vs-result agreement treats fields
# not present on both sides.
_SCHEMA_PINNED_MEMBERS = {
    "release_packet.json": "release_packet.schema.json",
    "manifest.json": "manifest.schema.json",
    "report.json": "report.schema.json",
}


def _schema_pin_cross_checks(
    artifacts: dict[str, dict],
) -> tuple[list[CrossCheck], list[str]]:
    """One cross-check per member declaring a schema pin: the artifact's
    schema_sha256 vs this verifier's own recomputation from the
    published schema file. Returns (cross_checks, errors) -- errors
    carries the schema-pin violations that belong to the required-field
    check (a declared hash without its schema_version is half a claim;
    the verifier must not guess which contract was meant), while the
    check proper reports match/mismatch/unavailable.

    Backward compatibility, same discipline as attestation/
    predecessor_release_id: an artifact carrying no pin at all
    predates pinning and reports "unavailable" -- never a failure."""
    checks: list[CrossCheck] = []
    errors: list[str] = []
    for member, schema_name in _SCHEMA_PINNED_MEMBERS.items():
        artifact = artifacts.get(member)
        if not isinstance(artifact, dict):
            continue
        declared = artifact.get("schema_sha256")
        version = artifact.get("schema_version")
        label = f"{member} vs published schema"
        if declared is None and version is None:
            checks.append(
                CrossCheck(
                    f"schema_sha256 ({label})",
                    "unavailable",
                    "artifact predates schema pinning (no schema_version/schema_sha256 declared)",
                )
            )
            continue
        if version is None:
            errors.append(
                f"{member} declares schema_sha256 without schema_version -- "
                "the pin is incomplete; refusing to guess which contract was meant"
            )
            continue
        expected = _published_schema_sha256(schema_name)
        if expected is None:
            checks.append(
                CrossCheck(
                    f"schema_sha256 ({label})",
                    "unavailable",
                    f"published schema file {schema_name} not shipped with this verifier",
                )
            )
            continue
        status = "match" if declared == expected else "mismatch"
        detail = "" if status == "match" else (
            "artifact was built against a different contract than the published "
            f"{schema_name} shipped with this verifier"
        )
        checks.append(
            CrossCheck(f"schema_sha256 ({label})", status, detail)
        )
    return checks, errors

# PR 39: release_result.json's own required fields -- a much smaller,
# derivative-free artifact than release_packet.json, produced for EVERY
# terminal release (done, refused, or failed), not just a successful one.
_FALLBACK_RELEASE_RESULT_FIELDS = (
    "spec_version",
    "release_id",
    "job_id",
    "document_id",
    "matter_id",
    "status",
    "policy_id",
    "profile_id",
    "recipient_type",
    "recipient_name",
    "purpose",
    "intended_external",
    "reason",
    "original_sha256",
    "created_at",
    "finished_at",
    "audit_refs",
    "legal_justifications",
    "limitations",
    "certificate_html_sha256",
    "generated_at",
    "anchor",
)


def _required_fields_from_schema(schema_name: str, fallback: tuple[str, ...]) -> tuple[str, ...]:
    """The verifier stays stdlib-only, but its required-field check should
    track the published schema files when they are available."""
    try:
        schema = json.loads((SCHEMA_DIR / schema_name).read_text())
    except (OSError, json.JSONDecodeError):
        return fallback
    required = schema.get("required")
    if not isinstance(required, list) or not all(isinstance(x, str) for x in required):
        return fallback
    return tuple(required)


REQUIRED_MANIFEST_FIELDS = _required_fields_from_schema(
    "release_packet.schema.json", _FALLBACK_RELEASE_PACKET_FIELDS
)
REQUIRED_RELEASE_RESULT_FIELDS = _required_fields_from_schema(
    "release_result.schema.json", _FALLBACK_RELEASE_RESULT_FIELDS
)


class PacketLoadError(Exception):
    """Raised when the packet can't even be opened/read -- not a
    verification failure of its content, a failure to get that far."""


@dataclass
class FileCheck:
    name: str
    status: str  # "match" | "mismatch" | "missing" | "ambiguous"
    detail: str = ""


@dataclass
class CrossCheck:
    name: str
    status: str  # "match" | "mismatch" | "unavailable"
    detail: str = ""


def _anchor_note(anchor_type: str | None, *, artifact: str) -> str:
    """Shared by both report types' to_text() -- the exact same honest
    disclaimer either way, never duplicated with a subtle wording drift
    between the packet verifier and the result verifier."""
    if anchor_type == "ed25519-operator":
        # PR 57 (MUST-2): an operator signature binds the packet's bytes
        # to the deployment's key, but it is the producing system
        # vouching for its own output -- the same self-attestation, one
        # cryptographically stronger, and still no independent party
        # confirming the content existed at the claimed time. The
        # disclaimer must survive the anchor upgrade or the tool starts
        # overstating what an operator signature proves.
        return (
            f"  NOT EXTERNALLY ANCHORED. The Ed25519 signature on this {artifact} is\n"
            "  an OPERATOR signature -- the producing system vouching for its own\n"
            "  output. No independent party has confirmed this content existed at\n"
            f"  the claimed time. The checks above confirm internal hash consistency\n"
            f"  (and, with --public-key, the operator signature); neither makes this\n"
            "  externally timestamped or unforgeable by the operator's own key."
        )
    if anchor_type in (None, "none"):
        return (
            f"  NOT EXTERNALLY ANCHORED. This {artifact}'s timestamp and content are\n"
            "  self-attested by the system that produced it. No independent party\n"
            "  has confirmed this content existed at the claimed time. The checks\n"
            f"  above confirm internal hash consistency only -- that the bytes in\n"
            f"  this {artifact} match what it itself declares -- not that its own\n"
            "  claims are independently timestamped or unforgeable."
        )
    if anchor_type == "rfc3161-tsa":
        return (
            f"  RFC 3161 TSA anchor: the reference is a TimeStampToken whose\n"
            f"  messageImprint is the sha256 of this {artifact}'s own Ed25519\n"
            "  signature bytes. The token's RSA signature was checked against\n"
            "  the TSA signing certificate pinned in this verifier; the token\n"
            "  asserts that digest existed at its genTime -- a time asserted by\n"
            "  the TSA's own clock, not this system's. A TSA timestamp attests\n"
            "  WHEN a digest existed; it does not make the packet unforgeable,\n"
            "  court-proof, or unimpeachable, and it does not vouch for the\n"
            "  derivative's content or the audit chain."
        )
    return f"  anchor reference: (type={anchor_type})"


# Shared by both report types, same reasoning as _anchor_note above: this
# tool has no database access, so audit_refs' seq numbers (bundle_
# download_seq / certificate_issued_seq / release_created_seq /
# release_terminal_seq, depending on artifact type) are declared facts,
# never independently confirmed the way a file hash is. Without this
# line, "every file check: ok" could read as "the whole packet was
# confirmed", which overstates what an offline, no-network tool can
# actually do for a claim that only the live audit chain can settle.
_AUDIT_REFS_NOTE = (
    "  audit_refs cites seq numbers in the matter's own tamper-evident audit\n"
    "  chain -- this tool has no database access, so those numbers are declared\n"
    "  here, not verified. Cross-check them against the real chain with\n"
    "  GET /v1/matters/{id}/audit."
)


_SIGNATURE_MARKERS = {
    "verified": "VERIFIED",
    "unsigned": "UNSIGNED (packet predates signatures)",
    "no_key": "NOT VERIFIED (no --public-key given)",
    "unknown_key": "NOT VERIFIED (key not provided)",
    "mismatch": "MISMATCH",
}


@dataclass
class VerificationReport:
    valid: bool
    schema_ok: bool
    file_checks: list[FileCheck] = field(default_factory=list)
    cross_checks: list[CrossCheck] = field(default_factory=list)
    anchor_type: str | None = None
    release_id: str | None = None
    errors: list[str] = field(default_factory=list)
    # MUST-1: the audit-chain cross-check's own outcome + the two
    # hash comparisons against it, so the chain section renders one
    # block and the comparisons render as ordinary cross-checks.
    audit_chain: AuditChainCheck | None = None
    chain_hash_checks: list[CrossCheck] = field(default_factory=list)
    # MUST-2: the packet-signature verdict -- its own field, not a
    # cross_check, because the signature is a claim about the packet's
    # ORIGIN (which operator's key vouches for it), not an agreement
    # between two in-packet fields.
    signature_status: str | None = None
    signature_detail: str = ""
    # RFC 3161 TSA anchor verification (rfc3161-tsa anchors only).
    anchor: TSAAnchorCheck | None = None

    def to_text(self) -> str:
        lines: list[str] = []
        # PR 39: a Release-aware packet (release_id present) is never
        # reported "VALID" -- see the module docstring's "Top-line
        # wording" section. A legacy, pre-Release packet keeps the
        # original wording unchanged.
        if self.release_id:
            lines.append("INTERNALLY CONSISTENT" if self.valid else "INTERNALLY INCONSISTENT")
        else:
            lines.append("VALID" if self.valid else "INVALID")
        lines.append("")
        lines.append("What was verified:")
        lines.append(f"  schema (required release_packet.json fields present): "
                      f"{'ok' if self.schema_ok else 'FAILED'}")
        for fc in self.file_checks:
            marker = {
                "match": "ok", "mismatch": "MISMATCH", "missing": "MISSING", "ambiguous": "AMBIGUOUS",
            }[fc.status]
            lines.append(f"  {fc.name}: {marker}" + (f" -- {fc.detail}" if fc.detail else ""))
        if self.cross_checks:
            lines.append("")
            lines.append("Cross-checks (release_packet.json vs. manifest.json and published schemas):")
            for cc in self.cross_checks:
                marker = {"match": "ok", "mismatch": "MISMATCH", "unavailable": "not checkable"}[cc.status]
                lines.append(f"  {cc.name}: {marker}" + (f" -- {cc.detail}" if cc.detail else ""))
        # MUST-2: the signature verdict gets its own line, never folded
        # into the file checks -- the signature is a claim about the
        # packet's origin (which custody key vouches for it), not a
        # member of the packet agreeing with itself. "VERIFIED" only for
        # a checked-out signature; never the word "VALID" for the same
        # honesty reasons as the top line (see module docstring).
        if self.signature_status is not None:
            lines.append("")
            lines.append("Signature:")
            marker = _SIGNATURE_MARKERS[self.signature_status]
            lines.append(f"  {marker}" + (f" -- {self.signature_detail}" if self.signature_detail else ""))
            if self.signature_status == "mismatch":
                lines.append(
                    "  signature check FAILED: the packet does not verify under the"
                    " key it names -- treat as tampered, not as a signing-key glitch."
                )
        lines.append("")
        # "no" for every self-attestation form: an operator signature
        # (ed25519-operator) is the producing system vouching for its
        # own output -- stronger self-attestation, not external
        # anchoring. An rfc3161-tsa anchor is external only when it
        # actually VERIFIED; a failed anchor claim is "CLAIMED", never
        # silently rendered as established.
        if self.anchor_type == "rfc3161-tsa":
            if self.anchor is not None and self.anchor.status == "verified":
                lines.append(
                    f"Externally anchored: yes (rfc3161-tsa) -- TimeStampToken verified "
                    f"under a pinned TSA certificate, genTime {self.anchor.gen_time}"
                )
            else:
                lines.append("Externally anchored: CLAIMED (rfc3161-tsa) -- anchor NOT verified (see RFC 3161 TSA anchor section)")
        elif self.anchor_type not in (None, "none", "ed25519-operator"):
            lines.append(f"Externally anchored: yes ({self.anchor_type})")
        else:
            lines.append("Externally anchored: no")
        lines.append(_anchor_note(self.anchor_type, artifact="packet"))
        if self.anchor is not None and self.anchor_type == "rfc3161-tsa":
            lines.append("")
            lines.append("RFC 3161 TSA anchor:")
            marker = {
                "verified": "VERIFIED",
                "unrecognized_tsa_certificate": "UNRECOGNIZED TSA CERTIFICATE",
                "cannot_verify": "CANNOT VERIFY ANCHOR",
            }[self.anchor.status]
            lines.append(f"  {marker}")
            lines.append(f"  {self.anchor.detail}")
        if self.audit_chain is not None:
            lines.append(self.audit_chain.to_text())
            for cc in self.chain_hash_checks:
                marker = {"match": "ok", "mismatch": "MISMATCH", "unavailable": "not checkable"}[cc.status]
                lines.append(f"  {cc.name}: {marker}" + (f" -- {cc.detail}" if cc.detail else ""))
            if self.audit_chain.provided and (
                not self.audit_chain.chain_ok or any(cc.status == "mismatch" for cc in self.chain_hash_checks)
            ):
                lines.append(
                    "  chain cross-check FAILED: the packet disagrees with the"
                    " chain-committed hashes (or the chain itself failed"
                    " verification) -- treat this packet as tampered, not as"
                    " an internally-consistent release."
                )
        else:
            lines.append(_AUDIT_REFS_NOTE)
        if self.errors:
            lines.append("")
            lines.append("Errors:")
            for e in self.errors:
                lines.append(f"  - {e}")
        return "\n".join(lines)


@dataclass
class ReleaseResultReport:
    """verify_release_result()'s own report -- deliberately smaller than
    VerificationReport: release_result.json has no derivative, no
    manifest.json, no report.json to cross-check against, just itself
    and an optional sibling certificate.html."""

    valid: bool
    schema_ok: bool
    file_checks: list[FileCheck] = field(default_factory=list)
    anchor_type: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        lines: list[str] = []
        # Always the conservative wording -- release_result.json is a
        # Release-aware artifact by definition, never legacy.
        lines.append("INTERNALLY CONSISTENT" if self.valid else "INTERNALLY INCONSISTENT")
        lines.append("")
        lines.append("What was verified:")
        lines.append(
            f"  schema (required release_result.json fields present): "
            f"{'ok' if self.schema_ok else 'FAILED'}"
        )
        for fc in self.file_checks:
            marker = {
                "match": "ok", "mismatch": "MISMATCH", "missing": "MISSING", "ambiguous": "AMBIGUOUS",
            }[fc.status]
            lines.append(f"  {fc.name}: {marker}" + (f" -- {fc.detail}" if fc.detail else ""))
        lines.append("")
        # Same rendering rule as VerificationReport above: an operator
        # signature is not external anchoring.
        _external = self.anchor_type not in (None, "none", "ed25519-operator")
        lines.append(f"Externally anchored: {'yes (' + self.anchor_type + ')' if _external else 'no'}")
        lines.append(_anchor_note(self.anchor_type, artifact="release result"))
        lines.append(_AUDIT_REFS_NOTE)
        if self.errors:
            lines.append("")
            lines.append("Errors:")
            for e in self.errors:
                lines.append(f"  - {e}")
        return "\n".join(lines)


def _load_packet_files(path: Path) -> dict[str, bytes]:
    """Returns {relative_path: bytes} for every file in the packet,
    whether *path* is a zip or an already-extracted directory."""
    if path.is_dir():
        return {
            str(p.relative_to(path)): p.read_bytes()
            for p in sorted(path.rglob("*"))
            if p.is_file()
        }
    if path.is_file():
        try:
            with zipfile.ZipFile(path) as zf:
                return {name: zf.read(name) for name in zf.namelist() if not name.endswith("/")}
        except zipfile.BadZipFile as e:
            raise PacketLoadError(f"{path} is not a valid zip file: {e}") from e
    raise PacketLoadError(f"{path} does not exist")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- Ed25519 packet-signature verification (MUST-2, 2026-08-29) ---------------
#
# The server signs release_packet.json with an Ed25519 keypair
# (service/app/security.py::sign_release_packet); this section verifies
# those signatures offline. The verifier stays stdlib-only by design
# (tests/test_release_packet_verifier.py pins its import surface), so
# Ed25519 verification is implemented here directly per RFC 8032 §5.1 --
# the same reference construction the RFC itself publishes. The
# app-side sign path uses the cryptography library; this verify path
# was cross-checked against it live (valid/tampered/wrong-key vectors)
# during development, and test_signature_cross_checks_against_cryptography
# keeps that pinned in CI where the library is importable.

_ED_P = 2**255 - 19
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_Q = 2**252 + 27742317777372353535851937790883648493
_ED_BASE_Y = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P


def _ed_inv(x: int) -> int:
    return pow(x, _ED_P - 2, _ED_P)


def _ed_recover_x(y: int, sign: int) -> int | None:
    xx = (y * y - 1) * _ed_inv(_ED_D * y * y + 1) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    if (x * x - xx) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_ED_BASE_X = _ed_recover_x(_ED_BASE_Y, 0) or 0


def _ed_point_add(P, Q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = P, Q
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_scalarmult(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_point_add(Q, P)
        P = _ed_point_add(P, P)
        s >>= 1
    return Q


def _ed_decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _ed_decodepoint(s: bytes):
    y = int.from_bytes(s[:32], "little") & ((1 << 255) - 1)
    x = _ed_recover_x(y, s[31] >> 7)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED_P)


_ED_BASE = (_ED_BASE_X, _ED_BASE_Y, 1, _ED_BASE_X * _ED_BASE_Y % _ED_P)


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1 reference verification. Returns False for any
    malformed input, wrong key, or altered message/signature -- never
    raises, so a hostile packet's garbage produces a deterministic
    'signature does not verify' verdict instead of a traceback."""
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _ed_decodepoint(public)
    if A is None:
        return False
    R = _ed_decodepoint(signature[:32])
    if R is None:
        return False
    S = _ed_decodeint(signature[32:])
    if S >= _ED_Q:
        return False
    h = _ed_decodeint(hashlib.sha512(signature[:32] + public + msg).digest()) % _ED_Q
    left = _ed_scalarmult(S, _ED_BASE)
    right = _ed_point_add(R, _ed_scalarmult(h, A))
    return (
        (left[0] * right[2] - right[0] * left[2]) % _ED_P == 0
        and (left[1] * right[2] - right[1] * left[2]) % _ED_P == 0
    )


def _parse_public_key_pem(pem_text: str) -> bytes:
    """Accept either a raw 32-byte hex string (the compact bundle form)
    or a SubjectPublicKeyInfo PEM (what GET /v1/custody-public-key and
    the operator's key file carry). Returns the 32 raw bytes Ed25519
    keys verify against. Raises ValueError on anything it can't parse
    -- a bad key is an operator error the CLI should report, not a
    packet verdict."""
    pem_text = pem_text.strip()
    if len(pem_text) == 64:
        try:
            return bytes.fromhex(pem_text)
        except ValueError as e:
            raise ValueError(f"not a 64-char hex public key: {e}") from e
    # Minimal SubjectPublicKeyInfo extraction: base64-decode the body,
    # take the last 32 bytes -- the standard SPKI encoding of an Ed25519
    # public key ends in exactly the 32 raw key bytes (12-byte prefix).
    import base64
    import re

    m = re.search(
        r"-----BEGIN PUBLIC KEY-----\s*(.*?)\s*-----END PUBLIC KEY-----", pem_text, re.DOTALL
    )
    if not m:
        raise ValueError("public key is neither 64-char hex nor a PUBLIC KEY PEM")
    der = base64.b64decode(m.group(1))
    if len(der) < 32:
        raise ValueError("PEM body too short for an Ed25519 public key")
    return der[-32:]


def _packet_canonical_bytes(packet: dict, *, exclude_anchor: bool = False) -> bytes:
    """The canonical bytes the server's signature covers: the packet
    minus its own signature block, sort_keys, compact separators,
    ensure_ascii. Mirrors service/app/security.py::
    packet_canonical_bytes byte-for-byte;
    test_packet_canonical_bytes_matches_app_construction pins that sync.

    exclude_anchor=True is the RFC 3161 release flow: the anchor is
    stamped AFTER signing (its digest is the signature's own sha256, which
    cannot precede the signature), so the signed content excludes it and
    the signature block's signed_fields marker records that fact. The
    verifier recomputes the same bytes from the marker (see
    check_packet_signature), never from guessing.
    """
    content = {k: v for k, v in packet.items() if k != "signature"}
    if exclude_anchor:
        content.pop("anchor", None)
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def check_packet_signature(packet: dict, public_keys: dict[str, bytes]) -> tuple[str, str]:
    """Returns (status, detail) where status is one of:
      "verified"   -- the signature checks out under the key the packet names
      "unsigned"   -- this packet predates signatures (a downgrade line, not
                      a failure: old packets must keep verifying)
      "no_key"     -- signature present but --public-key wasn't given
      "unknown_key"-- signature names a key_id not in the provided keys
      "mismatch"   -- the signature does not verify (tampered packet, wrong
                      key, or canonicalization drift -- all fail identically
                      and deterministically)
    """
    sig = packet.get("signature")
    if not isinstance(sig, dict) or "value" not in sig:
        return "unsigned", "packet predates signatures (no signature block)"
    key_id = sig.get("key_id")
    if not public_keys:
        return "no_key", "signature present but no --public-key given"
    if key_id not in public_keys:
        return "unknown_key", f"signature names key_id {key_id!r} which was not provided"
    try:
        pub = public_keys[key_id]
        value = bytes.fromhex(sig.get("value", ""))
        # The signature declares WHICH bytes it covers: with the RFC 3161
        # release flow the anchor is stamped after signing and excluded
        # from the signed content; anything else is the historical shape
        # with the anchor inside. An unknown marker is a mismatch, never
        # silently treated as either shape.
        signed_fields = sig.get("signed_fields")
        if signed_fields == _SIGNED_FIELDS_EXCLUDING_ANCHOR:
            canonical = _packet_canonical_bytes(packet, exclude_anchor=True)
        elif signed_fields in (None, _SIGNED_FIELDS_CANONICAL):
            canonical = _packet_canonical_bytes(packet)
        else:
            return "mismatch", f"signature names unknown signed_fields marker {signed_fields!r}"
        ok = ed25519_verify(pub, canonical, value)
    except (ValueError, TypeError):
        return "mismatch", "signature block malformed"
    if not ok:
        return "mismatch", "Ed25519 signature does not verify over the packet's canonical bytes"
    # Belt and suspenders: the signed digest must also match our own
    # recomputation, so canonicalization drift surfaces distinctly from
    # an opaque Ed25519 failure.
    declared = sig.get("digest", "")
    recomputed = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if declared != recomputed:
        return "mismatch", f"signed digest {declared!r} != recomputed {recomputed!r}"
    return "verified", f"Ed25519 signature verified under key_id {key_id} (digest {recomputed})"


# --- audit-chain cross-check (MUST-1, 2026-08-29) -----------------------------
#
# Every hash inside release_packet.json is declared by the packet itself
# and recomputed by this tool against the sibling files -- including
# manifest_json_sha256, which job_bundle computes at download time from
# whatever bytes sat on disk. Nothing about that check alone can detect
# a manifest altered before the packet was pulled: the packet would
# faithfully declare the tampered file's hash. The server-side fix
# chain-commits manifest_sha256/derivative_sha256 into the job.sanitize
# audit event at job-terminal time (service/app/audit.py::
# _terminal_hash_facts); this section consumes the other half -- an
# exported audit chain (GET /v1/matters/{id}/audit/export) -- so the
# declared hashes can be checked against something that is NOT the
# packet itself.
#
# The chain check is deliberately stronger than trusting the CSV's own
# claims: every row's row_hash is independently recomputed here
# (sha256(prev_hash|seq|actor_id|action|canonical_payload), the same
# construction as service/app/audit.py::event_hash), and the chain is
# walked for prev-hash linkage. A row edited after the fact -- or a
# middle row deleted -- fails the recheck exactly as it would live.


def _event_row_hash(prev_hash: str, seq: int, actor_id: str, action: str, payload: dict) -> str:
    """The audit chain's row-hash construction, reimplemented here so the
    offline check never depends on importing app code (the verifier stays
    stdlib-only and engine/app-free). Must match service/app/audit.py::
    event_hash byte-for-byte; test_event_hash_matches_app_construction
    pins that sync."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    material = f"{prev_hash}|{seq}|{actor_id}|{action}|{canonical}".encode()
    return hashlib.sha256(material).hexdigest()


@dataclass
class AuditChainCheck:
    """Outcome of the --audit-csv cross-check, reported as its own
    section rather than folded into valid -- the packet's internal
    consistency verdict stays meaningful even when no chain is
    provided, and a chain mismatch is a custody failure, not a hash
    typo."""

    provided: bool
    chain_ok: bool = False
    chain_detail: str = ""
    event_found: bool = False
    job_id: str | None = None
    manifest_sha256: str | None = None
    derivative_sha256: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        if not self.provided:
            return (
                "Audit-chain cross-check: not performed (no --audit-csv given).\n"
                "  The packet's hashes were checked only against the packet itself;"
                " a manifest altered before this packet was assembled would still\n"
                "  verify. Provide the matter's exported audit chain\n"
                "  (GET /v1/matters/{id}/audit/export) to check the declared\n"
                "  manifest/derivative hashes against the chain-committed values."
            )
        lines = ["Audit-chain cross-check:"]
        lines.append(f"  chain row hashes recomputed: {'ok' if self.chain_ok else 'FAILED'}"
                     + (f" -- {self.chain_detail}" if self.chain_detail else ""))
        if self.event_found:
            lines.append(f"  job.sanitize event for job {self.job_id}: found")
            if self.manifest_sha256:
                lines.append(f"  chain-committed manifest_sha256: {self.manifest_sha256}")
            else:
                lines.append("  chain-committed manifest_sha256: absent from the event"
                             " (packet issued before MUST-1, or bundle unreadable at terminal time)")
            if self.derivative_sha256:
                lines.append(f"  chain-committed derivative_sha256: {self.derivative_sha256}")
        else:
            lines.append(f"  job.sanitize event for job {self.job_id}: NOT FOUND in the exported chain")
        for e in self.errors:
            lines.append(f"  - {e}")
        return "\n".join(lines)


def _load_audit_chain(csv_path: Path) -> tuple[list[dict], str]:
    """Parse the audit-export CSV (columns: seq, at, action, actor_id,
    payload_json, prev_hash, row_hash) and recompute every row's hash.
    Returns (rows, fatal_error) -- rows are still returned on a chain
    mismatch so the caller can report which seq broke, but an unreadable
    or malformed CSV is fatal to the check."""
    import csv as _csv

    try:
        text = csv_path.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"unreadable audit CSV: {e}"
    reader = _csv.DictReader(io.StringIO(text))
    rows: list[dict] = []
    for raw in reader:
        try:
            rows.append(
                {
                    "seq": int(raw["seq"]),
                    "action": raw["action"],
                    "actor_id": raw["actor_id"],
                    "payload": json.loads(raw["payload_json"]),
                    "prev_hash": raw["prev_hash"],
                    "row_hash": raw["row_hash"],
                }
            )
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            return [], f"malformed audit CSV row {reader.line_num}: {e}"
    if not rows:
        return [], "audit CSV contains no events"
    return rows, ""


def _verify_audit_chain_rows(rows: list[dict]) -> tuple[bool, str]:
    """Recompute every row's row_hash and walk the prev-hash linkage --
    the same check as service/app/audit.py::verify_chain, minus trusting
    the server that ran it. seq must be contiguous from 0, so a deleted
    middle row fails here (a gap breaks both the seq walk and the
    prev-hash linkage)."""
    expected_prev = "0" * 64
    for i, row in enumerate(rows):
        if row["seq"] != i:
            return False, f"chain gap at seq {row['seq']} (expected {i})"
        if row["prev_hash"] != expected_prev:
            return False, f"chain break at seq {row['seq']}"
        if _event_row_hash(row["prev_hash"], row["seq"], row["actor_id"], row["action"], row["payload"]) \
                != row["row_hash"]:
            return False, f"hash mismatch at seq {row['seq']}"
        expected_prev = row["row_hash"]
    return True, f"{len(rows)} events intact"


def cross_check_audit_chain(csv_path: Path, packet_manifest: dict) -> AuditChainCheck:
    """The --audit-csv check proper: verify the exported chain
    independently, find THIS job's job.sanitize event, and pull the
    chain-committed hashes out of it. The comparison against the
    packet's declared hashes happens in verify_release_packet, which
    owns the packet's file_checks/cross_checks so the two sides render
    in one report."""
    job_id = packet_manifest.get("job_id")
    check = AuditChainCheck(provided=True, job_id=job_id)
    rows, fatal = _load_audit_chain(csv_path)
    if fatal:
        check.errors.append(fatal)
        return check
    check.chain_ok, check.chain_detail = _verify_audit_chain_rows(rows)
    if not check.chain_ok:
        check.errors.append(
            "exported audit chain failed independent verification -- every row below is untrusted"
        )
    events = [
        r for r in rows
        if r["action"] == "job.sanitize" and (r["payload"] or {}).get("job_id") == job_id
    ]
    if not events:
        check.errors.append(
            "no job.sanitize event for this packet's job_id in the exported chain"
            " -- the packet cannot be checked against a chain that never saw it"
        )
        return check
    check.event_found = True
    payload = events[-1]["payload"]
    check.manifest_sha256 = payload.get("manifest_sha256")
    check.derivative_sha256 = payload.get("derivative_sha256")
    return check


# --- RFC 3161 TSA anchor verification (2026-09-01) ----------------------------
#
# docs/rfc3161-anchor-implementation-proposal.md §5: a release packet may
# carry "anchor": {"type": "rfc3161-tsa", "digest": <sha256 hex of the
# packet's own Ed25519 signature bytes>, "reference": <base64 DER
# TimeStampToken>}. The token is a CMS SignedData whose messageImprint is
# that same digest, signed by a timestamp authority -- so the nesting is
# content <- Ed25519 signature <- TSA token, each link independently
# verified. The anchor is stamped AFTER signing (its digest is the
# signature's own sha256, which cannot precede the signature), and
# signed_fields records that the anchor was excluded from the signed
# bytes (see check_packet_signature).
#
# Three mandatory conditions from the proposal:
#  A. The TSA's signing certificate is pinned BYTES-DIRECTLY in this
#     verifier (_PINNED_TSA_SIGNING_CERT_DER_HEX). No chain validation,
#     no validity windows, no EKU parsing. A token whose signing cert
#     does not match a pin reports its own distinct finding
#     ("unrecognized TSA certificate"), never a signature failure.
#  B. Strict, fail-closed DER parsing: any non-canonical encoding
#     (long-form length where short-form suffices, BER indefinite
#     length, anything outside the exact expected shape) yields
#     "cannot verify anchor", never a lenient best-effort parse.
#  C. Differential fuzz testing against asn1crypto/cryptography (test-
#     only dependencies): tests/test_rfc3161_anchor_verification.py
#     mutates the real captured token byte-wise and asserts agreement on
#     accept/reject with the library stack for every mutation.
#
# The specific trap the proposal calls out: the CMS signature is computed
# over signedAttrs re-tagged as a SET OF (0x31), NOT over the TSTInfo
# content directly. This parser reconstructs the re-tagged signedAttrs,
# verifies the RSA signature over THOSE bytes, and separately confirms
# signedAttrs' contentType attribute is id-ct-TSTInfo and its
# messageDigest attribute equals sha256 of the actual eContent -- a token
# whose signature covers the content directly is rejected.
#
# Everything here is stdlib-only, like the rest of this module: the DER
# walk, the CMS/TSTInfo grammar, and the RSA-PKCS1v15-SHA256 verification
# (full expected-EM reconstruction and byte-for-byte comparison -- never
# scanning for the 0x00 separator). asn1crypto and cryptography appear
# ONLY in tests as the differential oracle.

# The signing certificate of the default TSA (timestamp.digicert.com,
# "DigiCert SHA256 RSA4096 Timestamp Responder 2025 1", serial
# 0x0a80ef184b8df10582d1c476a7957468), captured from the fixture token.
# Pinned as raw bytes, per condition A: the token's signing certificate
# must equal this exactly. When the TSA rotates its signing cert this
# constant must be updated -- accept that cost (proposal §5.1).
_PINNED_TSA_SIGNING_CERT_DER_HEX = (
    "308206ed308204d5a00302010202100a80ef184b8df10582d1c476a795746830"
    "0d06092a864886f70d01010b05003069310b3009060355040613025553311730"
    "15060355040a130e44696769436572742c20496e632e3141303f060355040313"
    "38446967694365727420547275737465642047342054696d655374616d70696e"
    "67205253413430393620534841323536203230323520434131301e170d323530"
    "3630343030303030305a170d3336303930333233353935395a3063310b300906"
    "035504061302555331173015060355040a130e44696769436572742c20496e63"
    "2e313b3039060355040313324469676943657274205348413235362052534134"
    "3039362054696d657374616d7020526573706f6e646572203230323520313082"
    "0222300d06092a864886f70d01010105000382020f003082020a0282020100d0"
    "46ac2d12c69ed0eaae6056b32b57ba6f51ff86700a01dfca37cc1942306332a8"
    "99df14d671fb0bc0ebd1c54c17706c7c0148e78ba6f3e767c64dfafa3c744dbf"
    "a4fbcec7f563f137214f2480d91e102a9543eddbcd661eb05b647a912bbd449b"
    "7fe10860b92b2ca77aa899eeccaf15727d03bdb0cc7a6405a314360ecc38bc48"
    "e84f51694b9e1d340a597ca63ad47025772b7134cf3d3d95d43ffe705965112b"
    "e21fc623a0f16f6528cab3748a3b540d51d15dd9a770e38c0370a807f8944913"
    "9420d0d3f7ca24b28b9331814e9c7a1187afbce8bb5ce738cf2875b92aa0afa5"
    "276e4b0870526a2db9085c83db70d980f7c3ac92492bbedea53c0c3fa78a0349"
    "166b7a2c01ef1f7292b8d2e864b7351dfd8934c54be10d4ea5bc9ba4c7b8e987"
    "1e340d0b7cdb27a9c9e925e22d2bf0e129b3f14d3b86a17ef024d76844e4556c"
    "f4755559c3b9278755995ce2c7803bee9ddac0b6ebf3d03dd3f9d61a35cc1a7e"
    "c5421992948503cbd67685281cb5a7a965377420b2146d6ba12ae01e348796af"
    "31ca62e78c26d22d9e3d90f9a4f22cb28b33432178fffdc3a0ad8eeb951c9395"
    "a0827f0eda49444ec27bbbcc447a11a27e02588bee88d3752e4f58fb167aea56"
    "b3b3690a1524e79e4ad3de95d61134c992177be8220305b4d1a1f3ac372121cd"
    "9b421a69d08a0a451ed8b9f024a6bc4c8970094355c29a709f80f7fcfb79a702"
    "03010001a382019530820191300c0603551d130101ff04023000301d0603551d"
    "0e04160414e43bfcf231edfdfdd7f3917163195043cf618ce8301f0603551d23"
    "041830168014ef6f534ae9e4067c7acae29056f62fd449eccb4e300e0603551d"
    "0f0101ff04040302078030160603551d250101ff040c300a06082b0601050507"
    "030830819506082b06010505070101048188308185302406082b060105050730"
    "018618687474703a2f2f6f6373702e64696769636572742e636f6d305d06082b"
    "060105050730028651687474703a2f2f636163657274732e6469676963657274"
    "2e636f6d2f446967694365727454727573746564473454696d655374616d7069"
    "6e6752534134303936534841323536323032354341312e637274305f0603551d"
    "1f045830563054a052a050864e687474703a2f2f63726c332e64696769636572"
    "742e636f6d2f446967694365727454727573746564473454696d655374616d70"
    "696e6752534134303936534841323536323032354341312e63726c3020060355"
    "1d20041930173008060667810c010402300b06096086480186fd6c0701300d06"
    "092a864886f70d01010b05000382020100652aadf11c2704b9ae6041ecd10844"
    "9e63407221f8e4f6224fdb358ba50ab56f85111a7c1605d1190fd801abd7cd68"
    "d9858fa121f3f6264437f14fb0b493c15416a361fadb2181be0ee8b82383c2bc"
    "7a50b8fa8582aa753f30bf6515f8a6f3ff722666527b617c010fd474a14eb63e"
    "d83139aa3cef66cec920882dd060850fd92dc742f1c6d450eef9652a5b875a22"
    "a4e85c513f250fc400181f6572d6534ce24cde91df281004731405a0796ddacf"
    "6c5e8c458b34de1e286c4327c58397f1505129ed6e367cd055378b9e2da71e45"
    "ff42abd79cd6fe6240c5931506b4c4da88b47dc23c54c6eda1102669ab253577"
    "421b5fa5aaf3f815bad0e88c120579196a01cb84553d1c2ac6fecc9344b2e101"
    "eceeff72ebd341ab2733d01670841f5639f3aefc22099f39104f0b524a918684"
    "b7639d0e1e0698ed3fe5c1de9402b6fe04e540920da83afa25fc326075d277e5"
    "74f17d4950fbc1e082df25d98bfbae86a770920571ba2305cc6545c186d0b221"
    "a7a1af45e40680c818c506d5d52dc2ad6a99cc1b7547dc4980a7f8ec27715517"
    "7f9dd525434e68c58cb6cd159516317b99caf80b7e0c8f7a1c09571c02f94a57"
    "d8c49ecb6b9e22ef531c55644feba6d6fb21113696c90a3c82606da3f9b769c6"
    "8ff50b2e2e3dc53701654f1ab6e7e4f84305fdc5ae882ecf3864fbe6a68beaf7"
    "42bc796c86d8dd3573822148ec6ab7cd67"
)
# Extra pins come from --tsa-cert (repeatable; PEM or DER). The embedded
# default is always in the set; operator-configured TSAs (proposal §6)
# add theirs via the flag.
_DEFAULT_TSA_PINS = (bytes.fromhex(_PINNED_TSA_SIGNING_CERT_DER_HEX),)

# The signature-block marker that records WHICH bytes were signed. When
# the release flow signs the packet before the anchor exists (RFC 3161
# anchoring), the anchor is excluded from the signed content and
# signed_fields carries the -excluding-anchor marker; otherwise the
# anchor is part of the signed bytes exactly as before.
_SIGNED_FIELDS_CANONICAL = "release_packet.v1.canonical"
_SIGNED_FIELDS_EXCLUDING_ANCHOR = "release_packet.v1.canonical-excluding-anchor"

_OID_ID_SIGNEDDATA = (1, 2, 840, 113549, 1, 7, 2)
_OID_ID_CT_TSTINFO = (1, 2, 840, 113549, 1, 9, 16, 1, 4)
_OID_SHA256 = (2, 16, 840, 1, 101, 3, 4, 2, 1)
_OID_RSA_ENCRYPTION = (1, 2, 840, 113549, 1, 1, 1)
_OID_ATTR_CONTENT_TYPE = (1, 2, 840, 113549, 1, 9, 3)
_OID_ATTR_MESSAGE_DIGEST = (1, 2, 840, 113549, 1, 9, 4)
_OID_SKI = (2, 5, 29, 14)


class _DerError(ValueError):
    """A strict-DER violation -- any of these fails the anchor check with
    "cannot verify anchor", never a lenient best-effort parse."""


def _der_read_tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    """Read one TLV at `off`: (tag, value_start, value_end). Strict
    canonical-DER length rules: short form whenever possible, minimal
    long-form octets otherwise, no indefinite (0x80) or reserved (0xFF)
    lengths, no high-tag-number form. Raises _DerError on anything else.
    The caller (the canonical walk / grammar walkers) enforces structure;
    this enforces encoding."""
    if off + 1 >= len(buf):
        raise _DerError("truncated element")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise _DerError("high-tag-number form")
    l0 = buf[off + 1]
    if l0 in (0x80, 0xFF):
        raise _DerError("indefinite/reserved length")
    if l0 < 0x80:
        ln, hdr = l0, 2
    else:
        n = l0 & 0x7F
        if n == 0 or n > 4 or off + 2 + n > len(buf):
            raise _DerError("length too long")
        ln = int.from_bytes(buf[off + 2 : off + 2 + n], "big")
        if ln < 0x80 or (n > 1 and ln < 1 << (8 * (n - 1))):
            raise _DerError("non-minimal length encoding")
        hdr = 2 + n
    end = off + hdr + ln
    if end > len(buf):
        raise _DerError("element overruns buffer")
    return tag, off + hdr, end


def _rfc3161_oid_arcs(val: bytes) -> tuple[int, ...]:
    """Decode an OID value into its arcs. The canonical walk has already
    validated minimal base-128 encoding; this is pure decoding. The first
    subidentifier combines arcs 0 and 1 (40*x + y, X.690 §8.19), so it
    must be split before comparison."""
    subs = []
    cur = count = 0
    for b in val:
        cur = (cur << 7) | (b & 0x7F)
        count += 1
        if not (b & 0x80):
            subs.append(cur)
            cur = count = 0
    first = subs[0]
    if first < 40:
        return (0, first, *tuple(subs[1:]))
    if first < 80:
        return (1, first - 40, *tuple(subs[1:]))
    return (2, first - 80, *tuple(subs[1:]))


def _rfc3161_check_oid(val: bytes) -> None:
    if not val:
        raise _DerError("empty OID")
    arcs, cur, count, byte_counts = [], 0, 0, []
    for b in val:
        cur = (cur << 7) | (b & 0x7F)
        count += 1
        if not (b & 0x80):
            arcs.append(cur)
            byte_counts.append(count)
            cur = count = 0
    if count != 0 or len(arcs) < 2:
        raise _DerError("malformed OID")
    for arc, bc in zip(arcs, byte_counts, strict=True):
        if bc > 1 and arc < (1 << (7 * (bc - 1))):
            raise _DerError("non-minimal OID arc")


def _rfc3161_check_calendar(y: int, m: int, d: int, hh: int, mm: int, ss: int) -> None:
    from datetime import datetime

    try:
        datetime(y, m, d, hh, mm, ss)
    except ValueError as e:
        raise _DerError(f"invalid time value: {e}") from e


def _rfc3161_check_utctime(val: bytes) -> None:
    if len(val) != 13 or not val[:12].isdigit() or val[12:13] != b"Z":
        raise _DerError("non-canonical UTCTime")
    yy = 2000 + int(val[0:2]) if int(val[0:2]) < 50 else 1900 + int(val[0:2])
    _rfc3161_check_calendar(yy, int(val[2:4]), int(val[4:6]), int(val[6:8]), int(val[8:10]), int(val[10:12]))


def _rfc3161_check_generalized_time(val: bytes) -> None:
    if len(val) != 15 or not val[:14].isdigit() or val[14:15] != b"Z":
        raise _DerError("non-canonical GeneralizedTime")
    _rfc3161_check_calendar(
        int(val[0:4]), int(val[4:6]), int(val[6:8]), int(val[8:10]), int(val[10:12]), int(val[12:14])
    )


_DER_PRINTABLE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")


def _rfc3161_canonical_walk(data: bytes) -> None:
    """Strict canonical-DER walk over EVERY byte of the token (condition
    B): minimal length encodings, no indefinite/reserved lengths, exact
    consumption, canonical BOOLEAN/INTEGER/OID, canonical+valid times,
    BIT STRING unused-bits <= 7, charset-valid strings. SET-OF ordering is
    deliberately NOT enforced: the real DigiCert token's certificates
    appear in descending order, so enforcing X.690 sorting would reject
    the genuine fixture (the test-only oracle library agrees)."""

    def walk(buf: bytes, lo: int, hi: int) -> None:
        i = lo
        while i < hi:
            if i + 1 >= len(buf):
                raise _DerError("truncated element")
            tag = buf[i]
            if tag & 0x1F == 0x1F:
                raise _DerError("high-tag-number form")
            l0 = buf[i + 1]
            if l0 in (0x80, 0xFF):
                raise _DerError("indefinite/reserved length")
            if l0 < 0x80:
                ln, hdr = l0, 2
            else:
                n = l0 & 0x7F
                if n == 0 or n > 4 or i + 2 + n > len(buf):
                    raise _DerError("length too long")
                ln = int.from_bytes(buf[i + 2 : i + 2 + n], "big")
                if ln < 0x80 or (n > 1 and ln < 1 << (8 * (n - 1))):
                    raise _DerError("non-minimal length encoding")
                hdr = 2 + n
            end = i + hdr + ln
            if end > len(buf) or end > hi:
                raise _DerError("element overruns its structure")
            val = buf[i + hdr : end]
            if tag == 0x01:
                if val not in (b"\x00", b"\xff"):
                    raise _DerError("non-canonical BOOLEAN")
            elif tag == 0x02:
                if not val:
                    raise _DerError("empty INTEGER")
                if len(val) > 1 and (
                    (val[0] == 0x00 and not (val[1] & 0x80)) or (val[0] == 0xFF and (val[1] & 0x80))
                ):
                    raise _DerError("non-minimal INTEGER")
            elif tag == 0x05:
                if val:
                    raise _DerError("NULL with content")
            elif tag == 0x06:
                _rfc3161_check_oid(val)
            elif tag == 0x03:
                if not val or val[0] > 7:
                    raise _DerError("invalid BIT STRING unused bits")
            elif tag == 0x17:
                _rfc3161_check_utctime(val)
            elif tag == 0x18:
                _rfc3161_check_generalized_time(val)
            elif tag == 0x0C:
                try:
                    val.decode("utf-8")
                except UnicodeDecodeError as e:
                    raise _DerError("invalid UTF-8") from e
            elif tag == 0x13:
                if not all(chr(b) in _DER_PRINTABLE for b in val):
                    raise _DerError("invalid PrintableString")
            elif tag == 0x16:
                if any(b > 0x7F for b in val):
                    raise _DerError("invalid IA5String")
            elif tag == 0x1E:
                if len(val) % 2:
                    raise _DerError("odd BMPString length")
                try:
                    val.decode("utf-16-be")
                except UnicodeDecodeError as e:
                    raise _DerError("invalid BMPString") from e
            if tag & 0x20:
                walk(buf, i + hdr, end)
            i = end

    walk(data, 0, len(data))


def _rfc3161_children(buf: bytes) -> list[tuple[int, bytes, bytes]]:
    """Split a buffer into its child TLVs: (tag, value, raw TLV bytes).
    Every child is read with strict length rules; a malformed child
    raises _DerError."""
    out: list[tuple[int, bytes, bytes]] = []
    i = 0
    while i < len(buf):
        tag = buf[i]
        if tag & 0x1F == 0x1F:
            raise _DerError("high-tag-number form")
        l0 = buf[i + 1] if i + 1 < len(buf) else 0x80
        if l0 in (0x80, 0xFF):
            raise _DerError("indefinite/reserved length")
        if l0 < 0x80:
            ln, hdr = l0, 2
        else:
            n = l0 & 0x7F
            if n == 0 or n > 4 or i + 2 + n > len(buf):
                raise _DerError("length too long")
            ln = int.from_bytes(buf[i + 2 : i + 2 + n], "big")
            if ln < 0x80 or (n > 1 and ln < 1 << (8 * (n - 1))):
                raise _DerError("non-minimal length encoding")
            hdr = 2 + n
        end = i + hdr + ln
        if end > len(buf):
            raise _DerError("element overruns buffer")
        out.append((tag, buf[i + hdr : end], buf[i:end]))
        i = end
    return out


def _rfc3161_require_algorithm(val: bytes, expected: tuple[int, ...], what: str, name: str) -> None:
    """AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY
    OPTIONAL }. The expected OID must match; parameters must be absent or
    an explicit NULL (real-world tokens vary between the two -- the
    proposal's trap list). Anything else fails closed."""
    kids = _rfc3161_children(val)
    if len(kids) not in (1, 2) or kids[0][0] != 0x06:
        raise _DerError(f"malformed {what} AlgorithmIdentifier")
    if _rfc3161_oid_arcs(kids[0][1]) != expected:
        raise _DerError(f"{what} is not {name}")
    if len(kids) == 2 and not (kids[1][0] == 0x05 and kids[1][1] == b""):
        raise _DerError(f"{what} parameters must be NULL or absent")


def _rfc3161_parse_spki(val: bytes) -> tuple[int, int]:
    """SubjectPublicKeyInfo -> (RSA modulus n, exponent e). Only RSA
    (rsaEncryption) is supported; anything else fails closed (no ECDSA in
    this pass, per the proposal's scope)."""
    kids = _rfc3161_children(val)
    if len(kids) != 2 or kids[0][0] != 0x30 or kids[1][0] != 0x03:
        raise _DerError("malformed SubjectPublicKeyInfo")
    _rfc3161_require_algorithm(kids[0][1], _OID_RSA_ENCRYPTION, "SPKI algorithm", "RSA")
    bit = kids[1][1]
    if not bit or bit[0] != 0:
        raise _DerError("subjectPublicKey must have zero unused bits")
    rsa_seq = _rfc3161_children(bit[1:])
    if len(rsa_seq) != 1 or rsa_seq[0][0] != 0x30:
        raise _DerError("malformed RSAPublicKey")
    rsa_kids = _rfc3161_children(rsa_seq[0][1])
    if len(rsa_kids) != 2 or rsa_kids[0][0] != 0x02 or rsa_kids[1][0] != 0x02:
        raise _DerError("malformed RSAPublicKey")
    n = int.from_bytes(rsa_kids[0][1], "big")
    e = int.from_bytes(rsa_kids[1][1], "big")
    if n.bit_length() < 2048:
        raise _DerError("RSA modulus too small")
    if not (3 <= e <= 2**32):
        raise _DerError("implausible RSA exponent")
    return n, e


def _rfc3161_parse_ski_extension(val: bytes) -> bytes | None:
    """The subjectKeyIdentifier from a certificate's extensions [3], or
    None when the certificate carries no SKI extension."""
    seq = _rfc3161_children(val)
    if len(seq) != 1 or seq[0][0] != 0x30:
        raise _DerError("malformed extensions")
    for ext in _rfc3161_children(seq[0][1]):
        ek = _rfc3161_children(ext[1])
        if len(ek) < 2 or ek[0][0] != 0x06:
            raise _DerError("malformed extension")
        if _rfc3161_oid_arcs(ek[0][1]) != _OID_SKI:
            continue
        vi = 1
        if ek[vi][0] == 0x01:  # critical BOOLEAN DEFAULT FALSE
            vi += 1
        if vi >= len(ek) or ek[vi][0] != 0x04:
            raise _DerError("malformed SKI extension value")
        inner = _rfc3161_children(ek[vi][1])
        if len(inner) != 1 or inner[0][0] != 0x04:
            raise _DerError("malformed KeyIdentifier")
        return inner[0][1]
    return None


def _rfc3161_parse_cert(der: bytes) -> dict:
    """Parse exactly the fields of an X.509 certificate this verifier
    needs -- serialNumber and issuer (for sid resolution), SPKI (for RSA
    verification) and the SKI extension (for the SKI sid form). No
    validity-window, chain, or EKU checks, per condition A."""
    tag, vs, ve = _der_read_tlv(der, 0)
    if ve != len(der) or tag != 0x30:
        raise _DerError("certificate is not a SEQUENCE")
    kids = _rfc3161_children(der[vs:ve])
    if len(kids) != 3 or kids[0][0] != 0x30:
        raise _DerError("malformed certificate")
    tbs = _rfc3161_children(kids[0][1])
    i = 0
    if tbs[i][0] == 0xA0:  # version [0] EXPLICIT INTEGER, v1 certs omit it
        i += 1
    if i >= len(tbs) or tbs[i][0] != 0x02:
        raise _DerError("certificate serialNumber missing")
    serial_raw = tbs[i][2]
    i += 1
    if i >= len(tbs) or tbs[i][0] != 0x30:
        raise _DerError("certificate signature algorithm missing")
    i += 1
    if i >= len(tbs) or tbs[i][0] != 0x30:
        raise _DerError("certificate issuer missing")
    issuer_raw = tbs[i][2]
    i += 1
    if i + 2 >= len(tbs) or tbs[i][0] != 0x30 or tbs[i + 1][0] != 0x30:
        raise _DerError("certificate validity/subject missing")
    i += 2
    if i >= len(tbs) or tbs[i][0] != 0x30:
        raise _DerError("certificate SPKI missing")
    n, e = _rfc3161_parse_spki(tbs[i][1])
    i += 1
    ski = None
    while i < len(tbs):
        if tbs[i][0] == 0xA3:  # extensions [3] EXPLICIT
            ski = _rfc3161_parse_ski_extension(tbs[i][1])
        elif tbs[i][0] not in (0xA1, 0xA2):  # issuerUniqueID / subjectUniqueID
            raise _DerError("unexpected tbsCertificate field")
        i += 1
    return {"serial": serial_raw, "issuer": issuer_raw, "n": n, "e": e, "ski": ski}


def _rfc3161_parse_tstinfo(econtent: bytes) -> tuple[bytes, str]:
    """Parse TSTInfo by FIELD PRESENCE, never fixed position: accuracy,
    ordering, nonce, tsa [0] and extensions [1] are OPTIONAL (ordering is
    DEFAULT FALSE and omitted in DER), so a positional parser breaks on
    real tokens. `econtent` is the DER-encoded TSTInfo (a full SEQUENCE
    TLV -- the double-wrap the proposal warns about). Returns
    (hashed_message, gen_time_iso)."""
    tag, vs, ve = _der_read_tlv(econtent, 0)
    if ve != len(econtent) or tag != 0x30:
        raise _DerError("TSTInfo is not a SEQUENCE")
    kids = _rfc3161_children(econtent[vs:ve])
    if len(kids) < 5:
        raise _DerError("TSTInfo too short")
    if kids[0][0] != 0x02 or int.from_bytes(kids[0][1], "big", signed=True) != 1:
        raise _DerError("TSTInfo version is not v1")
    if kids[1][0] != 0x06:
        raise _DerError("TSTInfo policy is not an OID")
    mi = kids[2]
    if mi[0] != 0x30:
        raise _DerError("messageImprint is not a SEQUENCE")
    mi_kids = _rfc3161_children(mi[1])
    if len(mi_kids) != 2 or mi_kids[0][0] != 0x30 or mi_kids[1][0] != 0x04:
        raise _DerError("malformed messageImprint")
    _rfc3161_require_algorithm(mi_kids[0][1], _OID_SHA256, "messageImprint hash algorithm", "SHA-256")
    hashed = mi_kids[1][1]
    if kids[3][0] != 0x02:
        raise _DerError("TSTInfo serialNumber is not an INTEGER")
    if kids[4][0] != 0x18:
        raise _DerError("genTime is not a GeneralizedTime")
    gen = kids[4][1]
    if len(gen) != 15 or not gen[:14].isdigit() or gen[14:15] != b"Z":
        raise _DerError("non-canonical genTime")
    for tag, _val, _raw in kids[5:]:  # optional fields, presence-based
        if tag not in (0x30, 0x01, 0x02, 0xA0, 0xA1):
            raise _DerError("unexpected TSTInfo field")
    gen_time = (
        f"{gen[0:4].decode()}-{gen[4:6].decode()}-{gen[6:8].decode()}"
        f"T{gen[8:10].decode()}:{gen[10:12].decode()}:{gen[12:14].decode()}+00:00"
    )
    return hashed, gen_time


def _rfc3161_parse_token(token_der: bytes) -> dict:
    """Strict parse of a TimeStampToken (ContentInfo wrapping a CMS
    SignedData). Raises _DerError on any deviation from the exact
    expected shape."""
    tag, vs, ve = _der_read_tlv(token_der, 0)
    if ve != len(token_der):
        raise _DerError("trailing data after ContentInfo")
    if tag != 0x30:
        raise _DerError("token is not a SEQUENCE")
    kids = _rfc3161_children(token_der[vs:ve])
    if len(kids) != 2 or kids[0][0] != 0x06:
        raise _DerError("ContentInfo must be SEQUENCE { OID, [0] }")
    if _rfc3161_oid_arcs(kids[0][1]) != _OID_ID_SIGNEDDATA:
        raise _DerError("contentType is not id-signedData")
    if kids[1][0] != 0xA0:
        raise _DerError("content is not [0]")
    sd_kids = _rfc3161_children(kids[1][1])
    if len(sd_kids) != 1 or sd_kids[0][0] != 0x30:
        raise _DerError("content [0] must wrap one SignedData")
    return _rfc3161_parse_signed_data(sd_kids[0][1])


def _rfc3161_parse_signed_data(val: bytes) -> dict:
    kids = _rfc3161_children(val)
    if len(kids) != 5:
        raise _DerError("SignedData must have exactly five children")
    if kids[0][0] != 0x02 or int.from_bytes(kids[0][1], "big", signed=True) != 3:
        raise _DerError("SignedData version is not v3")
    if kids[1][0] != 0x31:
        raise _DerError("digestAlgorithms is not a SET")
    for alg in _rfc3161_children(kids[1][1]):
        # Shape-only: AlgorithmIdentifier ::= SEQUENCE { OID, parameters
        # OPTIONAL } with NULL-or-absent parameters. The OID VALUE is
        # advisory metadata (the SignerInfo's digestAlgorithm governs the
        # actual signature), so only the shape is constrained -- but the
        # shape is constrained: a tag mutation inside the entry fails
        # closed, matching the oracle's re-encode check.
        if alg[0] != 0x30:
            raise _DerError("digestAlgorithms entry is not an AlgorithmIdentifier")
        a_kids = _rfc3161_children(alg[1])
        if len(a_kids) not in (1, 2) or a_kids[0][0] != 0x06:
            raise _DerError("malformed digestAlgorithm entry")
        if len(a_kids) == 2 and not (a_kids[1][0] == 0x05 and a_kids[1][1] == b""):
            raise _DerError("digestAlgorithm entry parameters must be NULL or absent")
    if kids[2][0] != 0x30:
        raise _DerError("encapContentInfo is not a SEQUENCE")
    eci = _rfc3161_children(kids[2][1])
    if len(eci) != 2 or eci[0][0] != 0x06:
        raise _DerError("malformed encapContentInfo")
    if _rfc3161_oid_arcs(eci[0][1]) != _OID_ID_CT_TSTINFO:
        raise _DerError("eContentType is not id-ct-TSTInfo")
    if eci[1][0] != 0xA0:
        raise _DerError("eContent is not [0]")
    wrap = _rfc3161_children(eci[1][1])
    if len(wrap) != 1 or wrap[0][0] != 0x04:
        raise _DerError("eContent [0] must wrap one OCTET STRING")
    econtent = wrap[0][1]
    if kids[3][0] != 0xA0:
        raise _DerError("certificates is not [0]")
    certs = _rfc3161_children(kids[3][1])
    for c in certs:
        if c[0] != 0x30:
            raise _DerError("certificate is not an X.509 SEQUENCE")
    if kids[4][0] != 0x31:
        raise _DerError("signerInfos is not a SET")
    sis = _rfc3161_children(kids[4][1])
    if len(sis) != 1 or sis[0][0] != 0x30:
        raise _DerError("expected exactly one SignerInfo")
    return {"econtent": econtent, "certs": certs, "si": _rfc3161_parse_signer_info(sis[0][1])}


def _rfc3161_parse_signer_info(val: bytes) -> dict:
    kids = _rfc3161_children(val)
    if len(kids) != 6:
        raise _DerError("SignerInfo must have exactly six children")
    if kids[0][0] != 0x02:
        raise _DerError("SignerInfo version is not an INTEGER")
    version = int.from_bytes(kids[0][1], "big", signed=True)
    sid = kids[1]
    if sid[0] == 0x30:  # issuerAndSerialNumber
        iasn = _rfc3161_children(sid[1])
        if len(iasn) != 2 or iasn[0][0] != 0x30 or iasn[1][0] != 0x02:
            raise _DerError("malformed issuerAndSerialNumber")
        if version != 1:
            raise _DerError("SignerInfo version must be v1 for issuerAndSerialNumber")
        sid_info = ("iasn", iasn[0][2], iasn[1][2])
    elif sid[0] == 0x80:  # subjectKeyIdentifier [0] IMPLICIT
        if version != 3:
            raise _DerError("SignerInfo version must be v3 for subjectKeyIdentifier")
        sid_info = ("ski", sid[1])
    else:
        raise _DerError("unrecognized SignerIdentifier form")
    if kids[2][0] != 0x30:
        raise _DerError("digestAlgorithm is not a SEQUENCE")
    _rfc3161_require_algorithm(kids[2][1], _OID_SHA256, "signer digest algorithm", "SHA-256")
    if kids[3][0] != 0xA0:
        raise _DerError("signedAttrs is not [0]")
    attrs = _rfc3161_parse_attributes(kids[3][1], kids[3][2])
    if kids[4][0] != 0x30:
        raise _DerError("signatureAlgorithm is not a SEQUENCE")
    _rfc3161_require_algorithm(kids[4][1], _OID_RSA_ENCRYPTION, "signer signature algorithm", "RSA")
    if kids[5][0] != 0x04:
        raise _DerError("signature is not an OCTET STRING")
    return {"sid": sid_info, "attrs": attrs, "signature": kids[5][1]}


def _rfc3161_parse_attributes(val: bytes, raw_tlv: bytes) -> dict:
    """Parse signedAttrs. Returns {"by_oid": {oid: [[value TLV, ...], ...]},
    "retagged": the DER-re-tagged SET OF (0x31) the CMS signature covers.
    The [0] IMPLICIT tag is swapped for the universal SET tag 0x31 with
    the SAME length encoding -- the exact construction RFC 5652 signs
    (verified byte-for-byte against the test-only oracle library's untag().dump())."""
    by_oid: dict[tuple[int, ...], list[list[tuple[int, bytes, bytes]]]] = {}
    for tag, aval, _araw in _rfc3161_children(val):
        if tag != 0x30:
            raise _DerError("attribute is not a SEQUENCE")
        akids = _rfc3161_children(aval)
        if len(akids) != 2 or akids[0][0] != 0x06 or akids[1][0] != 0x31:
            raise _DerError("malformed attribute")
        oid = _rfc3161_oid_arcs(akids[0][1])
        by_oid.setdefault(oid, []).append(_rfc3161_children(akids[1][1]))
    return {"by_oid": by_oid, "retagged": b"\x31" + raw_tlv[1:]}


def _rfc3161_resolve_signer(parsed: dict, si: dict) -> tuple[bytes, dict] | None:
    """Resolve the signer certificate via the SignerIdentifier CHOICE:
    issuerAndSerialNumber (exact DER bytes of issuer + serial) or
    subjectKeyIdentifier (the certificate's SKI extension). Exactly one
    match required -- zero or several fail closed."""
    sid = si["sid"]
    if sid[0] == "iasn":
        _form, issuer_raw, serial_raw = sid
        for _tag, _val, raw in parsed["certs"]:
            info = _rfc3161_parse_cert(raw)
            if info["issuer"] == issuer_raw and info["serial"] == serial_raw:
                return raw, info
        return None
    _form, ski = sid
    matches = []
    for _tag, _val, raw in parsed["certs"]:
        info = _rfc3161_parse_cert(raw)
        if info["ski"] == ski:
            matches.append((raw, info))
    return matches[0] if len(matches) == 1 else None


def _rsa_pkcs1v15_sha256_verify(n: int, e: int, signature: bytes, message: bytes) -> bool:
    """RSA PKCS#1 v1.5 with SHA-256, stdlib-only: reconstruct the full
    expected encoded message (EM) and compare byte-for-byte. Never scan
    for the 0x00 separator and trust what follows -- the trap the
    proposal warns about. Returns False on any malformed input, never
    raises."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k or not (3 <= e <= 2**32):
        return False
    s = int.from_bytes(signature, "big")
    if s <= 0 or s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest = hashlib.sha256(message).digest()
    # DigestInfo for SHA-256: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING }
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    ps_len = k - 3 - len(digest_info)
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + digest_info
    return em == expected


@dataclass
class TSAAnchorCheck:
    """Outcome of verifying a packet's rfc3161-tsa anchor claim.

    status:
      "verified"                  -- token parses strictly, signer cert is
                                     pinned, messageImprint matches, RSA
                                     signature verifies over signedAttrs
      "unrecognized_tsa_certificate" -- everything else intact, but the
                                     signer cert matches no pin -- its own
                                     distinct finding (condition A)
      "cannot_verify"             -- any strict-DER violation, structural
                                     deviation, digest mismatch, or
                                     signature failure (conditions B)
    """

    status: str
    detail: str
    gen_time: str | None = None


def verify_tsa_anchor(token_der: bytes, expected_digest: bytes, pinned_certs: list[bytes]) -> TSAAnchorCheck:
    """Verify a TimeStampToken against the digest it must timestamp.
    Never raises: any failure -- hostile garbage included -- returns a
    fail-closed TSAAnchorCheck."""
    try:
        _rfc3161_canonical_walk(token_der)
        parsed = _rfc3161_parse_token(token_der)
        si = parsed["si"]
        signer = _rfc3161_resolve_signer(parsed, si)
        if signer is None:
            return TSAAnchorCheck(
                "cannot_verify",
                "cannot verify anchor: no certificate in the token matches the signer identifier",
            )
        cert_raw, cert_info = signer
        if cert_raw not in pinned_certs:
            return TSAAnchorCheck(
                "unrecognized_tsa_certificate",
                f"unrecognized TSA certificate: the token's signing certificate "
                f"(sha256 {_sha256(cert_raw)}) is not any certificate this verifier pins",
            )
        # The signature is over the DER-re-tagged signedAttrs (0x31) --
        # never over the TSTInfo content directly (the proposal's trap).
        if not _rsa_pkcs1v15_sha256_verify(cert_info["n"], cert_info["e"], si["signature"], si["attrs"]["retagged"]):
            return TSAAnchorCheck(
                "cannot_verify",
                "cannot verify anchor: token signature does not verify under the signer certificate",
            )
        ct_attr = si["attrs"]["by_oid"].get(_OID_ATTR_CONTENT_TYPE, [])
        md_attr = si["attrs"]["by_oid"].get(_OID_ATTR_MESSAGE_DIGEST, [])
        if len(ct_attr) != 1 or len(ct_attr[0]) != 1 or ct_attr[0][0][0] != 0x06:
            return TSAAnchorCheck("cannot_verify", "cannot verify anchor: signedAttrs contentType missing or malformed")
        if _rfc3161_oid_arcs(ct_attr[0][0][1]) != _OID_ID_CT_TSTINFO:
            return TSAAnchorCheck("cannot_verify", "cannot verify anchor: signedAttrs contentType is not id-ct-TSTInfo")
        if len(md_attr) != 1 or len(md_attr[0]) != 1 or md_attr[0][0][0] != 0x04:
            return TSAAnchorCheck("cannot_verify", "cannot verify anchor: signedAttrs messageDigest missing or malformed")
        if md_attr[0][0][1] != hashlib.sha256(parsed["econtent"]).digest():
            return TSAAnchorCheck(
                "cannot_verify",
                "cannot verify anchor: signedAttrs messageDigest does not match the timestamped content",
            )
        hashed, gen_time = _rfc3161_parse_tstinfo(parsed["econtent"])
        if hashed != expected_digest:
            return TSAAnchorCheck(
                "cannot_verify",
                "cannot verify anchor: token messageImprint does not match the packet's signature digest",
            )
        return TSAAnchorCheck(
            "verified",
            f"TimeStampToken verified under the pinned TSA certificate; token genTime {gen_time}",
            gen_time,
        )
    except _DerError as e:
        return TSAAnchorCheck("cannot_verify", f"cannot verify anchor: {e}")
    except Exception as e:  # never crash on hostile input -- fail closed
        return TSAAnchorCheck("cannot_verify", f"cannot verify anchor: {type(e).__name__}")


def _check_packet_anchor(packet: dict, pinned_certs: list[bytes]) -> TSAAnchorCheck | None:
    """Verify the packet's rfc3161-tsa anchor claim end to end: the
    declared digest must equal sha256 of the packet's own Ed25519
    signature value (recomputed, never trusted), the reference must
    decode to a token, and the token must verify against that digest.
    Returns None when the packet carries no rfc3161-tsa anchor."""
    anchor = packet.get("anchor")
    if not isinstance(anchor, dict) or anchor.get("type") != "rfc3161-tsa":
        return None
    sig = packet.get("signature")
    if not isinstance(sig, dict) or not isinstance(sig.get("value"), str):
        return TSAAnchorCheck(
            "cannot_verify", "cannot verify anchor: packet carries no signature to bind the token to"
        )
    try:
        sig_bytes = bytes.fromhex(sig["value"])
    except ValueError:
        return TSAAnchorCheck("cannot_verify", "cannot verify anchor: packet signature value is not valid hex")
    if len(sig_bytes) != 64:
        return TSAAnchorCheck("cannot_verify", "cannot verify anchor: packet signature value is not 64 bytes")
    expected = hashlib.sha256(sig_bytes).digest()
    declared = anchor.get("digest")
    if not isinstance(declared, str) or declared.lower() != expected.hex():
        return TSAAnchorCheck(
            "cannot_verify",
            "cannot verify anchor: declared anchor digest does not match sha256 of the packet's signature bytes",
        )
    reference = anchor.get("reference")
    if not isinstance(reference, str):
        return TSAAnchorCheck("cannot_verify", "cannot verify anchor: anchor reference is missing")
    import base64

    try:
        token_der = base64.b64decode(reference, validate=True)
    except (ValueError, TypeError):
        return TSAAnchorCheck("cannot_verify", "cannot verify anchor: anchor reference is not valid base64")
    return verify_tsa_anchor(token_der, expected, pinned_certs)


def _load_tsa_certs(paths: list[Path]) -> list[bytes]:
    """--tsa-cert files: DER certificate bytes, or a PEM body (base64
    between the BEGIN/END lines). Raises SystemExit on an unreadable or
    malformed file -- an operator error to fix, like a bad public key."""
    import base64
    import re as _re

    certs: list[bytes] = []
    for p in paths:
        try:
            data = p.read_bytes()
        except OSError as e:
            raise SystemExit(f"--tsa-cert {p}: {e}") from e
        if b"-----BEGIN CERTIFICATE-----" in data:
            m = _re.search(
                rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", data, _re.DOTALL
            )
            if not m:
                raise SystemExit(f"--tsa-cert {p}: no CERTIFICATE PEM block found")
            try:
                data = base64.b64decode(b"".join(m.group(1).split()), validate=True)
            except ValueError as e:
                raise SystemExit(f"--tsa-cert {p}: PEM body is not valid base64") from e
        certs.append(data)
    return certs


def verify_release_packet(
    path: Path,
    audit_csv: Path | None = None,
    public_keys: dict[str, bytes] | None = None,
    tsa_certs: list[bytes] | None = None,
) -> VerificationReport:
    """The whole check, factored out of main() so tests (and a future
    static-web verifier reimplementing this in JS) can drive it directly.
    audit_csv: optional path to a GET /v1/matters/{id}/audit/export CSV
    -- when given, the packet's declared manifest/derivative hashes are
    also checked against the chain-committed values (MUST-1).
    public_keys: optional {key_id: 32 raw public bytes} -- when given,
    the packet's Ed25519 signature is verified (MUST-2). A signature
    mismatch fails the packet; a missing key or an unsigned legacy
    packet downgrades to an explicit "NOT VERIFIED" line without
    failing the rest of the (still meaningful) hash checks.
    tsa_certs: optional additional TSA signing certificate DER bytes to
    pin beyond the embedded default (--tsa-cert) -- an rfc3161-tsa
    anchor whose signer certificate is in none of the pins reports its
    own distinct finding and fails the packet (condition A)."""
    try:
        files = _load_packet_files(path)
    except PacketLoadError as e:
        return VerificationReport(valid=False, schema_ok=False, errors=[str(e)])

    errors: list[str] = []

    if "release_packet.json" not in files:
        return VerificationReport(
            valid=False, schema_ok=False, errors=["release_packet.json is missing from this packet"]
        )
    try:
        manifest = json.loads(files["release_packet.json"])
    except json.JSONDecodeError as e:
        return VerificationReport(
            valid=False, schema_ok=False, errors=[f"release_packet.json is not valid JSON: {e}"]
        )

    schema_ok = True
    for field_name in REQUIRED_MANIFEST_FIELDS:
        if field_name not in manifest:
            schema_ok = False
            errors.append(f"release_packet.json missing required field: {field_name!r}")

    # PR 63: schema-pin cross-checks. The packet's own schema_ok already
    # ran, so the pin check on release_packet.json itself only adds
    # signal; manifest.json/report.json members are parsed here (they are
    # only parse-required later for their own checks -- a malformed one
    # must not crash the pin check, it surfaces in its own file check /
    # cross-check below).
    pinned_artifacts: dict[str, dict] = {"release_packet.json": manifest}
    for member in ("manifest.json", "report.json"):
        if member in files:
            # A malformed member is not the pin check's failure to report;
            # it surfaces in its own hash/cross-check paths below.
            with contextlib.suppress(json.JSONDecodeError):
                pinned_artifacts[member] = json.loads(files[member])
    pin_checks, pin_errors = _schema_pin_cross_checks(pinned_artifacts)
    if pin_errors:
        schema_ok = False
        errors.extend(pin_errors)

    file_checks: list[FileCheck] = []

    def _check_hash(display_name: str, arcnames: list[str], expected: str | None) -> None:
        """*arcnames* are tried in order -- more than one candidate path
        exists only for the derivative (see below): the canonical zip
        always nests it under "derivative/", but a directory someone
        extracted a packet into (e.g. the Airlock CLI's own output,
        which deliberately keeps the derivative at the top level for
        easy access, not nested) is still a legitimate release packet
        layout, not a different one. Exactly one of the two layouts is
        accepted -- if *both* candidates are present (e.g. a directory
        with both derivative/<name> and a top-level <name>, planted
        separately with different bytes), that is never silently
        resolved by preferring one: it's reported as its own failure,
        even if the first candidate found happens to match the declared
        hash, because a verifier that silently ignores a second,
        unexplained copy of the derivative is exactly the kind of gap
        an adversarial packet would try to exploit."""
        if expected is None:
            file_checks.append(FileCheck(display_name, "missing", "no hash declared in release_packet.json"))
            return
        present = [n for n in arcnames if n in files]
        if len(present) > 1:
            file_checks.append(
                FileCheck(
                    display_name,
                    "ambiguous",
                    "packet has ambiguous derivative layout: both "
                    f"{present[0]!r} and {present[1]!r} are present. Exactly one "
                    "of the nested (derivative/<name>) or flat (<name>) layout "
                    "is expected, not both.",
                )
            )
            return
        if not present:
            file_checks.append(
                FileCheck(display_name, "missing", f"none of {arcnames} present in packet")
            )
            return
        arcname = present[0]
        actual = _sha256(files[arcname])
        if actual != expected:
            file_checks.append(
                FileCheck(display_name, "mismatch", f"declared {expected[:16]}…, actual {actual[:16]}…")
            )
        else:
            file_checks.append(FileCheck(display_name, "match"))

    hashes = manifest.get("hashes", {}) if schema_ok else {}
    _check_hash("manifest.json", ["manifest.json"], hashes.get("manifest_json_sha256"))
    _check_hash("report.json", ["report.json"], hashes.get("report_json_sha256"))
    _check_hash("certificate.html", ["certificate.html"], hashes.get("certificate_html_sha256"))
    _check_hash("README.txt", ["README.txt"], hashes.get("readme_txt_sha256"))
    deriv = hashes.get("derivative") or {}
    deriv_name = deriv.get("filename")
    if deriv_name:
        _check_hash("derivative", [f"derivative/{deriv_name}", deriv_name], deriv.get("sha256"))
    else:
        file_checks.append(FileCheck("derivative", "missing", "no derivative filename declared"))

    # Any required sibling file not already covered by a hash check above
    # (defensive -- every one of REQUIRED_SIBLING_FILES is already checked
    # by name above; this catches a future spec drift where a new required
    # file isn't wired into a _check_hash call).
    for req in REQUIRED_SIBLING_FILES:
        if req not in files and not any(fc.name == req and fc.status == "missing" for fc in file_checks):
            file_checks.append(FileCheck(req, "missing", "required file absent from packet"))

    cross_checks: list[CrossCheck] = []
    cross_checks.extend(pin_checks)
    if schema_ok and "manifest.json" in files:
        try:
            inner_manifest = json.loads(files["manifest.json"])
        except json.JSONDecodeError:
            inner_manifest = {}
        inner_policy = inner_manifest.get("policy") or {}
        outer_policy = manifest.get("policy") or {}
        if inner_policy.get("id") and outer_policy.get("id"):
            status = "match" if inner_policy["id"] == outer_policy["id"] else "mismatch"
            cross_checks.append(CrossCheck("policy.id (release_packet.json vs manifest.json)", status))
        inner_deriv_sha = (inner_manifest.get("derivative") or {}).get("sha256")
        outer_deriv_sha = deriv.get("sha256")
        if inner_deriv_sha and outer_deriv_sha:
            status = "match" if inner_deriv_sha == outer_deriv_sha else "mismatch"
            cross_checks.append(
                CrossCheck("derivative sha256 (release_packet.json vs manifest.json)", status)
            )

    # Deliberately NOT a grep of certificate.html's rendered prose for
    # matching substrings (removed, PR 39 -- see module docstring's
    # "Certificate verification" section): the certificate_html_sha256
    # file check above already proves the HTML is byte-identical to what
    # was declared, which is strictly stronger than "this string appears
    # somewhere in the page". release_packet.json is the authoritative
    # source of facts; certificate.html is verified for integrity, not
    # re-parsed for meaning.

    # original_sha256 (PR 39) is a declared fact, always required at the
    # schema level -- but only checkable as a FILE hash when the original
    # was actually included (include_original=true pulled an original/
    # member into the packet, which is optional by design). Its absence
    # is normal, not a defect, so it's reported only as an informational
    # cross-check, never a file-check "missing".
    original_sha256 = manifest.get("original_sha256") if schema_ok else None
    original_members = [n for n in files if n.startswith("original/")]
    if original_sha256 and original_members:
        if len(original_members) > 1:
            cross_checks.append(
                CrossCheck(
                    "original_sha256 vs included original/ file",
                    "mismatch",
                    f"ambiguous: multiple original/ members present ({original_members})",
                )
            )
        else:
            actual = _sha256(files[original_members[0]])
            status = "match" if actual == original_sha256 else "mismatch"
            cross_checks.append(CrossCheck("original_sha256 vs included original/ file", status))
    elif original_sha256:
        cross_checks.append(
            CrossCheck(
                "original_sha256 vs included original/ file",
                "unavailable",
                "original was not included in this packet (pass include_original=true to include it)",
            )
        )

    # MUST-1: when an exported audit chain is provided, the packet's
    # declared manifest/derivative hashes are checked against the
    # chain-committed values -- the only check in this tool that is NOT
    # the packet agreeing with itself. A chain that fails independent
    # verification fails the packet too: a tampered chain is not a
    # better witness than no chain.
    audit_chain: AuditChainCheck | None = None
    chain_hash_checks: list[CrossCheck] = []
    chain_failed = False
    if audit_csv is not None:
        audit_chain = cross_check_audit_chain(audit_csv, manifest)
        if not audit_chain.chain_ok or not audit_chain.event_found:
            chain_failed = True
        elif audit_chain.event_found:
            declared_manifest_sha = (manifest.get("hashes") or {}).get("manifest_json_sha256")
            if audit_chain.manifest_sha256 and declared_manifest_sha:
                status = "match" if audit_chain.manifest_sha256 == declared_manifest_sha else "mismatch"
                chain_hash_checks.append(
                    CrossCheck("manifest_json_sha256 (packet vs audit chain)", status)
                )
            else:
                chain_hash_checks.append(
                    CrossCheck(
                        "manifest_json_sha256 (packet vs audit chain)",
                        "unavailable",
                        "chain event carries no manifest_sha256 (pre-MUST-1 event)"
                        if audit_chain.event_found and not audit_chain.manifest_sha256
                        else "packet declares no manifest hash",
                    )
                )
            declared_deriv_sha = ((manifest.get("hashes") or {}).get("derivative") or {}).get("sha256")
            if audit_chain.derivative_sha256 and declared_deriv_sha:
                status = "match" if audit_chain.derivative_sha256 == declared_deriv_sha else "mismatch"
                chain_hash_checks.append(
                    CrossCheck("derivative sha256 (packet vs audit chain)", status)
                )
            else:
                chain_hash_checks.append(
                    CrossCheck(
                        "derivative sha256 (packet vs audit chain)",
                        "unavailable",
                        "chain event carries no derivative_sha256 (pre-MUST-1 event)"
                        if audit_chain.event_found and not audit_chain.derivative_sha256
                        else "packet declares no derivative hash",
                    )
                )

    # MUST-2: signature check -- only meaningful when the packet parsed
    # and carries the required fields (a malformed packet fails on
    # schema/hashes anyway; signing garbage adds no signal). Kept out of
    # the errors list so a downgrade (unsigned/no key) reads as its own
    # line, while a "mismatch" feeds valid=False below.
    signature_status: str | None = None
    signature_detail = ""
    if schema_ok:
        signature_status, signature_detail = check_packet_signature(manifest, public_keys or {})

    # RFC 3161 TSA anchor (rfc3161-tsa): the anchor's digest must equal
    # sha256 of the packet's OWN signature value (recomputed, never
    # trusted), and the token must verify against it under a pinned
    # certificate. A claimed-but-unverifiable anchor fails the packet --
    # the claim doesn't check out, like a hash or signature mismatch.
    anchor_check: TSAAnchorCheck | None = None
    if schema_ok:
        anchor_check = _check_packet_anchor(
            manifest, list(_DEFAULT_TSA_PINS) + list(tsa_certs or [])
        )

    valid = (
        schema_ok
        and not errors
        and all(fc.status == "match" for fc in file_checks)
        and all(cc.status != "mismatch" for cc in cross_checks)
        and all(cc.status != "mismatch" for cc in chain_hash_checks)
        and signature_status != "mismatch"
        and not chain_failed
        and (anchor_check is None or anchor_check.status == "verified")
    )
    return VerificationReport(
        valid=valid,
        schema_ok=schema_ok,
        file_checks=file_checks,
        cross_checks=cross_checks,
        anchor_type=(manifest.get("anchor") or {}).get("type") if schema_ok else None,
        release_id=manifest.get("release_id") if schema_ok else None,
        errors=errors,
        audit_chain=audit_chain,
        chain_hash_checks=chain_hash_checks,
        signature_status=signature_status,
        signature_detail=signature_detail,
        anchor=anchor_check,
    )


def verify_release_result(path: Path) -> ReleaseResultReport:
    """release_result.json on its own -- the artifact PR 39's Release
    object produces for EVERY terminal release, refused/failed included,
    so "packet or refusal" always resolves to something machine-checkable
    even when there's no derivative and no zip. *path* is either the
    release_result.json file itself, or a directory containing one
    (optionally alongside a sibling certificate.html, if a caller also
    saved the standalone certificate next to it)."""
    if path.is_dir():
        result_path = path / "release_result.json"
        cert_path = path / "certificate.html"
    else:
        result_path = path
        cert_path = path.parent / "certificate.html"

    if not result_path.is_file():
        return ReleaseResultReport(valid=False, schema_ok=False, errors=[f"{result_path} does not exist"])
    try:
        result = json.loads(result_path.read_bytes())
    except json.JSONDecodeError as e:
        return ReleaseResultReport(valid=False, schema_ok=False, errors=[f"{result_path} is not valid JSON: {e}"])

    errors: list[str] = []
    schema_ok = True
    for field_name in REQUIRED_RELEASE_RESULT_FIELDS:
        if field_name not in result:
            schema_ok = False
            errors.append(f"release_result.json missing required field: {field_name!r}")

    file_checks: list[FileCheck] = []
    expected_cert_sha = result.get("certificate_html_sha256") if schema_ok else None
    if expected_cert_sha:
        if cert_path.is_file():
            actual = _sha256(cert_path.read_bytes())
            status = "match" if actual == expected_cert_sha else "mismatch"
            file_checks.append(FileCheck("certificate.html", status))
        else:
            # Not a defect -- the certificate is fetched separately (GET
            # .../jobs/{job_id}/certificate) and saving it alongside
            # release_result.json is optional, unlike a full release
            # packet where certificate.html always travels in the zip.
            file_checks.append(
                FileCheck(
                    "certificate.html", "missing",
                    "certificate.html not found alongside release_result.json (optional -- "
                    "fetch it separately and save it next to this file to check it)",
                )
            )

    # Unlike verify_release_packet's file_checks (every one required),
    # the certificate.html check here is informational when "missing" --
    # the certificate is optional to include alongside release_result.json
    # (see the FileCheck above). Only "mismatch"/"ambiguous" invalidate.
    valid = schema_ok and not errors and all(fc.status not in ("mismatch", "ambiguous") for fc in file_checks)
    return ReleaseResultReport(
        valid=valid,
        schema_ok=schema_ok,
        file_checks=file_checks,
        anchor_type=(result.get("anchor") or {}).get("type") if schema_ok else None,
        errors=errors,
    )


# release_packet.json's field name -> release_result.json's field name, for
# every fact the two artifacts both claim to describe. "unavailable" (not a
# failure) when either side doesn't have the field at all -- e.g. profile_id
# is absent from a legacy, non-Release packet. Anything present on both
# sides that disagrees is a real MISMATCH: PR 44's whole point is that nothing
# ever silently prefers one artifact over the other when both exist.
_AGREEMENT_FIELDS = (
    ("release_id", "release_id"),
    ("job_id", "job_id"),
    ("document_id", "document_id"),
    ("matter_id", "matter_id"),
    ("status", "status"),
    ("original_sha256", "original_sha256"),
    ("legal_justifications", "legal_justifications"),
    ("limitations", "limitations"),
)


@dataclass
class CombinedReport:
    """verify_release_packet_and_result()'s own report: both artifacts
    verified independently (never silently preferring one when both
    exist in the same directory), plus an explicit cross-check that they
    describe the same release consistently."""

    valid: bool
    packet: VerificationReport
    result: ReleaseResultReport
    agreement: list[CrossCheck] = field(default_factory=list)

    def to_text(self) -> str:
        lines: list[str] = []
        lines.append("INTERNALLY CONSISTENT" if self.valid else "INTERNALLY INCONSISTENT")
        lines.append("")
        lines.append(
            "Both release_packet.json and release_result.json are present -- "
            "verified independently below, then cross-checked for agreement."
        )
        lines.append("")
        lines.append("=== release_packet.json ===")
        lines.append(self.packet.to_text())
        lines.append("")
        lines.append("=== release_result.json ===")
        lines.append(self.result.to_text())
        lines.append("")
        lines.append("=== Agreement between release_packet.json and release_result.json ===")
        for cc in self.agreement:
            marker = {"match": "ok", "mismatch": "MISMATCH", "unavailable": "not checkable"}[cc.status]
            lines.append(f"  {cc.name}: {marker}" + (f" -- {cc.detail}" if cc.detail else ""))
        return "\n".join(lines)


def verify_release_packet_and_result(
    path: Path,
    audit_csv: Path | None = None,
    public_keys: dict[str, bytes] | None = None,
    tsa_certs: list[bytes] | None = None,
) -> CombinedReport:
    """When a directory contains BOTH release_packet.json and
    release_result.json (e.g. the Airlock CLI's own output for a done
    release since PR 43), verify each independently and assert they
    agree on release_id/job_id/document_id/matter_id/status/policy or
    profile/original_sha256/limitations. Never silently picks one and
    ignores the other; a disagreement fails loudly (valid=False), not
    quietly. *path* must be a directory -- a bare release_packet.json
    .zip can never also contain a release_result.json alongside it.
    audit_csv threads through to the packet verifier's chain check;
    public_keys threads through to its signature check (MUST-2);
    tsa_certs threads through to its RFC 3161 anchor check."""
    packet_report = verify_release_packet(path, audit_csv=audit_csv, public_keys=public_keys, tsa_certs=tsa_certs)
    result_report = verify_release_result(path)

    agreement: list[CrossCheck] = []
    try:
        packet_manifest = json.loads((path / "release_packet.json").read_bytes())
    except (OSError, json.JSONDecodeError):
        packet_manifest = {}
    try:
        result_manifest = json.loads((path / "release_result.json").read_bytes())
    except (OSError, json.JSONDecodeError):
        result_manifest = {}

    for packet_field, result_field in _AGREEMENT_FIELDS:
        pv = packet_manifest.get(packet_field)
        rv = result_manifest.get(result_field)
        if pv is None or rv is None:
            agreement.append(
                CrossCheck(
                    f"{packet_field} (packet vs result)", "unavailable",
                    "not present in both artifacts",
                )
            )
            continue
        status = "match" if pv == rv else "mismatch"
        detail = "" if status == "match" else f"packet={pv!r} result={rv!r}"
        agreement.append(CrossCheck(f"{packet_field} (packet vs result)", status, detail))

    # policy_id: packet nests it at policy.id; result has it flat.
    packet_policy_id = (packet_manifest.get("policy") or {}).get("id")
    result_policy_id = result_manifest.get("policy_id")
    if packet_policy_id is not None and result_policy_id is not None:
        status = "match" if packet_policy_id == result_policy_id else "mismatch"
        detail = "" if status == "match" else f"packet={packet_policy_id!r} result={result_policy_id!r}"
        agreement.append(CrossCheck("policy_id (packet vs result)", status, detail))
    else:
        agreement.append(CrossCheck("policy_id (packet vs result)", "unavailable", "not present in both artifacts"))

    # profile_id: only present on a Release-aware packet's "release"
    # sub-object (PR 42) -- absent entirely for a legacy packet, which is
    # not a failure, just nothing to compare.
    packet_profile_id = (packet_manifest.get("release") or {}).get("profile_id")
    result_profile_id = result_manifest.get("profile_id")
    if packet_profile_id is not None and result_profile_id is not None:
        status = "match" if packet_profile_id == result_profile_id else "mismatch"
        detail = "" if status == "match" else f"packet={packet_profile_id!r} result={result_profile_id!r}"
        agreement.append(CrossCheck("profile_id (packet vs result)", status, detail))
    else:
        agreement.append(
            CrossCheck("profile_id (packet vs result)", "unavailable", "not present in both artifacts")
        )

    # MUST-2: the result's signature_ref names the key that signed the
    # packet next to it -- when both artifacts carry the claim, they must
    # agree. A disagreement means the two artifacts were not produced by
    # the same issuance, which is exactly what the combined mode exists
    # to catch. "unavailable" (legacy result, no ref) is not a failure.
    packet_sig_key = (packet_manifest.get("signature") or {}).get("key_id")
    result_ref_key = (result_manifest.get("signature_ref") or {}).get("key_id")
    if packet_sig_key is not None and result_ref_key is not None:
        status = "match" if packet_sig_key == result_ref_key else "mismatch"
        detail = "" if status == "match" else f"packet={packet_sig_key!r} result_ref={result_ref_key!r}"
        agreement.append(CrossCheck("signing key_id (packet signature vs result signature_ref)", status, detail))
    else:
        agreement.append(
            CrossCheck(
                "signing key_id (packet signature vs result signature_ref)",
                "unavailable",
                "not present in both artifacts",
            )
        )

    valid = (
        packet_report.valid
        and result_report.valid
        and all(cc.status != "mismatch" for cc in agreement)
    )
    return CombinedReport(valid=valid, packet=packet_report, result=result_report, agreement=agreement)


def _public_key_id(raw_public: bytes) -> str:
    """key_id the same way the server computes it (service/app/security
    .py::custody_key_id): sha256 of the raw public bytes, truncated --
    so an operator's key file identifies itself under the same id the
    packets it signed carry, and no separate key-id mapping is needed."""
    return hashlib.sha256(raw_public).hexdigest()[:16]


def _load_public_keys(paths: list[Path]) -> dict[str, bytes]:
    """--public-key can be given more than once (a bundle of keys
    covering multiple rotations). Returns {key_id: raw bytes} -- raises
    SystemExit on an unparseable file, since a bad key path is an
    operator error to fix, not a packet verdict.

    SHOULD-3 (review 2026-08-30): two DIFFERENT key files resolving to
    the same key_id is also an operator error, and it used to be a
    silent last-one-wins overwrite -- the operator believes their bundle
    covers two rotations while it actually holds one, and a packet
    signed by the shadowed key verifies against the wrong material
    without a word said. Same-file duplicates (a path passed twice) are
    the no-op they always were."""
    keys: dict[str, bytes] = {}
    seen_paths: dict[str, Path] = {}
    for p in paths:
        try:
            raw = _parse_public_key_pem(p.read_text())
        except (OSError, ValueError) as e:
            raise SystemExit(f"--public-key {p}: {e}") from e
        key_id = _public_key_id(raw)
        prior = seen_paths.get(key_id)
        if prior is not None and prior != p:
            raise SystemExit(
                f"--public-key: {prior} and {p} both resolve to key_id {key_id} "
                "-- two distinct files must not share one id"
            )
        seen_paths[key_id] = p
        keys[key_id] = raw
    return keys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "path", type=Path,
        help="release packet .zip/directory, or a release_result.json file/directory",
    )
    ap.add_argument(
        "--audit-csv", type=Path, default=None,
        help="optional: a matter's exported audit chain (GET /v1/matters/{id}/audit/export)"
             " -- independently recomputes every chain row hash and checks the"
             " packet's declared manifest/derivative hashes against the"
             " chain-committed values, so a manifest altered before packet"
             " assembly fails instead of re-hashing clean",
    )
    ap.add_argument(
        "--public-key", type=Path, default=None, action="append", dest="public_key_paths",
        help="optional (repeatable): the deployment's custody public key (PEM from"
             " GET /v1/custody-public-key, or a 64-char hex string) -- verifies the"
             " packet's Ed25519 signature. Without it a signed packet reports"
             " 'NOT VERIFIED (no key)' but still hash-checks",
    )
    ap.add_argument(
        "--tsa-cert", type=Path, default=None, action="append", dest="tsa_cert_paths",
        help="optional (repeatable): a TSA signing certificate (PEM or DER) to pin"
             " IN ADDITION to the embedded default (DigiCert). An rfc3161-tsa anchor"
             " signed by a TSA this verifier does not recognize reports"
             " 'unrecognized TSA certificate' and fails the packet until that TSA's"
             " certificate is pinned here -- an operator-configured TSA (proposal"
             " §6) is added this way",
    )
    ap.add_argument(
        "--verify-signature", action="store_true", default=False,
        help="strict signature mode: escalate signature downgrades to FAILURES --"
             " a packet that is unsigned, has no key available, or names an unknown"
             " key exits non-zero instead of passing with a 'NOT VERIFIED' line."
             " Use this when a signature is REQUIRED (e.g. checking your own"
             " deployment's output); the default stays lenient so legacy packets"
             " and key-less hash checks keep working. Needs --public-key too",
    )
    args = ap.parse_args(argv)

    # Auto-detect, in priority order:
    #   1. a directory with BOTH artifacts -> verify and cross-check both,
    #      never silently pick one (PR 44).
    #   2. a bare release_result.json, or a directory that has one but no
    #      release_packet.json (a refused/failed release's output has no
    #      packet at all) -> the smaller result verifier alone.
    #   3. otherwise -> the full packet verifier alone.
    path = args.path
    public_keys = _load_public_keys(args.public_key_paths) if args.public_key_paths else None
    tsa_certs = _load_tsa_certs(args.tsa_cert_paths) if args.tsa_cert_paths else None
    has_both = path.is_dir() and (path / "release_packet.json").is_file() and (path / "release_result.json").is_file()
    is_result = path.name == "release_result.json" or (
        path.is_dir() and (path / "release_result.json").is_file() and not (path / "release_packet.json").is_file()
    )
    if has_both:
        report = verify_release_packet_and_result(path, audit_csv=args.audit_csv, public_keys=public_keys, tsa_certs=tsa_certs)
    elif is_result:
        report = verify_release_result(path)
    else:
        report = verify_release_packet(path, audit_csv=args.audit_csv, public_keys=public_keys, tsa_certs=tsa_certs)
    if args.verify_signature:
        # Strict mode can only be satisfied by the packet verifier -- a
        # bare release_result.json is never signed (signature_ref only
        # names the key), so asking for strict signature checking on one
        # is an operator error, reported as such rather than silently
        # passing. The combined report escalates via its packet half.
        if is_result and not has_both:
            print(
                "--verify-signature applies to release packets, not a bare"
                " release_result.json (results carry only a signature_ref, the"
                " signature lives on the packet). Pass the packet's directory or zip."
            )
            return 2
        packet_half = report.packet if isinstance(report, CombinedReport) else report
        if packet_half.signature_status != "verified":
            packet_half.valid = False
            if packet_half.signature_status == "mismatch":
                pass  # already a failure by construction
            else:
                packet_half.signature_detail += (
                    " [--verify-signature: unsigned or unkeyed packets fail in strict mode]"
                )
            if isinstance(report, CombinedReport):
                report.valid = False
    print(report.to_text())
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
