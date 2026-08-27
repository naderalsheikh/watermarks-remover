#!/usr/bin/env python3
"""CounselClear release-packet / release-result verifier (PR 37, PR 39).

Offline, stdlib-only, no engine/app dependency: recomputes every content
hash a manifest declares against the bytes actually present, checks
required fields, cross-checks a few identifiers between JSON documents
where practical, and reports plainly what it could and could not verify
-- most importantly, whether the release is externally anchored (it
isn't, in this release; see the module docstring's "Anchor status"
section below).

Two artifact shapes, three entry points:

- `verify_release_packet()` -- a full release packet (.zip or extracted
  directory): derivative + manifest.json + report.json + certificate.html
  + release_packet.json + README.txt. Only exists for a `done` release.
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

Exit code 0: every check that could run, passed (still prints the
"NOT EXTERNALLY ANCHORED" notice -- that's not a failure, it's an honest
statement about what this release does not yet do). Exit code 1: at
least one check failed (a missing file, a hash mismatch, a schema
problem, or a cross-check disagreement).

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

Anchor status: as of this release, every packet/result ships with
`anchor.type: "none"` -- there is no external timestamp authority,
transparency log, or customer-held WORM copy backing any release's
timestamp or content yet (docs/release-packet-verification-and-
anchoring-proposal.md §5/§6 surveys the options; none are implemented).
This tool will never print "verified", "unforgeable", "independently
timestamped", "court-proof", or "unimpeachable" -- see that proposal's
§7. The only claim it makes is the narrower one that's actually true:
internal hash consistency, recomputed independently of the system that
produced it, using only the bytes handed to it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

REQUIRED_MANIFEST_FIELDS = (
    "spec_version",
    "packet_id",
    "matter_id",
    "document_id",
    "job_id",
    "kind",
    "status",
    "policy",
    "hashes",
    "audit_refs",
    "limitations",
    "generated_at",
    "generated_by",
    "anchor",
    # PR 39: original_sha256 travels at the top level -- binding original
    # to derivative never requires opening manifest.json's own nested
    # copy first. release_id is declared but NOT required (absent for a
    # legacy packet with no Release wrapper) -- see verify_release_packet.
    "original_sha256",
)

REQUIRED_SIBLING_FILES = ("manifest.json", "report.json", "certificate.html", "README.txt")

# PR 39: release_result.json's own required fields -- a much smaller,
# derivative-free artifact than release_packet.json, produced for EVERY
# terminal release (done, refused, or failed), not just a successful one.
REQUIRED_RELEASE_RESULT_FIELDS = (
    "spec_version",
    "release_id",
    "job_id",
    "document_id",
    "matter_id",
    "status",
    "policy_id",
    "reason",
    "original_sha256",
    "created_at",
    "finished_at",
    "audit_refs",
    "limitations",
    "certificate_html_sha256",
    "generated_at",
    "anchor",
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
    if anchor_type in (None, "none"):
        return (
            f"  NOT EXTERNALLY ANCHORED. This {artifact}'s timestamp and content are\n"
            "  self-attested by the system that produced it. No independent party\n"
            "  has confirmed this content existed at the claimed time. The checks\n"
            f"  above confirm internal hash consistency only -- that the bytes in\n"
            f"  this {artifact} match what it itself declares -- not that its own\n"
            "  claims are independently timestamped or unforgeable."
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


@dataclass
class VerificationReport:
    valid: bool
    schema_ok: bool
    file_checks: list[FileCheck] = field(default_factory=list)
    cross_checks: list[CrossCheck] = field(default_factory=list)
    anchor_type: str | None = None
    release_id: str | None = None
    errors: list[str] = field(default_factory=list)

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
            lines.append("Cross-checks (release_packet.json vs. manifest.json):")
            for cc in self.cross_checks:
                marker = {"match": "ok", "mismatch": "MISMATCH", "unavailable": "not checkable"}[cc.status]
                lines.append(f"  {cc.name}: {marker}" + (f" -- {cc.detail}" if cc.detail else ""))
        lines.append("")
        lines.append(f"Externally anchored: {'no' if self.anchor_type in (None, 'none') else self.anchor_type}")
        lines.append(_anchor_note(self.anchor_type, artifact="packet"))
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
        lines.append(f"Externally anchored: {'no' if self.anchor_type in (None, 'none') else self.anchor_type}")
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


def verify_release_packet(path: Path) -> VerificationReport:
    """The whole check, factored out of main() so tests (and a future
    static-web verifier reimplementing this in JS) can drive it directly."""
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

    valid = (
        schema_ok
        and not errors
        and all(fc.status == "match" for fc in file_checks)
        and all(cc.status != "mismatch" for cc in cross_checks)
    )
    return VerificationReport(
        valid=valid,
        schema_ok=schema_ok,
        file_checks=file_checks,
        cross_checks=cross_checks,
        anchor_type=(manifest.get("anchor") or {}).get("type") if schema_ok else None,
        release_id=manifest.get("release_id") if schema_ok else None,
        errors=errors,
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


def verify_release_packet_and_result(path: Path) -> CombinedReport:
    """When a directory contains BOTH release_packet.json and
    release_result.json (e.g. the Airlock CLI's own output for a done
    release since PR 43), verify each independently and assert they
    agree on release_id/job_id/document_id/matter_id/status/policy or
    profile/original_sha256/limitations. Never silently picks one and
    ignores the other; a disagreement fails loudly (valid=False), not
    quietly. *path* must be a directory -- a bare release_packet.json
    .zip can never also contain a release_result.json alongside it."""
    packet_report = verify_release_packet(path)
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

    valid = (
        packet_report.valid
        and result_report.valid
        and all(cc.status != "mismatch" for cc in agreement)
    )
    return CombinedReport(valid=valid, packet=packet_report, result=result_report, agreement=agreement)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "path", type=Path,
        help="release packet .zip/directory, or a release_result.json file/directory",
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
    has_both = path.is_dir() and (path / "release_packet.json").is_file() and (path / "release_result.json").is_file()
    is_result = path.name == "release_result.json" or (
        path.is_dir() and (path / "release_result.json").is_file() and not (path / "release_packet.json").is_file()
    )
    if has_both:
        report = verify_release_packet_and_result(path)
    elif is_result:
        report = verify_release_result(path)
    else:
        report = verify_release_packet(path)
    print(report.to_text())
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
