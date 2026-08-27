#!/usr/bin/env python3
"""CounselClear release-packet verifier (PR 37).

Offline, stdlib-only, no engine/app dependency: recomputes every content
hash `release_packet.json` declares against the bytes actually present in
a packet, checks the manifest's own required fields, cross-checks a few
identifiers across `release_packet.json`, `manifest.json`, and
`certificate.html` where practical, and reports plainly what it could and
could not verify -- most importantly, whether the packet is externally
anchored (it isn't, in this release; see the module docstring's "Anchor
status" section below).

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

<path> is either a release-packet .zip (as downloaded from
GET /v1/matters/{id}/jobs/{id}/bundle) or a directory it was already
extracted into.

Exit code 0: every check that could run, passed (still prints the
"NOT EXTERNALLY ANCHORED" notice -- that's not a failure, it's an honest
statement about what this release does not yet do). Exit code 1: at
least one check failed (a missing file, a hash mismatch, a schema
problem, or a cross-check disagreement).

Anchor status: as of this release, every packet ships with
`anchor.type: "none"` -- there is no external timestamp authority,
transparency log, or customer-held WORM copy backing any packet's
timestamp or content yet (docs/release-packet-verification-and-
anchoring-proposal.md §5/§6 surveys the options; none are implemented).
This tool will never print "verified", "unforgeable", "independently
timestamped", "court-proof", or "unimpeachable" -- see that proposal's
§7. The only claim it makes is the narrower one that's actually true:
internal hash consistency, recomputed independently of the system that
produced the packet, using only the bytes in the packet itself.
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
)

REQUIRED_SIBLING_FILES = ("manifest.json", "report.json", "certificate.html", "README.txt")


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


@dataclass
class VerificationReport:
    valid: bool
    schema_ok: bool
    file_checks: list[FileCheck] = field(default_factory=list)
    cross_checks: list[CrossCheck] = field(default_factory=list)
    anchor_type: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        lines: list[str] = []
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
            lines.append("Cross-checks (release_packet.json vs. manifest.json / certificate.html):")
            for cc in self.cross_checks:
                marker = {"match": "ok", "mismatch": "MISMATCH", "unavailable": "not checkable"}[cc.status]
                lines.append(f"  {cc.name}: {marker}" + (f" -- {cc.detail}" if cc.detail else ""))
        lines.append("")
        lines.append(f"Externally anchored: {'no' if self.anchor_type in (None, 'none') else self.anchor_type}")
        lines.append(
            "  NOT EXTERNALLY ANCHORED. This packet's timestamp and content are\n"
            "  self-attested by the system that produced it. No independent party\n"
            "  has confirmed this content existed at the claimed time. The checks\n"
            "  above confirm internal hash consistency only -- that the bytes in\n"
            "  this packet match what release_packet.json itself declares -- not\n"
            "  that release_packet.json's own claims are independently timestamped\n"
            "  or unforgeable."
            if self.anchor_type in (None, "none")
            else f"  anchor reference: (type={self.anchor_type})"
        )
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

    if schema_ok and "certificate.html" in files:
        cert_text = files["certificate.html"].decode("utf-8", errors="replace")
        for field_name, label in (
            ("job_id", "job_id"),
            ("matter_id", "matter_id"),
            ("document_id", "document_id"),
            ("status", "status"),
        ):
            value = manifest.get(field_name)
            if value:
                status = "match" if str(value) in cert_text else "mismatch"
                cross_checks.append(CrossCheck(f"{label} appears in certificate.html", status))
            else:
                cross_checks.append(CrossCheck(f"{label} appears in certificate.html", "unavailable"))

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
        errors=errors,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", type=Path, help="release packet .zip, or a directory it was extracted into")
    args = ap.parse_args(argv)

    report = verify_release_packet(args.path)
    print(report.to_text())
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
