#!/usr/bin/env python3
"""CounselClear Airlock CLI (PR 34, release-packet terminology since
PR 36, Release-native since PR 43) — the "invisible airlock" proof of
concept: one command, one file in, a release packet out (the derivative
and its custody proof, together by default -- see
docs/COUNSELCLEAR_DESIGN.md PR 36), no browser required.

Talks to an already-running CounselClear API over plain HTTP (cookie
session login, multipart upload, JSON, and two binary downloads) --
exactly the same endpoints the web dashboard itself calls. This is a
thin HTTP client, nothing more: it never imports the engine, never
touches a database, and never writes an audit event of its own -- every
custody/audit guarantee comes from the API it's calling, not from this
script. See docs/counselclear-strategy.md point 4 (the engine/control-
plane boundary this deliberately stays outside of) and the approved
proposal for this pass: an HTTP client of the existing API, not a
second engine-invoking write path.

Usage (single file)::

    COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 python3 tools/counselclear_airlock.py \\
        --matter-id <existing matter id> \\
        --file /path/to/document.docx \\
        --profile counterparty_deal_room \\
        --recipient-type opposing_counsel \\
        --output-dir ./airlock-out

Usage (batch -- a folder, or an explicit file list; PR 38)::

    COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 python3 tools/counselclear_airlock.py \\
        --matter-id <existing matter id> \\
        --folder ./intake \\
        --profile counterparty_deal_room \\
        --recipient-type opposing_counsel \\
        --output-dir ./airlock-out

    # or: --files a.docx b.pdf c.txt   (explicit list instead of a folder)

Batch mode processes every file in sequence through the exact same
per-file workflow as single-file mode (upload, release, poll, download/
write the release packet) -- one file's outcome (including a hard error:
a failed upload, a failed submit, a poll timeout) never aborts the rest
of the batch. Each file gets its own numbered subdirectory
(<output-dir>/001-<name>/, 002-<name>/, ...) containing the exact same
files single-file mode would have written there; a top-level
<output-dir>/BATCH_RESULT.json summarizes every file's status, job id,
its packet's subdirectory, and any limitations/refusal/failure/error --
release packets in a batch are not externally anchored, same as a
single one. --folder is not recursive: only files directly inside it
are processed. Every file in a batch shares the same --profile/
--recipient-type/etc. -- no per-file overrides.

Release profiles: only counterparty_deal_room and public_filing_anonymized
are offered in this first version, in both single-file and batch mode --
both are decision-free (RELEASE_PROFILES[*].policy_id resolves to a
POLICIES[*].bulk_safe policy in service/app/main.py), so every finding
resolves without a per-finding approve/keep decision this CLI has no
interactive way to supply. ediscovery_production is refused at the
argument-parser level, not silently degraded, so a caller finds out
immediately rather than after a job (or a whole batch) that would have
needed decisions this CLI can't provide.

Release-native since PR 43: this CLI calls POST .../releases (via
Client.release()), not the legacy POST .../sanitize-jobs -- a
--recipient-type is required on every release this tool prepares, and
every output directory gets a release_result.json (the lightweight,
always-present outcome record, written for every terminal release
including a successful one) alongside the full release packet when
done. --policy is no longer a recognized argument, and Client.sanitize()
-- the old caller-side wrapper for the legacy route -- is deleted (dead
code: nothing in this repo ever called it), so this CLI now has no code
path to the legacy sanitize-jobs route at all.

Legal basis (the PR 55/58 chain reaching an operator): findings that
SURVIVE a release (kept, flagged, inspect-only) can carry an operator-
supplied legal basis, which the certificate, release packet, and
release_result all then disclose. --legal-basis SUBTYPE=BASIS
(repeatable) + --legal-basis-note supply it, e.g.::

    --legal-basis comments_and_notes=privilege --legal-basis-note \\
        "AC-2024 redaction protocol"

BASIS is the controlled vocabulary (unspecified | privilege |
work_product | pii_confidentiality | relevance | court_order |
client_instruction | litigation_hold | gdpr_access | other); SUBTYPE is
a policy-engine subtype. Both are validated at argument parsing (the
backend would otherwise fail the whole job after the upload round
trip). Omitting both is fully supported: surviving findings are then
recorded as basis "unspecified" -- recorded honestly, never blocking
the release.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import io
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# Only two of the three v1 release profiles are decision-free
# (RELEASE_PROFILES[*].policy_id resolves to a POLICIES[*].bulk_safe
# policy in service/app/main.py) -- ediscovery_production (-> production)
# requires a per-finding decision workflow this CLI has no way to drive.
# Literal here, not fetched from GET /v1/release-profiles at runtime, so
# an unsupported --profile value is rejected before any network call.
SUPPORTED_PROFILES = ("counterparty_deal_room", "public_filing_anonymized")

# Mirrors service/app/main.py's RECIPIENT_TYPES -- same literal-not-
# imported reason as SUPPORTED_PROFILES above: this CLI has no control-
# plane dependency at all. --recipient-type is required (stricter than
# the backend's own "other" default) so every release this tool prepares
# forces a conscious recipient choice.
RECIPIENT_TYPES = ("opposing_counsel", "court", "client", "regulator", "internal_reviewer", "other")

# The controlled legal-basis vocabulary the backend accepts for findings
# that survive a derivative (LEGAL_JUSTIFICATION_BASES in service/scripts/
# policies.py, mirrored in finding.schema.json and release_packet.schema.
# json). Same deliberate-literal rule as RECIPIENT_TYPES above: no
# control-plane import. The backend rejects any value outside this list
# (a failed job), so validating here means a typo surfaces at argument
# parse, not after a full run.
LEGAL_BASIS_VALUES = (
    "unspecified",
    "privilege",
    "work_product",
    "pii_confidentiality",
    "relevance",
    "court_order",
    "client_instruction",
    "litigation_hold",
    "gdpr_access",
    "other",
)

# Policy-engine subtypes a legal basis can be attached to (SUBTYPES in
# service/scripts/policies.py), same literal-copy rule. The backend only
# records a basis on findings that SURVIVE the derivative (keep/flag/
# inspect_only action records) -- a basis on a stripped subtype is
# silently unused, which is why --legal-basis takes the subtype
# explicitly rather than guessing.
LEGAL_BASIS_SUBTYPES = (
    "authoring_props",
    "jpeg_gps",
    "comments_and_notes",
    "headers_footers",
    "hidden_structure",
    "hidden_text",
    "embeddings_ole",
    "custom_xml",
    "external_links",
    "pdf_js_actions",
    "pdf_acroform",
    "pdf_attachments",
    "pdf_annots",
    "tracked_changes",
    "pdf_incremental",
    "c2pa",
    "layer_a_body",
    "layer_a_non_body",
    "cms_or_xml_dsig",
    "macros_vba",
)


def parse_legal_basis_flags(raw: list[str] | None, note: str) -> dict[str, dict[str, str]]:
    """--legal-basis SUBTYPE=BASIS (repeatable) + one shared
    --legal-basis-note, into the {subtype: {basis, note}} shape the
    release API takes. Validated here, not just server-side: the
    backend turns an unknown subtype or basis into a FAILED JOB after
    the whole upload+release round trip, and a typo deserves to fail at
    argument parsing instead. Returns {} when nothing was supplied --
    legal basis stays purely additive, never a release requirement.
    """
    out: dict[str, dict[str, str]] = {}
    for item in raw or []:
        subtype, sep, basis = item.partition("=")
        if not sep or not subtype.strip() or not basis.strip():
            raise AirlockError(
                f"--legal-basis must be SUBTYPE=BASIS (e.g. "
                f"comments_and_notes=privilege), got: {item!r}"
            )
        subtype = subtype.strip()
        basis = basis.strip()
        if subtype not in LEGAL_BASIS_SUBTYPES:
            raise AirlockError(
                f"--legal-basis subtype {subtype!r} is not a known subtype "
                f"(known: {', '.join(LEGAL_BASIS_SUBTYPES)})"
            )
        if basis not in LEGAL_BASIS_VALUES:
            raise AirlockError(
                f"--legal-basis basis {basis!r} is not a known basis "
                f"(known: {', '.join(LEGAL_BASIS_VALUES)})"
            )
        if subtype in out:
            raise AirlockError(f"--legal-basis given twice for subtype {subtype!r}")
        out[subtype] = {"basis": basis, "note": note[:1000]}
    if note and not out:
        # A note with no basis to attach it to would otherwise be
        # silently dropped -- refuse it so the caller notices.
        raise AirlockError("--legal-basis-note given without any --legal-basis")
    return out

DEFAULT_TIMEOUT_S = 120.0
POLL_INTERVAL_S = 1.0


class AirlockError(Exception):
    """Raised for any unrecoverable step; main() turns this into exit 1."""


def _multipart_body(field_name: str, filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    parts = [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode(),
        f"Content-Type: {ctype}\r\n\r\n".encode(),
        content,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class Client:
    """Stdlib-only HTTP client (no `requests` dependency) against the
    CounselClear API -- same http.cookiejar session-cookie pattern as
    tools/seed_eval_matter.py, so the two tools/ scripts share one
    convention for talking to a live instance."""

    def __init__(self, base_url: str, timeout_s: float = 30.0):
        if not base_url.startswith(("http://", "https://")):
            raise AirlockError(f"--base-url must be http(s), got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _raw(
        self, method: str, path: str, *, data: bytes | None = None, headers: dict | None = None
    ) -> tuple[int, bytes, str]:
        req = urllib.request.Request(  # noqa: S310 -- base_url is operator-supplied, checked http(s) above
            self.base_url + path, data=data, method=method, headers=headers or {}
        )
        try:
            with self.opener.open(req, timeout=self.timeout_s) as resp:
                return resp.status, resp.read(), resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers.get("Content-Type", "") if e.headers else ""

    def _json(self, method: str, path: str, *, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        status, body, _ctype = self._raw(method, path, data=data, headers=headers)
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"detail": body.decode(errors="replace")}
        if status >= 400:
            raise AirlockError(f"{method} {path} failed ({status}): {parsed.get('detail', parsed)}")
        return parsed

    def login(self, password: str) -> None:
        self._json("POST", "/v1/auth/login", payload={"password": password})

    def upload_document(self, matter_id: str, path: Path) -> dict:
        content = path.read_bytes()
        data, ctype = _multipart_body("file", path.name, content)
        status, body, _ctype = self._raw(
            "POST", f"/v1/matters/{matter_id}/documents", data=data, headers={"Content-Type": ctype}
        )
        parsed = json.loads(body) if body else {}
        if status >= 400:
            raise AirlockError(f"upload {path.name} failed ({status}): {parsed.get('detail', parsed)}")
        return parsed

    def release(
        self,
        matter_id: str,
        doc_id: str,
        *,
        profile_id: str,
        recipient_type: str,
        recipient_name: str,
        purpose: str,
        intended_external: bool,
        reason: str,
        legal_justifications: dict[str, dict[str, str]] | None = None,
    ) -> dict:
        """POST .../releases (PR 39/43): returns {release, job,
        release_result} in one round trip -- release_result is the
        server's own precomputed release_result.json content (limitations
        included), so callers never need to hand-derive that from a raw
        manifest the way this CLI once did. legal_justifications is the
        operator-supplied legal basis for findings that survive the
        derivative, {subtype: {basis, note}} -- {} / None (the default)
        means none supplied, which the backend records as basis
        "unspecified" on surviving findings; it never gates a release."""
        payload: dict = {
            "profile_id": profile_id,
            "recipient_type": recipient_type,
            "recipient_name": recipient_name,
            "purpose": purpose,
            "intended_external": intended_external,
            "reason": reason,
        }
        if legal_justifications:
            payload["legal_justifications"] = legal_justifications
        return self._json(
            "POST",
            f"/v1/matters/{matter_id}/documents/{doc_id}/releases",
            payload=payload,
        )

    def get_job(self, matter_id: str, job_id: str) -> dict:
        return self._json("GET", f"/v1/matters/{matter_id}/jobs/{job_id}")

    def wait_for_terminal(self, matter_id: str, job_id: str, *, timeout_s: float) -> dict:
        """The single-document sanitize-jobs route runs synchronously today
        (service/app/main.py's sanitize_job calls _execute_job inline before
        returning) -- so in practice the POST response is already terminal.
        Polling anyway, rather than trusting that, means this CLI keeps
        working correctly if that ever changes, and it's the one place the
        approved spec explicitly asked for polling."""
        deadline = time.monotonic() + timeout_s
        job = self.get_job(matter_id, job_id)
        while job["status"] in ("queued", "running"):
            if time.monotonic() >= deadline:
                raise AirlockError(
                    f"job {job_id} did not reach a terminal state within {timeout_s:.0f}s "
                    f"(last status: {job['status']!r})"
                )
            time.sleep(POLL_INTERVAL_S)
            job = self.get_job(matter_id, job_id)
        return job

    def get_release_packet_zip(self, matter_id: str, job_id: str) -> bytes | None:
        """The release packet (service/app/main.py's job_bundle route,
        PR 36/37): derivative + manifest.json + report.json +
        certificate.html + release_packet.json + README.txt, all in one
        zip -- the same thing the web UI's "Download release packet"
        button fetches. None if the job isn't done (nothing to package)
        or the packet is incomplete server-side."""
        status, body, _ctype = self._raw("GET", f"/v1/matters/{matter_id}/jobs/{job_id}/bundle")
        if status in (404, 409):  # 409: job not done / release packet incomplete
            return None
        if status >= 400:
            raise AirlockError(f"GET release packet failed ({status}): {body.decode(errors='replace')}")
        return body

    def get_certificate_html(self, matter_id: str, job_id: str) -> bytes:
        status, body, _ctype = self._raw("GET", f"/v1/matters/{matter_id}/jobs/{job_id}/certificate")
        if status >= 400:
            raise AirlockError(f"GET certificate failed ({status}): {body.decode(errors='replace')}")
        return body


@dataclass
class AirlockResult:
    matter_id: str
    document_id: str
    job_id: str
    release_id: str
    profile_id: str
    recipient_type: str
    status: str
    error: str
    files_written: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "matter_id": self.matter_id,
            "document_id": self.document_id,
            "job_id": self.job_id,
            "release_id": self.release_id,
            "profile_id": self.profile_id,
            "recipient_type": self.recipient_type,
            "status": self.status,
            "error": self.error,
            "files_written": self.files_written,
            "limitations": self.limitations,
            "generated_at": self.generated_at,
        }


def run_airlock(
    client: Client,
    *,
    matter_id: str,
    file_path: Path,
    profile_id: str,
    recipient_type: str,
    recipient_name: str,
    purpose: str,
    intended_external: bool,
    reason: str,
    output_dir: Path,
    timeout_s: float,
    legal_justifications: dict[str, dict[str, str]] | None = None,
) -> AirlockResult:
    """The whole workflow, factored out of main() so tests can drive it
    against a fake or real Client without going through argv/exit codes."""
    if profile_id not in SUPPORTED_PROFILES:
        raise AirlockError(
            f"--profile {profile_id!r} is not supported by this CLI in v1 "
            f"(only {', '.join(SUPPORTED_PROFILES)} -- see the module docstring)"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    doc = client.upload_document(matter_id, file_path)
    document_id = doc["id"]

    response = client.release(
        matter_id,
        document_id,
        profile_id=profile_id,
        recipient_type=recipient_type,
        recipient_name=recipient_name,
        purpose=purpose,
        intended_external=intended_external,
        reason=reason,
        legal_justifications=legal_justifications,
    )
    release_id = response["release"]["id"]
    release_result = response["release_result"]
    job = client.wait_for_terminal(matter_id, response["job"]["id"], timeout_s=timeout_s)
    job_id = job["id"]

    result = AirlockResult(
        matter_id=matter_id,
        document_id=document_id,
        job_id=job_id,
        release_id=release_id,
        profile_id=profile_id,
        recipient_type=recipient_type,
        status=job["status"],
        error=job.get("error", ""),
        # The server's own precomputed limitations (_build_release_result,
        # service/app/main.py) -- this CLI no longer hand-derives them
        # from a raw manifest's actions[], which is what the now-deleted
        # _LIMITATION_MARKERS scan used to do.
        limitations=release_result.get("limitations", []),
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )

    # release_result.json: written verbatim for EVERY terminal release,
    # done included -- the lightweight, always-present outcome record
    # (PR 39's own framing). Sourced from the same POST response that
    # created the release, not a second round trip.
    (output_dir / "release_result.json").write_text(
        json.dumps(release_result, indent=2, sort_keys=True)
    )
    result.files_written.append("release_result.json")

    if job["status"] == "done":
        # One call gets everything else: derivative, manifest.json,
        # report.json, and certificate.html all travel together in the
        # full release packet (the same one the web UI's "Download
        # release packet" button fetches) -- not three separate requests
        # for the same content. release_result.json above is the
        # lightweight companion; this is the full artifact.
        packet_zip = client.get_release_packet_zip(matter_id, job_id)
        if packet_zip is not None:
            with zipfile.ZipFile(io.BytesIO(packet_zip)) as zf:
                names = zf.namelist()
                for name in names:
                    if name.startswith("derivative/") and not name.endswith("/"):
                        deriv_name = Path(name).name
                        (output_dir / deriv_name).write_bytes(zf.read(name))
                        result.files_written.append(deriv_name)
                if "manifest.json" in names:
                    # Written verbatim, same reasoning as release_packet.json
                    # below: release_packet.json's own manifest_json_sha256
                    # was computed over these exact bytes server-side, so a
                    # Python-reformatted re-encoding (even of equivalent
                    # JSON) would break that hash.
                    (output_dir / "manifest.json").write_bytes(zf.read("manifest.json"))
                    result.files_written.append("manifest.json")
                if "report.json" in names:
                    (output_dir / "report.json").write_bytes(zf.read("report.json"))
                    result.files_written.append("report.json")
                if "certificate.html" in names:
                    (output_dir / "certificate.html").write_bytes(zf.read("certificate.html"))
                    result.files_written.append("certificate.html")
                if "release_packet.json" in names:
                    # Written verbatim (not re-serialized) -- this is the
                    # exact machine-verifiable manifest a copy of
                    # tools/counselclear_verify_release_packet.py can check
                    # offline, so the CLI's copy must be byte-identical to
                    # what the server produced, not a Python-reformatted
                    # re-encoding of the same data.
                    (output_dir / "release_packet.json").write_bytes(zf.read("release_packet.json"))
                    result.files_written.append("release_packet.json")
                if "README.txt" in names:
                    # release_packet.json's hashes include README.txt --
                    # extracting it too (alongside this CLI's own richer
                    # AIRLOCK_RESULT.json) means this output directory is
                    # a complete, self-verifying packet on its own, not a
                    # partial one that would fail its own verifier.
                    (output_dir / "README.txt").write_bytes(zf.read("README.txt"))
                    result.files_written.append("README.txt")
    else:
        # refused/failed: no derivative, so no release packet either (the
        # server 409s -- see get_release_packet_zip). release_result.json
        # above is already this outcome's structured record; the
        # standalone certificate route is fetched too so
        # release_result.json's own certificate_html_sha256 has a real
        # sibling file to hash-check against, same as the web UI's own
        # "Download release result" link implies.
        cert_html = client.get_certificate_html(matter_id, job_id)
        (output_dir / "certificate.html").write_bytes(cert_html)
        result.files_written.append("certificate.html")

    result.files_written.append("AIRLOCK_RESULT.json")
    (output_dir / "AIRLOCK_RESULT.json").write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True))

    return result


@dataclass
class BatchItemResult:
    input_file: str
    output_dir: str
    # "done" / "refused" / "failed" mirror the job's own terminal status
    # (AirlockResult.status); "error" is batch-only -- it means run_airlock
    # itself raised AirlockError (upload failed, submit failed, or the poll
    # timed out) before a job status was ever reached for this file.
    status: str
    job_id: str = ""
    document_id: str = ""
    release_id: str = ""
    profile_id: str = ""
    recipient_type: str = ""
    limitations: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "input_file": self.input_file,
            "output_dir": self.output_dir,
            "status": self.status,
            "job_id": self.job_id,
            "document_id": self.document_id,
            "release_id": self.release_id,
            "profile_id": self.profile_id,
            "recipient_type": self.recipient_type,
            "limitations": self.limitations,
            "error": self.error,
        }


@dataclass
class BatchResult:
    matter_id: str
    profile_id: str
    recipient_type: str
    started_at: str
    finished_at: str = ""
    items: list[BatchItemResult] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counts = {"done": 0, "refused": 0, "failed": 0, "error": 0}
        for item in self.items:
            counts[item.status] = counts.get(item.status, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "matter_id": self.matter_id,
            "profile_id": self.profile_id,
            "recipient_type": self.recipient_type,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total": len(self.items),
            "counts": self.counts,
            "anchor_note": "release packets in this batch are not externally anchored",
            "items": [item.to_dict() for item in self.items],
        }


def run_airlock_batch(
    client: Client,
    *,
    matter_id: str,
    files: list[Path],
    profile_id: str,
    recipient_type: str,
    recipient_name: str,
    purpose: str,
    intended_external: bool,
    reason: str,
    output_dir: Path,
    timeout_s: float,
    legal_justifications: dict[str, dict[str, str]] | None = None,
) -> BatchResult:
    """Sequential per-file processing over run_airlock. One file's outcome
    -- including a hard AirlockError (a failed upload, a failed submit, or
    a poll timeout) -- never aborts the rest of the batch; it's recorded as
    that file's own status ("error") and the loop moves on. Profile is
    validated once, up front, so a batch that can't even start doesn't
    process any file partially. Every file in the batch shares the same
    profile/recipient/purpose/intent -- no per-file overrides. Each file
    gets its own numbered subdirectory under output_dir so outputs never
    collide, and a BATCH_RESULT.json summary is written at output_dir
    once every file has been attempted."""
    if profile_id not in SUPPORTED_PROFILES:
        raise AirlockError(
            f"--profile {profile_id!r} is not supported by this CLI in v1 "
            f"(only {', '.join(SUPPORTED_PROFILES)} -- see the module docstring)"
        )
    if not files:
        raise AirlockError("no input files given (empty --folder or --files list)")

    output_dir.mkdir(parents=True, exist_ok=True)
    batch = BatchResult(
        matter_id=matter_id,
        profile_id=profile_id,
        recipient_type=recipient_type,
        started_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )

    for i, file_path in enumerate(files, start=1):
        item_dir_name = f"{i:03d}-{file_path.stem}"
        item_output_dir = output_dir / item_dir_name
        try:
            result = run_airlock(
                client,
                matter_id=matter_id,
                file_path=file_path,
                profile_id=profile_id,
                recipient_type=recipient_type,
                recipient_name=recipient_name,
                purpose=purpose,
                intended_external=intended_external,
                reason=reason,
                output_dir=item_output_dir,
                timeout_s=timeout_s,
                legal_justifications=legal_justifications,
            )
            batch.items.append(
                BatchItemResult(
                    input_file=file_path.name,
                    output_dir=item_dir_name,
                    status=result.status,
                    job_id=result.job_id,
                    document_id=result.document_id,
                    release_id=result.release_id,
                    profile_id=result.profile_id,
                    recipient_type=result.recipient_type,
                    limitations=result.limitations,
                    error=result.error,
                )
            )
        except AirlockError as e:
            batch.items.append(
                BatchItemResult(
                    input_file=file_path.name,
                    output_dir=item_dir_name,
                    status="error",
                    error=str(e),
                )
            )

    batch.finished_at = datetime.now(UTC).isoformat(timespec="seconds")
    (output_dir / "BATCH_RESULT.json").write_text(json.dumps(batch.to_dict(), indent=2, sort_keys=True))
    return batch


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.environ.get("COUNSELCLEAR_API_URL", "http://127.0.0.1:8443"))
    ap.add_argument("--password", default=os.environ.get("COUNSELCLEAR_LOCAL_PASSWORD"))
    ap.add_argument("--matter-id", required=True, help="id of an existing matter to upload into")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", type=Path, help="local file to sanitize (single-file mode)")
    mode.add_argument(
        "--folder", type=Path,
        help="local folder; every regular file directly inside it is processed (batch mode, not recursive)",
    )
    mode.add_argument(
        "--files", nargs="+", type=Path, metavar="FILE",
        help="explicit list of local files to sanitize (batch mode)",
    )
    ap.add_argument("--profile", default="counterparty_deal_room", choices=SUPPORTED_PROFILES)
    ap.add_argument("--recipient-type", required=True, choices=RECIPIENT_TYPES)
    ap.add_argument("--recipient-name", default="")
    ap.add_argument("--purpose", default="")
    ap.add_argument(
        "--intended-external", dest="intended_external", action="store_true", default=True,
        help="this release is intended to leave the organization (default)",
    )
    ap.add_argument(
        "--internal-only", dest="intended_external", action="store_false",
        help="this release is not intended to leave the organization",
    )
    ap.add_argument("--reason", default="airlock CLI")
    ap.add_argument(
        "--legal-basis",
        action="append",
        default=None,
        metavar="SUBTYPE=BASIS",
        help=(
            "legal basis for a finding that survives the release, as "
            "SUBTYPE=BASIS (repeatable, e.g. --legal-basis "
            "comments_and_notes=privilege). BASIS is the controlled "
            f"vocabulary: {', '.join(LEGAL_BASIS_VALUES)}. Purely optional -- "
            "surviving findings without a supplied basis are recorded as "
            "'unspecified', never blocked"
        ),
    )
    ap.add_argument(
        "--legal-basis-note",
        default="",
        help=(
            "one note attached to every --legal-basis entry (the API takes "
            "a per-subtype note; with no per-entry flag this shared note is "
            "the whole note, truncated to 1000 chars server-side)"
        ),
    )
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--timeout-s", type=float, default=DEFAULT_TIMEOUT_S)
    args = ap.parse_args(argv)

    if not args.password:
        print("error: --password or COUNSELCLEAR_LOCAL_PASSWORD is required", file=sys.stderr)
        return 1

    try:
        legal_justifications = parse_legal_basis_flags(args.legal_basis, args.legal_basis_note)
    except AirlockError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.file is not None:
        if not args.file.is_file():
            print(f"error: --file not found: {args.file}", file=sys.stderr)
            return 1

        client = Client(args.base_url)
        try:
            client.login(args.password)
            result = run_airlock(
                client,
                matter_id=args.matter_id,
                file_path=args.file,
                profile_id=args.profile,
                recipient_type=args.recipient_type,
                recipient_name=args.recipient_name,
                purpose=args.purpose,
                intended_external=args.intended_external,
                reason=args.reason,
                output_dir=args.output_dir,
                timeout_s=args.timeout_s,
                legal_justifications=legal_justifications,
            )
        except AirlockError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

        print(f"job {result.job_id}: {result.status}")
        for name in result.files_written:
            print(f"  wrote {args.output_dir / name}")
        if result.limitations:
            print("limitations:")
            for item in result.limitations:
                print(f"  - {item}")
        return 0 if result.status == "done" else 2

    # Batch mode: --folder or --files.
    if args.folder is not None:
        if not args.folder.is_dir():
            print(f"error: --folder not found: {args.folder}", file=sys.stderr)
            return 1
        files = sorted((p for p in args.folder.iterdir() if p.is_file()), key=lambda p: p.name)
        if not files:
            print(f"error: --folder has no regular files: {args.folder}", file=sys.stderr)
            return 1
    else:
        missing = [str(p) for p in args.files if not p.is_file()]
        if missing:
            print(f"error: --files not found: {', '.join(missing)}", file=sys.stderr)
            return 1
        files = args.files

    client = Client(args.base_url)
    try:
        client.login(args.password)
        batch = run_airlock_batch(
            client,
            matter_id=args.matter_id,
            files=files,
            profile_id=args.profile,
            recipient_type=args.recipient_type,
            recipient_name=args.recipient_name,
            purpose=args.purpose,
            intended_external=args.intended_external,
            reason=args.reason,
            output_dir=args.output_dir,
            timeout_s=args.timeout_s,
            legal_justifications=legal_justifications,
        )
    except AirlockError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"batch: {len(batch.items)} file(s) processed")
    for item in batch.items:
        line = f"  {item.input_file}: {item.status}"
        if item.job_id:
            line += f" (job {item.job_id})"
        print(line)
        print(f"    output: {args.output_dir / item.output_dir}")
        if item.error:
            print(f"    error: {item.error}")
        for lim in item.limitations:
            print(f"    - {lim}")
    counts = batch.counts
    print(
        f"summary: done={counts['done']} refused={counts['refused']} "
        f"failed={counts['failed']} error={counts['error']}"
    )
    print(f"wrote {args.output_dir / 'BATCH_RESULT.json'}")
    print("Release packets are not externally anchored.")

    if counts["error"]:
        return 1
    if counts["done"] == len(batch.items):
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
