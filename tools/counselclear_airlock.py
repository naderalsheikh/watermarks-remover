#!/usr/bin/env python3
"""CounselClear Airlock CLI (PR 34, release-packet terminology since
PR 36) — the "invisible airlock" proof of concept: one command, one file
in, a release packet out (the derivative and its custody proof, together
by default -- see docs/COUNSELCLEAR_DESIGN.md PR 36), no browser required.

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

Usage::

    COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 python3 tools/counselclear_airlock.py \\
        --matter-id <existing matter id> \\
        --file /path/to/document.docx \\
        --policy external_sharing \\
        --output-dir ./airlock-out

Policies: only external_sharing and privacy_only are offered in this
first version -- both are decision-free (POLICIES[*].bulk_safe in
service/app/main.py), so every finding resolves without a per-finding
approve/keep decision this CLI has no interactive way to supply.
production is refused at the argument-parser level, not silently
degraded, so a caller finds out immediately rather than after a job
that would have needed decisions this CLI can't provide.
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

# Only two of the four v1 policies are decision-free (POLICIES[*].bulk_safe
# in service/app/main.py) -- production and evidence_preservation both
# require workflows (per-finding decisions, inspect-only) this CLI has no
# way to drive. Literal here, not fetched from GET /v1/policies at runtime,
# so an unsupported --policy value is rejected before any network call.
SUPPORTED_POLICIES = ("external_sharing", "privacy_only")

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

    def sanitize(self, matter_id: str, doc_id: str, *, policy_id: str, reason: str) -> dict:
        return self._json(
            "POST",
            f"/v1/matters/{matter_id}/documents/{doc_id}/sanitize-jobs",
            payload={"policy_id": policy_id, "reason": reason},
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
        PR 36): derivative + manifest.json + report.json + certificate.html
        + README.txt, all in one zip -- the same thing the web UI's
        "Download release packet" button fetches. None if the job isn't
        done (nothing to package) or the packet is incomplete server-side."""
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


# Mirrors service/app/main.py's NO_DECISION_MARKER / OPERATOR_KEPT_MARKER /
# APPROVED_BUT_NO_OP_MARKER (themselves literal-not-imported from
# scripts/policies.py, PR 17 isolation) -- a third literal copy, not an
# import of app.main, because this CLI has no control-plane dependency at
# all: pulling in service.app for three string constants would mean
# importing FastAPI/SQLAlchemy/the whole control plane into a script whose
# entire point is being a thin, independent HTTP client. Used only to build
# a human-readable summary; certificate.html (always fetched) remains the
# authoritative disclosure, not this list.
_LIMITATION_MARKERS = (
    "no operator decision was supplied",
    "reviewed and kept by operator",
    "approved, but this subtype has no strip action under this policy",
)


@dataclass
class AirlockResult:
    matter_id: str
    document_id: str
    job_id: str
    policy_id: str
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
            "policy_id": self.policy_id,
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
    policy_id: str,
    reason: str,
    output_dir: Path,
    timeout_s: float,
) -> AirlockResult:
    """The whole workflow, factored out of main() so tests can drive it
    against a fake or real Client without going through argv/exit codes."""
    if policy_id not in SUPPORTED_POLICIES:
        raise AirlockError(
            f"--policy {policy_id!r} is not supported by this CLI in v1 "
            f"(only {', '.join(SUPPORTED_POLICIES)} -- see the module docstring)"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    doc = client.upload_document(matter_id, file_path)
    document_id = doc["id"]

    job = client.sanitize(matter_id, document_id, policy_id=policy_id, reason=reason)
    job = client.wait_for_terminal(matter_id, job["id"], timeout_s=timeout_s)
    job_id = job["id"]

    result = AirlockResult(
        matter_id=matter_id,
        document_id=document_id,
        job_id=job_id,
        policy_id=policy_id,
        status=job["status"],
        error=job.get("error", ""),
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )

    if job["status"] == "done":
        # One call gets everything: derivative, manifest.json, report.json,
        # and certificate.html all travel together in the release packet
        # (the same one the web UI's "Download release packet" button
        # fetches) -- not three separate requests for the same content.
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
                    manifest = json.loads(zf.read("manifest.json"))
                    (output_dir / "manifest.json").write_text(
                        json.dumps(manifest, indent=2, sort_keys=True)
                    )
                    result.files_written.append("manifest.json")
                    actions = manifest.get("actions") or []
                    result.limitations = [a for a in actions if any(m in a for m in _LIMITATION_MARKERS)]
                if "report.json" in names:
                    (output_dir / "report.json").write_bytes(zf.read("report.json"))
                    result.files_written.append("report.json")
                if "certificate.html" in names:
                    (output_dir / "certificate.html").write_bytes(zf.read("certificate.html"))
                    result.files_written.append("certificate.html")
    else:
        # refused/failed: no derivative, so no release packet either (the
        # server 409s -- see get_release_packet_zip). The standalone
        # certificate route still renders correctly for both outcomes, so
        # that's this CLI's only source for certificate.html here.
        result.limitations = [f"job {job['status']}: {result.error or 'no further detail recorded'}"]
        cert_html = client.get_certificate_html(matter_id, job_id)
        (output_dir / "certificate.html").write_bytes(cert_html)
        result.files_written.append("certificate.html")

    result.files_written.append("AIRLOCK_RESULT.json")
    (output_dir / "AIRLOCK_RESULT.json").write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True))

    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.environ.get("COUNSELCLEAR_API_URL", "http://127.0.0.1:8443"))
    ap.add_argument("--password", default=os.environ.get("COUNSELCLEAR_LOCAL_PASSWORD"))
    ap.add_argument("--matter-id", required=True, help="id of an existing matter to upload into")
    ap.add_argument("--file", required=True, type=Path, help="local file to sanitize")
    ap.add_argument("--policy", default="external_sharing", choices=SUPPORTED_POLICIES)
    ap.add_argument("--reason", default="airlock CLI")
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--timeout-s", type=float, default=DEFAULT_TIMEOUT_S)
    args = ap.parse_args(argv)

    if not args.password:
        print("error: --password or COUNSELCLEAR_LOCAL_PASSWORD is required", file=sys.stderr)
        return 1
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
            policy_id=args.policy,
            reason=args.reason,
            output_dir=args.output_dir,
            timeout_s=args.timeout_s,
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


if __name__ == "__main__":
    raise SystemExit(main())
