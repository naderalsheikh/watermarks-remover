#!/usr/bin/env python3
"""Seed a CounselClear instance with a demo matter for evaluation.

Creates (or reuses) a matter, uploads a synthetic PDF fixture carrying
embedded-image EXIF metadata inside a JPEG XObject, and optionally triggers
inspect + sanitize jobs so a reviewer lands on populated results instead of
an empty matter. The sanitize job's manifest shows the "embedded-image
metadata removed" notice, proving the byte-preserving strip ran for real
against a live pipeline, not a mock.

This deliberately does NOT try to also demo the indirect-/Length "not
cleared" notice: an indirect `/Length N G R` image XObject is the one shape
strip_pdf_image_metadata skips rather than guesses at, but in this
deployment (qpdf + exiftool both present) that state is not reachable
through a real sanitize job. qpdf's own structural rewrite -- which runs
before the deep-image strip in clean_pdf's exiftool branch, and which
external_sharing/production hard-require to succeed -- normalizes indirect
/Length references to direct integers as a side effect, so there is never
an indirect reference left by the time the strip step runs. That nuance is
verified and documented in docs/pdf-deep-image-metadata.md ("A precise,
verified nuance on the indirect-`/Length` skip's reachability") and covered
by a direct unit test (test_clean_pdf_reports_indirect_length_images_honestly
in tests/test_pdf_deep_images.py) that calls clean_pdf directly rather than
through the HTTP API. Seeding a fixture here that claimed to reproduce it
through this script would misrepresent what the product actually does.

Talks to a running instance over its real HTTP API (cookie session login,
multipart upload) -- no direct DB/filesystem access, so this exercises the
same path a reviewer's browser does. Idempotent: reruns reuse the matter and
skip documents that are already uploaded by filename.

Usage:
    COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 \\
        python3 tools/seed_eval_matter.py --base-url http://127.0.0.1:8443
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import mimetypes
import os
import struct
import time
import urllib.error
import urllib.request
import uuid

# A real, valid, tiny (4x4 RGB) JPEG -- same fixture used in
# tests/test_pdf_deep_images.py, baked in here so this script has no test
# suite or image-library dependency.
_REAL_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/4gogSUNDX1BST0ZJTEUAAQEAAAoQAAAAAAIQAABt"
    "bnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwQVBQTAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApkZXNjAAAA/AAAAHxjcHJ0"
    "AAABeAAAACh3dHB0AAABoAAAABRia3B0AAABtAAAABRyWFlaAAAByAAAABRnWFlaAAAB"
    "3AAAABRiWFlaAAAB8AAAABRyVFJDAAACBAAACAxnVFJDAAACBAAACAxiVFJDAAACBAAA"
    "CAxkZXNjAAAAAAAAACJBcnRpZmV4IFNvZnR3YXJlIHNSR0IgSUNDIFByb2ZpbGUAAAAA"
    "AAAAAAAAACJBcnRpZmV4IFNvZnR3YXJlIHNSR0IgSUNDIFByb2ZpbGUAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdGV4dAAAAABDb3B5cmlnaHQgQXJ0aWZl"
    "eCBTb2Z0d2FyZSAyMDExAFhZWiAAAAAAAADzUQABAAAAARbMWFlaIAAAAAAAAAAAAAAA"
    "AAAAAABYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAA"
    "AAAAACSgAAAPhAAAts9jdXJ2AAAAAAAABAAAAAAFAAoADwAUABkAHgAjACgALQAyADcA"
    "OwBAAEUASgBPAFQAWQBeAGMAaABtAHIAdwB8AIEAhgCLAJAAlQCaAJ8ApACpAK4AsgC3"
    "ALwAwQDGAMsA0ADVANsA4ADlAOsA8AD2APsBAQEHAQ0BEwEZAR8BJQErATIBOAE+AUUB"
    "TAFSAVkBYAFnAW4BdQF8AYMBiwGSAZoBoQGpAbEBuQHBAckB0QHZAeEB6QHyAfoCAwIM"
    "AhQCHQImAi8COAJBAksCVAJdAmcCcQJ6AoQCjgKYAqICrAK2AsECywLVAuAC6wL1AwAD"
    "CwMWAyEDLQM4A0MDTwNaA2YDcgN+A4oDlgOiA64DugPHA9MD4APsA/kEBgQTBCAELQQ7"
    "BEgEVQRjBHEEfgSMBJoEqAS2BMQE0wThBPAE/gUNBRwFKwU6BUkFWAVnBXcFhgWWBaYF"
    "tQXFBdUF5QX2BgYGFgYnBjcGSAZZBmoGewaMBp0GrwbABtEG4wb1BwcHGQcrBz0HTwdh"
    "B3QHhgeZB6wHvwfSB+UH+AgLCB8IMghGCFoIbgiCCJYIqgi+CNII5wj7CRAJJQk6CU8J"
    "ZAl5CY8JpAm6Cc8J5Qn7ChEKJwo9ClQKagqBCpgKrgrFCtwK8wsLCyILOQtRC2kLgAuY"
    "C7ALyAvhC/kMEgwqDEMMXAx1DI4MpwzADNkM8w0NDSYNQA1aDXQNjg2pDcMN3g34DhMO"
    "Lg5JDmQOfw6bDrYO0g7uDwkPJQ9BD14Peg+WD7MPzw/sEAkQJhBDEGEQfhCbELkQ1xD1"
    "ERMRMRFPEW0RjBGqEckR6BIHEiYSRRJkEoQSoxLDEuMTAxMjE0MTYxODE6QTxRPlFAYU"
    "JxRJFGoUixStFM4U8BUSFTQVVhV4FZsVvRXgFgMWJhZJFmwWjxayFtYW+hcdF0EXZReJ"
    "F64X0hf3GBsYQBhlGIoYrxjVGPoZIBlFGWsZkRm3Gd0aBBoqGlEadxqeGsUa7BsUGzsb"
    "Yxsg"
)


def _jpeg_appn(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def _with_exif(jpeg: bytes) -> bytes:
    """Insert a fake EXIF APP1 segment (camera + GPS-shaped strings) right
    after SOI, before the real JPEG's own JFIF/ICC segments."""
    payload = b"Exif\x00\x00" + b"FakeCam Model X, GPS 37.7749N 122.4194W"
    return jpeg[:2] + _jpeg_appn(0xE1, payload) + jpeg[2:]


def _pdf_with_image_xobject(jpeg: bytes) -> bytes:
    """One-page PDF whose page resources hold a single JPEG (DCTDecode)
    image XObject with a direct /Length, mirroring the fixture builder in
    tests/test_pdf_deep_images.py."""
    w = h = 4
    content = b"q 200 0 0 200 0 0 cm /Im0 Do Q"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        b"<< /Type /XObject /Subtype /Image /Width %d /Height %d "
        b"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode "
        b"/Length %d >>\nstream\n" % (w, h, len(jpeg)) + jpeg + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objs) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def _demo_fixtures() -> dict[str, bytes]:
    exif_jpeg = _with_exif(_REAL_JPEG)
    return {
        "demo_photo_exif.pdf": _pdf_with_image_xobject(exif_jpeg),
    }


def _multipart_body(field: str, filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    parts = [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode(),
        f"Content-Type: {ctype}\r\n\r\n".encode(),
        content,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class Client:
    def __init__(self, base_url: str):
        if not base_url.startswith(("http://", "https://")):
            raise SystemExit(f"--base-url must be http(s), got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _request(self, method: str, path: str, *, data: bytes | None = None, headers: dict | None = None):
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers or {})  # noqa: S310
        try:
            with self.opener.open(req, timeout=30) as resp:
                body = resp.read()
                return resp.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except json.JSONDecodeError:
                return e.code, {"detail": body.decode(errors="replace")}

    def login(self, password: str) -> None:
        status, body = self._request(
            "POST",
            "/v1/auth/login",
            data=json.dumps({"password": password}).encode(),
            headers={"Content-Type": "application/json"},
        )
        if status != 200:
            raise SystemExit(f"login failed ({status}): {body}")

    def get_json(self, path: str):
        status, body = self._request("GET", path)
        if status != 200:
            raise SystemExit(f"GET {path} failed ({status}): {body}")
        return body

    def post_json(self, path: str, payload: dict):
        status, body = self._request(
            "POST", path, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
        )
        if status not in (200, 201):
            raise SystemExit(f"POST {path} failed ({status}): {body}")
        return body

    def upload(self, path: str, filename: str, content: bytes):
        data, ctype = _multipart_body("file", filename, content)
        status, body = self._request("POST", path, data=data, headers={"Content-Type": ctype})
        if status not in (200, 201):
            raise SystemExit(f"upload {filename} failed ({status}): {body}")
        return body

    def wait_for_job(self, matter_id: str, job_id: str, *, timeout_s: float = 30.0):
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            job = self.get_json(f"/v1/matters/{matter_id}/jobs/{job_id}")
            if job["status"] in ("done", "failed"):
                return job
            time.sleep(0.5)
        raise SystemExit(f"job {job_id} did not finish within {timeout_s}s")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.environ.get("COUNSELCLEAR_API_URL", "http://127.0.0.1:8443"))
    ap.add_argument("--web-url", default=os.environ.get("COUNSELCLEAR_WEB_URL", "http://localhost:3000"))
    ap.add_argument("--password", default=os.environ.get("COUNSELCLEAR_LOCAL_PASSWORD"))
    ap.add_argument("--matter-name", default="PDF Embedded-Image Metadata Demo")
    ap.add_argument("--policy", default="external_sharing")
    ap.add_argument("--no-jobs", action="store_true", help="upload documents only, skip inspect/sanitize")
    args = ap.parse_args()

    if not args.password:
        raise SystemExit("--password or COUNSELCLEAR_LOCAL_PASSWORD is required")

    client = Client(args.base_url)
    client.login(args.password)

    matters = client.get_json("/v1/matters")["matters"]
    existing = next((m for m in matters if m["name"] == args.matter_name), None)
    if existing:
        matter_id = existing["id"]
        print(f"reusing matter {matter_id!r} ({args.matter_name!r})")
    else:
        matter = client.post_json("/v1/matters", {"name": args.matter_name})
        matter_id = matter["id"]
        print(f"created matter {matter_id!r} ({args.matter_name!r})")

    existing_docs = {d["filename"]: d for d in client.get_json(f"/v1/matters/{matter_id}/documents")["documents"]}

    doc_ids: list[str] = []
    for filename, content in _demo_fixtures().items():
        if filename in existing_docs:
            print(f"  document already present: {filename}")
            doc_ids.append(existing_docs[filename]["id"])
            continue
        doc = client.upload(f"/v1/matters/{matter_id}/documents", filename, content)
        doc_ids.append(doc["id"])
        print(f"  uploaded {filename} ({doc['bytes']} bytes, sha256:{doc['sha256'][:16]}…)")

    if not args.no_jobs:
        for doc_id in doc_ids:
            inspect_job = client.post_json(f"/v1/matters/{matter_id}/documents/{doc_id}/inspect-jobs", {})
            client.wait_for_job(matter_id, inspect_job["id"])
            print(f"  inspect job {inspect_job['id']} done for {doc_id}")

            sanitize_job = client.post_json(
                f"/v1/matters/{matter_id}/documents/{doc_id}/sanitize-jobs",
                {"policy_id": args.policy, "reason": "eval seed", "signature_break_attestation": True},
            )
            client.wait_for_job(matter_id, sanitize_job["id"])
            print(f"  sanitize job {sanitize_job['id']} done for {doc_id}")

    print(f"\nOpen: {args.web_url}/matters/view?id={matter_id}")


if __name__ == "__main__":
    main()
