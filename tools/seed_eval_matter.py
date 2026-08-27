#!/usr/bin/env python3
"""Seed a CounselClear instance with a demo matter for evaluation (Release-native).

Creates (or reuses) a matter and, for each of three synthetic legal-document
fixtures, uploads it and prepares a release under the counterparty_deal_room
profile -- through POST .../documents/{doc_id}/releases, the same
Release-first route the web UI's "Prepare Release Packet" button and the
Airlock CLI's Client.release() both use. This deliberately does NOT use the
legacy POST .../sanitize-jobs route: seeding through it would demo a product
the UI no longer leads with.

The three fixtures are chosen to show three real outcomes under one profile,
not three different policies to also explain:

  - spa.docx    -- a done release. Tracked changes get Accept-All'd and a
                   comment strips; a hidden (w:vanish) "ATTORNEY WORK
                   PRODUCT" paragraph survives flagged (not stripped) --
                   one document, both behaviors.
  - macro.docm  -- a refused release. macros_vba is refused unconditionally
                   by this policy (service/scripts/policies.py) -- no
                   attestation ambiguity, no flaky outcome.
  - hidden.xlsx -- a done release with a visible kept/limited finding. A
                   comment and an external link strip; a hidden sheet is
                   flag-only under this policy and survives, listed under
                   "What was found" but not "Actions taken" on the job page.

No Layer B / watermark-rewrite sample is included here on purpose: that
capability is gated, off by default, and never the product this walkthrough
is meant to demonstrate (docs/COUNSELCLEAR_DESIGN.md, docs/COUNSELCLEAR_
ASSET_MAP.md §4).

Fixture bytes are baked in here, not read from tests/fixtures/legal/: this
script has no test-suite dependency (production images don't ship tests/
either -- service/Dockerfile.counselclear only COPYs scripts/ and app/), the
same reasoning the prior version of this script already followed for its own
inline fixture. The byte structure mirrors tests/fixtures/legal/generate.py's
spa.docx/macro.docm/hidden.xlsx exactly -- those are the real, already
regression-tested fixtures this reproduces, not a fresh invention.

Talks to a running instance over its real HTTP API (cookie session login,
multipart upload) -- no direct DB/filesystem access, so this exercises the
same path a reviewer's browser does. Idempotent: reruns reuse the matter,
skip documents already uploaded by filename, and skip releasing a document
that already has one.

Usage:
    COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 \\
        python3 tools/seed_eval_matter.py --base-url http://127.0.0.1:8443
"""

from __future__ import annotations

import argparse
import http.cookiejar
import io
import json
import mimetypes
import os
import urllib.error
import urllib.request
import uuid
import zipfile

W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'

SPA_CLAUSES = [
    "1. The Seller shall deliver the Shares on Closing.",
    "2. The Buyer shall pay the Consideration under Section 8.3.",
    "3. This Agreement is governed by the laws of Delaware.",
]
SPA_DELETED = "4. DELETED CLAUSE about the side payment."
SPA_INSERTED = "4. The Parties shall keep these terms confidential."


def _docx_bytes(parts: dict[str, str]) -> bytes:
    def decl(root: str, inner: str) -> str:
        return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><{root} {W_NS}>{inner}</{root}>'

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        ct = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            "<Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/>"
            "<Override PartName='/word/comments.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml'/>"
            "<Override PartName='/docProps/core.xml' ContentType='application/vnd.openxmlformats-package.core-properties+xml'/>"
            "<Override PartName='/docProps/app.xml' ContentType='application/vnd.openxmlformats-officedocument.extended-properties+xml'/>"
            "</Types>"
        )
        zf.writestr("[Content_Types].xml", ct)
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>",
        )
        zf.writestr(
            "docProps/core.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<dc:title>Sample Stock Purchase Agreement</dc:title>"
            "<dc:subject>Evaluation Sample</dc:subject>"
            "<dc:creator>Sample Associate</dc:creator>"
            "<cp:lastModifiedBy>Sample Associate</cp:lastModifiedBy>"
            "<cp:keywords>sample, evaluation</cp:keywords>"
            "</cp:coreProperties>",
        )
        zf.writestr(
            "docProps/app.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            "<Application>Microsoft Office Word</Application>"
            "<Company>Sample Firm LLP</Company>"
            "<Manager>Sample Manager</Manager>"
            "</Properties>",
        )
        zf.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdC" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>'
            "</Relationships>",
        )
        for name, xml in parts.items():
            if name == "word/document.xml":
                zf.writestr(name, decl("w:document", f"<w:body>{xml}</w:body>"))
            else:
                zf.writestr(name, decl(name.split("/")[-1].split(".")[0].capitalize(), xml))
    return buf.getvalue()


def _xlsx_bytes(parts: dict[str, str], sheets_xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        ct = (
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            "</Types>"
        )
        zf.writestr("[Content_Types].xml", ct)
        rels = (
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdX" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink" Target="externalLinks/externalLink1.xml"/>'
            "</Relationships>"
        )
        zf.writestr("xl/_rels/workbook.xml.rels", rels)
        zf.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f"<sheets>{sheets_xml}</sheets>"
            '<externalReferences><externalReference r:id="rIdX"/></externalReferences></workbook>',
        )
        for name, xml in parts.items():
            zf.writestr(name, xml)
    return buf.getvalue()


def _fixture_spa_docx() -> bytes:
    """Comment strips, tracked changes get Accept-All'd, and a hidden
    (w:vanish) paragraph survives flagged -- hidden_text is flag-only
    under this policy (service/scripts/policies.py). One document, both
    behaviors."""
    body_parts = [f"<w:p><w:r><w:t>{clause}</w:t></w:r></w:p>" for clause in SPA_CLAUSES]
    body_parts.append(
        f"<w:p><w:ins><w:r><w:t>{SPA_INSERTED}</w:t></w:r></w:ins>"
        f"<w:del><w:r><w:delText>{SPA_DELETED}</w:delText></w:r></w:del></w:p>"
    )
    body_parts.append(
        "<w:p><w:r><w:t>Consideration</w:t></w:r>"
        "<w:commentRangeStart/><w:r><w:t>amounts</w:t></w:r><w:commentRangeEnd/>"
        "<w:r><w:commentReference/></w:r><w:r><w:t> are final.</w:t></w:r></w:p>"
    )
    body_parts.append(
        "<w:p><w:r><w:rPr><w:vanish/></w:rPr>"
        "<w:t>ATTORNEY WORK PRODUCT — PRIVILEGED AND CONFIDENTIAL</w:t></w:r></w:p>"
    )
    return _docx_bytes(
        {
            "word/document.xml": "".join(body_parts),
            "word/comments.xml": "<w:comment/>",
        }
    )


def _fixture_macro_docm() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        zf.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?><w:document {W_NS}><w:body><w:p/></w:body></w:document>',
        )
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0VBA-STUB")
    return buf.getvalue()


def _fixture_hidden_xlsx() -> bytes:
    return _xlsx_bytes(
        {
            "xl/worksheets/sheet1.xml": (
                '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>'
            ),
            "xl/comments1.xml": '<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><comment ref="A1"/></comments>',
            "xl/persons/person1.xml": '<persons xmlns="http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"><person/></persons>',
            "xl/externalLinks/externalLink1.xml": '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
        },
        sheets_xml=(
            '<sheet name="Deal" sheetId="1" r:id="rId1"/>'
            '<sheet name="SideTerms" sheetId="2" state="hidden" r:id="rId2"/>'
        ),
    )


def _demo_fixtures() -> dict[str, bytes]:
    return {
        "Sample - Stock Purchase Agreement.docx": _fixture_spa_docx(),
        "Sample - Macro-Enabled Draft.docm": _fixture_macro_docm(),
        "Sample - Deal Terms Workbook.xlsx": _fixture_hidden_xlsx(),
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.environ.get("COUNSELCLEAR_API_URL", "http://127.0.0.1:8443"))
    ap.add_argument("--web-url", default=os.environ.get("COUNSELCLEAR_WEB_URL", "http://localhost:3000"))
    ap.add_argument("--password", default=os.environ.get("COUNSELCLEAR_LOCAL_PASSWORD"))
    ap.add_argument("--matter-name", default="Sample Matter — Release Gate Walkthrough (CLI)")
    ap.add_argument("--profile", default="counterparty_deal_room")
    ap.add_argument("--no-releases", action="store_true", help="upload documents only, skip preparing releases")
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

    if not args.no_releases:
        existing_releases = {
            j["document_id"]
            for j in client.get_json(f"/v1/matters/{matter_id}/jobs")["jobs"]
            if j.get("release_id")
        }
        for doc_id in doc_ids:
            if doc_id in existing_releases:
                print(f"  release already prepared for document {doc_id}")
                continue
            result = client.post_json(
                f"/v1/matters/{matter_id}/documents/{doc_id}/releases",
                {
                    "profile_id": args.profile,
                    "recipient_type": "opposing_counsel",
                    "recipient_name": "Sample Counterparty",
                    "purpose": "Release Gate evaluation walkthrough",
                    "intended_external": True,
                    "reason": "eval seed",
                },
            )
            release = result["release"]
            print(f"  release {release['id']} for document {doc_id}: {release['status']}")

    print(f"\nOpen: {args.web_url}/matters/view?id={matter_id}")
    print("Then: download a release result/packet from the job page and verify it offline with")
    print("  python3 tools/counselclear_verify_release_packet.py <downloaded-file-or-folder>")


if __name__ == "__main__":
    main()
