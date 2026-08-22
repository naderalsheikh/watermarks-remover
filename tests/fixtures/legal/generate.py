#!/usr/bin/env python3
"""Generate the synthetic legal-document regression corpus (PR 10).

Everything here is fabricated for tests — no real client material. Re-run to
regenerate byte-identical fixtures:

    .venv/bin/python tests/fixtures/legal/generate.py
"""

from __future__ import annotations

import io
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
ZWSP = "\u200b"

SPA_CLAUSES = [
    "1. The Seller shall deliver the Shares on Closing.",
    "2. The Buyer shall pay the Consideration under Section 8.3.",
    "3. This Agreement is governed by the laws of Delaware.",
]
SPA_DELETED = "4. DELETED CLAUSE about the side payment."
SPA_INSERTED = "4. The Parties shall keep these terms confidential."


def _docx(parts: dict[str, str]) -> bytes:
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
            "<dc:title>Merger Draft</dc:title>"
            "<dc:subject>Transaction</dc:subject>"
            "<dc:creator>Jane Associate</dc:creator>"
            "<cp:lastModifiedBy>Jane Associate</cp:lastModifiedBy>"
            "<cp:keywords>confidential, merger</cp:keywords>"
            "</cp:coreProperties>",
        )
        zf.writestr(
            "docProps/app.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            "<Application>Microsoft Office Word</Application>"
            "<Company>Preston &amp; Hale LLP</Company>"
            "<Manager>R. Hale</Manager>"
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


def _pdf(*objects: bytes, trailers: int = 1) -> bytes:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ]
    objs.extend(objects)
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    for _t in range(trailers):
        out += b"xref\n0 %d\n" % (len(objs) + 1)
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\n" % (len(objs) + 1)
        out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def _xlsx(parts: dict[str, str], sheets_xml: str) -> bytes:
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


def _tiff_gps() -> bytes:
    """Little-endian TIFF Exif IFD0 -> GPS sub-IFD (lat ref N only)."""
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    gps_offset = 8 + 2 + 12 + 4
    body = bytearray()
    body += struct.pack("<H", 1)
    body += struct.pack("<HHI", 34853, 4, 1)
    body += struct.pack("<I", gps_offset)
    body += struct.pack("<I", 0)
    body += struct.pack("<H", 1)
    body += struct.pack("<HHI", 1, 2, 2)
    body += b"N\x00\x00\x00"
    body += struct.pack("<I", 0)
    return header + bytes(body)


def main() -> None:
    # 1. Plain-text SPA excerpt with a Layer A carrier.
    spa_text = "\n".join(SPA_CLAUSES) + f"\n{SPA_INSERTED}\nConsideration{ZWSP}amounts are final.\n"
    (HERE / "spa.txt").write_text(spa_text, encoding="utf-8")

    # 2. DOCX SPA with tracked changes, a comment, and a privilege-legend header.
    body_parts = []
    for clause in SPA_CLAUSES:
        body_parts.append(f"<w:p><w:r><w:t>{clause}</w:t></w:r></w:p>")
    body_parts.append(
        f'<w:p><w:ins><w:r><w:t>{SPA_INSERTED}</w:t></w:r></w:ins>'
        f"<w:del><w:r><w:delText>{SPA_DELETED}</w:delText></w:r></w:del></w:p>"
    )
    body_parts.append(
        "<w:p><w:r><w:t>Consideration</w:t></w:r>"
        "<w:commentRangeStart/><w:r><w:t>amounts</w:t></w:r><w:commentRangeEnd/>"
        "<w:r><w:commentReference/></w:r><w:r><w:t> are final.</w:t></w:r></w:p>"
    )
    docx = _docx(
        {
            "word/document.xml": "".join(body_parts),
            "word/comments.xml": "<w:comment/>",
            "word/header1.xml": "<w:p><w:r><w:t>ATTORNEY WORK PRODUCT</w:t></w:r></w:p>",
        }
    )
    (HERE / "spa.docx").write_bytes(docx)

    # 3. Signed-PDF stub (/SigFlags + /ByteRange) with an AI producer.
    signed = _pdf(
        b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /SigFlags 3 >> /Perms << >> >>",
        b"<< /Type /Annot /Subtype /Widget /FT /Sig /ByteRange [0 100 200 300] >>",
        b"<< /Producer (Claude Opus) /Creator (Anthropic Claude) >>",
    )
    (HERE / "signed.pdf").write_bytes(signed)

    # 4. .docm carrying VBA.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?><w:document {W_NS}><w:body><w:p/></w:body></w:document>',
        )
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0VBA-STUB")
    (HERE / "macro.docm").write_bytes(buf.getvalue())

    # 5. XLSX with a hidden sheet, an external link, and a legacy comment.
    xlsx = _xlsx(
        {
            "xl/worksheets/sheet1.xml": (
                '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>'
            ),
            "xl/comments1.xml": "<comments xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><comment ref=\"A1\"/></comments>",
            # Real Excel numbers this part (person1.xml, person2.xml, ...); it
            # never writes the unnumbered person.xml this fixture used to use.
            "xl/persons/person1.xml": '<persons xmlns="http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"><person/></persons>',
            "xl/externalLinks/externalLink1.xml": '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
        },
        sheets_xml=(
            '<sheet name="Deal" sheetId="1" r:id="rId1"/>'
            '<sheet name="SideTerms" sheetId="2" state="hidden" r:id="rId2"/>'
        ),
    )
    (HERE / "hidden.xlsx").write_bytes(xlsx)

    # 6. Incremental-update PDF with identity-bearing /Info.
    incr = _pdf(
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Producer (Claude Opus) /Author (Attorney A) /Title (Draft SPA v3) >>",
        trailers=2,
    )
    (HERE / "incremental.pdf").write_bytes(incr)

    # 7. JPEG with GPS.
    exif = b"Exif\x00\x00" + _tiff_gps()
    jpg = bytearray(b"\xff\xd8")
    jpg += b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    jpg += b"\xff\xe1" + struct.pack(">H", len(exif) + 2) + exif
    jpg += b"\xff\xda\x00\x02\x00\x00\xff\xd9"
    (HERE / "gps.jpg").write_bytes(bytes(jpg))

    print("fixtures written:", ", ".join(sorted(p.name for p in HERE.glob("*.*") if p.name != "generate.py")))


if __name__ == "__main__":
    sys.exit(main())
