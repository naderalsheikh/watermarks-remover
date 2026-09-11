"""Synthetic message and document builders for the mail adapter harness.

Everything here is fabricated: no real matter documents, no real
addresses. The builders exist so the demo and the tests construct the same
kinds of messages Outlook clients produce (alternative bodies, related
inline images, base64 attachments, duplicate filenames) without depending on
a mailbox.
"""

from __future__ import annotations

import email.policy
import io
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from email.message import EmailMessage

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_CP_NS = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
_DC_NS = "http://purl.org/dc/elements/1.1/"

# Not a real image: enough of a PNG signature to be recognisable, nothing more.
FAKE_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def synthetic_docx(body_text: str, *, creator: str | None = "Jane Associate") -> bytes:
    """Minimal valid DOCX. With ``creator`` set the package carries authoring
    metadata the external-sharing policy strips, so an engine-backed run
    produces a derivative that differs from the input."""
    core = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="{_CP_NS}" xmlns:dc="{_DC_NS}">'
    if creator is not None:
        core += f"<dc:creator>{creator}</dc:creator>"
    core += "</cp:coreProperties>"
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{_W_NS}"><w:body><w:p><w:r><w:t>{body_text}</w:t></w:r></w:p>'
        "</w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        "</Relationships>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document)
        zf.writestr("docProps/core.xml", core)
    return buf.getvalue()


def synthetic_pdf(text: str = "Synthetic") -> bytes:
    """A tiny single-page PDF with a valid xref, enough for format sniffing
    and for qpdf-backed processing."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Contents 4 0 R >>",
        None,
    ]
    stream = f"BT /F1 12 Tf 10 50 Td ({text}) Tj ET".encode("latin-1")
    objects[3] = (
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
    )
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for index, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(out)


@dataclass(frozen=True)
class AttachmentSpec:
    filename: str | None
    content: bytes
    content_type: str = "application/octet-stream"
    disposition: str = "attachment"
    content_id: str | None = None


def build_message(
    *,
    sender: str = "sender@example.test",
    to: Sequence[str] = ("recipient@example.test",),
    cc: Sequence[str] = (),
    subject: str = "Synthetic message",
    text: str = "Please see the attached.",
    html: str | None = None,
    inline_images: Iterable[tuple[str, bytes]] = (),
    attachments: Iterable[AttachmentSpec] = (),
    extra_headers: Iterable[tuple[str, str]] = (),
    linesep: str = "\r\n",
    message_id: str = "<synthetic-0001@example.test>",
) -> bytes:
    """Serialize a synthetic message the way a mail client would."""
    msg = EmailMessage(policy=email.policy.SMTP)
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Message-ID"] = message_id
    msg["Date"] = "Fri, 11 Sep 2026 10:00:00 +0000"
    msg["MIME-Version"] = "1.0"
    for name, value in extra_headers:
        msg[name] = value

    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
        html_part = msg.get_payload()[-1]
        for cid, image in inline_images:
            html_part.add_related(image, "image", "png", cid=f"<{cid}>", disposition="inline")
    for spec in attachments:
        maintype, _, subtype = spec.content_type.partition("/")
        kwargs: dict[str, object] = {"disposition": spec.disposition}
        if spec.filename is not None:
            kwargs["filename"] = spec.filename
        if spec.content_id is not None:
            kwargs["cid"] = f"<{spec.content_id}>"
        msg.add_attachment(spec.content, maintype=maintype, subtype=subtype, **kwargs)

    policy = email.policy.SMTP.clone(linesep=linesep)
    return msg.as_bytes(policy=policy)
