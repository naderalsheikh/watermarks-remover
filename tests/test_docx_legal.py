#!/usr/bin/env python3
"""PR 6: DOCX legal content — comments, Accept All revisions, hidden text,
embeddings, quote-tolerant Content_Types prune.

Fixtures are minimal-but-valid DOCX zips built inline; the Accept All pass is
the stdlib-ElementTree algorithm from the design spec (unwrap w:ins/w:moveTo,
drop w:del/w:moveFrom/*Change subtrees and w:delText) applied to every
word/*.xml part carrying markup — including kept headers.
"""

from __future__ import annotations

import io
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import container_meta
from container_meta import _DOCX_COMMENT_PARTS, clean_docx, inspect_container
from findings import findings_for_report

W_DECL = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"'
)


def _document(inner: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<w:document {W_DECL}><w:body>{inner}'
        '<w:sectPr/></w:body></w:document>'
    ).encode()


def _header(inner: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<w:hdr {W_DECL}>{inner}</w:hdr>'
    ).encode()


def _run(text: str) -> str:
    return f'<w:r><w:t>{text}</w:t></w:r>'


def _docx(parts: dict[str, bytes]) -> bytes:
    """Minimal valid DOCX zip; [Content_Types] uses single quotes on purpose."""
    defaults = {
        "xml": "application/xml",
        "rels": "application/vnd.openxmlformats-package.relationships+xml",
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        overrides = [
            ("/word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
            ("/word/comments.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"),
            ("/word/people.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.people+xml"),
            ("/word/header1.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"),
        ]
        ct = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
        ct += "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>"
        for ext, mime in defaults.items():
            ct += f"<Default Extension='{ext}' ContentType='{mime}'/>"
        for pn, mime in overrides:
            name = pn.lstrip("/")
            if name in parts or name == "word/document.xml":
                ct += f"<Override PartName='{pn}' ContentType='{mime}'/>"
        ct += "</Types>"
        zf.writestr("[Content_Types].xml", ct.encode())
        zf.writestr(
            "_rels/.rels",
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            b"</Relationships>",
        )
        doc_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>'
            '<Relationship Id="rId11" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/people" Target="people.xml"/>'
            '<Relationship Id="rId12" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>'
            + (
                '<Relationship Id="rId13" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="embeddings/oleObject1.bin"/>'
                if "word/embeddings/oleObject1.bin" in parts
                else ""
            )
            + "</Relationships>"
        )
        zf.writestr("word/_rels/document.xml.rels", doc_rels.encode())
        for name, raw in parts.items():
            zf.writestr(name, raw)
    return buf.getvalue()


def _full_docx() -> bytes:
    body = (
        # accepted-state insertion must survive as text
        '<w:p><w:ins><w:r><w:t>inserted words</w:t></w:r></w:ins>'
        # deleted subtree must vanish entirely (delText included)
        '<w:del><w:r><w:delText>deleted words</w:delText></w:r></w:del>'
        # property change wrapper must drop, run kept
        '<w:r><w:rPr><w:rPrChange/></w:rPr><w:t>stable</w:t></w:r></w:p>'
        # hidden-text flags (inspect-only in v1)
        '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>sneaky</w:t></w:r>'
        '<w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>white</w:t></w:r></w:p>'
        # comment anchors to remove when comment parts are stripped
        "<w:p><w:commentRangeStart/><w:r><w:t>anchored</w:t></w:r>"
        "<w:commentRangeEnd/><w:r><w:commentReference/></w:r></w:p>"
    )
    comments = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:comments {W_DECL}><w:comment><w:p><w:r><w:t>look here</w:t></w:r></w:p></w:comment></w:comments>'
    ).encode()
    people = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:people {W_DECL}><w:person w:author="Attorney A"/></w:people>'
    ).encode()
    header = _header("<w:p><w:ins><w:r><w:t>H</w:t></w:r></w:ins></w:p>")
    return _docx(
        {
            "word/document.xml": _document(body),
            "word/comments.xml": comments,
            "word/people.xml": people,
            "word/header1.xml": header,
            "word/embeddings/oleObject1.bin": b"\xd0\xcf\x11\xe0OLE",
        }
    )


# --- inspect ------------------------------------------------------------------


def test_inspect_enumerates_all_legal_artifacts():
    rep = container_meta.inspect_docx(_full_docx())[3]
    legal = rep["docx_legal"]
    assert legal["comment_count"] == 1
    assert set(legal["comment_parts"]) >= {"word/comments.xml", "word/people.xml"}
    assert legal["insertions"] >= 2
    assert legal["deletions"] >= 2  # w:del + w:delText
    assert legal["format_changes"] >= 1
    assert legal["hidden_vanish"] == 1
    assert legal["hidden_white"] == 1
    assert legal["comment_markers"] >= 3
    assert legal["embeddings"] == 1


def test_inspect_findings_use_stable_prefixes():
    _, _, findings, _ = container_meta.inspect_docx(_full_docx())
    joined = "\n".join(findings)
    assert "docx-comments:" in joined
    assert "docx-tracked-changes:" in joined
    assert "docx-hidden-text:" in joined
    assert "docx-embeddings:" in joined


def test_clean_docx_has_no_legal_hits():
    _, _, findings, details = container_meta.inspect_docx(clean_docx(_full_docx())[0])
    legal = details["docx_legal"]
    assert legal["comment_parts"] == []
    assert legal["insertions"] == 0
    assert legal["deletions"] == 0
    assert legal["format_changes"] == 0
    assert legal["comment_markers"] == 0
    joined = "\n".join(findings)
    assert "docx-tracked-changes:" not in joined
    # hidden text is flag-only in v1: still present after clean
    assert "docx-hidden-text:" in joined
    # embeddings default-keep
    assert "docx-embeddings:" in joined


# --- clean: accept-all semantics ------------------------------------------------


def _clean_body_xml(data: bytes) -> ET.Element:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return ET.fromstring(zf.read("word/document.xml"))  # noqa: S314 - test fixture


def test_accept_all_keeps_insertions_and_drops_deletions():
    out, actions = clean_docx(_full_docx())
    root = _clean_body_xml(out)
    texts = [t.text or "" for t in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")]
    joined = "".join(texts)
    assert "inserted words" in joined
    assert "stable" in joined
    assert "deleted words" not in joined
    tags = {e.tag.rsplit('}', 1)[-1] for e in root.iter()}
    assert {"ins", "del", "delText", "rPrChange"} & tags == set()
    assert any("unwrapped" in a for a in actions)
    assert any("dropped" in a for a in actions)


def test_accept_all_resolves_markup_inside_kept_header():
    out, _actions = clean_docx(_full_docx())
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        assert "word/header1.xml" in zf.namelist()  # part kept...
        hdr = zf.read("word/header1.xml")
    assert b"<w:ins>" not in hdr  # ...markup resolved
    assert b"H" in hdr


def test_comment_parts_and_markers_removed_with_prunes():
    out, actions = clean_docx(_full_docx())
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        names = zf.namelist()
        assert not ({_DOCX_COMMENT_PARTS} & {n for n in names})
        assert "word/comments.xml" not in names
        assert "word/people.xml" not in names
        doc = zf.read("word/document.xml")
        rels = zf.read("word/_rels/document.xml.rels")
        ct = zf.read("[Content_Types].xml").decode()
    assert b"commentRangeStart" not in doc
    assert b"commentReference" not in doc
    assert b'Id="rId10"' not in rels  # dangling comment relationship pruned
    assert "PartName='/word/comments.xml'" not in ct  # single-quoted override pruned
    assert "PartName='/word/people.xml'" not in ct
    assert any("Content_Types overrides" in a for a in actions)


def test_embeddings_default_keep_explicit_strip():
    data = _full_docx()
    out, _ = clean_docx(data)
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        assert "word/embeddings/oleObject1.bin" in zf.namelist()
    out, actions = clean_docx(data, strip_embeddings=True)
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        names = zf.namelist()
        assert "word/embeddings/oleObject1.bin" not in names
        assert b'rId13' not in zf.read("word/_rels/document.xml.rels")
        assert "/word/embeddings/" not in zf.read("[Content_Types].xml").decode()
    assert any("drop part word/embeddings/oleObject1.bin" in a for a in actions)


def test_output_is_valid_zip_with_namespaces_preserved(tmp_path):
    out, _ = clean_docx(_full_docx())
    p = tmp_path / "t.docx"
    p.write_bytes(out)
    rep = inspect_container(p).to_dict()
    assert rep["format"] == "docx"
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        doc = zf.read("word/document.xml")
    ET.fromstring(doc)  # noqa: S314 - test fixture; well-formed check
    assert b'xmlns:w="' in doc  # prefix preserved, not ns0


def test_layer_a_still_runs_after_legal_pass():
    body = (
        '<w:p><w:ins><w:r><w:t>zero​width</w:t></w:r></w:ins></w:p>'
        '<w:p><w:del><w:r><w:delText>gone</w:delText></w:r></w:del></w:p>'
    )
    out, actions = clean_docx(_docx({"word/document.xml": _document(body)}))
    root = _clean_body_xml(out)
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    joined = "".join(t.text or "" for t in root.iter(W + "t"))
    assert "gone" not in joined
    # Layer A removed the zero-width space from the surviving insertion
    assert "zerowidth" in joined.replace("\u200b", "")
    assert any("layer A text" in a for a in actions)


# --- canonical findings projection ----------------------------------------------


def test_findings_project_docx_legal_signals():
    has_c2pa, has_ai, findings, _details = container_meta.inspect_docx(_full_docx())
    rep = {
        "format": "docx",
        "has_c2pa": has_c2pa,
        "has_ai_metadata": has_ai,
        "findings": findings,
    }
    found = findings_for_report("container", rep)
    by_subtype = {f.subtype: f for f in found}
    assert {"comments_and_notes", "office_tracked_changes", "hidden_text_formatting", "embeddings_ole"} <= set(by_subtype)
    assert by_subtype["office_tracked_changes"].category == "revision_history"
    assert by_subtype["office_tracked_changes"].action_recommended == "accept_all"
    assert by_subtype["hidden_text_formatting"].category == "invisible_text"
    assert by_subtype["hidden_text_formatting"].content_visible is False
    assert by_subtype["comments_and_notes"].action_recommended == "strip"


def test_accept_all_namespace_registration_does_not_leak_across_documents():
    """xml.etree.ElementTree.register_namespace mutates module-global state.
    Two documents that happen to use the same prefix name for different
    namespace URIs — real files are not required to avoid this — must not
    corrupt each other's serialization when processed in the same process
    (the still-shipped prototype server.py is exactly such a process: one
    long-lived interpreter handling every request)."""
    import xml.etree.ElementTree as ET

    def part(prefix: str, uri: str) -> bytes:
        return (
            f'<?xml version="1.0"?><w:document '
            f'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            f'xmlns:{prefix}="{uri}"><w:body><w:p><w:r {prefix}:paraId="1">'
            f"<w:t>hello</w:t></w:r></w:p></w:body></w:document>"
        ).encode()

    before = dict(ET._namespace_map)
    out_a1, _ = container_meta._docx_accept_all(
        part("w14", "urn:doc-A"), strip_comment_markers=False
    )
    container_meta._docx_accept_all(part("w14", "urn:doc-B"), strip_comment_markers=False)
    out_a2, _ = container_meta._docx_accept_all(
        part("w14", "urn:doc-A"), strip_comment_markers=False
    )

    assert b'xmlns:w14="urn:doc-A"' in out_a1
    assert b'xmlns:w14="urn:doc-A"' in out_a2, (
        "doc A's own prefix must survive an unrelated doc B being processed "
        "in between, not degrade to an auto-generated ns0/ns1"
    )
    assert dict(ET._namespace_map) == before, "global namespace map must be restored"


def test_accept_all_namespace_registration_survives_concurrent_documents():
    """Under contention, unsynchronized ET.register_namespace access can raise
    KeyError from inside the stdlib itself (it snapshots-then-deletes on the
    shared dict), not just silently corrupt a prefix. server.py's
    ThreadingHTTPServer makes this a real, not hypothetical, concurrent path."""
    import concurrent.futures
    import sys

    def part(prefix: str, uri: str) -> bytes:
        return (
            f'<?xml version="1.0"?><w:document '
            f'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            f'xmlns:{prefix}="{uri}"><w:body><w:p><w:r {prefix}:paraId="1">'
            f"<w:t>hello</w:t></w:r></w:p></w:body></w:document>"
        ).encode()

    def process(i: int) -> tuple[int, bool]:
        uri = f"urn:doc-{i}"
        out, _ = container_meta._docx_accept_all(
            part("wX", uri), strip_comment_markers=False
        )
        return i, f'xmlns:wX="{uri}"'.encode() in out

    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # widen the race window as far as possible
    try:
        errors = []

        def safe(i: int) -> bool:
            try:
                return process(i)[1]
            except Exception as e:  # the bug manifests as a raw stdlib KeyError
                errors.append(e)
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            results = list(ex.map(safe, range(1500)))
    finally:
        sys.setswitchinterval(old_interval)

    assert not errors, f"register_namespace race crashed {len(errors)} calls: {errors[:3]}"
    assert all(results), "a document's own prefix must survive concurrent siblings"


# --- Accept All: missing revision markers -----------------------------------

_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def _table_doc(rows_xml: str) -> bytes:
    return f'<?xml version="1.0"?><w:document {_W}><w:body><w:tbl>{rows_xml}</w:tbl></w:body></w:document>'.encode()


def test_accept_all_removes_a_deleted_row_and_its_visible_text():
    """w:trPr/w:del marks the whole ROW deleted, not just the marker element.
    Dropping only the marker (the generic tag-drop path) left a deleted
    row's cell text fully visible after Accept All."""
    xml = _table_doc(
        '<w:tr><w:tc><w:p><w:r><w:t>keep me</w:t></w:r></w:p></w:tc></w:tr>'
        '<w:tr><w:trPr><w:del w:id="1" w:author="A" w:date="2026-01-01T00:00:00Z"/></w:trPr>'
        '<w:tc><w:p><w:r><w:t>PRIVILEGED SETTLEMENT TERMS</w:t></w:r></w:p></w:tc></w:tr>'
    )
    out, stats = container_meta._docx_accept_all(xml, strip_comment_markers=False)
    text = out.decode()
    assert "PRIVILEGED SETTLEMENT TERMS" not in text
    assert "keep me" in text
    assert stats["rows_deleted"] == 1
    assert text.count("<w:tr>") == 1


def test_accept_all_keeps_an_inserted_row():
    """w:trPr/w:ins is the mirror case: accepting an insertion means the row
    (and its properties marker, now unremarkable) stays."""
    xml = _table_doc(
        '<w:tr><w:trPr><w:ins w:id="1" w:author="A" w:date="2026-01-01T00:00:00Z"/></w:trPr>'
        '<w:tc><w:p><w:r><w:t>newly added row</w:t></w:r></w:p></w:tc></w:tr>'
    )
    out, stats = container_meta._docx_accept_all(xml, strip_comment_markers=False)
    text = out.decode()
    assert "newly added row" in text
    assert text.count("<w:tr>") == 1
    assert stats["rows_deleted"] == 0


def test_accept_all_drops_property_change_and_range_bookmark_markers():
    xml = (
        f'<?xml version="1.0"?><w:document {_W}><w:body>'
        '<w:p><w:moveFromRangeStart w:id="1" w:author="A" w:date="2026-01-01T00:00:00Z" w:name="m"/>'
        '<w:r><w:t>body text</w:t></w:r>'
        '<w:moveFromRangeEnd w:id="1"/>'
        '<w:moveToRangeStart w:id="2" w:author="A" w:date="2026-01-01T00:00:00Z" w:name="m2"/>'
        '<w:moveToRangeEnd w:id="2"/>'
        '<w:customXmlInsRangeStart w:id="3" w:author="A" w:date="2026-01-01T00:00:00Z"/>'
        '<w:customXmlInsRangeEnd w:id="3"/>'
        '<w:customXmlDelRangeStart w:id="4" w:author="A" w:date="2026-01-01T00:00:00Z"/>'
        '<w:customXmlDelRangeEnd w:id="4"/>'
        "</w:p>"
        '<w:tbl><w:tblGrid><w:tblGridChange w:id="5"><w:tblGrid><w:gridCol w:w="1"/></w:tblGrid>'
        "</w:tblGridChange></w:tblGrid>"
        '<w:tr><w:trPr><w:trPrChange w:id="6" w:author="A" w:date="2026-01-01T00:00:00Z">'
        "<w:trPr/></w:trPrChange></w:trPr>"
        '<w:tc><w:tcPr><w:tcPrChange w:id="7" w:author="A" w:date="2026-01-01T00:00:00Z">'
        "<w:tcPr/></w:tcPrChange></w:tcPr>"
        "<w:p><w:r><w:t>cell text</w:t></w:r></w:p></w:tc></w:tr></w:tbl>"
        "</w:body></w:document>"
    ).encode()
    out, stats = container_meta._docx_accept_all(xml, strip_comment_markers=False)
    text = out.decode()
    for tag in (
        "moveFromRangeStart", "moveFromRangeEnd", "moveToRangeStart", "moveToRangeEnd",
        "customXmlInsRangeStart", "customXmlInsRangeEnd",
        "customXmlDelRangeStart", "customXmlDelRangeEnd",
        "tblGridChange", "trPrChange", "tcPrChange",
    ):
        assert f"<w:{tag}" not in text, f"{tag} should have been dropped"
    assert "body text" in text and "cell text" in text
    assert stats["dropped"] == 11


def test_cell_level_revisions_are_flagged_not_silently_dropped():
    """cellIns/cellDel/cellMerge are not auto-resolved (grid-span surgery
    risks an unopenable document) but must not be invisible either."""
    xml = (
        f'<?xml version="1.0"?><w:document {_W}><w:body><w:tbl><w:tr>'
        '<w:tc><w:tcPr><w:cellDel w:id="1" w:author="A" w:date="2026-01-01T00:00:00Z"/></w:tcPr>'
        "<w:p><w:r><w:t>cell</w:t></w:r></w:p></w:tc>"
        "</w:tr></w:tbl></w:body></w:document>"
    ).encode()
    with zipfile.ZipFile(io.BytesIO(_docx_from_document_xml(xml))) as zf:
        report, findings = container_meta._inspect_docx_legal(zf, [0])
    assert report["cell_revisions"] == 1
    assert any("cell-revisions" in f for f in findings)


def _docx_from_document_xml(document_xml: bytes) -> bytes:
    """Minimal valid docx wrapping just word/document.xml, for tests that
    only need _inspect_docx_legal's zip-walking behaviour."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()


# --- Accept All: paragraph-mark merges ---------------------------------------

_DEL_MARK = '<w:del w:id="1" w:author="A" w:date="2026-01-01T00:00:00Z"/>'


def _body_doc(body_xml: str) -> bytes:
    return f'<?xml version="1.0"?><w:document {_W}><w:body>{body_xml}</w:body></w:document>'.encode()


def test_deleted_paragraph_mark_merges_into_the_next_paragraph():
    """Word's Accept All merges a paragraph into its successor when the
    paragraph's ending mark was deleted — dropping only the w:del marker
    (the generic tag-drop path) left two separate paragraphs where Word
    would show one."""
    xml = _body_doc(
        f'<w:p><w:pPr><w:rPr>{_DEL_MARK}</w:rPr></w:pPr><w:r><w:t>First sentence.</w:t></w:r></w:p>'
        '<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:t> Second sentence.</w:t></w:r></w:p>'
        '<w:p><w:r><w:t>Third, untouched.</w:t></w:r></w:p>'
    )
    out, stats = container_meta._docx_accept_all(xml, strip_comment_markers=False)
    text = out.decode()
    assert stats["paragraphs_merged"] == 1
    assert text.count("<w:p>") == 2
    assert "First sentence." in text and "Second sentence." in text
    assert "Third, untouched." in text
    # merged paragraph keeps the *next* paragraph's own properties
    assert '<w:jc w:val="center"' in text


def test_paragraph_merge_skips_when_either_side_has_a_section_break():
    xml = _body_doc(
        f'<w:p><w:pPr><w:sectPr/><w:rPr>{_DEL_MARK}</w:rPr></w:pPr><w:r><w:t>A</w:t></w:r></w:p>'
        '<w:p><w:r><w:t>B</w:t></w:r></w:p>'
    )
    out, stats = container_meta._docx_accept_all(xml, strip_comment_markers=False)
    text = out.decode()
    assert stats["paragraphs_merged"] == 0
    assert text.count("<w:p>") == 2
    assert "<w:sectPr" in text, "section break must survive, not be silently dropped"


def test_paragraph_merge_on_last_paragraph_does_not_crash():
    xml = _body_doc(f'<w:p><w:pPr><w:rPr>{_DEL_MARK}</w:rPr></w:pPr><w:r><w:t>only paragraph</w:t></w:r></w:p>')
    out, stats = container_meta._docx_accept_all(xml, strip_comment_markers=False)
    assert stats["paragraphs_merged"] == 0
    assert "only paragraph" in out.decode()


def test_chained_paragraph_mark_deletions_merge_in_one_pass():
    xml = _body_doc(
        f'<w:p><w:pPr><w:rPr>{_DEL_MARK}</w:rPr></w:pPr><w:r><w:t>A </w:t></w:r></w:p>'
        f'<w:p><w:pPr><w:rPr>{_DEL_MARK}</w:rPr></w:pPr><w:r><w:t>B </w:t></w:r></w:p>'
        '<w:p><w:r><w:t>C</w:t></w:r></w:p>'
    )
    out, stats = container_meta._docx_accept_all(xml, strip_comment_markers=False)
    text = out.decode()
    assert stats["paragraphs_merged"] == 2
    assert text.count("<w:p>") == 1
    assert "A " in text and "B " in text and "C" in text
