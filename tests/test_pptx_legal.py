#!/usr/bin/env python3
"""PR 8: PPTX legal content — speaker notes, hidden slides, comments.

Notes and comment parts strip on the sharing path (parts dropped, dangling
rels + Content_Types overrides pruned); hidden slides are flag-only: never
deleted, show attribute untouched.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

from container_meta import clean_pptx, inspect_container
from findings import findings_for_report

_PPT_NS = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'


def _slide(show_attr: str = "") -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<p:sld {_PPT_NS} {show_attr}><p:cSld><p:spTree/></p:cSld></p:sld>'
    ).encode()


def _pptx(parts: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        ct = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>"
            "<Default Extension='xml' ContentType='application/xml'/>"
            "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>"
        )
        for name in parts:
            if name.startswith("ppt/slides/slide"):
                n = name.split("slide")[-1].split(".")[0]
                ct += (
                    f"<Override PartName='/ppt/slides/slide{n}.xml' "
                    "ContentType='application/vnd.openxmlformats-officedocument.presentationml.slide+xml'/>"
                )
            elif name.startswith("ppt/notesSlides/notesSlide"):
                n = name.split("notesSlide")[-1].split(".")[0]
                ct += (
                    f"<Override PartName='/ppt/notesSlides/notesSlide{n}.xml' "
                    "ContentType='application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml'/>"
                )
            elif name == "ppt/commentAuthors.xml":
                ct += (
                    "<Override PartName='/ppt/commentAuthors.xml' "
                    "ContentType='application/vnd.openxmlformats-officedocument.presentationml.commentAuthors+xml'/>"
                )
        ct += "</Types>"
        zf.writestr("[Content_Types].xml", ct.encode())
        zf.writestr(
            "ppt/_rels/presentation.xml.rels",
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
        )
        # slide rels reference notes/comments so dangling-rel pruning is exercised
        for i in (1, 2):
            slide_rels = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                f'<Relationship Id="rIdN{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../notesSlides/notesSlide{i}.xml"/>'
                "</Relationships>"
            )
            if f"ppt/slides/slide{i}.xml" in parts:
                zf.writestr(f"ppt/slides/_rels/slide{i}.xml.rels", slide_rels.encode())
        for name, raw in parts.items():
            zf.writestr(name, raw)
    return buf.getvalue()


def _full_pptx() -> bytes:
    return _pptx(
        {"ppt/slides/slide1.xml": _slide(), "ppt/slides/slide2.xml": _slide('show="0"'),
         "ppt/notesSlides/notesSlide1.xml": b"<p:notes/>",
         "ppt/notesSlides/notesSlide2.xml": b"<p:notes/>",
         "ppt/comments/comment1.xml": b"<p:cmLst/>",
         "ppt/commentAuthors.xml": b"<p:cmAuthorLst/>"},
    )


# --- inspect ------------------------------------------------------------------


def test_inspect_enumerates_notes_hidden_slides_comments(tmp_path):
    p = tmp_path / "t.pptx"
    p.write_bytes(_full_pptx())
    rep = inspect_container(p).to_dict()
    legal = rep["details"]["pptx_legal"]
    assert legal["slide_count"] == 2
    assert legal["hidden_slides"] == 1
    assert legal["notes_parts"] == 2
    assert legal["comment_parts"] == 2
    joined = "\n".join(rep["findings"])
    assert "pptx-notes: 2 speaker-notes part(s)" in joined
    assert "pptx-comments: 2 comment part(s)" in joined
    assert "pptx-hidden-slides: 1 hidden slide(s)" in joined


def test_clean_pptx_has_no_note_or_comment_hits(tmp_path):
    out, _ = clean_pptx(_full_pptx())
    p = tmp_path / "cleaned.pptx"
    p.write_bytes(out)
    legal = inspect_container(p).to_dict()["details"]["pptx_legal"]
    assert legal["notes_parts"] == 0
    assert legal["comment_parts"] == 0
    # hidden slide is flag-only: still there, still flagged
    assert legal["hidden_slides"] == 1


# --- clean ----------------------------------------------------------------------


def test_clean_strips_notes_and_comments_with_prunes():
    out, actions = clean_pptx(_full_pptx())
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        names = zf.namelist()
        assert not any(n.startswith("ppt/notesSlides/") for n in names)
        assert not any(n.startswith("ppt/comments/") for n in names)
        assert "ppt/commentAuthors.xml" not in names
        rels = zf.read("ppt/slides/_rels/slide1.xml.rels").decode()
        ct = zf.read("[Content_Types].xml").decode()
    assert "rIdN1" not in rels  # dangling notesSlide relationship pruned
    assert "/ppt/notesSlides/" not in ct
    assert "/ppt/commentAuthors.xml" not in ct
    assert any("drop part ppt/notesSlides/notesSlide1.xml" in a for a in actions)


def test_hidden_slide_never_deleted_and_show_kept():
    out, _ = clean_pptx(_full_pptx())
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        names = zf.namelist()
        assert "ppt/slides/slide2.xml" in names
        assert b'show="0"' in zf.read("ppt/slides/slide2.xml")


def test_clean_opt_out_flags_keep_parts():
    data = _full_pptx()
    out_keep_all, _ = clean_pptx(data, strip_notes=False, strip_comments=False)
    with zipfile.ZipFile(io.BytesIO(out_keep_all)) as zf:
        names = zf.namelist()
    assert "ppt/notesSlides/notesSlide1.xml" in names
    assert "ppt/commentAuthors.xml" in names

    out_notes_only, _ = clean_pptx(data, strip_comments=False)
    with zipfile.ZipFile(io.BytesIO(out_notes_only)) as zf:
        names = zf.namelist()
    assert "ppt/notesSlides/notesSlide1.xml" not in names
    assert "ppt/commentAuthors.xml" in names


def test_clean_plain_deck_reports_no_artifacts():
    _out, actions = clean_pptx(
        _pptx({"ppt/slides/slide1.xml": _slide()})
    )
    assert any("no PPTX legal artifacts found" in a for a in actions)


# --- canonical findings projection ----------------------------------------------


def test_findings_project_pptx_legal_signals(tmp_path):
    p = tmp_path / "t.pptx"
    p.write_bytes(_full_pptx())
    rep = inspect_container(p).to_dict()
    by_subtype = {
        f.subtype: f for f in findings_for_report("container", rep) if f.format == "pptx"
    }
    assert by_subtype["comments_and_notes"].action_recommended == "strip"
    assert by_subtype["comments_and_notes"].risk_level == "high"
    hs = by_subtype["hidden_structure"]
    assert hs.category == "hidden_structure"
    assert hs.action_recommended == "flag"
    assert hs.content_visible is False
