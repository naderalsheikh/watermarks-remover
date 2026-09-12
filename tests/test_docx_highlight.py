"""Policy-driven DOCX highlight removal preserves visible document content."""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service" / "scripts"))

import container_meta
from engine_api import inspect_bytes
from policies import apply_actions, plan_actions
from verify import verify_derivative

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def document(body: str, prefix: str = "w") -> bytes:
    return (
        f'<{prefix}:document xmlns:{prefix}="{W}"><{prefix}:body>'
        f"{body}</{prefix}:body></{prefix}:document>"
    ).encode()


def package(body: str, extra: dict[str, bytes] | None = None) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
            'officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        zf.writestr(
            "_rels/.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        )
        zf.writestr("word/document.xml", document(body))
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return out.getvalue()


def part(data: bytes, name: str = "word/document.xml") -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return zf.read(name)


def xml_root(data: bytes):
    return ET.fromstring(data)  # noqa: S314 - synthetic test fixture


HIGHLIGHTED = (
    '<w:p><w:r><w:rPr><w:b/><w:highlight w:val="yellow"/></w:rPr>'
    '<w:t xml:space="preserve"> Highlighted clause &amp; words. </w:t></w:r>'
    "<w:r><w:t>Ordinary clause.</w:t></w:r></w:p>"
)


def test_external_sharing_removes_highlight_and_passes_existing_verification():
    original = package(HIGHLIGHTED)
    plan = plan_actions(inspect_bytes(original, "review.docx"), "external_sharing")
    assert plan.actions["hidden_text"]["action"] == "strip"

    cleaned, records = apply_actions(original, plan)
    before, after = xml_root(part(original)), xml_root(part(cleaned))
    assert [t.text for t in after.iter(f"{{{W}}}t")] == [t.text for t in before.iter(f"{{{W}}}t")]
    assert len(list(after.iter(f"{{{W}}}r"))) == len(list(before.iter(f"{{{W}}}r")))
    assert len(list(after.iter(f"{{{W}}}b"))) == 1
    assert not list(after.iter(f"{{{W}}}highlight"))
    assert any("removed highlight formatting" in record.detail for record in records)
    verification = verify_derivative(
        original, cleaned, plan, pre_present=set(plan.present_subtypes), name="review.docx"
    )
    assert verification["pass"], verification


def test_operator_keep_decision_preserves_highlight_and_visible_words():
    original = package(HIGHLIGHTED)
    plan = plan_actions(
        inspect_bytes(original, "review.docx"), "external_sharing", {"hidden_text": "keep"}
    )
    assert plan.actions["hidden_text"]["action"] == "flag"
    cleaned, _ = apply_actions(original, plan)
    root = xml_root(part(cleaned))
    assert list(root.iter(f"{{{W}}}highlight"))
    assert " Highlighted clause & words. " in [t.text for t in root.iter(f"{{{W}}}t")]


@pytest.mark.parametrize(
    "name", ["word/header1.xml", "word/footnotes.xml", "word/glossary/document.xml"]
)
def test_highlight_removal_covers_body_bearing_parts(name):
    original = package("<w:p/>", {name: document(HIGHLIGHTED)})
    cleaned, actions = container_meta.clean_docx(original, strip_hidden_text=True)
    root = xml_root(part(cleaned, name))
    assert not list(root.iter(f"{{{W}}}highlight"))
    assert " Highlighted clause & words. " in [t.text for t in root.iter(f"{{{W}}}t")]
    assert any("removed highlight formatting" in action and name in action for action in actions)


def test_highlight_never_changes_which_runs_are_concealed():
    body = HIGHLIGHTED + (
        '<w:p><w:r><w:rPr><w:rStyle w:val="Concealed"/>'
        '<w:highlight w:val="cyan"/></w:rPr><w:t>Hidden by style.</w:t></w:r>'
        '<w:r><w:rPr><w:vanish/><w:highlight w:val="green"/></w:rPr>'
        "<w:t>Directly hidden.</w:t></w:r></w:p>"
    )
    styles = (
        f'<w:styles xmlns:w="{W}"><w:style w:type="character" w:styleId="Concealed">'
        "<w:rPr><w:vanish/></w:rPr></w:style></w:styles>"
    ).encode()
    original = package(body, {"word/styles.xml": styles})
    assert container_meta.extract_docx_hidden_text(original) == [
        "Hidden by style.",
        "Directly hidden.",
    ]
    cleaned, actions = container_meta.clean_docx(original, strip_hidden_text=True)
    texts = [t.text for t in xml_root(part(cleaned)).iter(f"{{{W}}}t")]
    assert texts == [" Highlighted clause & words. ", "Ordinary clause."]
    assert container_meta.extract_docx_hidden_text(cleaned) == []
    assert any("removed highlight formatting from 1 run(s)" in action for action in actions)


def test_style_highlight_is_retained_and_existing_verification_still_blocks_it():
    styles = (
        f'<w:styles xmlns:w="{W}"><w:style w:type="character" w:styleId="Marked">'
        '<w:rPr><w:highlight w:val="yellow"/></w:rPr></w:style></w:styles>'
    ).encode()
    original = package(
        '<w:p><w:r><w:rPr><w:rStyle w:val="Marked"/></w:rPr><w:t>Styled.</w:t></w:r></w:p>',
        {"word/styles.xml": styles},
    )
    plan = plan_actions(inspect_bytes(original, "review.docx"), "external_sharing")
    cleaned, _ = apply_actions(original, plan)
    assert list(xml_root(part(cleaned, "word/styles.xml")).iter(f"{{{W}}}highlight"))
    verification = verify_derivative(original, cleaned, plan, name="review.docx")
    targeted = next(c for c in verification["checks"] if c["name"] == "reinspect_targeted_gone")
    assert not targeted["pass"], verification


def test_highlight_helper_uses_namespace_not_prefix_and_preserves_other_properties():
    xml = document(HIGHLIGHTED.replace("w:", "wx:"), prefix="wx")
    result = container_meta._docx_strip_highlight(xml)
    assert result is not None
    cleaned, counts = result
    root = xml_root(cleaned)
    assert not list(root.iter(f"{{{W}}}highlight"))
    assert len(list(root.iter(f"{{{W}}}b"))) == 1
    assert counts == {"runs_affected": 1}


@pytest.mark.parametrize(
    "body",
    [
        '<w:p><w:r><w:rPr><w:highlight w:val="none"/></w:rPr><w:t>Visible.</w:t></w:r></w:p>',
        '<w:p><w:pPr><w:rPr><w:highlight w:val="yellow"/></w:rPr></w:pPr>'
        "<w:r><w:t>Visible.</w:t></w:r></w:p>",
        '<w:p><w:r><w:rPr><a:highlight xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"/>'
        "</w:rPr><w:t>Visible.</w:t></w:r></w:p>",
    ],
)
def test_highlight_helper_leaves_non_target_formatting_byte_identical(body):
    xml = document(body)
    assert container_meta._docx_strip_highlight(xml) == (xml, {"runs_affected": 0})


def test_highlight_helper_fails_without_partially_transforming_malformed_xml():
    assert container_meta._docx_strip_highlight(b"<broken") is None
