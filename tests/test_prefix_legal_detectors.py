"""Task 5 — namespace-prefix-tolerant DOCX legal detectors.

OOXML namespace prefixes are arbitrary: binding the wordprocessingml-2006
main URI to ``wx:`` instead of ``w:`` is spec-valid XML and a conforming
parser sees the identical document. Every DOCX legal detector that matched
the literal bytes ``<w:ins`` / ``<w:del`` / ``<w:delText`` / ``<w:vanish``
therefore reported a spec-valid re-prefixed document as carrying no tracked
changes and no hidden text: it never ran Accept All, never stripped the
vanish run, and passed verification with a clean record while the deleted
clause survived in the derivative.

These tests pin the fix at three levels:

1. detector parity — a wx:-prefixed document yields the same tracked-changes
   and hidden-text findings as its w: twin;
2. end to end — the wx: document runs Accept All under external_sharing,
   the deleted clause is REMOVED from the derivative, and verify_derivative
   refuses to pass on a clean record while deletion survives;
3. composition with the Task 3 oracle — a vanish run in a glossary part
   with a wx: prefix fails hidden_text_removed loudly (never "confirmed
   absent") instead of being invisible to the one check that exists to
   catch concealed text.

The tests assert detector/verifier behavior ONLY. Whether real Word opens
a wx:-prefixed file identically was never verified (no Word in this
environment); nothing here may be read as asserting it.
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

import container_meta
from engine_api import inspect_bytes
from policies import apply_actions, plan_actions
from verify import verify_derivative

# The same wordprocessingml-2006 main URI bound to two different prefixes.
# Only the prefix differs; a conforming XML parser must treat the pair as
# the same document.
W_URI = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _decl(prefix: str) -> str:
    return f'xmlns:{prefix}="{W_URI}"'


def _document(prefix: str, inner: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f"<{prefix}:document {_decl(prefix)}><{prefix}:body>{inner}"
        f"</{prefix}:body></{prefix}:document>"
    ).encode()


def _docx(parts: dict[str, bytes]) -> bytes:
    """Minimal valid DOCX zip (no comments/rels beyond the required ones)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        ct = (
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
            "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>"
            "<Default Extension='xml' ContentType='application/xml'/>"
            "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>"
            "<Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-"
            "officedocument.wordprocessingml.document.main+xml'/>"
            "</Types>"
        )
        zf.writestr("[Content_Types].xml", ct.encode())
        zf.writestr(
            "_rels/.rels",
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            b'relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        )
        zf.writestr(
            "word/_rels/document.xml.rels",
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
            b'relationships"></Relationships>',
        )
        for name, raw in parts.items():
            zf.writestr(name, raw)
    return buf.getvalue()


DELETED_CLAUSE = "DELETED CLAUSE about the side payment."
# A fake "secret" for fixtures, not a credential (S105 is a false positive
# here; ruff cannot know that).
HIDDEN_SECRET = "WX VANISH SECRET"  # noqa: S105


def _pair_body(prefix: str) -> str:
    """One tracked deletion and one vanish run — the audit's reproduction."""
    return (
        f"<{prefix}:p><{prefix}:r><{prefix}:t>Visible contract text.</{prefix}:t></{prefix}:r></{prefix}:p>"
        f"<{prefix}:del><{prefix}:r><{prefix}:delText>{DELETED_CLAUSE}</{prefix}:delText>"
        f"</{prefix}:r></{prefix}:del>"
        f"<{prefix}:p><{prefix}:r><{prefix}:rPr><{prefix}:vanish/></{prefix}:rPr>"
        f"<{prefix}:t>{HIDDEN_SECRET}</{prefix}:t></{prefix}:r></{prefix}:p>"
    )


def _pair_docx(prefix: str) -> bytes:
    return _docx({"word/document.xml": _document(prefix, _pair_body(prefix))})


def _body_of(blob: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return zf.read("word/document.xml").decode("utf-8")


# --- 1. detector parity -------------------------------------------------------


def test_wx_prefix_yields_same_findings_as_w():
    """The core bug: a spec-valid re-prefixed document was reported as
    carrying no tracked changes and no hidden text (authoring_props only).
    The two prefixes must produce the same detector findings."""
    w_legal = container_meta.inspect_docx(_pair_docx("w"))[3]["docx_legal"]
    wx_legal = container_meta.inspect_docx(_pair_docx("wx"))[3]["docx_legal"]
    assert w_legal["insertions"] == 0 and w_legal["deletions"] >= 2
    assert w_legal["hidden_vanish"] == 1
    assert wx_legal["insertions"] == w_legal["insertions"], wx_legal
    assert wx_legal["deletions"] == w_legal["deletions"], wx_legal
    assert wx_legal["hidden_vanish"] == w_legal["hidden_vanish"], wx_legal

    joined = "\n".join(container_meta.inspect_docx(_pair_docx("wx"))[2])
    assert "docx-tracked-changes:" in joined, joined
    assert "docx-hidden-text:" in joined, joined


def test_wx_deleted_text_oracle_sees_the_deleted_clause():
    """extract_docx_deleted_text is the verifier's only content-level oracle
    for Accept All; on the wx: document it saw nothing, so the oracle check
    was never even added."""
    wx_deleted = container_meta.extract_docx_deleted_text(_pair_docx("wx"))
    w_deleted = container_meta.extract_docx_deleted_text(_pair_docx("w"))
    assert w_deleted and DELETED_CLAUSE in " ".join(w_deleted)
    assert wx_deleted == w_deleted, wx_deleted


def test_wx_hidden_text_oracle_sees_the_vanish_run():
    """extract_docx_hidden_text (Task 3's oracle) is QName-based and already
    prefix-agnostic; pinned here so the wx: document's concealed run is
    visible to it exactly as the w: run is."""
    assert container_meta.extract_docx_hidden_text(_pair_docx("wx")) == [HIDDEN_SECRET]
    assert container_meta.extract_docx_hidden_text(_pair_docx("w")) == [HIDDEN_SECRET]


def test_wx_plaintext_extraction_matches_w():
    """extract_ooxml_plaintext (stylometry + the oracle's leak probe) matched
    only <w:t> literals; on the wx: document it returned an empty body, so
    even a correct clean could not be leak-checked. The two prefixes must
    yield identical plaintext. (The deleted clause is not expected here:
    it lives in w:delText, which plaintext never included under EITHER
    prefix -- the oracle for it is extract_docx_deleted_text, tested above.)"""
    w_text = container_meta.extract_ooxml_plaintext(_pair_docx("w"), "docx")
    wx_text = container_meta.extract_ooxml_plaintext(_pair_docx("wx"), "docx")
    assert wx_text == w_text, (wx_text, w_text)
    assert "Visible contract text." in wx_text and HIDDEN_SECRET in wx_text


def test_gate_fires_on_wx_markup():
    """_DOCX_LEGAL_MARKUP_RE gates the whole XML-aware pass; with the literal
    bytes it never fired for wx: markup, so _docx_accept_all never ran."""
    raw = _pair_docx("wx")
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        doc = zf.read("word/document.xml")
    assert container_meta._DOCX_LEGAL_MARKUP_RE.search(doc), (
        "wx:-prefixed revision markup must open the XML-aware pass"
    )


def test_accept_all_resolves_wx_markup():
    """The transformer itself is QName-based (already prefix-agnostic); the
    gate was the blocker. With the gate firing, Accept All must resolve the
    wx: document to the same accepted state as its w: twin."""
    w_out, w_stats = container_meta._docx_accept_all(
        _document("w", _pair_body("w")), strip_comment_markers=True
    )
    wx_out, wx_stats = container_meta._docx_accept_all(
        _document("wx", _pair_body("wx")), strip_comment_markers=True
    )
    # One drop: the w:del/wx:del subtree (its delText goes with it, being
    # inside it). Prefixes must resolve identically; the accepted states
    # carry the same visible text.
    assert w_stats["dropped"] == 1 and wx_stats["dropped"] == w_stats["dropped"]
    assert DELETED_CLAUSE.encode() not in wx_out
    assert HIDDEN_SECRET.encode() in wx_out  # accept_all does not strip vanish
    assert b"Visible contract text." in w_out and b"Visible contract text." in wx_out


# --- 2. end to end: no clean record while deletion survives --------------------


def _plan_and_apply(data: bytes, policy: str = "external_sharing"):
    res = inspect_bytes(data, "d.docx")
    plan = plan_actions(res, policy)
    cleaned, _records = apply_actions(data, plan)
    return plan, cleaned


def test_wx_document_runs_accept_all_and_removes_deleted_clause():
    plan, cleaned = _plan_and_apply(_pair_docx("wx"))
    assert plan.actions["tracked_changes"]["action"] == "accept_all", plan.actions
    body = _body_of(cleaned)
    assert DELETED_CLAUSE not in body, "deleted clause survived the clean"
    assert "delText" not in body and "<wx:del>" not in body


def test_wx_verify_fails_while_deletion_survives():
    """Rule (1): never let a record claim more than the code enforces. The
    pre-fix behavior was a passing verify over a surviving deleted clause;
    a derivative that keeps the deletion must fail, and the failure must
    name the leaked content rather than report a clean record."""
    data = _pair_docx("wx")
    plan, cleaned = _plan_and_apply(data)
    # Forge the failure mode this test exists to catch: a derivative that
    # still carries the deleted clause.
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(cleaned)) as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for info in zin.infolist():
            if info.filename == "word/document.xml":
                doc = zin.read(info.filename).decode("utf-8")
                doc = doc.replace(
                    "<wx:t>Visible contract text.</wx:t>",
                    f"<wx:t>Visible contract text. {DELETED_CLAUSE}</wx:t>",
                )
                zout.writestr(info, doc.encode())
            else:
                zout.writestr(info, zin.read(info.filename))
    doctored = buf.getvalue()
    report = verify_derivative(data, doctored, plan, name="d.docx")
    assert report["pass"] is False, [c for c in report["checks"] if not c["pass"]]
    oracle = next(c for c in report["checks"] if c["name"] == "accept_all_deleted_text_absent")
    assert oracle["pass"] is False, oracle


def test_wx_clean_verify_passes_with_oracle_check_present():
    """The honest-path record: the wx: clean passes AND the oracle check is
    actually added (pre-fix it was never added, because the verifier's plan
    never said accept_all and the oracle never saw deleted text)."""
    data = _pair_docx("wx")
    plan, cleaned = _plan_and_apply(data)
    report = verify_derivative(data, cleaned, plan, name="d.docx")
    oracle = next(c for c in report["checks"] if c["name"] == "accept_all_deleted_text_absent")
    assert oracle["pass"] is True, oracle
    assert report["pass"] is True, [c for c in report["checks"] if not c["pass"]]


# --- 3. composition with Task 3: glossary vanish run, wx: prefix ---------------


def _glossary_wx_docx() -> bytes:
    glossary_header = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f"<wx:hdr {_decl('wx')}>"
        "<wx:p><wx:r><wx:t>Glossary header.</wx:t></wx:r></wx:p>"
        "<wx:p><wx:r><wx:rPr><wx:vanish/></wx:rPr>"
        "<wx:t>GLOSSARY SECRET</wx:t></wx:r></wx:p></wx:hdr>"
    ).encode()
    return _docx(
        {
            "word/document.xml": _document(
                "wx",
                "<wx:p><wx:r><wx:t>Visible body.</wx:t></wx:r></wx:p>",
            ),
            "word/glossary/header1.xml": glossary_header,
        }
    )


def test_glossary_wx_vanish_run_fails_hidden_text_oracle():
    """Task 5 x Task 3 composition: a wx:-prefixed vanish run in a glossary
    sub-part (outside the remover's body-part scope) must fail the
    hidden_text oracle loudly — not silently, and never as a false
    'confirmed absent'. The remover's scope decision itself is unchanged
    (widen it or not is a separate decision, same as Task 3)."""
    original = _glossary_wx_docx()

    # The oracle sees the concealed run in the glossary part.
    assert container_meta.extract_docx_hidden_text(original) == ["GLOSSARY SECRET"]

    plan = plan_actions(inspect_bytes(original, "d.docx"), "external_sharing")
    cleaned, _actions = container_meta.clean_docx(original, strip_hidden_text=True)

    # The remover's scope decision is unchanged: the glossary sub-part is
    # outside the body-part set it strips, so the run survives there.
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        glossary = zf.read("word/glossary/header1.xml").decode("utf-8")
    assert "GLOSSARY SECRET" in glossary, "scope expectation changed; adjudicate"

    result = verify_derivative(original, cleaned, plan, name="d.docx")
    check = next(c for c in result["checks"] if c["name"] == "hidden_text_removed")
    assert not check["pass"], check
    assert "confirmed absent" not in check["detail"]
    assert result["pass"] is False


# --- DrawingML guard: the widening must not over-match ------------------------


def test_drawingml_move_to_does_not_trip_the_gate_or_detector():
    """The tolerance is scoped to WordprocessingML bindings (w:, w9:), NOT
    blind <(?:\\w+:)?:. DrawingML custom geometry puts an a:moveTo inside
    ordinary word/document.xml; a blind dialect would have widened the
    legal-markup gate to nearly every document containing a shape."""
    geom = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        b'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        b"<w:body><w:p><w:r><w:t>shape</w:t></w:r></w:p>"
        b'<a:custGeom><a:pathLst><a:path><a:moveTo><a:pt x="0" y="0"/></a:moveTo>'
        b"</a:path></a:pathLst></a:custGeom></w:body></w:document>"
    )
    assert not container_meta._DOCX_LEGAL_MARKUP_RE.search(geom)
    assert not container_meta._DOCX_INS_RE.search(geom)
    assert not container_meta._DOCX_DEL_RE.search(geom)


def test_w9_transitional_binding_is_tolerated():
    """The 2004 transitional wordprocessingml URI (prefix w9 in the wild on
    Word 2003/2007 XML documents) is the same vocabulary: detectors must
    treat it like w: rather than as no markup at all."""
    doc = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w9:document xmlns:w9="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w9:body><w9:p><w9:r><w9:rPr><w9:vanish/></w9:rPr>"
        f"<w9:t>{HIDDEN_SECRET}</w9:t></w9:r></w9:p></w9:body></w9:document>"
    ).encode()
    legal = container_meta.inspect_docx(_docx({"word/document.xml": doc}))[3]["docx_legal"]
    assert legal["hidden_vanish"] == 1, legal
