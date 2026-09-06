"""ODF honesty fix: outward-facing policies refuse ODT/ODS/ODP rather than
emit a clean record the engine cannot earn.

Before this pass, every non-OOXML, non-PDF container took the "other
containers" branch of apply_actions, which ignored the resolved policy
entirely: one generic ODF cleaner (container_meta.clean_odt -- the same
cleaner .ods/.odp reach via the sniff) ran regardless of what the plan
demanded, and the job was recorded as a single honest-looking
ActionRecord("file_metadata", "strip", "odt sharing-clean executed").
Meanwhile office:annotation comments, text:tracked-changes deletions,
embedded objects, external links and non-AI dc:creator authoring fields
survived verbatim -- while the certificate printed the policy description
promising comments stripped / tracked changes accepted.

Mirrors tests/test_pdf_content_refusal.py (PR 48): the engine has no ODF
inspector for this content, so an outward-facing policy must refuse rather
than ship a partial result labeled clean. The refusal is capability-gated
(policies._ODF_UNSTRIPPABLE_SUBTYPES), not presence-gated: unlike PDFs,
nothing in an ODF inspect report enumerates annotations or tracked
changes, so "not seen" means nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import pytest
from engine_api import clean_to_bundle, inspect_bytes
from policies import (
    ODF_CONTENT_REFUSAL_MARKER,
    PDF_CONTENT_REFUSAL_MARKER,
    PolicyError,
    apply_actions,
    plan_actions,
)


def _make_odt(
    *,
    annotation: str | None = "COMMENT: do not reveal the reserve to them",
    tracked_deletion: bool = True,
) -> bytes:
    """A plain LibreOffice document: a visible paragraph, an author
    comment, a tracked deletion, and a human dc:creator. No AI/C2PA
    markers anywhere, so the only findings the inspector can produce are
    Layer A -- none of which drive this refusal."""
    import io
    import zipfile

    annotation_xml = (
        f'<office:annotation office:name="__Annotation__1">'
        f'<dc:creator>Jane Associate</dc:creator>'
        f"<text:p>{annotation}</text:p></office:annotation>"
        if annotation
        else ""
    )
    tracked_xml = (
        '<text:tracked-changes text:track-changes="false">'
        '<text:changed-region xml:id="ct1" text:id="1">'
        "<text:deletion>"
        '<text:p>Reserve figure is 4.2, do not disclose</text:p>'
        "</text:deletion>"
        "</text:changed-region>"
        "</text:tracked-changes>"
        '<text:p>Approved figures follow<text:change-start text:change-id="ct1"/>'
        "<text:change/>"
        '<text:change-end text:change-id="ct1"/>.</text:p>'
        if tracked_deletion
        else "<text:p>Approved figures follow.</text:p>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr(
            "meta.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<office:document-meta '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
            'office:version="1.2">'
            "<dc:creator>Jane Associate</dc:creator>"
            "<meta:creation-date>2026-03-02T10:11:12</meta:creation-date>"
            "</office:document-meta>",
        )
        zf.writestr(
            "content.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<office:document-content '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'office:version="1.2">'
            "<office:body><office:text>"
            + tracked_xml
            + annotation_xml
            + "<text:p>Approved figures follow in the summary.</text:p>"
            "</office:text></office:body></office:document-content>",
        )
        zf.writestr(
            "META-INF/manifest.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<manifest:manifest '
            'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
            'manifest:version="1.2"/>',
        )
    return buf.getvalue()


def _plan_and_expect_refusal(data: bytes, name: str, *, policy="external_sharing"):
    res = inspect_bytes(data, name)
    plan = plan_actions(res, policy)
    with pytest.raises(PolicyError) as exc_info:
        apply_actions(data, plan)
    return str(exc_info.value)


def test_odt_with_comments_and_tracked_changes_refuses_under_external_sharing():
    """The exact brief repro: an ordinary LibreOffice document with an
    author comment and a tracked deletion, under external_sharing. Used to
    return cleaned bytes plus ActionRecord("file_metadata", "strip",
    "odt sharing-clean executed") with the comment and deletion surviving
    verbatim; now the job refuses before any derivative exists."""
    data = _make_odt()
    msg = _plan_and_expect_refusal(data, "brief.odt")
    assert ODF_CONTENT_REFUSAL_MARKER in msg
    # the demanded rows are named with their policy labels
    assert "Comments & speaker notes" in msg
    assert "Tracked changes" in msg
    assert "Author & company identity" in msg
    # no PDF-flavoured capability copy in an ODF refusal
    assert PDF_CONTENT_REFUSAL_MARKER not in msg
    assert "sharing-clean executed" not in msg


def test_plain_odt_refuses_under_external_sharing():
    """The refusal is capability-gated, not content-gated: the engine
    cannot see annotations or tracked changes in an ODF, so a document
    that carries none of the demanded content still refuses -- otherwise
    an uninspectable document would sail through on the absence of
    evidence."""
    data = _make_odt(annotation=None, tracked_deletion=False)
    msg = _plan_and_expect_refusal(data, "plain.odt")
    assert ODF_CONTENT_REFUSAL_MARKER in msg


def test_ods_sniffed_package_refuses_under_external_sharing():
    """.ods/.odp have no detection row of their own; a spreadsheet package
    (content.xml + meta.xml) sniffs as "odt" and takes the same gate. This
    pins that the ODS route really does reach the refusal rather than
    falling out of the gate via some other fmt value."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.spreadsheet")
        zf.writestr(
            "meta.xml",
            '<?xml version="1.0"?><office:document-meta '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            "<dc:creator>Jane Associate</dc:creator></office:document-meta>",
        )
        zf.writestr(
            "content.xml",
            '<?xml version="1.0"?><office:document-content '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0">'
            "<office:body><office:spreadsheet>"
            '<table:table table:name="Figures"><table:table-row>'
            "<table:table-cell><text:p>4.2</text:p></table:table-cell>"
            "</table:table-row></table:table>"
            "</office:spreadsheet></office:body></office:document-content>",
        )
        zf.writestr(
            "META-INF/manifest.xml",
            '<?xml version="1.0"?><manifest:manifest '
            'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>',
        )
    msg = _plan_and_expect_refusal(buf.getvalue(), "figures.ods")
    assert ODF_CONTENT_REFUSAL_MARKER in msg
    assert "ODT/ODS/ODP" in msg


def test_production_refuses_plain_odt():
    """production is outward-facing too: same refusal, no operator
    decision changes it (the demanded authoring_props strip is a plain
    policy row here, not an approve-default the operator can decline)."""
    data = _make_odt(annotation=None, tracked_deletion=False)
    msg = _plan_and_expect_refusal(data, "plain.odt", policy="production")
    assert ODF_CONTENT_REFUSAL_MARKER in msg


def test_privacy_only_odt_still_takes_the_generic_clean():
    """Scope guard for the chosen gate: privacy_only keeps the generic ODF
    cleaner. Its one removal demand (authoring_props=strip_listed) is
    deliberately not in the refusal tuple -- strip_listed is a narrower
    promise than the engine's AI-only scrub covers, and privacy_only is
    not an outward-facing release path. The generic cleaner stays
    honest for it precisely because nothing it skips is promised."""
    data = _make_odt()
    res = inspect_bytes(data, "privacy.odt")
    plan = plan_actions(res, "privacy_only")
    cleaned, _records = apply_actions(data, plan)  # must not raise
    assert bool(cleaned)  # completed without refusing


def test_evidence_preservation_odt_still_refused_at_plan_time():
    """evidence_preservation never produces derivatives at all; pin that
    its ODF behaviour is unchanged (refusal comes from the plan gate, not
    the new ODF one, and carries neither marker)."""
    data = _make_odt()
    res = inspect_bytes(data, "evidence.odt")
    plan = plan_actions(res, "evidence_preservation")
    with pytest.raises(PolicyError) as exc_info:
        apply_actions(data, plan)
    msg = str(exc_info.value)
    assert "evidence_preservation never produces derivatives" in msg
    assert ODF_CONTENT_REFUSAL_MARKER not in msg


def test_non_odf_other_containers_unaffected():
    """The gate is ODF-specific: svg/epub keep the generic sharing-clean
    path (their cleaners really do what the record says). NB html/md
    bytes re-detect as "unknown" inside apply_actions itself (the branch
    re-runs detect_container_format without the filename's extension), a
    pre-existing quirk of that branch that no part of this change
    touches."""
    svg = (
        b'<?xml version="1.0"?>\n'
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b"<metadata>some tool stamp</metadata>"
        b'<circle cx="1" cy="1" r="1"/></svg>'
    )
    res = inspect_bytes(svg, "figure.svg")
    plan = plan_actions(res, "external_sharing")
    cleaned, records = apply_actions(svg, plan)
    assert cleaned  # completed without refusing
    assert all(ODF_CONTENT_REFUSAL_MARKER not in r.detail for r in records)


def test_clean_to_bundle_refuses_and_writes_no_packet(tmp_path: Path):
    """End-to-end, mirroring how PDF refusals behave: engine_api
    clean_to_bundle wraps the PolicyError as CustodyError("plan refused:
    ...") -- service/app/worker.py maps that exact prefix to job status
    "refused" -- and leaves out_dir untouched (no manifest, no
    derivative)."""
    import custody as custody_mod

    src = tmp_path / "brief.odt"
    src.write_bytes(_make_odt())
    out_dir = tmp_path / "bundle"
    with pytest.raises(custody_mod.CustodyError) as exc_info:
        clean_to_bundle(src, out_dir, policy_id="external_sharing")
    assert str(exc_info.value).startswith("plan refused: ")
    assert ODF_CONTENT_REFUSAL_MARKER in str(exc_info.value)
    # no packet/manifest/derivative was produced
    assert not (out_dir / "manifest.json").exists()
    assert not (out_dir / "derivative").exists()


def test_refusal_marker_names_are_greppable_and_distinct():
    """The frontend distinguishes capability refusals from deliberate
    policy refusals by exact substring (web/app/matters/job/page.tsx
    mirrors PDF_CONTENT_REFUSAL_MARKER); the ODF marker must stay a
    distinct string so an ODF refusal cannot render PDF advice."""
    assert ODF_CONTENT_REFUSAL_MARKER != PDF_CONTENT_REFUSAL_MARKER
    assert "pdf" not in ODF_CONTENT_REFUSAL_MARKER.lower()
