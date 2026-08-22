#!/usr/bin/env python3
"""PR 7 groundwork: XLSX legal inspectors (hidden/veryHidden sheets, legacy +
threaded comments, external links, hidden defined names, persons/core meta)."""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))
import pytest
import xlsx_legal
from container_meta import clean_xlsx, inspect_container

CONTENT_TYPES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
</Types>"""

WORKBOOK_RELS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""

SHEET1_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>"""

COMMENTS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<commentList>
<comment ref="A1" authorId="0"><text><r><t>first note</t></r></text></comment>
<comment ref="B2" authorId="0"><text><r><t>second note</t></r></text></comment>
</commentList>
</comments>"""

ONE_COMMENT_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<commentList><comment ref="C3" authorId="0"><text><r><t>solo</t></r></text></comment></commentList>
</comments>"""

THREADED_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<tr:threadedComments xmlns:tr="http://schemas.microsoft.com/office/spreadsheetml/2022/threadedcomments">
<tr:threadedComment ref="A1" personId="p1" dt="2026-01-01T00:00:00Z"><tr:text>hello</tr:text></tr:threadedComment>
</tr:threadedComments>"""

EXTERNAL_LINK_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<externalBook r:id="rId1"/></externalLink>"""

PERSONS_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><persons/>'

CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:creator>Nader Alsheikh</dc:creator>
<cp:lastModifiedBy>Some Agent</cp:lastModifiedBy>
</cp:coreProperties>"""


def _workbook_xml(
    sheets: str = '<sheet name="Sheet1" sheetId="1" r:id="rId1"/>',
    defined_names: str = "",
) -> str:
    names = f"<definedNames>{defined_names}</definedNames>" if defined_names else ""
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>{sheets}</sheets>{names}</workbook>"""


def _xlsx(*members: tuple[str, bytes | str], workbook_xml: str | None = None) -> bytes:
    member_names = {name for name, _ in members}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if "[Content_Types].xml" not in member_names:
            zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML)
        if "xl/_rels/workbook.xml.rels" not in member_names:
            zf.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML)
        zf.writestr(
            "xl/workbook.xml", workbook_xml if workbook_xml is not None else _workbook_xml()
        )
        if "xl/worksheets/sheet1.xml" not in member_names:
            zf.writestr("xl/worksheets/sheet1.xml", SHEET1_XML)
        for name, content in members:
            zf.writestr(name, content)
    return buf.getvalue()


def _xlsx_with_unreadable_member(member: str, content: str) -> bytes:
    """Build an xlsx whose named member reads as corrupt (flipped payload byte → CRC fail)."""
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML)
    zf.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML)
    zf.writestr("xl/workbook.xml", _workbook_xml())
    zf.writestr("xl/worksheets/sheet1.xml", SHEET1_XML)
    info = zipfile.ZipInfo(member)
    info.compress_type = zipfile.ZIP_STORED
    zf.writestr(info, content)
    offset = info.header_offset
    zf.close()
    out = bytearray(buf.getvalue())
    nlen = int.from_bytes(out[offset + 26 : offset + 28], "little")
    elen = int.from_bytes(out[offset + 28 : offset + 30], "little")
    out[offset + 30 + nlen + elen] ^= 0xFF
    return bytes(out)


CLEAN_SCAN = {
    "hidden_sheets": [],
    "very_hidden_sheets": [],
    "visible_sheet_count": 1,
    "comment_part_count": 0,
    "comment_count": 0,
    "threaded_comment_parts": 0,
    "external_links": 0,
    "defined_name_count": 0,
    "defined_names_hidden": 0,
    "persons_part": False,
    "hidden_rows": 0,
    "hidden_cols": 0,
    "core_info": None,
}


# --- scanner ------------------------------------------------------------------


def test_clean_workbook_has_zero_flags():
    assert xlsx_legal.scan_xlsx_legal(_xlsx()) == CLEAN_SCAN


def test_hidden_and_very_hidden_sheet_states():
    wb = _workbook_xml(
        sheets=(
            '<sheet name="Public" sheetId="1" r:id="rId1"/>'
            '<sheet name="Secret" sheetId="2" state="hidden" r:id="rId2"/>'
            '<sheet name="DeepSecret" sheetId="3" state="veryHidden" r:id="rId3"/>'
        )
    )
    scan = xlsx_legal.scan_xlsx_legal(_xlsx(workbook_xml=wb))
    assert scan["hidden_sheets"] == ["Secret"]
    assert scan["very_hidden_sheets"] == ["DeepSecret"]
    assert scan["visible_sheet_count"] == 1


def test_multiple_hidden_sheets_state_case_insensitive():
    wb = _workbook_xml(
        sheets=(
            '<sheet name="A" sheetId="1" state="hidden" r:id="rId1"/>'
            '<sheet name="B" sheetId="2" state="HIDDEN" r:id="rId2"/>'
            '<sheet name="C" sheetId="3" state="veryHidden" r:id="rId3"/>'
            '<sheet name="D" sheetId="4" r:id="rId4"/>'
        )
    )
    scan = xlsx_legal.scan_xlsx_legal(_xlsx(workbook_xml=wb))
    assert scan["hidden_sheets"] == ["A", "B"]
    assert scan["very_hidden_sheets"] == ["C"]
    assert scan["visible_sheet_count"] == 1
    # <sheets>/<sheetData> containers must not be mistaken for <sheet> tags.
    assert xlsx_legal.legal_findings(scan) == ["xlsx-hidden-sheets: 2 hidden (1 veryHidden)"]


def test_comments_and_threaded_parts_counted():
    data = _xlsx(
        ("xl/comments1.xml", COMMENTS_XML),
        ("xl/comments2.xml", ONE_COMMENT_XML),
        ("xl/threadedComments/threadedComment1.xml", THREADED_XML),
    )
    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["comment_part_count"] == 2
    assert scan["comment_count"] == 3
    assert scan["threaded_comment_parts"] == 1


def test_external_links_exclude_rels_siblings():
    data = _xlsx(
        ("xl/externalLinks/externalLink1.xml", EXTERNAL_LINK_XML),
        ("xl/externalLinks/externalLink2.xml", EXTERNAL_LINK_XML),
        ("xl/externalLinks/_rels/externalLink1.xml.rels", "<Relationships/>"),
    )
    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["external_links"] == 2
    assert xlsx_legal.legal_findings(scan) == ["xlsx-external-links: 2 part(s)"]


def test_defined_names_hidden_attribute_order_insensitive():
    wb = _workbook_xml(
        defined_names=(
            '<definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">Sheet1!$A$1:$A$5</definedName>'
            '<definedName name="Rate">Sheet1!$B$1</definedName>'
            "<definedName name='SecretRange' hidden='true'>Sheet1!$C$1:$C$9</definedName>"
        )
    )
    scan = xlsx_legal.scan_xlsx_legal(_xlsx(workbook_xml=wb))
    assert scan["defined_name_count"] == 3
    assert scan["defined_names_hidden"] == 2
    assert xlsx_legal.legal_findings(scan) == ["xlsx-hidden-names: 2 hidden defined name(s)"]


def test_persons_part_detected_only_when_present():
    assert xlsx_legal.scan_xlsx_legal(_xlsx())["persons_part"] is False
    scan = xlsx_legal.scan_xlsx_legal(_xlsx(("xl/persons/person.xml", PERSONS_XML)))
    assert scan["persons_part"] is True


def test_core_info_redacts_creator_and_last_modified_by():
    data = _xlsx(("docProps/core.xml", CORE_XML), ("xl/persons/person.xml", PERSONS_XML))
    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["core_info"] == {
        "creator": "present (14 chars)",
        "last_modified_by": "present (10 chars)",
    }


def test_core_info_none_when_absent_or_fieldless():
    assert xlsx_legal.scan_xlsx_legal(_xlsx())["core_info"] is None
    bare = '<?xml version="1.0"?><cp:coreProperties xmlns:cp="urn:x"/>'
    scan = xlsx_legal.scan_xlsx_legal(_xlsx(("docProps/core.xml", bare)))
    assert scan["core_info"] == {"creator": None, "last_modified_by": None}


def test_combined_scan_and_exact_finding_strings():
    wb = _workbook_xml(
        sheets=(
            '<sheet name="V" sheetId="1" r:id="rId1"/>'
            '<sheet name="H1" sheetId="2" state="hidden" r:id="rId2"/>'
            '<sheet name="H2" sheetId="3" state="veryHidden" r:id="rId3"/>'
        ),
        defined_names='<definedName name="N1" hidden="1">Sheet1!$A$1</definedName>',
    )
    data = _xlsx(
        ("xl/comments1.xml", COMMENTS_XML),
        ("xl/threadedComments/threadedComment1.xml", THREADED_XML),
        ("xl/externalLinks/externalLink1.xml", EXTERNAL_LINK_XML),
        ("xl/persons/person.xml", PERSONS_XML),
        ("docProps/core.xml", CORE_XML),
        workbook_xml=wb,
    )
    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["hidden_sheets"] == ["H1"]
    assert scan["very_hidden_sheets"] == ["H2"]
    assert scan["visible_sheet_count"] == 1
    assert scan["comment_part_count"] == 1
    assert scan["comment_count"] == 2
    assert scan["threaded_comment_parts"] == 1
    assert scan["external_links"] == 1
    assert scan["defined_name_count"] == 1
    assert scan["defined_names_hidden"] == 1
    assert scan["persons_part"] is True
    assert scan["core_info"]["creator"] == "present (14 chars)"
    assert xlsx_legal.legal_findings(scan) == [
        "xlsx-hidden-sheets: 1 hidden (1 veryHidden)",
        "xlsx-comments: 2 comment(s)",
        "xlsx-threaded-comments: 1 part(s)",
        "xlsx-external-links: 1 part(s)",
        "xlsx-hidden-names: 1 hidden defined name(s)",
    ]


def test_unreadable_member_skipped_gracefully():
    data = _xlsx_with_unreadable_member("xl/comments1.xml", COMMENTS_XML)
    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["comment_part_count"] == 0
    assert scan["comment_count"] == 0
    # The rest of the package still scans.
    assert scan["visible_sheet_count"] == 1


def test_garbage_xml_in_comment_part_tolerated():
    data = _xlsx(("xl/comments1.xml", b"\x00\x01this is not xml at all\xff"))
    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["comment_part_count"] == 1
    assert scan["comment_count"] == 0


def test_non_zip_bytes_raise_value_error_with_cause():
    with pytest.raises(ValueError, match="not a valid XLSX zip") as excinfo:
        xlsx_legal.scan_xlsx_legal(b"this is definitely not a zip file")
    assert excinfo.value.__cause__ is not None


# --- findings -----------------------------------------------------------------


def test_findings_empty_for_clean_scan():
    assert xlsx_legal.legal_findings(xlsx_legal.scan_xlsx_legal(_xlsx())) == []
    assert xlsx_legal.legal_findings(dict(CLEAN_SCAN)) == []


# --- hidden rows/cols (PR 7 addition) ------------------------------------------


def test_hidden_rows_and_cols_counted():
    ws = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<cols><col min="2" max="3" width="9" hidden="1"/><col min="5" max="5" width="9"/></cols>'
        '<sheetData>'
        '<row r="1"><c r="A1"><v>visible</v></c></row>'
        '<row r="4" hidden="1"><c r="A4"><v>secret</v></c></row>'
        '<row r="7" hidden="true"><c r="A7"><v>also</v></c></row>'
        "</sheetData></worksheet>"
    )
    data = _xlsx(("xl/worksheets/sheet1.xml", ws))
    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["hidden_rows"] == 2
    assert scan["hidden_cols"] == 1


# --- engine wiring: inspect -----------------------------------------------------


def _full_xlsx() -> bytes:
    wb = _workbook_xml(
        sheets=(
            '<sheet name="Public" sheetId="1" r:id="rId1"/>'
            '<sheet name="Secret" sheetId="2" state="hidden" r:id="rId2"/>'
        ),
        defined_names='<definedName name="HiddenRange" hidden="1">\'Secret\'!$A$1</definedName>',
    ) + '<externalReferences><externalReference r:id="rIdX"/></externalReferences>'
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rIdX" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink" Target="externalLinks/externalLink1.xml"/>'
        "</Relationships>"
    )
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        "<Override PartName='/xl/comments1.xml' ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml'/>"
        "<Override PartName='/xl/externalLinks/externalLink1.xml' ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml'/>"
        "</Types>"
    )
    return _xlsx(
        ("xl/comments1.xml", "<comments><comment ref=\"A1\"/></comments>"),
        ("xl/threadedComments/threadedComment1.xml", "<threadedComments/>"),
        ("xl/persons/person.xml", "<persons><person/></persons>"),
        ("xl/externalLinks/externalLink1.xml", "<externalLink/>"),
        (
            "xl/worksheets/sheet1.xml",
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<legacyDrawing r:id="rId1"/><sheetData><row r="9" hidden="1"/></sheetData></worksheet>',
        ),
        ("xl/_rels/workbook.xml.rels", rels),
        ("[Content_Types].xml", ct),
        workbook_xml=wb,
    )


def test_inspect_xlsx_surfaces_legal_findings(tmp_path):
    p = tmp_path / "t.xlsx"
    p.write_bytes(_full_xlsx())
    rep = inspect_container(p).to_dict()
    scan = rep["details"]["xlsx_legal"]
    assert scan["hidden_sheets"] == ["Secret"]
    assert scan["comment_count"] == 1
    assert scan["external_links"] == 1
    assert scan["defined_names_hidden"] == 1
    assert scan["hidden_rows"] == 1
    joined = "\n".join(rep["findings"])
    assert "xlsx-hidden-sheets: 1 hidden (0 veryHidden)" in joined
    assert "xlsx-comments:" in joined
    assert "xlsx-threaded-comments:" in joined
    assert "xlsx-external-links:" in joined
    assert "xlsx-hidden-names:" in joined
    assert "xlsx-hidden-rows-cols: 1 row(s) 0 col(s)" in joined


# --- engine wiring: clean --------------------------------------------------------


def test_clean_strips_comments_and_external_links_keeps_visibility(tmp_path):
    out, actions = clean_xlsx(_full_xlsx())
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        names = zf.namelist()
        assert "xl/comments1.xml" not in names
        assert "xl/threadedComments/threadedComment1.xml" not in names
        assert "xl/persons/person.xml" not in names
        assert not any(n.startswith("xl/externalLinks") for n in names)
        wb = zf.read("xl/workbook.xml").decode()
        sheet = zf.read("xl/worksheets/sheet1.xml").decode()
        ct = zf.read("[Content_Types].xml").decode()
        rels = zf.read("xl/_rels/workbook.xml.rels").decode()
    assert "externalReferences" not in wb
    assert "legacyDrawing" not in sheet
    assert "/xl/comments1.xml" not in ct and "externalLink" not in ct
    # workbook-level dangling relationship to externalLink pruned
    assert 'Id="rIdX"' not in rels
    # flag-only: hidden sheet still present, still marked hidden
    assert any("drop part xl/comments1.xml" in a for a in actions)
    assert any("externalReferences" in a for a in actions)

    p = tmp_path / "cleaned.xlsx"
    p.write_bytes(out)
    scan = xlsx_legal.scan_xlsx_legal(p.read_bytes())
    assert scan["hidden_sheets"] == ["Secret"]  # never auto-unhide
    assert scan["comment_part_count"] == 0
    assert scan["external_links"] == 0


def test_clean_xlsx_opt_out_flags_keep_parts():
    out, _actions = clean_xlsx(_full_xlsx(), strip_comments=False, strip_external_links=False)
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        names = zf.namelist()
    assert "xl/comments1.xml" in names
    assert "xl/persons/person.xml" in names
    assert "xl/externalLinks/externalLink1.xml" in names


def test_numbered_persons_part_detected_and_stripped():
    """Regression: real Excel numbers this part (person1.xml, person2.xml, ...)
    and never writes the unnumbered xl/persons/person.xml alone. The scanner
    and the sharing-clean drop logic must both match the numbered form, or
    commenter names/emails silently survive an external_sharing clean."""
    data = _xlsx(("xl/persons/person1.xml", PERSONS_XML))

    scan = xlsx_legal.scan_xlsx_legal(data)
    assert scan["persons_part"] is True

    out, actions = clean_xlsx(data)
    with zipfile.ZipFile(io.BytesIO(out)) as zf:
        names = zf.namelist()
    assert "xl/persons/person1.xml" not in names
    assert any("xl/persons/person1.xml" in a for a in actions)


# --- canonical findings projection ----------------------------------------------


def test_findings_project_xlsx_legal_signals(tmp_path):
    from findings import findings_for_report

    p = tmp_path / "t.xlsx"
    p.write_bytes(_full_xlsx())
    rep = inspect_container(p).to_dict()
    found = findings_for_report("container", rep)
    by_subtype = {f.subtype: f for f in found}
    assert {"hidden_structure", "comments_and_notes", "external_links"} <= set(by_subtype)
    assert by_subtype["hidden_structure"].category == "hidden_structure"
    assert by_subtype["hidden_structure"].action_recommended == "flag"
    assert by_subtype["comments_and_notes"].action_recommended == "strip"
    assert by_subtype["external_links"].risk_level == "high"


def test_findings_project_defined_names_and_rows_cols():
    from findings import findings_for_report

    rep = {
        "format": "xlsx",
        "findings": [
            "xlsx-hidden-names: 2 hidden defined name(s)",
            "xlsx-hidden-rows-cols: 3 row(s) 1 col(s)",
        ],
    }
    found = {f.subtype: f for f in findings_for_report("container", rep)}
    assert set(found) == {"defined_names_hidden_range", "hidden_structure"}
    assert found["defined_names_hidden_range"].risk_level == "low"
    assert found["defined_names_hidden_range"].confidence == "probable"
