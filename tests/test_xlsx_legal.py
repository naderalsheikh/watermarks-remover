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
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES_XML)
        zf.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML)
        zf.writestr(
            "xl/workbook.xml", workbook_xml if workbook_xml is not None else _workbook_xml()
        )
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
