"""The disposition vocabulary, bound to an actual test.

`custody.py` and `main.py` both carried comments citing THIS FILE as the
regression test pinning their retaining-action lists equal. The file did not
exist, and the lists were not equal. Under the product's own doctrine
(counselclear-strategy.md §5) a vocabulary is only as good as the test
behind it, and a citation to a missing file is worse than no comment: it
stops the next reader from checking.

Found by an adversarial audit of the 2026-09-05 surface, against code
written the same day.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "service" / "scripts"), str(REPO / "service")):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.main import RETAINING_ACTIONS
from custody import _RETAINING_ACTIONS, build_dispositions
from policies import _NON_REMOVING_ACTIONS


def test_the_three_retaining_action_lists_relate_as_intended():
    """They are NOT equal, and the difference is deliberate.

    `custody._RETAINING_ACTIONS` carries `refuse` because it classifies a
    planned action; the other two describe actions that leave a finding in a
    DERIVATIVE, and a refused job produces no derivative at all. The lists
    must therefore agree on the three derivative-bearing actions and differ
    only by `refuse` -- which is exactly what the old comment got wrong when
    it called them equal.
    """
    derivative_bearing = {"keep", "flag", "inspect_only"}
    assert set(_NON_REMOVING_ACTIONS) == derivative_bearing
    assert set(RETAINING_ACTIONS) == derivative_bearing
    assert set(_RETAINING_ACTIONS) == derivative_bearing | {"refuse"}
    # main.py deliberately re-declares rather than imports (PR 17 isolation:
    # the control plane must not import the engine), so drift between those
    # two is the failure this assertion exists to catch.
    assert set(RETAINING_ACTIONS) == set(_NON_REMOVING_ACTIONS)


@pytest.mark.parametrize(
    ("action", "still_present", "expected"),
    [
        ("strip", False, "removed_confirmed"),
        ("sanitize", False, "removed_confirmed"),
        ("strip", True, "retained_unplanned"),
        ("flag", True, "retained_as_planned"),
        ("keep", True, "retained_as_planned"),
        ("inspect_only", True, "retained_as_planned"),
    ],
)
def test_postcondition_table(action, still_present, expected):
    (row,) = build_dispositions(
        plan_actions={"hidden_text": {"action": action, "reason": "policy_default"}},
        subtypes_before=["hidden_text"],
        subtypes_after=["hidden_text"] if still_present else [],
    )
    assert row["postcondition"] == expected


def test_a_finding_the_policy_promised_to_KEEP_and_lost_is_not_a_success():
    """The audit's finding #6, fixed here.

    A retaining action whose finding disappears used to be labelled
    `removed_confirmed` -- a success. It is the opposite: the operator asked
    for the finding to be preserved and the engine destroyed it. That
    matters most under `evidence_preservation` and `privacy_only`, whose
    entire product is not touching things, and where a recipient needing the
    provenance to validate a document had no way to learn from the manifest
    that it was removed against policy.
    """
    (row,) = build_dispositions(
        plan_actions={"c2pa": {"action": "keep", "reason": "policy_default"}},
        subtypes_before=["c2pa"],
        subtypes_after=[],
    )
    assert row["postcondition"] == "removed_unplanned", (
        "a finding the policy promised to keep, which vanished, must never "
        "be recorded as a confirmed removal"
    )
    assert row["present_after"] is False


def test_no_observation_is_never_reported_as_removal():
    (row,) = build_dispositions(
        plan_actions={"hidden_text": {"action": "strip", "reason": "policy_default"}},
        subtypes_before=["hidden_text"],
        subtypes_after=None,
    )
    assert row["postcondition"] == "not_verifiable"
    assert row["present_after"] is None


def test_every_postcondition_value_is_in_the_published_schema():
    """The ledger travels inside every packet, so its vocabulary is part of
    the published contract, not an internal enum."""
    import json

    schema = json.loads(
        (REPO / "service" / "scripts" / "schemas" / "manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    allowed = set(schema["$defs"]["disposition"]["properties"]["postcondition"]["enum"])
    produced = set()
    for action in ("strip", "keep", "flag", "inspect_only"):
        for after in ([], ["x"], None):
            for row in build_dispositions(
                plan_actions={"x": {"action": action, "reason": "policy_default"}},
                subtypes_before=["x"],
                subtypes_after=after,
            ):
                produced.add(row["postcondition"])
    assert produced <= allowed, produced - allowed


# --- Task 4: the action record is the custody record, so it cannot be
# --- capped silently or classified by the cleaner's prose. -------------------


def _many_message_docx() -> bytes:
    """A DOCX whose cleaner produces MORE than 12 messages: every identity
    and session field carrying content in docProps/core.xml (10) and
    docProps/app.xml (4) under external_sharing -- which also strips
    authoring exhaust -- plus one OLE embedding drop and one customXml
    drop. The old msgs[:12] cap cut that tail from the record silently."""
    core_fields = (
        "<dc:creator>Jane Counsel</dc:creator>"
        "<cp:lastModifiedBy>Bob Reviewer</cp:lastModifiedBy>"
        "<dc:description>settlement draft</dc:description>"
        "<cp:keywords>kw1, kw2</cp:keywords>"
        "<dc:subject>subj</dc:subject>"
        "<cp:category>cat</cp:category>"
        "<dcterms:created>2026-01-01T00:00:00Z</dcterms:created>"
        "<dcterms:modified>2026-01-02T00:00:00Z</dcterms:modified>"
        "<cp:revision>7</cp:revision>"
        "<TotalTime>42</TotalTime>"
    )
    core = (
        b'<?xml version="1.0"?>'
        b'<cp:coreProperties xmlns:cp="c" xmlns:dc="d" xmlns:dcterms="t">'
        + core_fields.encode()
        + b"</cp:coreProperties>"
    )
    app_fields = (
        "<Application>Microsoft Word</Application>"
        "<AppVersion>16.0000</AppVersion>"
        "<Company>ACME LLP</Company>"
        "<Manager>Mgr</Manager>"
    )
    app_props = (
        b'<?xml version="1.0"?><Properties xmlns="p">' + app_fields.encode() + b"</Properties>"
    )
    body = "<w:p><w:r><w:t>Agreement text.</w:t></w:r></w:p>"
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}<w:sectPr/></w:body></w:document>"
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        ct = (
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
            "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>"
            "<Default Extension='xml' ContentType='application/xml'/>"
            "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>"
            "<Default Extension='bin' ContentType='application/vnd.openxmlformats-officedocument.oleObject'/>"
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
        zf.writestr("word/document.xml", document)
        zf.writestr("docProps/core.xml", core)
        zf.writestr("docProps/app.xml", app_props)
        zf.writestr("word/embeddings/oleObject1.bin", b"OLE payload bytes")
        zf.writestr("customXml/item1.xml", "<customProps><ai>true</ai></customProps>")
    return buf.getvalue()


def test_action_records_beyond_twelve_are_never_silently_dropped():
    """policies.py's container branch used `for m in msgs[:12]`: every
    cleaner message past the twelfth vanished from the custody record with
    no marker. The dropped tail includes limitation disclosures (`warning:
    ... not well-formed XML`). A record that stops without saying it
    stopped claims completeness it does not have."""
    from engine_api import inspect_bytes
    from policies import apply_actions, plan_actions

    data = _many_message_docx()
    plan = plan_actions(inspect_bytes(data, "many.docx"), "external_sharing", {})
    _cleaned, records = apply_actions(data, plan)
    details = [r.detail for r in records]
    # The identity scrubs alone exceed 12; the record must carry them all,
    # or carry an explicit truncation record naming the dropped count.
    truncation = [d for d in details if "more cleaner messages" in d or "truncat" in d.lower()]
    assert len(records) > 12 or truncation, (
        f"record holds {len(records)} entries with no truncation marker"
    )
    # Every scrub message the cleaner produced must be represented: the
    # identity fields are individually named in the detail strings.
    scrubbed = [d for d in details if d.startswith("scrub ")]
    assert scrubbed, details
    assert len(scrubbed) >= 12, f"only {len(scrubbed)} scrub records survived the cap"


def test_ole_part_drop_is_not_recorded_as_custom_xml():
    """Subtype was inferred by substring-matching the cleaner's prose with
    a final `else "custom_xml"`, so dropping word/embeddings/oleObject1.bin
    was recorded as custom_xml|strip. A prose reword in a cleaner moved
    custody facts; the subtype must come from structural facts (the part
    path), not from which substring happened to match."""
    from engine_api import inspect_bytes
    from policies import apply_actions, plan_actions

    body = "<w:p><w:r><w:t>Agreement text.</w:t></w:r></w:p>"
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}<w:sectPr/></w:body></w:document>"
    ).encode()
    ole = b"OLE payload bytes - content irrelevant, presence is the point"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        ct = (
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
            "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>"
            "<Default Extension='xml' ContentType='application/xml'/>"
            "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>"
            "<Default Extension='bin' ContentType='application/vnd.openxmlformats-"
            "officedocument.oleObject'/>"
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
        zf.writestr("word/document.xml", document)
        zf.writestr("word/embeddings/oleObject1.bin", ole)
    data = buf.getvalue()

    plan = plan_actions(inspect_bytes(data, "ole.docx"), "external_sharing", {})
    _cleaned, records = apply_actions(data, plan)
    dropped = [r for r in records if "oleObject1.bin" in r.detail]
    assert dropped, f"OLE drop not recorded at all: {[r.detail for r in records]}"
    assert all(r.subtype == "embeddings_ole" for r in dropped), [
        (r.subtype, r.detail) for r in dropped
    ]
