"""Custody-record truthfulness invariants (2026-09-02 test-case review).

The review that produced these tests found CounselClear's *sanitizer*
sound and its *record* overstated: a derivative whose manifest said

    hidden_text:flag: flagged by policy; finding remains in derivative
    legal basis: unspecified

shipped with a certificate reading "No limitations flagged for this job"
directly above "Verification: passed". Nothing was falsified — the
retention was disclosed under manifest actions — but the certificate's
summary claim was stronger than its own underlying record, which is the
one failure mode a custody product cannot have.

These are product-truth invariants, not formatting checks:

1. every finding that survives into the derivative produces a limitation,
   whatever the policy called the action that retained it;
2. every finding present before sanitization gets an explicit
   disposition and postcondition, so no reader has to infer which
   operation disposed of which finding;
3. a detector reports what it actually observed — a style-level white
   font is not described in the language of concealed text;
4. an unanchored artifact says what it is unanchored *about*.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "service" / "scripts"
APP_DIR = REPO / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

import container_meta
from app.config import Config
from app.db import make_engine
from app.main import _retention_limitations, create_app
from app.migrate import upgrade_head
from custody import build_dispositions
from policies import ActionRecord, apply_actions, plan_actions

PW = "pw12345"
W_DECL = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"'
)


# --- fixtures ---------------------------------------------------------------


def _docx(parts: dict[str, bytes]) -> bytes:
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


def _document(inner: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f"<w:document {W_DECL}><w:body>{inner}<w:sectPr/></w:body></w:document>"
    ).encode()


def _hidden_text_docx() -> bytes:
    """A document whose only finding is hidden text — which every mutating
    policy *flags* rather than removes. This is the shape that produced a
    limitation-free certificate for a knowingly retained finding."""
    body = (
        "<w:p><w:r><w:t>Visible contract text.</w:t></w:r></w:p>"
        '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>concealed clause</w:t></w:r></w:p>'
    )
    return _docx({"word/document.xml": _document(body)})


def _style_only_white_docx(rules: int = 119) -> bytes:
    """No concealed text at all: white run colours live only in styles.xml
    and numbering.xml, exactly as ordinary Word formatting machinery puts
    them there."""
    styles = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f"<w:styles {W_DECL}>"
        + "".join(
            f'<w:style w:styleId="S{i}"><w:rPr><w:color w:val="FFFFFF"/></w:rPr></w:style>'
            for i in range(rules)
        )
        + "</w:styles>"
    ).encode()
    body = "<w:p><w:r><w:t>Nothing is hidden in this document.</w:t></w:r></w:p>"
    return _docx({"word/document.xml": _document(body), "word/styles.xml": styles})


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    cfg = Config(tmp_path / "data")
    make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    yield c
    c.close()


def _job_with_retained_finding(c) -> tuple[str, dict, dict]:
    """Run a real sanitize of a hidden-text document and return
    (matter_id, job, manifest)."""
    mid = c.post("/v1/matters", json={"name": "Truthfulness"}).json()["id"]
    doc = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("hidden.docx", _hidden_text_docx(), "application/octet-stream")},
    ).json()["id"]
    job = c.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert job["status"] == "done", job
    manifest = c.get(f"/v1/matters/{mid}/jobs/{job['id']}/manifest").json()
    return mid, job, manifest


# --- 1. a retained finding is always a limitation ---------------------------


def test_flagged_retained_finding_is_recorded_as_retained():
    """The engine-side half: a policy ``flag`` outcome marks its action
    record ``retained_finding``. Before this, only the three
    approve-default keeps carried any machine-readable retention signal,
    and a flag carried none at all."""
    data = _hidden_text_docx()
    from engine_api import inspect_bytes

    plan = plan_actions(inspect_bytes(data, "h.docx"), "external_sharing")
    _cleaned, records = apply_actions(data, plan)
    flagged = [r for r in records if r.action == "flag"]
    assert flagged, "hidden text should be flagged by external_sharing"
    assert all(r.retained_finding for r in flagged)
    # And the inverse: a no-op "nothing was found" keep is NOT a retention.
    assert not ActionRecord("layer_a_body", "keep", "text unchanged").retained_finding


def test_retention_limitations_reports_every_surviving_finding():
    """Unit-level proof of the P1: a manifest whose only retention is a
    ``flag`` used to yield zero limitations."""
    manifest = {
        "schema_version": 2,
        "action_records": [
            {"subtype": "authoring_props", "action": "strip", "detail": "cleared"},
            {
                "subtype": "hidden_text",
                "action": "flag",
                "detail": "flagged by policy; finding remains in derivative",
                "legal_justification": {"basis": "unspecified", "note": ""},
                "retained_finding": True,
            },
        ],
    }
    limits = _retention_limitations(manifest, [])
    assert len(limits) == 1
    assert "hidden_text" in limits[0]
    assert "REMAINS IN THE DERIVATIVE" in limits[0]
    # The specific combination the review called out: retained AND
    # unjustified. Both halves must be legible, not just the retention.
    assert "NO OPERATOR LEGAL BASIS WAS SUPPLIED" in limits[0]
    # A strip is not a limitation.
    assert "authoring_props" not in limits[0]


def test_supplied_legal_basis_is_named_rather_than_flagged_as_missing():
    manifest = {
        "schema_version": 2,
        "action_records": [
            {
                "subtype": "hidden_text",
                "action": "flag",
                "detail": "flagged by policy; finding remains in derivative",
                "legal_justification": {"basis": "work_product", "note": "Counsel notes."},
                "retained_finding": True,
            }
        ],
    }
    (limit,) = _retention_limitations(manifest, [])
    assert "work_product" in limit and "Counsel notes." in limit
    assert "NO OPERATOR LEGAL BASIS" not in limit


def test_legacy_v1_manifest_keeps_marker_derivation():
    """A manifest issued before schema v2 has no retention flag at all.
    Reporting it as limitation-free would be a new lie in place of the old
    one, so those fall back to the original marker matching."""
    from app.main import NO_DECISION_MARKER

    manifest = {"action_records": [{"subtype": "comments_and_notes", "action": "keep", "detail": "x"}]}
    actions = [f"comments_and_notes:keep: kept: {NO_DECISION_MARKER} for this finding"]
    limits = _retention_limitations(manifest, actions)
    assert len(limits) == 1 and NO_DECISION_MARKER in limits[0]


def test_certificate_never_claims_no_limitations_over_a_retained_finding(client):
    """End-to-end: the exact defect. Sanitize a document whose hidden-text
    finding the policy retains, then read the certificate the recipient
    actually gets."""
    mid, job, manifest = _job_with_retained_finding(client)

    retained = [r for r in manifest["action_records"] if r.get("retained_finding")]
    assert retained, "expected the hidden-text finding to be retained"

    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    assert "No limitations flagged for this job" not in html
    assert "REMAINS IN THE DERIVATIVE" in html
    # Verification still passes -- that is correct and is precisely why the
    # limitations section has to carry the retention: a reader seeing
    # "passed" must not also see an unqualified all-clear.
    assert manifest["verification"]["pass"] is True


def test_release_result_limitations_match_the_certificate(client):
    """release_result.json repeats limitations; the two artifacts must not
    be able to disagree about whether any exist."""
    mid = client.post("/v1/matters", json={"name": "Release truth"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("hidden.docx", _hidden_text_docx(), "application/octet-stream")},
    ).json()["id"]
    rel = client.post(
        f"/v1/matters/{mid}/documents/{doc}/releases",
        json={
            "profile_id": "counterparty_deal_room",
            "recipient_type": "opposing_counsel",
            "recipient_name": "Jane Doe, Esq.",
            "purpose": "production",
        },
    )
    assert rel.status_code == 200, rel.text
    result = rel.json()["release_result"]
    assert result["limitations"], "a retained finding must reach release_result.json"
    assert any("REMAINS IN THE DERIVATIVE" in x for x in result["limitations"])


# --- 2. one-to-one disposition accounting -----------------------------------


def test_every_pre_sanitize_finding_gets_a_disposition(client):
    _mid, _job, manifest = _job_with_retained_finding(client)
    dispositions = manifest["dispositions"]
    assert dispositions, "manifest must carry a disposition ledger"
    by_subtype = {d["subtype"]: d for d in dispositions}
    # The retained finding is accounted for as retained, not omitted.
    assert by_subtype["hidden_text"]["postcondition"] == "retained_as_planned"
    assert by_subtype["hidden_text"]["present_after"] is True
    # Anything the policy stripped is confirmed absent by re-inspection,
    # not merely assumed gone because a stripper returned.
    for d in dispositions:
        assert d["present_before"] is True
        assert d["postcondition"] in (
            "removed_confirmed",
            "retained_as_planned",
            "retained_unplanned",
            "not_verifiable",
        )
        if d["action"] in ("strip", "sanitize", "accept_all", "rebuild"):
            assert d["postcondition"] == "removed_confirmed", d


def test_disposition_ledger_and_limitations_cannot_disagree(client):
    """The invariant behind the certificate's cross-check: a retained row
    in the ledger and an empty limitations list is an inconsistent
    certificate, and must be unreachable."""
    mid, job, manifest = _job_with_retained_finding(client)
    retained_rows = [
        d
        for d in manifest["dispositions"]
        if d["postcondition"] in ("retained_as_planned", "retained_unplanned")
    ]
    assert retained_rows
    result = client.get(f"/v1/matters/{mid}/jobs/{job['id']}").json()
    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    assert result["status"] == "done"
    assert "Finding dispositions" in html
    for row in retained_rows:
        assert row["subtype"] in html


def test_build_dispositions_postconditions():
    """Unit table for the four postconditions, including the one the
    verifier's own gate should make unreachable in production."""
    rows = build_dispositions(
        plan_actions={
            "authoring_props": {"action": "strip", "reason": "policy_default"},
            "hidden_text": {"action": "flag", "reason": "policy_default"},
            "comments_and_notes": {"action": "strip", "reason": "policy_default"},
        },
        subtypes_before=["authoring_props", "hidden_text", "comments_and_notes"],
        subtypes_after=["hidden_text", "comments_and_notes"],
    )
    by = {r["subtype"]: r for r in rows}
    assert by["authoring_props"]["postcondition"] == "removed_confirmed"
    assert by["hidden_text"]["postcondition"] == "retained_as_planned"
    # Planned for removal, still observed: never silently reported as gone.
    assert by["comments_and_notes"]["postcondition"] == "retained_unplanned"
    # No post-sanitize observation at all is "not verifiable", never removed.
    unknown = build_dispositions(
        plan_actions={"authoring_props": {"action": "strip", "reason": "policy_default"}},
        subtypes_before=["authoring_props"],
        subtypes_after=None,
    )
    assert unknown[0]["postcondition"] == "not_verifiable"
    assert unknown[0]["present_after"] is None


# --- 3. the white-font finding says what it observed ------------------------


def test_style_level_white_is_not_reported_as_concealed_text():
    """The review's second finding: 'white=119' counted FFFFFF colour
    declarations across every word/*.xml part — styles and numbering
    included — and read to a reviewer as 119 pieces of concealed text."""
    _c2pa, _ai, findings, details = container_meta.inspect_docx(_style_only_white_docx(119))
    legal = details["docx_legal"]
    assert legal["hidden_white"] == 119, "the rule-level count is still reported"
    assert legal["hidden_white_applied_runs"] == 0, "no run of text is actually white"
    assert legal["hidden_white_rule_parts"] == {"word/styles.xml": 119}
    assert legal["hidden_white_applied_parts"] == []

    (hidden,) = [f for f in findings if f.startswith("docx-hidden-text:")]
    assert "white_applied_runs=0" in hidden
    assert "white_rules=119" in hidden
    # The finding string must name its own detection basis, so a reader can
    # tell a style condition from concealed text without the original file.
    assert "style and numbering definitions included" in hidden
    assert "word/styles.xml" in hidden


def test_applied_white_run_is_counted_separately():
    body = (
        "<w:p><w:r><w:t>visible</w:t></w:r>"
        '<w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr><w:t>invisible</w:t></w:r></w:p>'
    )
    data = _docx({"word/document.xml": _document(body)})
    _c2pa, _ai, _findings, details = container_meta.inspect_docx(data)
    legal = details["docx_legal"]
    assert legal["hidden_white_applied_runs"] == 1
    assert legal["hidden_white_applied_parts"] == ["word/document.xml"]


def test_vanish_findings_name_their_parts():
    _c2pa, _ai, _findings, details = container_meta.inspect_docx(_hidden_text_docx())
    legal = details["docx_legal"]
    assert legal["hidden_vanish"] == 1
    assert legal["hidden_vanish_parts"] == ["word/document.xml"]


# --- 4. an unanchored artifact says what it is unanchored about -------------


def test_release_result_anchor_scopes_itself_to_its_own_bytes(client):
    """`release_result.json` reporting `anchor: none` next to a
    `release_packet.json` carrying an RFC 3161 anchor read as a
    contradiction. Both statements were true; only one of them said what
    it was about."""
    mid = client.post("/v1/matters", json={"name": "Anchor scope"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("hidden.docx", _hidden_text_docx(), "application/octet-stream")},
    ).json()["id"]
    rel = client.post(
        f"/v1/matters/{mid}/documents/{doc}/releases",
        json={
            "profile_id": "counterparty_deal_room",
            "recipient_type": "opposing_counsel",
            "recipient_name": "Jane Doe, Esq.",
            "purpose": "production",
        },
    )
    assert rel.status_code == 200, rel.text
    release_id = rel.json()["release"]["id"]
    # Fetched back through the standalone route, not read off the create
    # response: the artifact a recipient actually receives is the one that
    # has to carry the scoping.
    result = client.get(f"/v1/matters/{mid}/releases/{release_id}/result").json()
    anchor = result["anchor"]
    assert anchor["type"] == "none", "the honest claim about these bytes is unchanged"
    assert anchor["scope"] == "release_result_bytes"
    assert "release_packet.json" in anchor["note"]
    assert "not as a conflict" in anchor["note"].lower()


def test_verifier_note_scopes_release_result_anchor():
    sys.path.insert(0, str(REPO / "tools"))
    try:
        import counselclear_verify_release_packet as verifier
    finally:
        sys.path.remove(str(REPO / "tools"))

    result_note = verifier._anchor_note("none", artifact="release result")
    packet_note = verifier._anchor_note("none", artifact="packet")
    assert "THIS FILE only" in result_note
    assert "release_packet.json" in result_note
    # The packet's own note must NOT gain the scoping sentence: for a
    # packet, "not anchored" really is the whole claim.
    assert "THIS FILE only" not in packet_note
    # And the honest disclaimer survives in both.
    assert "NOT EXTERNALLY ANCHORED" in result_note and "NOT EXTERNALLY ANCHORED" in packet_note


# --- helpers ----------------------------------------------------------------


def test_manifest_schema_documents_the_new_contract():
    """Both new fields are part of the published contract, and the version
    moved with them -- a pin that did not move would let a v2 artifact
    claim it was built against v1."""
    schema = json.loads((SCRIPTS / "schemas" / "manifest.schema.json").read_text())
    assert schema["version"] >= 2
    assert "retained_finding" in schema["$defs"]["action_record"]["properties"]
    assert "dispositions" in schema["properties"]
    assert schema["$defs"]["disposition"]["properties"]["postcondition"]["enum"]


# --- 5. residual authoring exhaust: acted on, and stated ---------------------


def _exhaust_docx() -> bytes:
    """A document carrying the authoring exhaust the review found riding
    through a "clean" derivative: RSIDs, a persistent docId, original
    timestamps, a revision count and an editing-minutes counter."""
    settings = (
        '<?xml version="1.0"?>'
        f'<w:settings {W_DECL} xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml">'
        '<w:rsids><w:rsidRoot w:val="00AB12CD"/><w:rsid w:val="00112233"/></w:rsids>'
        '<w15:docId w15:val="{DEAD-BEEF}"/><w14:docId w14:val="{0000-1111}"/>'
        "</w:settings>"
    ).encode()
    core = (
        b'<?xml version="1.0"?>'
        b'<cp:coreProperties xmlns:cp="c" xmlns:dc="d" xmlns:dcterms="t">'
        b"<dc:title>Independent Contractor Services Agreement - Final Draft</dc:title>"
        b"<dc:creator>Jane Counsel</dc:creator><cp:revision>4</cp:revision>"
        b"<dcterms:created>2026-09-02T02:30:00Z</dcterms:created>"
        b"<dcterms:modified>2026-09-02T02:31:00Z</dcterms:modified>"
        b"</cp:coreProperties>"
    )
    app_props = (
        b'<?xml version="1.0"?><Properties><Application>Microsoft Word</Application>'
        b"<TotalTime>2</TotalTime><Words>900</Words><Characters>5100</Characters>"
        b"<Template>Normal.dotm</Template></Properties>"
    )
    body = (
        '<w:p w:rsidR="00112233" w:rsidRDefault="00112233">'
        '<w:r w:rsidR="00AB12CD"><w:t>Agreement text.</w:t></w:r></w:p>'
    )
    return _docx(
        {
            "word/document.xml": _document(body),
            "word/settings.xml": settings,
            "docProps/core.xml": core,
            "docProps/app.xml": app_props,
        }
    )


def test_external_sharing_strips_edit_session_correlators():
    """RSIDs and persistent document ids are pure cross-document
    correlators with no rendering effect: they link two files to the same
    drafting session, and survived every prior 'clean'."""
    cleaned, actions = container_meta.clean_docx(_exhaust_docx())
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        settings = zf.read("word/settings.xml").decode()
        document = zf.read("word/document.xml").decode()
        core = zf.read("docProps/core.xml").decode()
        app_props = zf.read("docProps/app.xml").decode()

    assert "w:rsid" not in settings and "docId" not in settings
    assert "w:rsidR" not in document
    assert "Agreement text." in document, "stripping correlators must not touch text"
    assert any("authoring exhaust" in a for a in actions)

    # Session timestamps and counters are emptied, not deleted: the element
    # staying present keeps the part valid and makes the blanking visible.
    for field in ("dcterms:created", "dcterms:modified", "cp:revision"):
        assert f"<{field}></{field}>" in core, field
    assert "<TotalTime></TotalTime>" in app_props


def test_deliberately_retained_fields_are_actually_retained():
    """The other half of the owner's decision: title, statistics and the
    template reference stay. They are document-descriptive or affect how
    Word opens the file, and removing them was not the ask."""
    cleaned, _actions = container_meta.clean_docx(_exhaust_docx())
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        core = zf.read("docProps/core.xml").decode()
        app_props = zf.read("docProps/app.xml").decode()
    assert "Independent Contractor Services Agreement" in core
    assert "<Words>900</Words>" in app_props
    assert "Normal.dotm" in app_props
    # But identity is still gone -- the retention is scoped, not a rollback.
    assert "<dc:creator></dc:creator>" in core
    assert "<Application></Application>" in app_props


def test_privacy_only_does_not_strip_correlators():
    """privacy_only promises a byte-faithful document apart from the named
    identity fields. Silently removing RSIDs there would break that
    promise, so the exhaust pass must be scoped to the sharing policies."""
    cleaned, _actions = container_meta.clean_docx(
        _exhaust_docx(), prop_fields=container_meta._PRIVACY_PROP_FIELDS
    )
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        settings = zf.read("word/settings.xml").decode()
        core = zf.read("docProps/core.xml").decode()
    assert "w:rsid" in settings, "privacy_only must leave the session table alone"
    assert "2026-09-02T02:30:00Z" in core, "privacy_only must not reset timestamps"
    assert "<dc:creator></dc:creator>" in core, "identity is still scrubbed"


def test_manifest_states_both_halves_of_the_exhaust_policy(client):
    """The actual defect the review named was silence: a reader could not
    tell a decision from an oversight. Both halves must be on the record."""
    mid = client.post("/v1/matters", json={"name": "Exhaust"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("icsa.docx", _exhaust_docx(), "application/octet-stream")},
    ).json()["id"]
    job = client.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert job["status"] == "done", job
    manifest = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/manifest").json()

    residual = manifest["residual_metadata"]
    stripped = " ".join(residual["stripped"])
    assert "rsid" in stripped and "docId" in stripped
    assert "dcterms:created" in stripped and "cp:revision" in stripped
    retained_fields = {r["field"] for r in residual["retained"]}
    assert "dc:title" in retained_fields
    # Every retention carries its reason -- a bare list of kept fields is
    # still a policy that does not say why.
    assert all(r["reason"] for r in residual["retained"])

    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    assert "Residual authoring metadata" in html
    assert "Deliberately retained" in html


# --- 6. an approval that was not acted on says so (A7) -----------------------


def test_approve_resolving_to_flag_discloses_the_no_op():
    """`APPROVED_BUT_NO_OP_MARKER` originally fired only for
    `action == "keep"`, on the stated belief that `layer_a_non_body` was the
    only subtype that could reach it. That held for "keep" and not for the
    case as a whole: three more approve-default subtypes resolve to "flag",
    and produced no disclosure at all.

    `hidden_text` is the one that matters. An operator approving it under
    `production` is asking for concealed text to be removed; the engine has
    no removal path, so they get a flag. Before this, nothing on the
    certificate said their approval had not been acted on."""
    from engine_api import inspect_bytes

    data = _hidden_text_docx()
    plan = plan_actions(inspect_bytes(data, "h.docx"), "production", {"hidden_text": "approve"})
    assert plan.actions["hidden_text"] == {
        "action": "flag",
        "reason": "operator_approved",
        "legal_justification": {"basis": "unspecified", "note": ""},
    }
    _cleaned, records = apply_actions(data, plan)
    (record,) = [r for r in records if r.subtype == "hidden_text"]

    # The record keeps the action that actually ran. Flattening it to "keep"
    # would make the manifest wrong about what the policy did.
    assert record.action == "flag"
    assert record.retained_finding
    assert "approved, but this subtype has no strip action" in record.detail
    assert "NOT removed" in record.detail


def test_approved_no_op_gate_is_the_action_not_a_subtype_list():
    """Every approve-default subtype whose resolved action is non-removing
    must be covered -- the gate is the action, so a future policy edit that
    makes another subtype resolve this way needs no code change."""
    from policies import _APPROVE_RESOLVES_TO, _NON_REMOVING_ACTIONS
    from policies import DEFAULT_POLICIES as POLICIES

    reachable = {
        st
        for row in POLICIES.values()
        for st, a in row.items()
        if a == "approve" and _APPROVE_RESOLVES_TO.get(st) in _NON_REMOVING_ACTIONS
    }
    # Four, not the one the old comment claimed. Asserted by name so a
    # policy change that adds or drops one fails here and gets re-reasoned.
    assert reachable == {"hidden_structure", "hidden_text", "pdf_acroform", "layer_a_non_body"}


def test_approved_no_op_reaches_the_certificate_limitations(client):
    mid = client.post("/v1/matters", json={"name": "Approve no-op"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("hidden.docx", _hidden_text_docx(), "application/octet-stream")},
    ).json()["id"]
    job = client.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={"policy_id": "production", "finding_decisions": {"hidden_text": "approve"}},
    ).json()
    assert job["status"] == "done", job

    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    limitations = html.split('class="limitations"')[1]
    assert "NOT removed" in limitations
