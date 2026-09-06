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


def _hidden_structure_xlsx() -> bytes:
    """A workbook with hidden sheets/rows. Used wherever a test needs a
    finding the policy still FLAGS: since the Lane B stripper landed,
    hidden_text is removed rather than flagged under every outward-facing
    policy, so it can no longer exercise the release gate. hidden_structure
    remains flag-only -- unhiding a sheet changes what a reader sees, which
    is not a change a sanitizer may make unasked."""
    return (REPO / "tests" / "fixtures" / "legal" / "hidden.xlsx").read_bytes()


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
        # The release gate: hidden_text is flag-only under external_sharing,
        # so reaching `done` at all now requires acknowledging it by name.
        # The retention -- and its limitation -- survive the acknowledgement;
        # that is the point. An acknowledged finding is still in the
        # derivative, and the certificate must still say so.
        json={"policy_id": "external_sharing", "finding_decisions": {"hidden_text": "keep"}},
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

    plan = plan_actions(
        inspect_bytes(data, "h.docx"), "external_sharing", {"hidden_text": "keep"}
    )
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
            "finding_decisions": {"hidden_text": "keep"},
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
            "finding_decisions": {"hidden_text": "keep"},
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


def _clean_docx() -> bytes:
    """A DOCX carrying NONE of the authoring exhaust: no w:rsid* anywhere,
    no w:rsids session table, no w14/w15:docId, no session counters -- the
    shape a plain single-session Word document actually has. Its only
    finding is authoring identity, which every mutating policy strips."""
    core = (
        b'<?xml version="1.0"?>'
        b'<cp:coreProperties xmlns:cp="c" xmlns:dc="d" xmlns:dcterms="t">'
        b"<dc:creator>Jane Counsel</dc:creator></cp:coreProperties>"
    )
    app_props = (
        b'<?xml version="1.0"?><Properties><Application>Microsoft Word</Application></Properties>'
    )
    body = "<w:p><w:r><w:t>Agreement text.</w:t></w:r></w:p>"
    return _docx(
        {
            "word/document.xml": _document(body),
            "docProps/core.xml": core,
            "docProps/app.xml": app_props,
        }
    )


def _residual_removed_section(html: str) -> str:
    """The certificate's Removed sub-section, scoped so assertions cannot
    be satisfied by the words rsid/docId appearing elsewhere in the page."""
    tail = html.split("Residual authoring metadata", 1)[-1]
    return tail.split("Deliberately retained", 1)[0]


def test_certificate_does_not_claim_removals_this_document_never_carried(client):
    """The defect (2026-09-06, most serious §5 violation): the certificate's
    "Removed" list was keyed only to (policy_id, format), so a DOCX that
    never carried a single w:rsid or docId still got a printed custody
    certificate asserting those were removed from IT. A printed
    certificate is the artifact most likely to reach opposing counsel with
    none of the surrounding UI; it must not know more than the document
    does. The list must be driven by the per-document exhaust counts the
    engine actually observed."""
    mid = client.post("/v1/matters", json={"name": "Clean Truth"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("plain.docx", _clean_docx(), "application/octet-stream")},
    ).json()["id"]
    job = client.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert job["status"] == "done", job
    manifest = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/manifest").json()

    # Ground truth: the engine's own action list for THIS document must
    # show no authoring-exhaust scrub happened -- there was nothing to
    # scrub. (The identity scrub of core.xml/app.xml still runs.)
    assert not any("authoring exhaust" in a for a in manifest["actions"]), manifest["actions"]

    residual = manifest["residual_metadata"]
    joined = " ".join(residual["stripped"])
    assert "rsid" not in joined.lower(), joined
    assert "docId" not in joined, joined

    # The printed certificate -- the artifact that travels alone -- must
    # carry the same scoping: no claim that RSIDs/docIds were removed from
    # a document that never had them.
    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    removed_section = _residual_removed_section(html)
    assert "rsid" not in removed_section.lower(), removed_section
    assert "docId" not in removed_section, removed_section


def test_certificate_removed_list_names_what_this_document_carried(client):
    """The positive half of the same invariant: a document that DOES carry
    session correlators gets them named in the certificate's Removed list,
    with the counts that came from its own scrub -- so the list is evidence
    about this document, not a policy table restated."""
    mid = client.post("/v1/matters", json={"name": "Exhaust Cert"}).json()["id"]
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

    assert any("authoring exhaust" in a for a in manifest["actions"]), manifest["actions"]
    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    removed_section = _residual_removed_section(html)
    # The _exhaust_docx fixture carries 3 w:rsid* attributes, 1 w:rsids
    # session table and 2 persistent docIds; the certificate must show the
    # counts, proving the list came from this document's scrub record.
    assert "3" in removed_section and "rsid" in removed_section.lower(), removed_section
    assert "2" in removed_section and "docId" in removed_section, removed_section


def test_pptx_certificate_makes_no_word_exhaust_claims(client):
    """The fixed list also fired for PPTX, naming w:rsid* attributes and a
    w:rsids settings.xml table -- Word mechanisms a presentation cannot
    even carry -- while the engine has no exhaust scrub for PPTX at all.
    A deck's certificate must claim none of it."""
    presentation = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>'
    )
    slide = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        b"<p:cSld/></p:sld>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
            "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>"
            "<Default Extension='xml' ContentType='application/xml'/>"
            "<Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/>"
            "<Override PartName='/ppt/presentation.xml' ContentType='application/vnd."
            "openxmlformats-officedocument.presentationml.presentation.main+xml'/>"
            "<Override PartName='/ppt/slides/slide1.xml' ContentType='application/vnd."
            "openxmlformats-officedocument.presentationml.slide+xml'/>"
            "</Types>",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>',
        )
        zf.writestr("ppt/presentation.xml", presentation)
        zf.writestr("ppt/slides/slide1.xml", slide)
    deck = buf.getvalue()

    mid = client.post("/v1/matters", json={"name": "Deck Truth"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("deck.pptx", deck, "application/octet-stream")},
    ).json()["id"]
    job = client.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert job["status"] == "done", job
    manifest = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/manifest").json()

    residual = manifest["residual_metadata"]
    joined = " ".join(residual["stripped"])
    assert "rsid" not in joined.lower(), joined
    assert "docId" not in joined, joined
    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    removed_section = _residual_removed_section(html)
    assert "rsid" not in removed_section.lower(), removed_section
    assert "docId" not in removed_section, removed_section


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


def test_approval_that_cannot_be_honoured_is_refused_not_disclosed():
    """An operator who APPROVES a finding has asked for it to be REMOVED.
    Where `_APPROVE_RESOLVES_TO` maps that approval onto a non-removing
    action, they get a flagged derivative and hold a false belief about
    what it contains -- worse than being uninformed, and not something a
    disclosure after the fact repairs. The gate refuses and says the
    approval cannot be honoured.

    Uses hidden_structure: hidden_text used to demonstrate this and no
    longer can, because the Lane B stripper gave it a real removal path."""
    from engine_api import inspect_bytes
    from policies import RELEASE_GATE_MARKER, PolicyError

    res = inspect_bytes(_hidden_structure_xlsx(), "hidden.xlsx")
    with pytest.raises(PolicyError) as excinfo:
        plan_actions(res, "production", {"hidden_structure": "approve"})
    message = str(excinfo.value)
    assert RELEASE_GATE_MARKER in message
    assert "NOT REMOVABLE" in message
    assert "cannot be honoured" in message
    assert '"hidden_structure": "keep"' in message


def test_gate_cannot_be_routed_around_by_changing_profile():
    """hidden_structure is `flag` under external_sharing and `approve` under
    production. Gating only the flag would leave an operator free to pick
    the other profile and ship the same finding as an unreviewed
    `no_decision` keep."""
    from engine_api import inspect_bytes
    from policies import PolicyError

    res = inspect_bytes(_hidden_structure_xlsx(), "hidden.xlsx")
    for policy in ("external_sharing", "production"):
        with pytest.raises(PolicyError, match="not acknowledged"):
            plan_actions(res, policy)

    # privacy_only and evidence_preservation are not release paths and are
    # excluded by intent -- they exist to leave documents alone.
    for policy in ("privacy_only", "evidence_preservation"):
        plan = plan_actions(res, policy)
        assert plan.actions["hidden_structure"]["action"] == "keep"


def test_composition_rule_keeps_are_not_gated():
    """A `policy_default` KEEP is the composition rule, not the policy
    declining to act on something it noticed. Gating it would refuse a
    release over a stray zero-width space in a footer, so the gate is
    scoped to flags and to never-reviewed approve-defaults."""
    from engine_api import inspect_bytes

    # spa.docx carries comments and tracked changes but nothing flag-only,
    # so it must still release cleanly with no acknowledgement at all.
    data = (REPO / "tests" / "fixtures" / "legal" / "spa.docx").read_bytes()
    plan = plan_actions(inspect_bytes(data, "spa.docx"), "external_sharing")
    assert plan.actions["comments_and_notes"]["action"] == "strip"


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
    # Asserted by name so a policy change that adds or drops one fails here
    # and gets re-reasoned. hidden_text was in this set until the Lane B
    # stripper landed: approving it now resolves to a real `strip`, so it
    # drops out. That shrinkage is the stripper working -- one fewer subtype
    # an operator can approve and not get.
    assert reachable == {"hidden_structure", "pdf_acroform", "layer_a_non_body"}


def test_acknowledged_finding_is_still_a_disclosed_limitation(client):
    """Acknowledgement is not absolution. The finding still travels, so the
    certificate must still carry it as a limitation -- now recording that a
    named operator was shown it and confirmed it, rather than that a default
    table left it in."""
    mid = client.post("/v1/matters", json={"name": "Acknowledged"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("hidden.docx", _hidden_text_docx(), "application/octet-stream")},
    ).json()["id"]
    job = client.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={
            "policy_id": "external_sharing",
            "finding_decisions": {"hidden_text": "keep"},
            "legal_justifications": {
                "hidden_text": {"basis": "work_product", "note": "Drafting notes."}
            },
        },
    ).json()
    assert job["status"] == "done", job

    manifest = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/manifest").json()
    (record,) = [r for r in manifest["action_records"] if r["subtype"] == "hidden_text"]
    assert record["retained_finding"] is True
    assert "acknowledged by operator before release" in record["detail"]

    html = client.get(f"/v1/matters/{mid}/jobs/{job['id']}/certificate").text
    limitations = html.split('class="limitations"')[1]
    assert "REMAINS IN THE DERIVATIVE" in limitations
    # The basis was supplied, so the "no basis" alarm must NOT fire.
    assert "NO OPERATOR LEGAL BASIS" not in limitations
    assert "work_product" in limitations


def test_release_refused_by_the_gate_still_produces_a_result_artifact(client):
    """"Packet or refusal" has to hold for a gate refusal too: the release
    is refused, and the refusal is a machine-checkable record naming what
    blocked it -- not a silent failure the operator has to interpret."""
    mid = client.post("/v1/matters", json={"name": "Gate refusal"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("hidden.xlsx", _hidden_structure_xlsx(), "application/octet-stream")},
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
    body = rel.json()
    assert body["release"]["status"] == "refused"
    result = body["release_result"]
    assert result["status"] == "refused"
    assert "not acknowledged" in result["reason"]
    assert "hidden_structure" in result["reason"]
    assert result["limitations"], "a refused release still discloses limitations"


# --- 7. the hidden-text stripper (Lane B) ------------------------------------
#
# The engine could see concealed text and had no way to remove it; every
# policy resolved hidden_text to a non-removing action, and the release gate
# could only force someone to acknowledge that a document carried it. These
# assert the removal is real, is honest about what it cannot do, and cannot
# report success over text that is still there.


def _styles(inner: str) -> bytes:
    return f'<?xml version="1.0"?><w:styles {W_DECL}>{inner}</w:styles>'.encode()


def _vanish_docx(styles: str | None = None, body: str | None = None) -> bytes:
    body = body or (
        "<w:p><w:r><w:t>Agreement body.</w:t></w:r></w:p>"
        '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>PRIVILEGED WORK PRODUCT</w:t></w:r></w:p>'
    )
    parts = {"word/document.xml": _document(body)}
    if styles:
        parts["word/styles.xml"] = _styles(styles)
    return _docx(parts)


def _body_of(blob: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return zf.read("word/document.xml").decode()


def test_vanish_text_is_removed_not_unhidden():
    """The single most important property. Un-hiding would surface
    privileged text into the visible document -- the exact disclosure the
    release exists to prevent, performed by the tool meant to prevent it."""
    cleaned, actions = container_meta.clean_docx(_vanish_docx(), strip_hidden_text=True)
    body = _body_of(cleaned)
    assert "PRIVILEGED WORK PRODUCT" not in body, "concealed text must be GONE"
    assert "w:vanish" not in body
    assert "Agreement body." in body, "visible text must survive"
    assert any(a.startswith("hidden-text: removed") for a in actions), actions


def test_explicit_vanish_off_is_visible_text_and_must_survive():
    """`<w:vanish w:val="0"/>` is an explicit OFF -- documents write it to
    cancel a hidden style on one run. Treating it as hidden would delete
    text the reader can see, the worst failure this pass can have."""
    body = (
        '<w:p><w:r><w:rPr><w:vanish w:val="0"/></w:rPr><w:t>VISIBLE RUN</w:t></w:r></w:p>'
    )
    cleaned, _ = container_meta.clean_docx(
        _vanish_docx(body=body), strip_hidden_text=True
    )
    assert "VISIBLE RUN" in _body_of(cleaned)


def test_hidden_paragraph_mark_does_not_delete_paragraph_content():
    """w:vanish inside w:pPr/w:rPr hides the pilcrow, joining the paragraph
    to the next one visually. Its runs stay visible."""
    body = (
        "<w:p><w:pPr><w:rPr><w:vanish/></w:rPr></w:pPr>"
        "<w:r><w:t>PARAGRAPH TEXT</w:t></w:r></w:p>"
    )
    cleaned, _ = container_meta.clean_docx(
        _vanish_docx(body=body), strip_hidden_text=True
    )
    assert "PARAGRAPH TEXT" in _body_of(cleaned)


def test_style_and_docdefaults_concealment_is_resolved():
    """Two bugs the first implementation had, both of which made the
    stripper MISS hidden text while reporting success -- the overclaim this
    product exists to refuse. A run is hidden by w:docDefaults, by its
    paragraph style, by its character style, or by w:basedOn inheritance,
    not only by direct formatting."""
    # docDefaults hides everything by default.
    cleaned, _ = container_meta.clean_docx(
        _vanish_docx(
            styles="<w:docDefaults><w:rPrDefault><w:rPr><w:vanish/></w:rPr>"
            "</w:rPrDefault></w:docDefaults>",
            body="<w:p><w:r><w:t>HIDDEN BY DEFAULT</w:t></w:r></w:p>",
        ),
        strip_hidden_text=True,
    )
    assert "HIDDEN BY DEFAULT" not in _body_of(cleaned)

    # A paragraph style, reached through w:basedOn.
    cleaned, _ = container_meta.clean_docx(
        _vanish_docx(
            styles='<w:style w:styleId="Base"><w:rPr><w:vanish/></w:rPr></w:style>'
            '<w:style w:styleId="Hid"><w:basedOn w:val="Base"/></w:style>',
            body='<w:p><w:pPr><w:pStyle w:val="Hid"/></w:pPr>'
            "<w:r><w:t>HIDDEN BY STYLE</w:t></w:r></w:p>",
        ),
        strip_hidden_text=True,
    )
    assert "HIDDEN BY STYLE" not in _body_of(cleaned)


def test_formatting_cascade_precedence():
    """docDefaults -> paragraph style -> character style -> direct run.
    The first level that specifies vanish, reading from the top, wins --
    which is how a document exposes one visible run inside hidden text."""
    cleaned, _ = container_meta.clean_docx(
        _vanish_docx(
            styles='<w:style w:styleId="HidP"><w:rPr><w:vanish/></w:rPr></w:style>'
            '<w:style w:styleId="VisC"><w:rPr><w:vanish w:val="0"/></w:rPr></w:style>',
            body='<w:p><w:pPr><w:pStyle w:val="HidP"/></w:pPr>'
            '<w:r><w:rPr><w:rStyle w:val="VisC"/></w:rPr>'
            "<w:t>CHARACTER STYLE WINS</w:t></w:r></w:p>",
        ),
        strip_hidden_text=True,
    )
    assert "CHARACTER STYLE WINS" in _body_of(cleaned)


def test_basedon_cycle_does_not_recurse_forever():
    model = container_meta.docx_hidden_model(
        _styles(
            '<w:style w:styleId="A"><w:basedOn w:val="B"/></w:style>'
            '<w:style w:styleId="B"><w:basedOn w:val="A"/></w:style>'
        )
    )
    assert all(state is None for state in model.style_state.values())


def test_malformed_styles_do_not_disable_direct_stripping():
    """A styles part that will not parse must not turn a partial capability
    into none at all: direct-formatting vanish is still removed."""
    parts = {
        "word/document.xml": _document(
            '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>STILL REMOVED</w:t></w:r></w:p>'
        ),
        "word/styles.xml": b"<w:styles",
    }
    cleaned, _ = container_meta.clean_docx(_docx(parts), strip_hidden_text=True)
    assert "STILL REMOVED" not in _body_of(cleaned)


def test_extractor_and_remover_share_one_definition_of_hidden():
    """If these disagreed, verify's postcondition would go green while
    concealed text sat in the derivative -- a passing check over a false
    claim, the one outcome this engine may not produce."""
    blob = _vanish_docx(
        styles='<w:style w:styleId="Hid"><w:rPr><w:vanish/></w:rPr></w:style>',
        body='<w:p><w:pPr><w:pStyle w:val="Hid"/></w:pPr>'
        "<w:r><w:t>BY STYLE</w:t></w:r></w:p>"
        '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>BY DIRECT</w:t></w:r></w:p>'
        "<w:p><w:r><w:t>Visible.</w:t></w:r></w:p>",
    )
    assert sorted(container_meta.extract_docx_hidden_text(blob)) == ["BY DIRECT", "BY STYLE"]
    cleaned, _ = container_meta.clean_docx(blob, strip_hidden_text=True)
    assert container_meta.extract_docx_hidden_text(cleaned) == []
    assert "Visible." in _body_of(cleaned)


def test_white_only_concealment_refuses_rather_than_silently_doing_nothing():
    """The stripper is partial by design: whether white text is invisible
    depends on the shading behind it, which this engine does not resolve, so
    removing on a colour match could delete visible white-on-dark text.

    A white-only document therefore has no removal path. Saying so is the
    honest outcome; letting `strip` no-op would leave the finding in place,
    fail the re-inspect gate, and kill the job with an opaque message."""
    from engine_api import inspect_bytes
    from policies import WHITE_ONLY_HIDDEN_REFUSAL, PolicyError

    white = _vanish_docx(
        body='<w:p><w:r><w:rPr><w:color w:val="FFFFFF"/></w:rPr>'
        "<w:t>WHITE ON WHITE</w:t></w:r></w:p>"
    )
    res = inspect_bytes(white, "w.docx")
    with pytest.raises(PolicyError) as excinfo:
        plan_actions(res, "external_sharing")
    assert WHITE_ONLY_HIDDEN_REFUSAL in str(excinfo.value)
    # The refusal must name a remedy that actually works -- a gate that
    # rejects the flag its own message recommends is a dead end.
    assert '"hidden_text": "keep"' in str(excinfo.value)
    plan = plan_actions(res, "external_sharing", {"hidden_text": "keep"})
    assert plan.actions["hidden_text"]["reason"] == "operator_acknowledged"
    cleaned, _records = apply_actions(white, plan)
    assert "WHITE ON WHITE" in _body_of(cleaned), "acknowledged white text stays"


def test_strip_declining_is_scoped_to_hidden_text():
    """An operator may decline the hidden-text strip, because its removal is
    partial. They may NOT decline a strip whose removal is complete -- the
    comments strip is the whole point of an external-sharing release."""
    from engine_api import inspect_bytes

    data = (REPO / "tests" / "fixtures" / "legal" / "spa.docx").read_bytes()
    plan = plan_actions(
        inspect_bytes(data, "spa.docx"),
        "external_sharing",
        {"comments_and_notes": "keep"},
    )
    assert plan.actions["comments_and_notes"]["action"] == "strip"


def test_verify_fails_when_hidden_text_is_surfaced_instead_of_removed():
    """The catastrophic failure mode, asserted end to end: a derivative that
    UN-HID concealed text must fail verification, not pass it.

    The fragment is deliberately split across two <w:t> elements, which Word
    produces routinely at spell-check and rsid boundaries. The extractor
    concatenates per run and the plaintext projection splits per w:t, so
    without whitespace normalisation the comparison misses and the check
    reports 'confirmed absent' over privileged text now visible."""
    from engine_api import inspect_bytes
    from verify import verify_derivative

    split = (
        "<w:p><w:r><w:t>Body.</w:t></w:r></w:p>"
        '<w:p><w:r><w:rPr><w:vanish/></w:rPr>'
        "<w:t>PRIVILEGED </w:t><w:t>WORK PRODUCT</w:t></w:r></w:p>"
    )
    original = _vanish_docx(body=split)
    plan = plan_actions(inspect_bytes(original, "d.docx"), "external_sharing")

    honest, _ = container_meta.clean_docx(original, strip_hidden_text=True)
    result = verify_derivative(original, honest, plan, name="d.docx")
    check = next(c for c in result["checks"] if c["name"] == "hidden_text_removed")
    assert check["pass"], check

    # Same words, no longer concealed: removal was never performed.
    surfaced = _vanish_docx(
        body="<w:p><w:r><w:t>Body.</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>PRIVILEGED </w:t><w:t>WORK PRODUCT</w:t></w:r></w:p>"
    )
    result = verify_derivative(original, surfaced, plan, name="d.docx")
    check = next(c for c in result["checks"] if c["name"] == "hidden_text_removed")
    assert not check["pass"]
    assert "SURFACED" in check["detail"]
    assert result["pass"] is False, "a surfaced-text derivative must fail the whole gate"


def test_verify_does_not_false_positive_on_dual_use_fragments():
    """A fragment concealed in one place and printed visibly in another is
    not a leak. Failing the job over it would refuse correct work and teach
    operators to distrust the gate."""
    from engine_api import inspect_bytes
    from verify import verify_derivative

    original = _vanish_docx(
        body="<w:p><w:r><w:t>CONFIDENTIAL</w:t></w:r></w:p>"
        '<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>CONFIDENTIAL</w:t></w:r></w:p>'
    )
    plan = plan_actions(inspect_bytes(original, "d.docx"), "external_sharing")
    cleaned, _ = container_meta.clean_docx(original, strip_hidden_text=True)
    result = verify_derivative(original, cleaned, plan, name="d.docx")
    check = next(c for c in result["checks"] if c["name"] == "hidden_text_removed")
    assert check["pass"], check
