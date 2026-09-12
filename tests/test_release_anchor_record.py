"""The anchoring outcome reaches the operator's own records (Lane E3).

Anchoring is computed inside job_bundle while the packet is assembled and
then travels only inside the packet. Two things followed from that, and
this module pins the fix for both.

**No read-scoped route could report it.** Every anchor string in web/
asserted "not externally anchored" unconditionally, which stopped being
true when RFC 3161 anchoring merged, and there was nothing for the UI to
read instead.

**A TSA failure left no trace here at all.** When the timestamp authority
is unreachable the release still succeeds -- one retry, 5s timeout, packet
issued unanchored with that fact in its own anchor field. That is correct:
a release must never block on a third party. But the only record of it
lived in the packet the RECIPIENT holds. The operator's log said a bundle
was downloaded and nothing about whether the timestamp they believe they
are getting was obtained.

The central design point, asserted below: anchoring is a fact about ONE
DOWNLOAD, never a property of the release. A packet is rebuilt per
download and legitimately differs each time -- each download is its own
audited custody event, so audit_refs advances and the signature over the
packet's facts follows -- and the TSA token attests to those signature
bytes.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "service" / "scripts"), str(REPO / "service")):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.config import Config
from app.db import make_engine
from app.main import create_app
from app.migrate import upgrade_head
from test_custody_truthfulness import _document, _docx

PW = "pw12345"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _client(tmp_path, monkeypatch, tsa_url):
    if tsa_url is None:
        monkeypatch.delenv("COUNSELCLEAR_TSA_URL", raising=False)
    else:
        monkeypatch.setenv("COUNSELCLEAR_TSA_URL", tsa_url)
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    cfg = Config(tmp_path / "data")
    make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    return c


def _release(c):
    mid = c.post("/v1/matters", json={"name": "Anchor record"}).json()["id"]
    blob = _docx({"word/document.xml": _document("<w:p><w:r><w:t>Body.</w:t></w:r></w:p>")})
    doc = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("a.docx", blob, "application/octet-stream")},
    ).json()["id"]
    r = c.post(
        f"/v1/matters/{mid}/documents/{doc}/releases",
        json={
            "profile_id": "counterparty_deal_room",
            "recipient_type": "opposing_counsel",
            "recipient_name": "X",
            "purpose": "p",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return mid, body["release"]["id"], body["job"]["id"]


def _anchored_events(c, mid):
    return [
        e
        for e in c.get(f"/v1/matters/{mid}/audit").json()["events"]
        if e["action"] == "bundle.anchored"
    ]


def test_unknown_until_a_packet_is_actually_built(tmp_path, monkeypatch):
    """NULL means "no packet has been downloaded yet". A UI must render
    that as *not yet known*, never as "unanchored" -- the difference
    between an unanswered question and a negative answer is the entire
    reason these fields exist."""
    c = _client(tmp_path, monkeypatch, "off")
    mid, rid, _jid = _release(c)
    assert c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"] is None


def test_zero_egress_records_an_operator_anchor_not_an_external_one(tmp_path, monkeypatch):
    """With anchoring off the packet carries an ed25519-operator anchor --
    this system signing its own output, which is emphatically not what
    "externally anchored" means, and must not be reported as such."""
    c = _client(tmp_path, monkeypatch, "off")
    mid, rid, jid = _release(c)
    assert c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle").status_code == 200

    last = c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"]
    assert last["type"] == "ed25519-operator"
    assert last["externally_anchored"] is False
    assert last["at"]

    (event,) = _anchored_events(c, mid)
    # "We never asked" -- configuration, not an outage.
    assert event["payload"]["anchoring_requested"] is False
    assert event["payload"]["externally_anchored"] is False


def test_unreachable_tsa_is_recorded_as_asked_and_not_obtained(tmp_path, monkeypatch):
    """The gap this closes. The release must still succeed -- never block
    on a third party -- and the operator's own log must now say the
    timestamp they believe they are getting was not obtained.

    `anchoring_requested` is what separates this from the zero-egress case
    above: one is an outage worth noticing across many releases, the other
    is a deployment choice."""
    # Port 9 (discard) refuses immediately rather than hanging the suite.
    c = _client(tmp_path, monkeypatch, "http://127.0.0.1:9/tsa")
    mid, rid, jid = _release(c)

    response = c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle")
    assert response.status_code == 200, "a TSA outage must not fail the release"

    last = c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"]
    assert last["type"] == "ed25519-operator"
    assert last["externally_anchored"] is False

    (event,) = _anchored_events(c, mid)
    assert event["payload"]["anchoring_requested"] is True
    assert event["payload"]["externally_anchored"] is False


def test_successful_tsa_records_an_external_anchor(tmp_path, monkeypatch):
    """The positive path, against the captured real DigiCert reply so the
    token is genuinely parsed rather than mocked at the boundary."""
    from test_tsa_anchor_client import MockTSA

    srv = MockTSA({"body": (FIXTURES / "rfc3161_reply_full_a.der").read_bytes()})
    try:
        c = _client(tmp_path, monkeypatch, srv.url)
        mid, rid, jid = _release(c)
        response = c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle")
        assert response.status_code == 200

        last = c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"]
        assert last["type"] == "rfc3161-tsa"
        assert last["externally_anchored"] is True
        assert last["digest"], "the digest ties this row to a specific packet"

        (event,) = _anchored_events(c, mid)
        assert event["payload"]["anchoring_requested"] is True
        assert event["payload"]["externally_anchored"] is True
    finally:
        srv.close()


def test_the_record_agrees_with_the_packet_the_recipient_holds(tmp_path, monkeypatch):
    """A record that disagreed with the artifact would be worse than no
    record: the operator would be reassured by a row while the recipient
    holds something else."""
    c = _client(tmp_path, monkeypatch, "off")
    mid, rid, jid = _release(c)
    response = c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle")
    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        packet = json.loads(zf.read("release_packet.json"))

    last = c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"]
    assert packet["anchor"]["type"] == last["type"]
    assert packet["anchor"].get("digest") == last["digest"]


def test_anchoring_is_per_download_not_per_release(tmp_path, monkeypatch):
    """The design point behind the `last_` prefix. Each download is its own
    audited custody event, so the packet's audit_refs advance and its
    signature changes; the TSA token attests to THOSE bytes. One event per
    download, each citing the download it belongs to."""
    c = _client(tmp_path, monkeypatch, "off")
    mid, _rid, jid = _release(c)
    c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle")
    c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle")

    events = _anchored_events(c, mid)
    assert len(events) == 2
    seqs = {e["payload"]["bundle_download_seq"] for e in events}
    assert len(seqs) == 2, "each observation must cite its own download"


def test_legacy_job_without_a_release_still_downloads_and_records(tmp_path, monkeypatch):
    """A bundle pulled from the unwrapped /sanitize-jobs route has no
    Release row to denormalize onto. The audit event is still written --
    the chain is the durable record; the columns are only a read-scoped
    convenience."""
    c = _client(tmp_path, monkeypatch, "off")
    mid = c.post("/v1/matters", json={"name": "legacy"}).json()["id"]
    blob = _docx({"word/document.xml": _document("<w:p><w:r><w:t>B.</w:t></w:r></w:p>")})
    doc = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("a.docx", blob, "application/octet-stream")},
    ).json()["id"]
    job = c.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert job["status"] == "done", job

    assert c.get(f"/v1/matters/{mid}/jobs/{job['id']}/bundle").status_code == 200
    assert len(_anchored_events(c, mid)) == 1


def test_anchored_event_does_not_amend_the_download_event(tmp_path, monkeypatch):
    """It has to be a separate event: bundle.download is written BEFORE the
    packet is assembled, because release_packet.json cites its seq, and the
    log is hash-chained -- amending a committed row is not available, and
    would not be honest if it were."""
    c = _client(tmp_path, monkeypatch, "off")
    mid, _rid, jid = _release(c)
    c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle")

    events = c.get(f"/v1/matters/{mid}/audit").json()["events"]
    download = [e for e in events if e["action"] == "bundle.download"]
    anchored = [e for e in events if e["action"] == "bundle.anchored"]
    assert len(download) == 1 and len(anchored) == 1
    assert "anchor_type" not in download[0]["payload"]
    assert anchored[0]["seq"] > download[0]["seq"]
    # And the chain still verifies with the extra event in it.
    assert c.get(f"/v1/matters/{mid}/audit").json()["chain_ok"] is True


def test_concurrent_anchor_write_race_guarded_by_cas(tmp_path, monkeypatch):
    """Regression test for F3.2 (lossy anchor write race):
    Concurrent bundle downloads with distinct TSA anchor tokens must not
    arbitrarily clobber the Release row with a stale/concurrent write, and
    both observations must be immutably recorded in the bundle.anchored audit chain."""
    import itertools
    import threading

    import app.main as main_mod
    from app import tsa as tsa_mod

    counter = itertools.count(1)

    def fake_anchor(sig_bytes):
        n = next(counter)
        return {"type": "rfc3161-tsa", "digest": f"{n:064x}", "reference": "tsa://test"}

    monkeypatch.setattr(main_mod, "request_anchor", fake_anchor)
    monkeypatch.setattr(main_mod, "anchor_enabled", lambda: True)
    monkeypatch.setattr(tsa_mod, "request_anchor", fake_anchor)

    c = _client(tmp_path, monkeypatch, "off")
    mid, rid, jid = _release(c)

    results = {}
    barrier = threading.Barrier(2, timeout=15)
    orig_get = c.get

    def hit(tag):
        barrier.wait()
        r = orig_get(f"/v1/matters/{mid}/jobs/{jid}/bundle")
        z = zipfile.ZipFile(io.BytesIO(r.content))
        packet = json.loads(z.read("release_packet.json"))
        results[tag] = (packet.get("anchor") or {}).get("digest")

    t1 = threading.Thread(target=lambda: hit("A"))
    t2 = threading.Thread(target=lambda: hit("B"))
    t1.start()
    t2.start()
    t1.join(30)
    t2.join(30)

    # Both downloads succeeded and acquired distinct anchor digests
    assert results.get("A") and results.get("B")
    assert results["A"] != results["B"]

    # Both observations are immutably captured in the audit log
    anchored_events = list(_anchored_events(c, mid))
    assert len(anchored_events) == 2
    event_digests = {e["payload"]["anchor_digest"] for e in anchored_events}
    assert results["A"] in event_digests
    assert results["B"] in event_digests

    # The Release row holds a valid anchor from one of the downloads
    last = c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"]
    assert last["type"] == "rfc3161-tsa"
    assert last["digest"] in (results["A"], results["B"])
    assert last["externally_anchored"] is True


def test_anchor_cas_prevents_stale_overwrite(tmp_path, monkeypatch):
    """Proves CAS specifically refuses to overwrite with an older or identical timestamp."""
    from app.db import make_session_factory
    from app.models import Release
    from sqlalchemy import or_, update

    c = _client(tmp_path, monkeypatch, "off")
    mid, rid, jid = _release(c)
    # First download sets last_anchor_at
    c.get(f"/v1/matters/{mid}/jobs/{jid}/bundle")
    first_last = c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"]
    first_digest = first_last["digest"]
    first_at = first_last["at"]

    cfg = Config(tmp_path / "data")
    engine = make_engine(cfg)
    sf = make_session_factory(engine)
    with sf() as s:
        stmt = (
            update(Release)
            .where(
                Release.id == rid,
                or_(
                    Release.last_anchor_at.is_(None),
                    Release.last_anchor_at < first_at,  # Same timestamp should be rejected
                ),
            )
            .values(
                last_anchor_type="rfc3161-tsa",
                last_anchor_at=first_at,
                last_anchor_digest="stale_digest_should_not_overwrite",
            )
        )
        res = s.execute(stmt)
        s.commit()
        assert res.rowcount == 0, "CAS must not update row with equal or older timestamp"

    # Row still retains first_digest
    re_read = c.get(f"/v1/matters/{mid}/releases/{rid}").json()["last_anchor"]
    assert re_read["digest"] == first_digest
