"""Published custody key + fingerprint pinning (Lane E1, Phase 1).

Every packet's README used to say, honestly and without mitigation, that
"a lost public key makes every packet issued under it unverifiable". The
evidentiary durability of every packet a deployment had ever issued rested
on an operator not losing a 32-byte file.

Phase 1 publishes the public key inside the packet, which fixes
AVAILABILITY -- the maths can always be checked -- and deliberately does
nothing for AUTHENTICITY, because an adversary who can alter a packet can
also replace the embedded key and re-sign. Every internal check then
passes.

That circularity is the whole risk of this feature, and these tests exist
to keep it visible: a signature checked against a key the packet supplied
about itself must NEVER be reported with the same word as one checked
against a key the recipient obtained out of band. Getting that wrong would
put a green VERIFIED over a self-consistent forgery, which is the exact
failure this product exists to refuse.

See docs/counselclear-key-durability-proposal.md §1a and §3.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "service" / "scripts"), str(REPO / "service"), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import counselclear_verify_release_packet as verifier
from app.config import Config
from app.db import make_engine
from app.main import create_app
from app.migrate import upgrade_head
from test_custody_truthfulness import _document, _docx

PW = "pw12345"


@pytest.fixture()
def packet(tmp_path, monkeypatch):
    """A real release packet, extracted, plus its parsed release_packet.json."""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PW)
    monkeypatch.setenv("COUNSELCLEAR_TSA_URL", "off")
    cfg = Config(tmp_path / "data")
    make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    c = TestClient(create_app(cfg.data_root))
    assert c.post("/v1/auth/login", json={"password": PW}).status_code == 200
    mid = c.post("/v1/matters", json={"name": "keys"}).json()["id"]
    blob = _docx({"word/document.xml": _document("<w:p><w:r><w:t>Body.</w:t></w:r></w:p>")})
    doc = c.post(
        f"/v1/matters/{mid}/documents",
        files={"file": ("a.docx", blob, "application/octet-stream")},
    ).json()["id"]
    job = c.post(
        f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    assert job["status"] == "done", job
    raw = c.get(f"/v1/matters/{mid}/jobs/{job['id']}/bundle").content
    out = tmp_path / "packet"
    out.mkdir()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(out)
    return out, json.loads((out / "release_packet.json").read_text(encoding="utf-8"))


def _fingerprint(pkt) -> str:
    return hashlib.sha256(bytes.fromhex(pkt["signature"]["public_key"])).hexdigest()


def test_packet_publishes_a_key_that_matches_its_own_key_id(packet):
    _dir, pkt = packet
    sig = pkt["signature"]
    assert len(sig["public_key"]) == 64
    # key_id is sha256(public)[:16] -- a packet whose published key does not
    # produce its own key_id is internally inconsistent about its own key.
    assert hashlib.sha256(bytes.fromhex(sig["public_key"])).hexdigest()[:16] == sig["key_id"]


def test_packet_still_validates_against_its_published_schema(packet):
    import jsonschema

    _dir, pkt = packet
    schema = json.loads(
        (REPO / "service" / "scripts" / "schemas" / "release_packet.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(pkt, schema)


def test_anchor_excluding_signed_fields_is_schema_legal():
    """Regression for a defect found while adding public_key: signed_fields
    was a `const` naming only the anchor-inclusive marker, so every
    SUCCESSFULLY TSA-anchored packet failed its own published schema. It
    stayed latent because a packet only takes that path when the TSA
    actually answers, which it usually does not in tests."""
    import jsonschema
    from app.security import (
        PACKET_SIGNATURE_SIGNED_FIELDS,
        PACKET_SIGNATURE_SIGNED_FIELDS_EXCLUDING_ANCHOR,
    )

    schema = json.loads(
        (REPO / "service" / "scripts" / "schemas" / "release_packet.schema.json").read_text(
            encoding="utf-8"
        )
    )
    allowed = schema["properties"]["signature"]["properties"]["signed_fields"]["enum"]
    assert PACKET_SIGNATURE_SIGNED_FIELDS in allowed
    assert PACKET_SIGNATURE_SIGNED_FIELDS_EXCLUDING_ANCHOR in allowed
    jsonschema.Draft202012Validator.check_schema(schema)


def test_self_published_key_is_never_reported_as_verified(packet):
    """The central invariant. A recipient with no key file can check the
    maths, and must be told plainly that this says nothing about whose key
    it is."""
    _dir, pkt = packet
    status, detail = verifier.check_packet_signature(pkt, {})
    assert status == "self_key", (status, detail)
    assert "does NOT confirm whose key" in detail
    marker = verifier._SIGNATURE_MARKERS["self_key"]
    assert marker != "VERIFIED"
    assert "SELF-PUBLISHED" in marker


def test_a_self_consistent_forgery_cannot_reach_verified(packet):
    """The attack the published key invites: alter the content, swap in
    your own key, re-sign. Every internal check passes -- which is exactly
    why the status must not be the same word."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _dir, pkt = packet
    honest_fingerprint = _fingerprint(pkt)

    attacker = Ed25519PrivateKey.generate()
    attacker_pub = attacker.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    forged = json.loads(json.dumps(pkt))
    forged["purpose"] = "TAMPERED"
    canonical = verifier._packet_canonical_bytes(forged)
    forged["signature"] = {
        "algorithm": "ed25519",
        "key_id": hashlib.sha256(attacker_pub).hexdigest()[:16],
        "signed_fields": "release_packet.v1.canonical",
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "value": attacker.sign(canonical).hex(),
        "public_key": attacker_pub.hex(),
    }

    status, _detail = verifier.check_packet_signature(forged, {})
    assert status == "self_key", "a forgery must never reach 'verified'"
    # And the honest deployment's pin does not vouch for it.
    status, _detail = verifier.check_packet_signature(
        forged, {}, pinned_fingerprints={honest_fingerprint}
    )
    assert status == "self_key"


def test_published_key_that_lies_about_its_key_id_is_ignored(packet):
    """A packet whose public_key does not produce its declared key_id is
    incoherent about its own signature. It falls back to "no key", never to
    silently trusting the supplied bytes."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _dir, pkt = packet
    other = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    )
    lying = json.loads(json.dumps(pkt))
    lying["signature"]["public_key"] = other.hex()
    status, _detail = verifier.check_packet_signature(lying, {})
    assert status == "no_key"


def test_pinned_fingerprint_promotes_to_verified(packet):
    """The pin is the recipient's own act, recorded in their own records --
    which is precisely why it can carry weight a packet's self-description
    cannot."""
    _dir, pkt = packet
    status, detail = verifier.check_packet_signature(
        pkt, {}, pinned_fingerprints={_fingerprint(pkt)}
    )
    assert status == "verified"
    assert "you pinned" in detail


def test_wrong_pin_does_not_promote(packet):
    _dir, pkt = packet
    status, _detail = verifier.check_packet_signature(pkt, {}, pinned_fingerprints={"a" * 64})
    assert status == "self_key"


def test_operator_supplied_key_takes_precedence_and_reports_plainly(packet):
    _dir, pkt = packet
    sig = pkt["signature"]
    status, detail = verifier.check_packet_signature(
        pkt, {sig["key_id"]: bytes.fromhex(sig["public_key"])}
    )
    assert status == "verified"
    # The fingerprint is printed so a recipient can record it for next time.
    assert _fingerprint(pkt) in detail


def test_strict_mode_rejects_a_self_published_key(packet):
    """--verify-signature exists to demand real assurance. A key the packet
    supplied about itself is not that, so strict mode must fail on it and
    pass only once the fingerprint is pinned."""
    path, pkt = packet
    assert verifier.main([str(path), "--verify-signature"]) == 1
    assert (
        verifier.main([str(path), "--verify-signature", "--key-fingerprint", _fingerprint(pkt)])
        == 0
    )


def test_malformed_fingerprint_is_an_argument_error(packet):
    path, _pkt = packet
    assert verifier.main([str(path), "--key-fingerprint", "nothex"]) == 2
    assert verifier.main([str(path), "--key-fingerprint", "abc"]) == 2
