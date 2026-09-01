"""RFC 3161 TSA anchor verification (docs/rfc3161-anchor-implementation-proposal.md §5).

Tests the hand-rolled, stdlib-only DER/CMS parser + RSA-PKCS1v15
verification added to tools/counselclear_verify_release_packet.py.

Three hard conditions from the proposal, each with a NAMED test:

- Condition A: pin the TSA's signing certificate bytes directly in the
  verifier -- no chain validation, no validity-window checks, no EKU
  parsing. A token whose signing cert does not match the pin reports
  its own distinct finding ("unrecognized TSA certificate"), never
  conflated with a signature failure and never silently passed.
  -> test_unpinned_signing_cert_reports_unrecognized_tsa_certificate

- Condition B: strict, fail-closed DER. Any non-canonical encoding
  (long-form length where short-form suffices, BER indefinite-length,
  anything outside the exact expected shape) yields "cannot verify
  anchor", never a lenient best-effort parse.
  -> test_noncanonical_der_variants_cannot_verify_anchor

- Condition C: differential fuzz testing -- the real captured DigiCert
  token (tests/fixtures/rfc3161_token_a.der) is mutated byte-wise across
  thousands of variations and the hand-rolled parser/verifier must agree
  with the asn1crypto+cryptography oracle on accept/reject for every one.
  -> test_differential_fuzz_agrees_with_library_oracle

The trap the proposal calls the most likely silent-accept forgery gets
its own named test: a token whose CMS signature covers the TSTInfo
eContent directly instead of the DER-re-tagged signedAttrs (0x31) must
be REJECTED -- and the test proves the same signature WOULD fool a naive
verifier, so the rejection is the parser's doing, not the fixture's.
-> test_signedattrs_forgery_tstinfo_direct_signature_rejected

Fixtures:
- tests/fixtures/rfc3161_token_a.der / rfc3161_sig_a.bin: a real
  TimeStampToken captured against the default TSA (timestamp.digicert.com)
  plus the exact Ed25519 signature bytes it timestamps; token_b/sig_b is
  a second capture. rfc3161_signing_cert.der is the token's signing
  certificate -- the verifier's embedded pin must equal these bytes
  (test_embedded_pinned_cert_matches_checked_in_fixture).
- Test-built tokens (own RSA key + self-signed certificate, built with
  asn1crypto/cryptography -- TEST-ONLY dependencies, the same
  test-only-oracle pattern as the Ed25519 cross-check) cover the cases a
  real third-party token can never be produced for on demand: an
  unrecognized signing certificate, a signature computed over TSTInfo
  directly, a non-SHA-256 messageImprint, the subjectKeyIdentifier form
  of SignerIdentifier, and non-canonical DER encodings.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
FIXTURES = REPO / "tests" / "fixtures"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import counselclear_verify_release_packet as verifier

REAL_TOKEN_A = (FIXTURES / "rfc3161_token_a.der").read_bytes()
REAL_SIG_A = (FIXTURES / "rfc3161_sig_a.bin").read_bytes()
REAL_TOKEN_B = (FIXTURES / "rfc3161_token_b.der").read_bytes()
REAL_SIG_B = (FIXTURES / "rfc3161_sig_b.bin").read_bytes()
PIN_CERT = (FIXTURES / "rfc3161_signing_cert.der").read_bytes()
DIGEST_A = hashlib.sha256(REAL_SIG_A).digest()
DIGEST_B = hashlib.sha256(REAL_SIG_B).digest()

REAL_GENTIME = "2026-09-01T03:35:57+00:00"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- test-built token factory (asn1crypto + cryptography, TEST-ONLY) ----------


def _test_key_and_cert(cn: str = "Test TSA Responder"):
    """A fresh RSA keypair + self-signed certificate (with a
    subjectKeyIdentifier extension, so both SignerIdentifier forms can be
    exercised). Built with cryptography -- test-only dependencies -- so it
    is guaranteed well-formed DER for the hand-rolled parser to read."""
    from datetime import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234567890ABCDEF)
        .not_valid_before(datetime(2026, 1, 1))
        .not_valid_after(datetime(2027, 1, 1))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return key, cert.public_bytes(serialization.Encoding.DER), pem


def _cert_ski(cert_der: bytes) -> bytes:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(cert_der)
    return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest


def build_test_token(
    *,
    digest: bytes,
    key,
    cert_der: bytes,
    sid_form: str = "iasn",
    sign_over_tstinfo: bool = False,
    imprint_alg: str = "sha256",
):
    """Build a well-formed RFC 3161 TimeStampToken (ContentInfo) signed by
    `key` with `cert_der` embedded. asn1crypto construction is canonical
    DER by construction, so a token that fails verification does so
    because of the verifier, not the fixture.

    sign_over_tstinfo=True reproduces the classic CMS forgery the proposal
    warns about: the RSA signature is computed over the TSTInfo eContent
    bytes directly instead of the DER-re-tagged signedAttrs (tag 0x31)
    that CMS requires -- exactly what a naive verifier would check, and
    exactly what this parser must not accept.
    """
    from asn1crypto import cms, core, tsp
    from asn1crypto import x509 as asn1x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    tstinfo = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "2.16.840.1.114412.7.1",
            "message_imprint": tsp.MessageImprint(
                {"hash_algorithm": {"algorithm": imprint_alg}, "hashed_message": digest}
            ),
            "serial_number": 0x0C2F0DD4B7DD2A900C33F5358AD9A5488,
            "gen_time": core.GeneralizedTime("20260901033557Z"),
        }
    )
    econtent = tstinfo.dump()

    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {"type": "content_type", "values": ["1.2.840.113549.1.9.16.1.4"]}
            ),
            cms.CMSAttribute(
                {"type": "message_digest", "values": [core.OctetString(hashlib.sha256(econtent).digest())]}
            ),
        ]
    )
    signed_bytes = econtent if sign_over_tstinfo else signed_attrs.untag().dump()  # the forgery: signature over content, not attrs
    signature = key.sign(signed_bytes, padding.PKCS1v15(), hashes.SHA256())

    cert = asn1x509.Certificate.load(cert_der)
    if sid_form == "ski":
        sid = cms.SignerIdentifier({"subject_key_identifier": _cert_ski(cert_der)})
        si_version = "v3"
    else:
        sid = cms.SignerIdentifier(
            {
                "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                    {
                        "issuer": cert["tbs_certificate"]["issuer"],
                        "serial_number": cert["tbs_certificate"]["serial_number"],
                    }
                )
            }
        )
        si_version = "v1"

    signer_info = cms.SignerInfo(
        {
            "version": si_version,
            "sid": sid,
            "digest_algorithm": {"algorithm": "sha256", "parameters": core.Null()},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "1.2.840.113549.1.1.1", "parameters": core.Null()},
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": cms.EncapsulatedContentInfo(
                {"content_type": "1.2.840.113549.1.9.16.1.4", "content": cms.ParsableOctetString(econtent)}
            ),
            "certificates": [cert],
            "signer_infos": [signer_info],
        }
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()


def _surgical(tok: bytes, target: bytes, replacement: bytes) -> bytes:
    """Replace the first occurrence of the exact TLV `target` with
    `replacement`, re-encoding every enclosing TLV's length so the result
    stays structurally coherent DER. Used to build tokens that deviate
    from canonical DER in exactly one chosen way (condition B)."""
    idx = tok.find(target)
    assert idx != -1, "target TLV not found"

    def tlv(buf, off):
        tag = buf[off]
        l0 = buf[off + 1]
        if l0 < 0x80:
            return tag, 2, l0
        n = l0 & 0x7F
        return tag, 2 + n, int.from_bytes(buf[off + 2 : off + 2 + n], "big")

    def enc(tag, payload):
        n = len(payload)
        if n < 0x80:
            return bytes((tag, n)) + payload
        nb = (n.bit_length() + 7) // 8
        return bytes((tag, 0x80 | nb)) + n.to_bytes(nb, "big") + payload

    def rebuild(buf, off, end):
        tag, hdr, length = tlv(buf, off)
        val_start, val_end = off + hdr, off + hdr + length
        if off == idx:
            return replacement
        if not (off < idx < val_end):
            return buf[off:val_end]
        # The edit is inside this TLV's value -- which may be a primitive
        # whose value itself wraps a DER structure (the eContent OCTET
        # STRING wraps the TSTInfo TLV), so re-walk it as a TLV list.
        inner = bytearray()
        pos = val_start
        while pos < val_end:
            inner += rebuild(buf, pos, val_end)
            _, chdr, clen = tlv(buf, pos)
            pos += chdr + clen
        assert pos == val_end
        return enc(tag, bytes(inner))

    return rebuild(tok, 0, len(tok))


def _ber_indefinite(tok: bytes) -> bytes:
    """Re-encode the top-level SEQUENCE with a BER indefinite length."""
    l0 = tok[1]
    hdr = 2 if l0 < 0x80 else 2 + (l0 & 0x7F)
    return tok[:1] + b"\x80" + tok[hdr:] + b"\x00\x00"


# --- oracle: asn1crypto + cryptography full pipeline (test-only) --------------

# asn1crypto is deliberately BER-lenient: probes show it ACCEPTS long-form
# lengths where short-form suffices, non-minimal INTEGER/OID encodings,
# BOOLEAN TRUE as 0x01 and lowercase-'z' times, while strict mode still
# rejects indefinite lengths, trailing bytes, invalid calendar times and
# invalid string charsets. Condition B therefore needs a strict-DER policy
# layer on top of the library parse; _oracle_strict_policy_ok() is that
# layer, an independent implementation of the same canonical-DER rules the
# verifier's walker enforces. The differential then proves the hand-rolled
# implementation accepts/rejects exactly what the library stack does under
# the same policy.

_PRINTABLE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")


def _oracle_time_ok(y, m, d, hh, mm, ss) -> bool:
    try:
        from datetime import datetime

        datetime(y, m, d, hh, mm, ss)
        return True
    except ValueError:
        return False


def _oracle_oid_ok(v: bytes) -> bool:
    if not v:
        return False
    arcs, cur, count = [], 0, 0
    byte_counts = []
    for b in v:
        cur = (cur << 7) | (b & 0x7F)
        count += 1
        if not (b & 0x80):
            arcs.append(cur)
            byte_counts.append(count)
            cur, count = 0, 0
    if count != 0 or len(arcs) < 2:
        return False
    return all(
        not (bc > 1 and arc < 1 << (7 * (bc - 1))) for arc, bc in zip(arcs, byte_counts, strict=True)
    )


def _oracle_strict_policy_ok(data: bytes) -> bool:
    """Canonical-DER policy layer (condition B): minimal length encodings,
    no indefinite/reserved lengths, exact consumption, canonical BOOLEAN,
    minimal INTEGERs, minimal OIDs, canonical+valid times, BIT STRING
    unused-bits <= 7, charset-valid strings. SET-OF ordering is NOT
    enforced: the real DigiCert token's certificates appear in descending
    order (asn1crypto accepts it), so enforcing X.690 sorting would reject
    the genuine fixture."""

    def walk(buf, lo, hi) -> bool:
        i = lo
        while i < hi:
            if i + 1 >= len(buf):
                return False
            tag = buf[i]
            if tag & 0x1F == 0x1F:
                return False  # high-tag-number form not expected
            l0 = buf[i + 1]
            if l0 in (0x80, 0xFF):
                return False  # indefinite / reserved
            if l0 < 0x80:
                ln, hdr = l0, 2
            else:
                n = l0 & 0x7F
                if n == 0 or n > 4 or i + 2 + n > len(buf):
                    return False
                ln = int.from_bytes(buf[i + 2 : i + 2 + n], "big")
                if ln < 0x80 or (n > 1 and ln < 1 << (8 * (n - 1))):
                    return False  # non-minimal length encoding
                hdr = 2 + n
            end = i + hdr + ln
            if end > len(buf) or end > hi:
                return False
            val = buf[i + hdr : end]
            if tag == 0x01:  # BOOLEAN: DER allows exactly 00 and FF
                if val not in (b"\x00", b"\xff"):
                    return False
            elif tag == 0x02:  # INTEGER: minimal two's-complement
                if not val:
                    return False
                if len(val) > 1:
                    if val[0] == 0x00 and not (val[1] & 0x80):
                        return False
                    if val[0] == 0xFF and (val[1] & 0x80):
                        return False
            elif tag == 0x05:  # NULL must be empty
                if val:
                    return False
            elif tag == 0x06:  # OID
                if not _oracle_oid_ok(val):
                    return False
            elif tag == 0x03:  # BIT STRING
                if not val or val[0] > 7:
                    return False
            elif tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
                if len(val) != 13 or not val[:12].isdigit() or val[12:13] != b"Z":
                    return False
                yy = 2000 + int(val[0:2]) if int(val[0:2]) < 50 else 1900 + int(val[0:2])
                if not _oracle_time_ok(yy, *[int(val[i : i + 2]) for i in (2, 4, 6, 8, 10)]):
                    return False
            elif tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
                if len(val) != 15 or not val[:14].isdigit() or val[14:15] != b"Z":
                    return False
                if not _oracle_time_ok(*[int(val[i : i + 2]) for i in (0, 4, 6, 8, 10, 12)]):
                    return False
            elif tag == 0x0C:  # UTF8String
                try:
                    val.decode("utf-8")
                except UnicodeDecodeError:
                    return False
            elif tag == 0x13:  # PrintableString
                if not all(chr(b) in _PRINTABLE for b in val):
                    return False
            elif tag == 0x16:  # IA5String
                if any(b > 0x7F for b in val):
                    return False
            elif tag == 0x1E:  # BMPString
                if len(val) % 2:
                    return False
                try:
                    val.decode("utf-16-be")
                except UnicodeDecodeError:
                    return False
            if tag & 0x20 and not walk(buf, i + hdr, end):
                return False
            i = end
        return True

    return walk(data, 0, len(data))


def _oracle_accepts(token: bytes, expected_digest: bytes, pinned_certs: list[bytes]) -> bool:
    """The library-stack oracle for condition C: asn1crypto parses the
    token strictly, the strict-DER policy layer passes, the RSA-PKCS1v15
    signature verifies under the sid-resolved signer certificate via
    cryptography, and the RFC 3161 bindings (contentType attribute,
    messageDigest attribute == sha256(eContent), SHA-256 messageImprint ==
    expected digest, pinned signer certificate) all hold."""
    try:
        from asn1crypto import cms, tsp
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        if not _oracle_strict_policy_ok(token):
            return False
        ci = cms.ContentInfo.load(token, strict=True)
        if ci["content_type"].native != "signed_data":
            return False
        sd = ci["content"]
        if sd["version"].native != "v3":
            return False
        # Schema-shape canonicality: asn1crypto tolerates tag mutations
        # (a SET parsed as a SEQUENCE, a certificate parsed under a
        # different CHOICE), so every subtree this verifier semantically
        # constrains must also re-encode byte-identically -- the cached
        # encoding (dump()) vs a fresh re-encode (dump(force=True)).
        # Per-subtree only: the whole-token force re-encode re-sorts the
        # certificates SET, which the real token legitimately violates,
        # and cert interiors are only ENCODING-checked, not shape-checked
        # (no per-cert force-dump -- the verifier walks their TLVs
        # canonically but interprets only the fields it consumes).
        for field in (sd["digest_algorithms"], sd["encap_content_info"], sd["signer_infos"]):
            if field.dump() != field.dump(force=True):
                return False
        for choice in sd["certificates"]:
            if choice.name != "certificate":
                return False
        eci = sd["encap_content_info"]
        if eci["content_type"].native != "tst_info":
            return False
        econtent = eci["content"].contents  # raw octets, NOT .native (parsed structure)
        if not isinstance(econtent, bytes):
            return False
        if len(sd["signer_infos"]) != 1:
            return False
        si = sd["signer_infos"][0]
        if si["digest_algorithm"]["algorithm"].native != "sha256":
            return False
        dp = si["digest_algorithm"]["parameters"]
        if dp is not None and dp.native is not None:
            return False
        if si["signature_algorithm"]["algorithm"].native != "rsassa_pkcs1v15":
            return False
        sp = si["signature_algorithm"]["parameters"]
        if sp is not None and sp.native is not None:
            return False
        sid_name = si["sid"].name
        if sid_name not in ("issuer_and_serial_number", "subject_key_identifier"):
            return False
        if sid_name == "issuer_and_serial_number" and si["version"].native != "v1":
            return False
        if sid_name == "subject_key_identifier" and si["version"].native != "v3":
            return False
        attrs = si["signed_attrs"]
        if attrs is None:
            return False
        if si.dump() != si.dump(force=True) or attrs.dump() != attrs.dump(force=True):
            return False
        ct_attr = [a for a in attrs if a["type"].dotted == "1.2.840.113549.1.9.3"]
        md_attr = [a for a in attrs if a["type"].dotted == "1.2.840.113549.1.9.4"]
        if len(ct_attr) != 1 or len(md_attr) != 1:
            return False
        if ct_attr[0]["values"][0].native != "tst_info":
            return False
        if md_attr[0]["values"][0].native != hashlib.sha256(econtent).digest():
            return False
        # sid -> signer cert resolution (issuer+serial or SKI extension)
        signer_cert = None
        if sid_name == "issuer_and_serial_number":
            sid = si["sid"].chosen
            for choice in sd["certificates"]:
                c = choice.chosen
                if (
                    c["tbs_certificate"]["issuer"].dump() == sid["issuer"].dump()
                    and c["tbs_certificate"]["serial_number"].native == sid["serial_number"].native
                ):
                    signer_cert = c
                    break
        else:
            ski = si["sid"].chosen.native
            for choice in sd["certificates"]:
                c = choice.chosen
                for ext in c["tbs_certificate"]["extensions"]:
                    if ext["extn_id"].dotted == "2.5.29.14" and ext["extn_value"].parsed.native == ski:
                        signer_cert = c
                        break
                if signer_cert is not None:
                    break
        if signer_cert is None:
            return False
        if signer_cert.dump() not in pinned_certs:
            return False
        spki = signer_cert["tbs_certificate"]["subject_public_key_info"]
        pub = rsa.RSAPublicNumbers(
            spki["public_key"].parsed["public_exponent"].native,
            spki["public_key"].parsed["modulus"].native,
        ).public_key()
        try:
            pub.verify(si["signature"].native, attrs.untag().dump(), padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return False
        tst = tsp.TSTInfo.load(econtent, strict=True)
        if tst.dump() != tst.dump(force=True):
            return False
        if tst["version"].native != "v1":
            return False
        if tst["message_imprint"]["hash_algorithm"]["algorithm"].native != "sha256":
            return False
        return tst["message_imprint"]["hashed_message"].native == expected_digest
    except Exception:
        return False


# --- release-packet builder ----------------------------------------------------


def _packet_files(*, signature: dict, anchor: dict) -> dict[str, bytes]:
    """A release_packet.json carrying `signature` and `anchor` verbatim
    plus the sibling files, built so every hash check verifies."""
    action_records = [
        {
            "subtype": "comments_and_notes",
            "action": "keep",
            "detail": "kept: reviewed and kept by operator",
            "legal_justification": {"basis": "privilege", "note": "Attorney-client comments withheld."},
        }
    ]
    manifest_json = json.dumps(
        {
            "policy": {"id": "external_sharing", "version": 1},
            "derivative": {"sha256": _sha256(b"fake derivative bytes"), "filename": "out.docx"},
            "action_records": action_records,
        },
        sort_keys=True,
    ).encode()
    report_json = json.dumps(
        {
            "report_version": 1,
            "verification": {"pass": True, "checks": []},
            "findings_before": [],
            "action_records": action_records,
        },
        sort_keys=True,
    ).encode()
    cert_html = b"<!doctype html><html><body>certificate</body></html>"
    readme_txt = b"CounselClear release packet\n"

    packet = {
        "spec_version": "1.0",
        "packet_id": "JOB1",
        "release_id": "REL1",
        "matter_id": "MAT1",
        "document_id": "DOC1",
        "job_id": "JOB1",
        "original_sha256": "0" * 64,
        "kind": "sanitize",
        "status": "done",
        "policy": {"id": "external_sharing", "version": 1, "digest": None},
        "hashes": {
            "derivative": {"filename": "out.docx", "sha256": _sha256(b"fake derivative bytes")},
            "manifest_json_sha256": _sha256(manifest_json),
            "report_json_sha256": _sha256(report_json),
            "certificate_html_sha256": _sha256(cert_html),
            "readme_txt_sha256": _sha256(readme_txt),
        },
        "audit_refs": {"bundle_download_seq": 1, "certificate_issued_seq": 2},
        "legal_justifications": action_records,
        "limitations": [],
        "generated_at": "2026-08-27T00:00:00+00:00",
        "generated_by": "operator",
        "anchor": anchor,
        "signature": signature,
    }
    return {
        "manifest.json": manifest_json,
        "report.json": report_json,
        "certificate.html": cert_html,
        "README.txt": readme_txt,
        "derivative/out.docx": b"fake derivative bytes",
        "release_packet.json": json.dumps(packet, indent=2, sort_keys=True).encode(),
    }


def _write_dir(tmp_path: Path, files: dict[str, bytes], name: str = "packet") -> Path:
    out = tmp_path / name
    for arcname, data in files.items():
        p = out / arcname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return out


def _real_signature_block(value: bytes) -> dict:
    return {
        "algorithm": "ed25519",
        "key_id": "a" * 16,
        "signed_fields": verifier._SIGNED_FIELDS_CANONICAL,
        "digest": "sha256:" + _sha256(value),
        "value": value.hex(),
    }


def _real_anchor(token_der: bytes, digest: bytes) -> dict:
    return {
        "type": "rfc3161-tsa",
        "digest": digest.hex(),
        "reference": base64.b64encode(token_der).decode("ascii"),
    }


# --- Condition A / B / C named tests -------------------------------------------


def test_embedded_pinned_cert_matches_checked_in_fixture():
    """The pin shipped inside the verifier must be exactly the bytes of
    the signing certificate captured from the real token -- drift here
    would silently make every real token 'unrecognized'."""
    assert bytes.fromhex(verifier._PINNED_TSA_SIGNING_CERT_DER_HEX) == PIN_CERT


def test_real_token_all_correct_verifies_clean(tmp_path):
    """The all-correct fixture: real DigiCert token + the exact signature
    bytes it timestamps. The token verifies standalone and end-to-end in
    a full packet, and the report says everything it should say."""
    check = verifier.verify_tsa_anchor(REAL_TOKEN_A, DIGEST_A, [PIN_CERT])
    assert check.status == "verified", check.detail
    assert check.gen_time == REAL_GENTIME

    files = _packet_files(
        signature=_real_signature_block(REAL_SIG_A), anchor=_real_anchor(REAL_TOKEN_A, DIGEST_A)
    )
    report = verifier.verify_release_packet(_write_dir(tmp_path, files))
    assert report.valid, report.to_text()
    assert report.anchor is not None and report.anchor.status == "verified"
    text = report.to_text()
    assert "Externally anchored: yes (rfc3161-tsa)" in text
    assert REAL_GENTIME in text
    assert "RFC 3161 TSA anchor" in text
    assert "unrecognized TSA certificate" not in text.lower()


def test_real_second_capture_also_verifies(tmp_path):
    check = verifier.verify_tsa_anchor(REAL_TOKEN_B, DIGEST_B, [PIN_CERT])
    assert check.status == "verified", check.detail
    assert check.gen_time == REAL_GENTIME

    files = _packet_files(
        signature=_real_signature_block(REAL_SIG_B), anchor=_real_anchor(REAL_TOKEN_B, DIGEST_B)
    )
    report = verifier.verify_release_packet(_write_dir(tmp_path, files))
    assert report.valid, report.to_text()
    assert report.anchor is not None and report.anchor.status == "verified"


def test_fully_signed_and_anchored_packet_verifies_end_to_end(tmp_path):
    """The complete chain a real release produces: a genuine Ed25519
    signature over the packet (anchor excluded from the signed bytes --
    the new release flow), a test-built token timestamping that exact
    signature's sha256, the custody public key, and the test TSA's
    certificate provided as an additional pin. Every check the tool has
    is green at once."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(pub_raw).hexdigest()[:16]

    # Build the packet exactly like the new release flow: canonical bytes
    # exclude the anchor (it cannot precede the signature it binds).
    base = _packet_files(signature={}, anchor={})
    packet = json.loads(base["release_packet.json"])
    canonical = verifier._packet_canonical_bytes(packet, exclude_anchor=True)
    sig = key.sign(canonical)
    rsa_key, cert_der, _ = _test_key_and_cert()
    token = build_test_token(digest=hashlib.sha256(sig).digest(), key=rsa_key, cert_der=cert_der)
    packet["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "signed_fields": verifier._SIGNED_FIELDS_EXCLUDING_ANCHOR,
        "digest": "sha256:" + _sha256(canonical),
        "value": sig.hex(),
    }
    packet["anchor"] = _real_anchor(token, hashlib.sha256(sig).digest())
    base["release_packet.json"] = json.dumps(packet, indent=2, sort_keys=True).encode()

    report = verifier.verify_release_packet(
        _write_dir(tmp_path, base), public_keys={key_id: pub_raw}, tsa_certs=[cert_der]
    )
    assert report.signature_status == "verified", report.to_text()
    assert report.anchor is not None and report.anchor.status == "verified", report.to_text()
    assert report.valid, report.to_text()


def test_condition_a_unpinned_signing_cert_reports_unrecognized_tsa_certificate(tmp_path):
    """Condition A: a token that is otherwise perfect -- valid signature,
    valid bindings, valid structure -- but whose signing certificate is
    not the pinned one reports the DISTINCT 'unrecognized TSA certificate'
    finding. Never conflated with a signature failure, never passed."""
    rsa_key, cert_der, _ = _test_key_and_cert()
    token = build_test_token(digest=DIGEST_A, key=rsa_key, cert_der=cert_der)

    check = verifier.verify_tsa_anchor(token, DIGEST_A, [PIN_CERT])  # only the embedded DigiCert pin
    assert check.status == "unrecognized_tsa_certificate"
    assert "unrecognized tsa certificate" in check.detail.lower()
    assert "signature" not in check.detail.lower()  # not conflated with a signature failure

    files = _packet_files(signature=_real_signature_block(REAL_SIG_A), anchor=_real_anchor(token, DIGEST_A))
    report = verifier.verify_release_packet(_write_dir(tmp_path, files))
    assert not report.valid
    assert report.anchor is not None and report.anchor.status == "unrecognized_tsa_certificate"
    text = report.to_text()
    assert "unrecognized tsa certificate" in text.lower()
    assert "Externally anchored: CLAIMED (rfc3161-tsa)" in text

    # Positive control: the SAME token verifies once its cert is provided
    # as an additional pin -- proving the rejection was purely the pin.
    check2 = verifier.verify_tsa_anchor(token, DIGEST_A, [PIN_CERT, cert_der])
    assert check2.status == "verified", check2.detail


def test_condition_b_noncanonical_der_variants_cannot_verify_anchor():
    """Condition B: strict, fail-closed DER. Every non-canonical encoding
    variant -- long-form length where short-form suffices, BER
    indefinite-length, non-minimal INTEGER, trailing garbage -- must
    produce 'cannot verify anchor', never a lenient best-effort parse."""
    rsa_key, cert_der, _ = _test_key_and_cert()
    tok = build_test_token(digest=DIGEST_A, key=rsa_key, cert_der=cert_der)
    assert verifier.verify_tsa_anchor(tok, DIGEST_A, [cert_der]).status == "verified"  # control

    # 1. long-form length where short-form suffices: TSTInfo version
    #    02 01 01 -> 02 81 01 01 (same value, non-minimal length)
    long_form = _surgical(tok, b"\x02\x01\x01", b"\x02\x81\x01\x01")
    check = verifier.verify_tsa_anchor(long_form, DIGEST_A, [cert_der])
    assert check.status == "cannot_verify"
    assert "cannot verify anchor" in check.detail.lower()

    # 2. BER indefinite-length at the top level
    indefinite = _ber_indefinite(tok)
    check = verifier.verify_tsa_anchor(indefinite, DIGEST_A, [cert_der])
    assert check.status == "cannot_verify"
    assert "cannot verify anchor" in check.detail.lower()

    # 3. non-minimal INTEGER: the serial's high bit is set, so its minimal
    #    encoding carries a required leading 0x00 -- add a SECOND leading
    #    0x00 (02 11 00 ... -> 02 12 00 00 ...), which is non-minimal.
    serial_val = (0x0C2F0DD4B7DD2A900C33F5358AD9A5488).to_bytes(16, "big")
    pos = tok.find(serial_val)
    assert pos >= 3 and tok[pos - 3] == 0x02, "serial INTEGER not found in built token"
    serial_tlv = tok[pos - 3 : pos + 16]
    nonmin_int = _surgical(tok, serial_tlv, b"\x02" + bytes([serial_tlv[1] + 1, 0x00]) + serial_tlv[2:])
    check = verifier.verify_tsa_anchor(nonmin_int, DIGEST_A, [cert_der])
    assert check.status == "cannot_verify"
    assert "cannot verify anchor" in check.detail.lower()

    # 4. trailing garbage after the top-level SEQUENCE
    trailing = tok + b"\x00"
    check = verifier.verify_tsa_anchor(trailing, DIGEST_A, [cert_der])
    assert check.status == "cannot_verify"
    assert "cannot verify anchor" in check.detail.lower()


def test_signedattrs_forgery_tstinfo_direct_signature_rejected():
    """THE trap from the proposal: a token whose CMS signature is computed
    over the TSTInfo eContent directly -- not the DER-re-tagged signedAttrs
    (0x31) -- must be REJECTED. The test proves the forged signature WOULD
    fool a naive verifier (cryptography accepts it over the eContent
    bytes), so the rejection is the parser checking signedAttrs, not an
    accident of a broken fixture."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    rsa_key, cert_der, _ = _test_key_and_cert()
    forged = build_test_token(digest=DIGEST_A, key=rsa_key, cert_der=cert_der, sign_over_tstinfo=True)
    # The naive check the trap describes: the token's embedded signature
    # verifies over the TSTInfo eContent bytes directly. A naive verifier
    # that checks the signature against the content instead of the
    # re-tagged signedAttrs would accept this token -- cryptography
    # proves it (must not raise).
    from asn1crypto import cms

    sd = cms.ContentInfo.load(forged)["content"]
    econtent = sd["encap_content_info"]["content"].contents
    embedded_sig = sd["signer_infos"][0]["signature"].native
    rsa_key.public_key().verify(embedded_sig, econtent, padding.PKCS1v15(), hashes.SHA256())

    check = verifier.verify_tsa_anchor(forged, DIGEST_A, [cert_der])
    assert check.status == "cannot_verify"
    assert "signedattrs" in check.detail.lower() or "signature" in check.detail.lower()


def test_content_type_attribute_must_be_tst_info():
    """signedAttrs' contentType attribute must be id-ct-TSTInfo -- the
    attribute that tells a verifier what the signed content actually is."""
    rsa_key, cert_der, _ = _test_key_and_cert()
    # Build a token whose signedAttrs contentType is id-data instead
    from asn1crypto import cms, core, tsp
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    tstinfo = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "2.16.840.1.114412.7.1",
            "message_imprint": tsp.MessageImprint({"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": DIGEST_A}),
            "serial_number": 0x0C2F0DD4B7DD2A900C33F5358AD9A5488,
            "gen_time": core.GeneralizedTime("20260901033557Z"),
        }
    )
    econtent = tstinfo.dump()
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["1.2.840.113549.1.9.16.1.4"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [core.OctetString(hashlib.sha256(econtent).digest())]}),
        ]
    )
    # Wrong contentType in the signedAttrs:
    signed_attrs[0]["values"][0] = "1.2.840.113549.1.7.1"  # id-data
    signature = rsa_key.sign(signed_attrs.untag().dump(), padding.PKCS1v15(), hashes.SHA256())
    from asn1crypto import x509 as asn1x509

    cert_obj = asn1x509.Certificate.load(cert_der)
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": cert_obj["tbs_certificate"]["issuer"],
                            "serial_number": cert_obj["tbs_certificate"]["serial_number"],
                        }
                    )
                }
            ),
            "digest_algorithm": {"algorithm": "sha256", "parameters": core.Null()},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "1.2.840.113549.1.1.1", "parameters": core.Null()},
            "signature": signature,
        }
    )
    token = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": cms.SignedData(
                {
                    "version": "v3",
                    "digest_algorithms": [{"algorithm": "sha256"}],
                    "encap_content_info": cms.EncapsulatedContentInfo(
                        {"content_type": "1.2.840.113549.1.9.16.1.4", "content": cms.ParsableOctetString(econtent)}
                    ),
                    "certificates": [cert_obj],
                    "signer_infos": [signer_info],
                }
            ),
        }
    ).dump()

    check = verifier.verify_tsa_anchor(token, DIGEST_A, [cert_der])
    assert check.status == "cannot_verify"
    assert "contenttype" in check.detail.lower() or "content type" in check.detail.lower()


def test_message_imprint_hash_algorithm_downgrade_rejected():
    """The downgrade path: a token whose messageImprint declares a
    non-SHA-256 hash algorithm must be rejected even though everything
    else is intact."""
    rsa_key, cert_der, _ = _test_key_and_cert()
    token = build_test_token(digest=DIGEST_A, key=rsa_key, cert_der=cert_der, imprint_alg="sha1")
    check = verifier.verify_tsa_anchor(token, DIGEST_A, [cert_der])
    assert check.status == "cannot_verify"
    assert "sha-256" in check.detail.lower()


def test_subject_key_identifier_sid_form_verifies():
    """SignerIdentifier is a CHOICE: issuerAndSerialNumber (real token)
    OR subjectKeyIdentifier -- both must resolve deterministically."""
    rsa_key, cert_der, _ = _test_key_and_cert()
    token = build_test_token(digest=DIGEST_A, key=rsa_key, cert_der=cert_der, sid_form="ski")
    check = verifier.verify_tsa_anchor(token, DIGEST_A, [cert_der])
    assert check.status == "verified", check.detail


def test_unsigned_packet_with_tsa_anchor_claim_cannot_verify(tmp_path):
    """An rfc3161-tsa anchor over a packet with NO signature at all has
    nothing to bind the token to -- reported, and the packet fails."""
    files = _packet_files(signature=None, anchor=_real_anchor(REAL_TOKEN_A, DIGEST_A))
    report = verifier.verify_release_packet(_write_dir(tmp_path, files))
    assert not report.valid
    assert report.anchor is not None and report.anchor.status == "cannot_verify"
    assert "no signature" in report.anchor.detail.lower()


def test_tampered_message_imprint_is_rejected(tmp_path):
    """The token's messageImprint must equal sha256 of the packet's own
    Ed25519 signature bytes. A token timestamping a DIFFERENT digest is
    not bound to this packet."""
    files = _packet_files(
        signature=_real_signature_block(REAL_SIG_A),
        anchor=_real_anchor(REAL_TOKEN_A, DIGEST_B),  # token timestamps SIG_A; packet carries DIGEST_B claim
    )
    report = verifier.verify_release_packet(_write_dir(tmp_path, files))
    assert not report.valid
    assert report.anchor is not None and report.anchor.status == "cannot_verify"
    assert "messageimprint" in report.anchor.detail.lower() or "digest" in report.anchor.detail.lower()

    # The same token against its own digest still verifies standalone.
    check = verifier.verify_tsa_anchor(REAL_TOKEN_A, DIGEST_B, [PIN_CERT])
    assert check.status == "cannot_verify"
    assert "messageimprint" in check.detail.lower()


def test_condition_c_differential_fuzz_agrees_with_library_oracle():
    """Condition C: mutate the real captured token byte-wise across a
    large number of variations; the hand-rolled parser/verifier must
    agree with the asn1crypto+cryptography oracle on accept/reject for
    EVERY mutation. Deterministic (fixed patterns, no RNG) so a CI
    failure reproduces."""
    token = REAL_TOKEN_A
    mutations: list[bytes] = [token]  # case 0: pristine -- both must accept
    for i in range(len(token)):
        b = token[i]
        mutations.append(token[:i] + bytes([b ^ 0x01]) + token[i + 1 :])
        mutations.append(token[:i] + bytes([b ^ 0x80]) + token[i + 1 :])
    for cut in range(1, len(token), 97):
        mutations.append(token[:cut])  # truncation
    for pos in range(0, len(token), 151):
        mutations.append(token[:pos] + b"\x00" + token[pos:])  # insertion

    accepted_both = 0
    rejected_both = 0
    disagreements: list[tuple[int, bool, bool]] = []
    for idx, mut in enumerate(mutations):
        mine = verifier.verify_tsa_anchor(mut, DIGEST_A, [PIN_CERT]).status == "verified"
        oracle = _oracle_accepts(mut, DIGEST_A, [PIN_CERT])
        if mine == oracle:
            if mine:
                accepted_both += 1
            else:
                rejected_both += 1
        else:
            disagreements.append((idx, mine, oracle))

    assert not disagreements, (
        f"hand-rolled verifier disagreed with the library oracle on "
        f"{len(disagreements)} of {len(mutations)} mutations; first: {disagreements[:3]}"
    )
    # The differential is only meaningful if both directions occurred:
    assert accepted_both >= 1, "no mutation was accepted by both -- the fuzz never tested the accept path"
    assert rejected_both >= len(mutations) // 2, "fuzz unexpectedly accepted most mutations"


def test_tsa_cert_cli_flag_adds_pin(tmp_path, capsys):
    """--tsa-cert (repeatable, PEM or DER) adds pins beyond the embedded
    DigiCert certificate -- the operator-configured-TSA story from the
    proposal §6. A packet anchored by that TSA fails without the flag and
    verifies with it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    rsa_key, cert_der, cert_pem = _test_key_and_cert()
    sig = key.sign(b"x")
    token = build_test_token(digest=hashlib.sha256(sig).digest(), key=rsa_key, cert_der=cert_der)

    files = _packet_files(signature=_real_signature_block(sig), anchor=_real_anchor(token, hashlib.sha256(sig).digest()))
    out = _write_dir(tmp_path, files)

    # Without the flag: unrecognized TSA certificate -> exit 1.
    rc = verifier.main([str(out)])
    assert rc == 1
    assert "unrecognized tsa certificate" in capsys.readouterr().out.lower()

    # With a PEM pin: the token verifies -> exit 0.
    pem_file = tmp_path / "tsa.pem"
    pem_file.write_bytes(cert_pem)
    rc = verifier.main([str(out), "--tsa-cert", str(pem_file)])
    assert rc == 0, capsys.readouterr().out

    # With a DER pin: same result.
    der_file = tmp_path / "tsa.der"
    der_file.write_bytes(cert_der)
    rc = verifier.main([str(out), "--tsa-cert", str(der_file)])
    assert rc == 0, capsys.readouterr().out


def test_report_rendering_avoids_forbidden_claims(tmp_path):
    """The rfc3161 anchor rendering must obey the same claims discipline as
    the rest of the tool: never the affirmative forbidden phrases."""
    files = _packet_files(
        signature=_real_signature_block(REAL_SIG_A), anchor=_real_anchor(REAL_TOKEN_A, DIGEST_A)
    )
    report = verifier.verify_release_packet(_write_dir(tmp_path, files))
    text = report.to_text().lower()
    for claim in (
        "is unforgeable", "this is unforgeable",
        "is independently timestamped", "this is independently timestamped",
        "is court-proof", "this is court-proof",
        "is unimpeachable", "this is unimpeachable",
        "this packet is verified", "packet is verified",
    ):
        assert claim not in text, f"affirmative claim {claim!r} must never appear in verifier output"


def test_rsa_pkcs1v15_verify_cross_checks_against_cryptography():
    """The hand-rolled RSA-PKCS1v15-SHA256 verify (reconstruct-and-compare,
    never scan for the 0x00 separator) must agree with cryptography on a
    valid signature and every failure mode -- the same pattern as the
    Ed25519 cross-check."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = key.public_key().public_numbers().n
    e = key.public_key().public_numbers().e
    msg = b"the signed message"

    sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    assert verifier._rsa_pkcs1v15_sha256_verify(n, e, sig, msg) is True
    key.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())

    for tampered in (msg + b"x", b"", b"different"):
        assert verifier._rsa_pkcs1v15_sha256_verify(n, e, sig, tampered) is False
        try:
            key.public_key().verify(sig, tampered, padding.PKCS1v15(), hashes.SHA256())
            raise AssertionError("cryptography must reject a tampered message")
        except InvalidSignature:
            pass

    bad_sig = bytearray(sig)
    bad_sig[0] ^= 1
    assert verifier._rsa_pkcs1v15_sha256_verify(n, e, bytes(bad_sig), msg) is False

    # Wrong key
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert verifier._rsa_pkcs1v15_sha256_verify(other.public_key().public_numbers().n, e, sig, msg) is False

    # Signature longer than the modulus must be rejected, not crash.
    assert verifier._rsa_pkcs1v15_sha256_verify(n, e, sig + b"\x00", msg) is False


def test_verifier_source_imports_no_asn1crypto_or_cryptography():
    """The stdlib-only discipline: the shipped verifier module must never
    import the test-only oracle libraries (or anything else new)."""
    src = (TOOLS / "counselclear_verify_release_packet.py").read_text()
    code = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
    for banned in ("asn1crypto", "cryptography", "import requests", "import urllib", "import socket"):
        assert banned not in code, f"verifier must not reference {banned}"


def test_signed_fields_marker_switch_and_app_sync():
    """The release flow signs the packet WITHOUT the anchor (the token
    binds the signature, which cannot precede the anchor that contains
    it); signed_fields records which canonicalization was used. The
    verifier must recompute the exact bytes the app produced, and the two
    marker constants must agree with service/app/security.py."""
    assert verifier._SIGNED_FIELDS_CANONICAL == "release_packet.v1.canonical"
    assert verifier._SIGNED_FIELDS_EXCLUDING_ANCHOR == "release_packet.v1.canonical-excluding-anchor"

    sys.path.insert(0, str(REPO / "service"))
    try:
        from app.security import (
            PACKET_SIGNATURE_SIGNED_FIELDS,
            PACKET_SIGNATURE_SIGNED_FIELDS_EXCLUDING_ANCHOR,
            packet_canonical_bytes,
        )

        assert PACKET_SIGNATURE_SIGNED_FIELDS == verifier._SIGNED_FIELDS_CANONICAL
        assert PACKET_SIGNATURE_SIGNED_FIELDS_EXCLUDING_ANCHOR == verifier._SIGNED_FIELDS_EXCLUDING_ANCHOR

        packet = {
            "release_id": "R1",
            "matter_id": "M1",
            "anchor": {"type": "rfc3161-tsa", "digest": "ab" * 32, "reference": "c2" * 100},
            "signature": {"value": "ef" * 64},
        }
        # Old marker: anchor stays inside the signed bytes.
        assert verifier._packet_canonical_bytes(packet) == packet_canonical_bytes(packet)
        assert b"anchor" in verifier._packet_canonical_bytes(packet)
        # New marker: anchor excluded from the signed bytes, both sides.
        assert verifier._packet_canonical_bytes(packet, exclude_anchor=True) == packet_canonical_bytes(
            packet, exclude_anchor=True
        )
        assert b"anchor" not in verifier._packet_canonical_bytes(packet, exclude_anchor=True)
    finally:
        sys.path.remove(str(REPO / "service"))
