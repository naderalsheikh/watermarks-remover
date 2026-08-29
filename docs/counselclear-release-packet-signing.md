# Release-packet signing (MUST-2, PR 57)

**Decision date:** 2026-08-29
**Status:** implemented (service/app/security.py, service/app/config.py, service/app/main.py, tools/counselclear_verify_release_packet.py)
**Origin:** custody-doctrine review finding MUST-2 — *"nothing about the packet is signed; an attacker with filesystem access can rewrite release_packet.json and its hashes and the offline verifier re-hashes the tampered files happily."*

This is the written decision doc the implementation was required to precede. It answers the four questions the review posed before any signing code was written: symmetric vs. asymmetric, key lifecycle, what exactly gets signed, and how the offline verifier stays honest about what a signature does and does not prove.

---

## 1. Symmetric HMAC vs. asymmetric Ed25519 → **Ed25519**

The repo already has `sign_hmac_sha256` (service/app/security.py) for server-side tokens, and the review explicitly warned against reusing it here. The distinction is not cryptographic strength — it's *who can verify*:

- **HMAC is symmetric.** Anyone holding the key can verify — and anyone holding the key can *forge*. The whole point of a release-packet signature is that the *recipient* — opposing counsel's expert, a regulator, the client — verifies offline, outside our infrastructure. Hand them an HMAC key and you have handed them the signing key. The choice is disqualifying, not a tradeoff.
- **Ed25519 (RFC 8032)** is asymmetric: the private half never leaves the deployment; the public half is published in the packet README, over `GET /v1/custody-public-key`, and out-of-band to recipients. A recipient can verify everything and forge nothing.
- Why Ed25519 specifically (vs. RSA/ECDSA): 64-byte signatures, deterministic signing (no nonce, so no nonce-reuse catastrophe class), fast pure-Python verification is tractable (the offline verifier needs no third-party library), and the `cryptography` package already in the dependency tree supports it first-class.

## 2. Key lifecycle

**Where the key lives:** `data/auth/custody_signing_key.pem` — a PKCS#8 PEM, auto-generated on first packet issuance, mode `0600`, written atomically (tempfile + `os.replace`), following exactly the provisioning doctrine of `cookie.secret` and `attest.secret` (see `Config.ensure_custody_signing_key`). Deliberately *not* in the database: a signing key readable by the same DB owner and backup path as the audit chain it witnesses is no separation at all. Filesystem, `auth/` directory, same ACL surface as the local password hash.

**Provisioning:** lazy — the key is generated the first time a packet is actually signed, not at boot. A deployment that never issues a packet never writes a key it doesn't use.

**Rotation:** the operator's act of replacing the file. Existing-file-wins on every boot, so rotation is never accidental. Packets carry the signing key's `key_id` (sha256 of the raw public key, first 16 hex chars) in the signature block, and `--public-key` is repeatable — an operator can hand a recipient a bundle of keys covering multiple rotations, and the verifier selects by `key_id`. Old packets never break: their signature names the key that signed them, not "the current key."

**Compromise:** rotate the file (generate a new key, archive the old public key). Packets signed under the compromised key can no longer be *trusted as authentic* — the signature still verifies, but the operator's out-of-band notification to recipients ("packets with key_id X issued before date D are unreliable") is the disclosure mechanism, exactly as it would be for any CA incident. This is an operational runbook item, not a code path; the code path that matters is that rotation is *deliberate* (existing-file-wins) and *identifiable* (key_id in every signature).

**Loss:** a lost *private* key only blocks *issuing* new packets under that key_id — verification of already-issued packets uses the public half, which the operator should hold alongside every packet (and every recipient holds). A lost *public* key makes every packet issued under that key_id unverifiable by third parties — this is why the README in every packet tells the recipient to keep the public key with the packet. The packet's own README is the transmission mechanism; `GET /v1/custody-public-key` is the convenience path, and its docstring is explicit that the *trust root* is the operator's out-of-band transmittal, not the HTTP response.

## 3. What exactly gets signed

**The whole packet minus the signature block, canonicalized.** `packet_canonical_bytes` (service/app/security.py): the packet dict with the `signature` key removed, `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.

Why the whole packet and not just the `hashes` block: the hashes block binds the *files* to each other, but nothing binds the *metadata* — `release_id`, `matter_id`, `job_id`, `policy`, `audit_refs`, `legal_justifications`, `limitations` — to those files. An attacker who can rewrite release_packet.json can swap a packet's matter_id, claim a different policy was applied, or cite different audit seq numbers, and recompute every file hash honestly over the swapped content. Signing the whole packet binds metadata and hashes together: any single-byte change anywhere — metadata or hash — breaks the signature. (The MUST-2 tamper tests exercise exactly this: a flipped `matter_id` with every file hash still clean.)

Why canonical bytes and not the literal file bytes: the packet *file* is written `indent=2, sort_keys=True` for humans. The signature deliberately does not cover that formatting — only the parsed *content* — so the verifier can reproduce the signed bytes from any parse of the file, and a re-serialization (e.g. the file passing through a tool that reformats whitespace) doesn't break verification while a *content* change still does. Byte-stability holds because the packet schema contains only strings, ints, nulls, booleans, and nested dicts/lists — no floats — so Python's `json.dumps` is deterministic across versions for everything that can appear.

**The signature block** (schema-required, schema-optional on the packet — see §5): `algorithm: "ed25519"`, `key_id` (16 hex), `signed_fields: "release_packet.v1.canonical"`, `digest: "sha256:<canonical-bytes-hash>"`, `value: <128-hex Ed25519 signature>`. The `digest` is belt-and-suspenders alongside the Ed25519 value: the verifier recomputes it from the canonical bytes before the signature check, so a canonicalization *drift* (verifier and signer disagreeing on serialization) surfaces as a specific digest mismatch rather than an opaque Ed25519 failure.

**Ordering is load-bearing** (a bug the e2e smoke caught): the `anchor` field is part of the signed content, so it must be set *before* signing — and its `digest` sub-field is therefore unsatisfiable (a digest of signed bytes cannot appear inside those bytes), so `anchor.digest` stays `None` and the binding digest lives in the signature block one key over. `anchor.reference` carries the `key_id`, which is a property of the key, stable pre-signing.

## 4. What release_result.json carries

A **reference, not a signature** (`signature_ref`: algorithm/key_id/signed_fields). The lighter artifact is deliberately not signed itself: it has no derivative to protect, it summarizes facts the packet's signature already binds, and a second signature over overlapping facts would create a second tampering surface without adding a single checkable claim. Combined mode (`verify_release_packet_and_result`) cross-checks that the result's `signature_ref.key_id` agrees with the packet signature's `key_id` — a disagreement means the two artifacts came from different issuances, which fails loudly.

## 5. Verifier behavior (the honesty rules)

`tools/counselclear_verify_release_packet.py` stays **stdlib-only** (pinned by `test_verifier_never_imports_the_engine_or_app_internals`), so Ed25519 verification is implemented directly per RFC 8032 §5.1 and cross-checked against the `cryptography` library by `test_signature_cross_checks_against_cryptography`.

Status vocabulary (rendered as its own `Signature:` section, never the word "VALID"):

| status | rendering | effect on `valid` |
|---|---|---|
| `verified` | `VERIFIED` | pass |
| `unsigned` | `UNSIGNED (packet predates signatures)` | pass — legacy packets must keep verifying |
| `no_key` | `NOT VERIFIED (no --public-key given)` | pass — hash checks still meaningful |
| `unknown_key` | `NOT VERIFIED (key not provided)` | pass — operator error, not tamper evidence |
| `mismatch` | `MISMATCH` + "treat as tampered" | **fail** |

The lenient defaults exist so the tool stays usable: a recipient with only a packet (no key) still gets the full hash-consistency verdict; a legacy pre-PR-57 packet (no signature block) is *exactly* as verifiable as the day it was issued — the schema marks `signature` optional for that reason, and unsigned instances still validate against `release_packet.schema.json`.

`--verify-signature` is the strict opt-in for operators checking their *own* deployment's output: it escalates every non-`verified` status to a failure (exit 1), and refuses a bare `release_result.json` (results are never signed; the signature lives on the packet).

**Anchor honesty:** `anchor.type: "ed25519-operator"` is rendered `Externally anchored: no`, with the disclaimer rewritten to say what an operator signature actually is — the producing system vouching for its own output. The signature authenticates the packet's *origin* (whose key vouches for it, and that nothing changed after issuance); it says nothing about *time*, and the tool keeps saying so.

## 6. Test coverage map

- `test_signed_packet_verifies_with_public_key` — happy path, real signing flow
- `test_signed_packet_tampered_metadata_fails_signature` — **THE MUST-2 tamper sim** (metadata byte flip, all file hashes clean, signature fails)
- `test_signed_packet_tampered_manifest_fails_hash_not_signature` — the two nets are independent and stay that way
- `test_signed_packet_wrong_key_reports_not_verified` / `..._without_key_downgrades...` / `test_unsigned_legacy_packet...` — downgrade matrix
- `test_strict_mode_*` — `--verify-signature` escalation matrix
- `test_public_key_cli_accepts_pem_and_hex_forms` — both key formats, same key_id
- `test_signature_cross_checks_against_cryptography` — stdlib verify pinned against the library
- `test_ed25519_verify_never_raises_on_garbage` — hostile-input determinism
- `test_packet_canonical_bytes_matches_app_construction` — signer/verifier canonicalization sync
- `test_combined_mode_checks_signature_ref_agreement` (+ legacy variant) — packet/result agreement
- e2e (test_app.py): real route signs, real public-key route, real verifier says VERIFIED; real-packet metadata tamper fails offline; key file 0600 + idempotent; release_result carries the ref
