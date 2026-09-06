# Custody key durability — proposal

**Status:** proposal. §3 (Phase 1) is implemented; §4–§6 are decisions for the product owner, not scheduled work.
**Date:** 2026-09-05
**Origin:** Lane E1 of `docs/counselclear-custody-truthfulness-plan.md`, itself the last open item from the 2026-09-02 custody review, which called it out as the remaining single point of evidentiary failure.

---

## 1. The problem, stated exactly

Every release packet carries this in its `README.txt` (`service/app/main.py`, the readme block in `job_bundle`):

> Keep the public key the operator sent you alongside this packet: without it the signature cannot be verified, and the operator's copy is the only source — a lost public key makes every packet issued under it unverifiable.

That is honest, which is why it survived the claim-copy audit untouched. It is also a description of a real failure mode with no mitigation. Concretely, today:

- The signing key is generated on first use by `Config.ensure_custody_signing_key()` and lives in the deployment's data root. Nothing else holds it.
- `signature.key_id` is `sha256(public_bytes)[:16]` (`security.custody_key_id`), which **names** a key but does not **contain** one.
- A recipient verifies with `--public-key <key.pem>`, obtained from `GET /v1/custody-public-key` or from the operator's transmittal email.
- With no key, the verifier reports `NOT VERIFIED (no --public-key given)` — correct, and permanent.

So the evidentiary durability of every packet a deployment has ever issued rests on an operator not losing a 32-byte file, and on each recipient not losing their copy of it. A packet produced today and challenged in three years is verifiable only if someone, somewhere, still has that key and can be shown to have had it all along.

### 1a. The circularity that makes this hard

The obvious fix — put the public key in the packet — does not, on its own, work. An adversary who can alter a packet can also replace the embedded key and re-sign, and every internal check passes. Embedding the key solves **availability** (can I check the maths?) and contributes nothing to **authenticity** (is this the operator's key?).

Authenticity requires something the adversary does not control: a fingerprint the recipient obtained separately, a signature from a key with independent standing, or a third-party record. Every option in §4–§6 is a different answer to *where does that come from*.

This distinction is load-bearing for the rest of this document, and any implementation that blurs it produces exactly the overclaim this product exists to refuse — a green `VERIFIED` over a self-consistent forgery.

---

## 2. What we are and are not trying to solve

**In scope:** a recipient holding a packet, months or years later, being able to (a) check the signature at all, and (b) establish that the key it checks under is the one the operator was using at issuance.

**Not in scope:** protecting against a compromised deployment at the moment of issuance. If the signing key is stolen while in use, every option here signs the attacker's packets just as happily. That is a key-custody problem (§6 touches it) and an RFC 3161 anchor partially bounds it by fixing *when* a signature existed.

**Not in scope:** making CounselClear an identity authority. The product signs its own output; the trust root is and remains the operator's relationship with the recipient. Nothing below should be read as this system vouching for who anybody is.

---

## 3. Phase 1 — publish the key, pin the fingerprint (IMPLEMENTED)

The cheapest change that removes the *availability* half of the failure without pretending to solve the *authenticity* half.

**Emit the public key in the packet.** `signature.public_key` carries the 64-char hex of the raw Ed25519 public bytes, alongside the existing `key_id`. A recipient who lost the operator's key file can now still check the maths.

**Report it as what it is.** The verifier gains a distinct status, `VERIFIED (self-published key — provenance unconfirmed)`, which is never the same string as a check against an operator-supplied key. The report states the circularity in the packet's own honest register: anyone able to alter the packet could also have replaced this key. This is the one thing Phase 1 must not get wrong.

**Give the recipient something to pin.** The verifier prints the key fingerprint (`sha256` of the raw public bytes, full hex) in every report, and accepts `--key-fingerprint <hex>`. A recipient who confirms the fingerprint once — over the phone, in an engagement letter, from a prior packet they trust — can verify every future packet from that deployment with no key file at all, and the verifier reports `VERIFIED (fingerprint pinned)`.

This is trust-on-first-use with an explicit pin, and it is honest because the pin is the recipient's own act, recorded in their own records, not something the packet asserts about itself.

**What Phase 1 does not do:** it does not help a recipient who never pinned anything and has lost the key file. They get a mathematically checked signature under an unconfirmed key, and the verifier tells them precisely that.

---

## 4. Option A — signed key manifest with rotation and revocation

A `key_manifest.json`, published at a stable URL and included in packets, listing every key the deployment has used: key id, public bytes, validity window, and status (`active` / `retired` / `revoked`, with a reason). The manifest is itself signed by a long-lived **root** key held offline, and every packet's key is expected to appear in it.

**Buys:** rotation without invalidating history (the current design already tolerates rotation via `key_id`, but nothing records that a key *was* ours); revocation, which nothing today can express at all; and a single artifact a recipient pins once instead of one fingerprint per key.

**Costs:** introduces a root key whose loss is a strictly worse version of the current problem, and which must be held offline to be worth having. Requires publishing infrastructure with its own availability story. Meaningful implementation: manifest schema and emitter, offline root-signing ceremony and its documentation, verifier chain-checking, and a revocation-checking policy (a verifier that cannot fetch the manifest must not fail closed, or an outage becomes an evidentiary event).

**Judgement:** correct for a multi-deployment or multi-tenant product. Heavy for a single-firm deployment, and the root key's ceremony is the kind of process that quietly does not happen.

---

## 5. Option B — durable public-key registry

Publish each public key to a record outside the operator's control: a transparency-log-style append-only service, DNS, or a third-party notary. A recipient checks the packet's key against that record.

**Buys:** the only option that survives the operator losing *everything*, and the only one where authenticity does not depend on the recipient having done something at the right moment.

**Costs:** an external dependency on the verification path, which the verifier is deliberately built to avoid — it makes no network calls, imports nothing from the service, and touches only bytes handed to it locally. Adding a lookup either breaks that property or makes the registry advisory, in which case it buys much less. Also a privacy surface: publishing key ids externally leaks that a deployment exists and roughly when it was active.

**Judgement:** the strongest answer and the worst fit for this tool's architecture. Revisit if CounselClear is ever hosted rather than deployed.

---

## 6. Option C — organizational escrow

The operator's own key management: the private key held in a KMS/HSM with the organization's backup and succession policy, and the public key deposited with counsel or in the firm's records-retention system.

**Buys:** no new code, no new dependency, and it puts the durability where the legal obligation already sits — the firm's records-retention policy, which already covers matter files that outlive individual custodians.

**Costs:** entirely procedural, so it can be adopted and then not followed, and CounselClear cannot verify or enforce any of it. Worth pairing with §7 so the product at least *asks*.

**Judgement:** the right default recommendation for a single-firm deployment, and complementary to every option above rather than an alternative to them.

---

## 7. Recommendation

1. **Phase 1 (done).** Publish the key, report self-published provenance honestly, support fingerprint pinning.
2. **Adopt Option C as documented guidance** — a short section in `COUNSELCLEAR_PRODUCTION.md` telling operators to back the key up under their existing records-retention policy and to send recipients the fingerprint, not just the key. Cheap and it addresses the common case.
3. **Defer Options A and B.** Revisit A when a second deployment or a rotation requirement makes revocation a live need; revisit B only if the product becomes hosted.

Deliberately not recommended: any scheme where the verifier reports a stronger word than the evidence supports. `VERIFIED` against a key the packet supplied about itself is exactly that, and Phase 1's separate status exists to make it impossible to write by accident.

---

## 8. Vocabulary this proposal is bound by

Per `docs/release-packet-verification-and-anchoring-proposal.md` §7 and the tests in `tests/test_release_packet_verifier.py`, the verifier may never print `unforgeable`, `independently timestamped`, `court-proof`, or `unimpeachable` as affirmative claims, and never the bare word `VALID`. Phase 1 adds a status string; it is subject to the same ban, and the existing forbidden-claim test covers it automatically because that test scans rendered report text rather than an allowlist of known strings.
