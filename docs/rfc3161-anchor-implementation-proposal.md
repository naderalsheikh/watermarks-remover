# Proposal: RFC 3161 timestamp anchor for release packets

Proposal only — no implementation in this pass. Picks up exactly where
`docs/release-packet-verification-and-anchoring-proposal.md` §5 left
off: that proposal defined the packet spec and verifier (now shipped,
PR 36/63) and deliberately deferred anchor selection to a later pass.
The anchor mechanism (RFC 3161 TSA) has now been chosen; this defines
the concrete digest format and implementation shape for it.

## 1. What actually exists today (grounded in the current code, not the
older proposal's mockup)

- `release_packet.json`'s `anchor` field is currently populated as
  `{"type": "ed25519-operator", ...}` (`service/app/main.py:3344`) —
  the deployment's own Ed25519 key signs the packet
  (`sign_release_packet`, called after every other field including the
  PR 63 schema pin is stamped in). The verifier already treats
  `ed25519-operator` as *not* externally anchored
  (`tools/counselclear_verify_release_packet.py`: `_external =
  self.anchor_type not in (None, "none", "ed25519-operator")`) — this
  is correct today and stays correct: an operator-held key proves
  internal consistency, not that anyone outside CounselClear confirmed
  anything.
- `cryptography==50.0.0` is already a dependency
  (`service/requirements-app.txt`) and is what signs with Ed25519
  today. It does not, on its own, give RFC 3161 client/token-parsing
  support (that's CMS/TSTInfo structure, a different ASN.1 shape than
  what `cryptography`'s high-level API covers well) — a purpose-built
  RFC 3161 library is a new dependency, not an extension of the
  existing one.

## 2. What gets timestamped

**The Ed25519 signature bytes, not a fresh whole-packet digest.**

The signature is already computed over the packet's full canonical
content (everything else, including the PR 63 schema pin, is stamped
in *before* `sign_release_packet` runs — verified when I reviewed that
pass). Timestamping the signature transitively proves the signed
content existed by the same time, without introducing a second,
separate question of exactly which byte range a fresh digest would
need to cover (before/after which field is inserted) — that ordering
question doesn't need a new answer if what's timestamped is a value
that's already finalized, already verified by the existing signature
check, and always exactly 64 bytes.

Concretely: `digest = sha256(release_packet["signature"]["signature"])`
(or wherever the raw signature bytes live in that dict — confirm the
exact field name against `sign_release_packet`'s return shape) is what
gets submitted to the TSA as the RFC 3161 `messageImprint`.

## 3. Anchor field shape

```json
"anchor": {
  "type": "rfc3161-tsa",
  "digest": "<sha256 hex of the packet's own Ed25519 signature bytes>",
  "reference": "<base64 of the raw DER-encoded RFC 3161 TimeStampToken>",
  "tsa_url": "<TSA endpoint actually used for this packet>",
  "tsa_cert_fingerprint": "<sha256 of the TSA signing cert, for a verifier's own cross-check>",
  "timestamped_at": "<the time asserted BY THE TOKEN, not this system's clock>"
}
```

`digest` here plays the same role the PR 63 schema pin's
`schema_sha256` plays: the verifier recomputes it independently and a
mismatch is the finding, never a value the verifier just trusts from
the packet. `tsa_cert_fingerprint` lets the verifier flag "this packet
was anchored by a TSA whose cert I don't recognize" as a distinct,
honestly-reported case from "the token is cryptographically invalid" —
those are different findings and shouldn't be collapsed into one.

## 4. TSA client flow (at packet-creation time, after signing)

1. Compute `digest` per §2.
2. Build an RFC 3161 `TimeStampReq` for that digest (SHA-256,
   `certReq=true` so the response includes the TSA's cert for offline
   verification without a second network call).
3. POST it (`Content-Type: application/timestamp-query`) to the
   configured TSA URL.
4. Parse the `TimeStampResp`; on success, extract the DER-encoded
   `TimeStampToken` and store it (§3's `reference`).
5. **Failure handling — this must never block a release.** A release
   completes and ships with `anchor.type: "ed25519-operator"` (today's
   behavior) if the TSA call fails or times out (network issue, TSA
   downtime, rate limit). Anchoring is an enhancement layered on top
   of an already-complete, already-signed packet, not a release-gating
   dependency. A short timeout (a few seconds) and a single retry are
   reasonable; anything beyond that should fall through to unanchored
   rather than hold up the response. A later backfill pass (a separate,
   smaller piece of work — not in this proposal's scope) could
   re-anchor previously-shipped `ed25519-operator` packets whose TSA
   call failed at creation time, since the signature being timestamped
   doesn't change after the fact.
6. Library: needs a maintained RFC 3161 client (`TimeStampReq`
   construction, `TimeStampResp`/`TimeStampToken` CMS parsing) — do
   not hand-roll ASN.1/CMS parsing. Confirm current maintenance status
   at implementation time rather than pinning a choice here; likely
   candidates are a dedicated `rfc3161`-family PyPI package or
   `pyhanko`'s timestamping module (mature, used for PDF long-term
   validation, actively maintained as of this writing). Whichever is
   chosen must be stdlib-adjacent enough to not conflict with the
   engine-isolation doctrine — this code lives in the control plane
   (`service/app/`), not the engine, so a real dependency is fine here
   (unlike `tools/counselclear_verify_release_packet.py`, which stays
   stdlib-only per its own discipline — see §5).

## 5. Verifier changes (stdlib-only constraint stays)

This is the one place this proposal's stdlib-only-verifier discipline
gets genuinely tested: RFC 3161 token verification means parsing a CMS
SignedData structure and checking an RSA/ECDSA signature over it —
nothing in Python's stdlib does that. Options, in order of preference:

1. **Vendor the minimal ASN.1 parsing needed**, by hand, scoped
   narrowly to exactly the TimeStampToken fields this verifier reads
   (messageImprint hash, genTime, signing cert, signature) — more code
   than importing a library, but keeps the "no third-party dependency"
   property that makes this tool trustworthy to run against a
   downloaded packet with nothing but a stock Python install. This is
   real, non-trivial work (CMS/PKCS7 structures are not simple) and is
   the most defensible choice given what this specific tool is *for*
   (a recipient with no reason to trust CounselClear's own tooling
   ecosystem, running it standalone).
2. **Accept a dependency for the verifier specifically**, breaking the
   stdlib-only rule for this one check, clearly flagged in the tool's
   own output/docs as a departure from its established discipline.

This is a real design fork this proposal is flagging, not resolving —
worth your call before implementation starts, since it changes what
"stdlib-only" means for this tool going forward.

## 6. TSA endpoint

Configurable via an env var (e.g. `COUNSELCLEAR_TSA_URL`), not
hardcoded — a public/free TSA is fine to default to for development
and this proposal's own testing, but a production deployment should be
free to point at a TSA the operator has a real (paid, SLA-backed)
relationship with. Document the default clearly as "not vetted for
production reliability" in whatever ships as the default.

## 7. Tests

Cannot depend on a live network TSA in CI (flaky, and a real security
smell to have tests reach out to a live third party). Needed:

- A recorded fixture: one real `TimeStampToken` captured once against
  a real TSA, checked into `tests/fixtures/`, used to test the
  verifier's parsing/validation logic without a network call.
- A tiny local mock TSA (a test-only HTTP handler that returns a
  syntactically valid but test-signed token) for exercising the client
  flow end-to-end, including the failure-handling path (§4.5) — a mock
  that can be told to time out, return a malformed response, or return
  a token whose messageImprint doesn't match, to prove the client
  degrades to `ed25519-operator` cleanly in each case rather than
  raising into the release path.
- A tampered-token fixture (wrong messageImprint, or a token signed by
  an unrecognized cert) proving the verifier reports a mismatch rather
  than silently passing.

## 8. What this unlocks, and what it still doesn't

Per `docs/release-packet-verification-and-anchoring-proposal.md` §7,
"independently timestamped" becomes an honestly available claim once
this is implemented and load-bearing (not before). "Unforgeable",
"court-proof", and "unimpeachable" remain forbidden regardless — an
RFC 3161 TSA proves *when* a digest existed, from a party independent
of CounselClear; it says nothing about whether the underlying database
row it points at could be selectively omitted, nor does it make the
signing key's own custody unforgeable. Those are different claims,
and this anchor does not earn them.
