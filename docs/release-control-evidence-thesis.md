# Strategy note: CounselClear as release-control evidence infrastructure

Product-thesis refinement, 2026-08-26 — supersedes the "defensibility
wedge" framing's emphasis on litigation as the trigger. No code in this
pass; this sharpens the proof model before the next architecture chunk.
See `docs/counselclear-strategy.md` (doctrine, unchanged) and
`docs/release-packet-pdf-append.md` (the release packet this note now
reframes the purpose of).

## 1. Revised thesis

CounselClear is **release-control evidence infrastructure**, not a file
cleaner and not merely "internal custody tooling."

The earlier framing — sanitization quality is not the moat, procedural
defensibility is — was directionally right but still implicitly aimed
at a courtroom: *prove to a judge, someday, that you checked.* That
trigger is real but rare. The sharper, more frequent trigger is
**recurring, contractually- or actuarially-mandated proof that a
reasonable release-control process exists and was followed** — an
obligation that recurs annually or per-engagement, has a named
enforcer, and does not require anyone to ever litigate anything.

The product's job is not "clean the document." It is: **produce, by
default and without extra operator effort, the artifact a firm needs
to answer "how do you control what leaves the building" — every time
someone with contractual or regulatory leverage asks, not just the one
time someone in a courtroom does.**

## 2. Buyer and enforcer

The must-have trigger is not litigation. It is recurring compliance
attestation, with several distinct, real enforcers:

- **Client outside-counsel guidelines (OCGs).** Large corporate clients
  contractually dictate how outside counsel handles their documents —
  including metadata/hygiene requirements — as a condition of
  engagement. This is a forced buy with an enforcer (the client) who
  reviews compliance on an ongoing basis, not a hypothetical future
  dispute.
- **Malpractice carriers.** Renewal questionnaires increasingly probe
  process maturity (data handling, technical competence per ABA Model
  Rule 1.1 cmt. 8 and state equivalents). Demonstrable process can
  affect premium or eligibility — an annual, structural pressure, not
  an incident-driven one.
- **Cyber insurers.** Overlapping but distinct from malpractice:
  underwriting increasingly wants evidence of data-handling controls,
  not just a checkbox.
- **Procurement / vendor security review.** When a firm itself is
  being vetted as a vendor by a regulated client (financial services,
  healthcare, government-adjacent), document-handling evidence is
  requested as part of that review, on the client's schedule, not the
  firm's.
- **Regulated-client audits.** Clients in regulated industries conduct
  their own periodic audits of outside counsel and other vendors that
  touch their data; this is procedural, recurring, and contractually
  backed the same way OCGs are.

Common shape across all five: the enforcer is not "whoever might sue
someday" but a specific counterparty who asks **on a schedule**, holds
**contractual or regulatory leverage**, and wants an **artifact**, not
an assurance. That is what makes this a forced buy rather than a nice
one.

## 3. Proof model: what current manifests/hash chains actually prove

Precise, not aspirational, since the next section depends on being
honest here.

**What the current design proves:**
- **Internal consistency.** Each audit row's `row_hash` is a
  recomputable function of its own `prev_hash`, `seq`, `actor_id`,
  `action`, and `payload` (`service/app/audit.py::event_hash`);
  `verify_chain` re-walks the full sequence and would detect any row
  whose stored hash doesn't match a recompute, or any gap/reorder in
  `seq`. This proves the chain, *as stored in this database*, has not
  been edited after the fact without leaving a detectable break.
- **Content binding.** SHA-256 of the original and derivative are
  recorded in the manifest; the certificate exposes both. This proves
  a specific derivative is bound to a specific original, *given that
  the hashes themselves are trusted inputs*.
- **Disclosure completeness for what ran.** The certificate's
  limitations section (kept-without-review, operator-kept,
  approve-resolved-to-no-op, refused/failed) is derived directly from
  the same manifest data the derivative was built from — there is no
  separate, drift-able summary.

**What it does not prove:**
- **That the tool wasn't modified, or the timeline wasn't fabricated.**
  A hash chain proves sequence and internal non-tampering *after* the
  fact of creation; it proves nothing about *when*, relative to
  external events, the chain was created, or whether the software that
  produced it was the unmodified, trusted build. Nothing here is
  anchored to a clock or record outside CounselClear's own database.
- **That the input document was authentic before ingestion.** Custody
  starts at upload. If a document was already altered before it
  reached this system, the chain faithfully proves custody of *that*
  version — it says nothing about what existed before.
- **Non-repudiation against the operator of the database itself.**
  Everything — the chain, the certificate, the manifest — currently
  lives in a database this product's own operator controls. A party
  with database access (a malicious insider, a compelled disclosure,
  a compromised deployment) could, in principle, regenerate a
  self-consistent alternate history. The chain protects against
  *external* tampering and *accidental* corruption; it does not yet
  protect against the operator's own database being the point of
  compromise.
- **Anything about documents this system never touched.** It cannot
  prove a *negative* about a document that bypassed the tool entirely.

The honest one-line summary: **the chain proves "this is what our
system recorded, unmodified, in this order" — it does not yet prove
"this record could not have been fabricated by whoever controls the
system."** Closing that second gap requires an anchor outside the
system's own control.

## 4. External anchoring options

Ranked roughly by implementation cost vs. strength of the claim it
unlocks, not in a required order — see §5 for what's recommended near-term.

| Option | What it adds | Cost/complexity | Notes |
|---|---|---|---|
| **RFC 3161 timestamp authority (TSA)** | A trusted third party's cryptographic timestamp on a digest, proving that digest existed at or before a given time | Low-moderate: one outbound call per anchored digest to a TSA (several free/cheap public TSAs exist), verify the returned token offline | Proves *when*, not *who*/*what* beyond the digest. Doesn't require trusting CounselClear's clock. Well-established, boring technology — a strength here. |
| **Public transparency log** (Certificate-Transparency-style, e.g. Sigstore/Rekor-style append-only log) | A publicly auditable, append-only record that a digest was submitted, with inclusion proofs anyone can check independently of the vendor | Moderate: needs either a hosted public log or running/adopting one; verification tooling for the recipient | Strongest "not just the vendor's word" story — the log itself is operated by a third party or a federation, not CounselClear. Newer/less familiar to a legal audience than a TSA. |
| **Customer-controlled WORM / Object Lock** | The customer's *own* S3 Object Lock / immutable storage (already used for custody originals per PR 21) becomes the anchor — CounselClear writes, the customer's own retention policy makes post-hoc alteration by CounselClear itself infeasible | Low: largely already-built infrastructure (`service/scripts/custody.py`, S3 Object Lock support exists); extend the *audit chain*, not just originals, into customer-controlled immutable storage | Directly answers "what if the vendor's own database is the compromise" — the customer, not CounselClear, holds the retention lock. Strong fit with an enterprise/regulated buyer who already wants data under their own control. |
| **Signed daily digest** | A single signed hash-of-hashes covering a day's (or matter's) audit chain, published or handed to the customer, so any later dispute only needs to check *that day's* root against a small number of independently-held copies | Low-moderate: mostly composition of the above (sign with a key, optionally also TSA-stamp *that* signature) — meaningfully cheaper than anchoring every event individually | Practical middle ground: bounds how much any single compromise can retroactively rewrite (at most, back to the last unanchored digest), without the operational cost of anchoring every row. |
| **Third-party attestation / warranty partner** | An external party (an auditor, an insurer, a bonding partner) stands behind the process itself, not just the cryptography | High: a business relationship, not an engineering task | This is the "sell it like a warranty" implication from the earlier reflection — likely a later-stage move once the technical anchoring above is real, not a substitute for it. Out of scope for a near-term architecture chunk. |

None of these are mutually exclusive; a credible near-term story
likely combines a signed daily digest with either TSA timestamping or
customer-controlled WORM extension (both are comparatively cheap and
both close the "vendor could rewrite their own database" gap from a
different angle).

## 5. Recommended near-term product changes

Ordered as a rough sequence; none of these are approved for
implementation by this note — they're the candidate shape for the next
planning pass.

1. **Release intent/context.** Capture *why* a document is being
   released as first-class data at the point of sanitize/release, not
   reconstructed after the fact — recipient/matter context, the
   business reason already captured loosely in `reason`, formalized
   enough that a compliance reviewer can answer "what was this for"
   without guessing. This is what turns a certificate from "we ran a
   tool" into "we controlled a release."
2. **Release packet as the default artifact, not an optional
   download.** Already the direction as of PR 36; this thesis is the
   reason it's right, not just tidier. Every release-control question
   an enforcer in §2 asks is answered by "here is the packet for that
   release," not "let us pull logs."
3. **Policy outcome summary.** A structured (not just prose)
   summary of what a policy did across a period — counts of
   cleared/kept/refused/failed, which policies were used, whether any
   job had unreviewed limitations — is exactly the shape an OCG
   compliance review or a carrier questionnaire wants, and doesn't
   exist yet (the matter summary report is close but per-matter, not
   period/policy-oriented).
4. **Anchor-ready digest format.** Before implementing any specific
   anchor from §4, define the digest CounselClear would anchor — almost
   certainly a periodic (daily, or per-batch) hash-of-hashes over the
   audit chain, structured so that swapping *which* anchor mechanism is
   used later (TSA now, transparency log later, both eventually)
   doesn't require re-deriving the digest format. Getting this shape
   right is cheap now and expensive to redo after real anchors exist
   and customers depend on a specific format.

## 6. Claims that must be avoided until anchoring exists

The following words are false or misleading claims about the *current*
system and must not appear in product copy, certificates, README
files, or generated reports until at least one external anchor from
§4 is actually implemented and load-bearing:

- **"Unforgeable"** — false today. A party with database access could
  construct a self-consistent alternate chain; nothing external
  prevents that.
- **"Independently verifiable"** — false today in the strong sense.
  Internal consistency is independently *recomputable* (anyone can
  re-run `event_hash` against the stored rows), but that's verifying
  the system's own claim using the system's own data — not independent
  in the sense a skeptical outside party means it. Precise substitute:
  *"internally consistent — every event's hash is recomputable from
  the recorded data."*
- **"Unimpeachable"** — a legal-sounding claim this product cannot
  back and should never make; it invites exactly the adversarial
  challenge (§3's "when was this actually created") the system
  currently has no answer to.
- **"Court-proof"** — implies a legal conclusion (admissibility,
  weight) this product has no standing to assert and that depends on
  jurisdiction, rules of evidence, and facts outside the software
  entirely.

Until anchoring lands, honest language is available and should be used
instead: *"a hash-chained record of what this system did, with every
event's integrity independently recomputable from the stored data."*
That is a true, still-valuable claim — it should not be inflated into
one the product can't yet support.
