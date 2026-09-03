# CounselClear — Custody Truthfulness: orchestration plan

**Status:** plan. Lane A is implemented and green in the working tree (uncommitted); Lanes B–E are not started. All three owner decisions were resolved 2026-09-02 — nothing is gated on a decision.
**Date:** 2026-09-02
**Origin:** external custody test case (2026-09-02) on the Aurelia/ICSA release packet, plus a second agent report reviewed against the tree.
**Ground truth:** every claim below was re-verified against the working tree on 2026-09-02. Where the second agent's report disagrees with the tree, the tree wins and the correction is stated inline.

---

## The finding that reorders everything

**There is no hidden-text removal path anywhere in the engine.** `w:vanish` appears only in the detector (`service/scripts/container_meta.py:1191-1265`); no function removes hidden-text formatting in any format. `hidden_text` therefore resolves to a non-removing action under **every** policy:

| policy | `hidden_text` | effective outcome |
|---|---|---|
| `external_sharing` | `flag` | retained |
| `production` | `approve` → `_APPROVE_RESOLVES_TO` → **`flag`** | retained |
| `privacy_only` | `keep` | retained |
| `evidence_preservation` | `keep` | retained |

Verified by execution, not by reading the table: sanitizing a `w:vanish` document under `production` with an explicit `{"hidden_text": "approve"}` decision yields `{'action': 'flag', 'reason': 'operator_approved'}`, and the derivative's decompressed `word/document.xml` still contains both the `w:vanish` markup and the concealed text. Re-inspection of the derivative still reports `docx-hidden-text: vanish=1`.

Three consequences:

1. **The proposed re-scrub of the Aurelia deliverable under `production` is unexecutable as described.** It produces a byte-different but equally contaminated derivative, differing only in `reason` (`operator_approved` vs `policy_default`). Anyone re-running it and reporting "zero riding findings" would be reporting a result the engine cannot produce. This is the single most important correction in this document.
2. **"Flip `hidden_text` to strip-by-default" is not a config change.** `DEFAULT_POLICIES` cannot name an action the engine does not implement — and `policies.py` already refuses to ship silently partial derivatives for exactly this class of gap (see `_PDF_UNSTRIPPABLE_SUBTYPES`, `PDF_CONTENT_REFUSAL_MARKER`). Setting `"hidden_text": "strip"` today would either no-op or need the same honest-refusal treatment.
3. **Lane A's work is what currently protects the product here.** The retention is now impossible to miss on the certificate. That is containment, not a fix.

---

## Lane A — Record truthfulness (DONE, uncommitted)

Closes items 1–5 of the external review. `1343 passed, 1 skipped`, ruff clean. Baseline before this work: 1324 passed.

| # | Item | Where |
|---|---|---|
| A1 | Retained findings always produce a limitation, derived structurally from `action_record.retained_finding` — not by matching marker substrings | `policies.py:503-530`, `main.py:_retention_limitations` |
| A2 | `white=N` split into `white_rules` (declarations anywhere in `word/*.xml`) vs `white_applied_runs` (inside `w:rPr` in a body-bearing part), with parts named and detection basis stated | `container_meta.py:_inspect_docx_legal` |
| A3 | `manifest.dispositions`: one row per pre-sanitize finding → policy decision → post-sanitize observation, with a four-value `postcondition` | `custody.build_dispositions`, `verify.py` (`subtypes_before`/`subtypes_after`) |
| A4 | Authoring exhaust stripped (RSIDs, `w14/w15:docId`, `dcterms:created/modified`, `cp:revision`, `TotalTime`); `dc:title`, statistics and `Template` retained **with stated reasons** in `manifest.residual_metadata` | `container_meta._strip_authoring_exhaust`, `engine_api._residual_metadata` |
| A5 | `release_result.json`'s `anchor` gains `scope` + `note` so it stops reading as a conflict with the packet's anchor; verifier note scoped to match | `main.py:_build_release_result`, `counselclear_verify_release_packet._anchor_note` |
| A6 | Schema durability: `manifest`/`report` bumped to v2, prior bytes archived under `schemas/archive/`, pins resolved by **declared** version so already-issued packets keep verifying | `schemas_meta.schema_sha256_for_version`, `_published_schema_sha256` |

**Remaining in this lane — A7 (small, do with the commit):** `APPROVED_BUT_NO_OP_MARKER` is gated on `action == "keep"` (`policies.py:820`). An operator who clicks **Approve** on `hidden_text` gets `reason=operator_approved, action=flag` — a retention they affirmatively asked to have removed — and no "approved but not removed" disclosure. The limitation is honest ("REMAINS IN THE DERIVATIVE under policy action 'flag'") but does not say the operator asked otherwise. Widen the marker to cover `operator_approved` resolving to any non-removing action.

**Done criteria:** committed to a branch off `main`, full suite green, `docs/claim-copy-audit.md` line references refreshed where Lane A moved them (the certificate disclaimer moved from ~`main.py:514`).

---

## Lane B — Hidden text: capability + control (DECIDED, blocks the client deliverable)

The only lane with client-visible exposure.

**B1 — DECIDED (owner, 2026-09-02): build the stripper *and* gate the release.** The earlier framing of these as three competing options was wrong — (a) and (c) are different layers, not alternatives, and the owner's question ("why can't we do both?") is the correct read:

- **(a) The stripper is the capability.** Remove `w:vanish` runs, and white-on-white runs where `white_applied_runs > 0`. Until this exists, `strip` is an action `DEFAULT_POLICIES` cannot honestly name for `hidden_text`.
- **(c) The gate is the control.** A release under an external-facing policy carrying any flag-only finding cannot reach `done` without an affirmative per-finding operator decision.
- **(b) Refusal is the fallback**, not a third option: it is what the gate does for the cases the stripper cannot handle honestly — principally white-on-white text, where removal changes visible content and the postcondition ("the reader can now see this") is not machine-checkable the way `w:vanish` removal is.

Why both, stated plainly: **the gate without the stripper is a one-option choice.** Today an operator who clicks Approve on `hidden_text` gets `flag` regardless — a gate on top of that would only ever offer "retain with a recorded basis", which improves the record without improving the document. The stripper is what turns the gate into a real choice: *remove it*, or *keep it and say why on the certificate*.

**Sequencing within the lane:** ship the gate first — it mutates no content, so it needs no visual-compare pass and can land while the stripper is still in proposal. Then the stripper lands behind it and the gate's second option becomes live.

**B2 — Proposal before code**, per repo convention (`docs/rfc3161-anchor-implementation-proposal.md`, `docs/release-packet-verification-and-anchoring-proposal.md`). It must state: what "removed" means for hidden text; the postcondition check (the model is `verify.py`'s `accept_all_deleted_text_absent` — prove the concealed *text* is absent from the derivative's plaintext, not merely that the markup stopped matching a detector); which cases fall to refusal instead; and what, if anything, changes for `privacy_only`'s byte-fidelity promise (intended answer: nothing).

**B3 — Re-scrub the Aurelia deliverable.** Blocked on the gate and stripper landing. Until then, the honest client communication is: *the derivative retains hidden-text formatting; the current release's certificate now discloses this as a limitation; no configuration of the product removes it today.* Do not re-issue a packet claiming otherwise.

**Done criteria:** proposal merged; gate implemented with a regression test that a hidden-text document cannot reach a `done` external release without either removal or an affirmative recorded decision; stripper implemented with a postcondition check proving the concealed text is absent from the derivative's plaintext; superseding release issued for the Aurelia matter.

---

## Lane C — Copy that no longer matches the code (PARALLEL, low risk)

All rows already exist in `docs/claim-copy-audit.md`; this lane executes them.

| # | Item | Where | Note |
|---|---|---|---|
| C1 | "Chain verified" → "Chain internally consistent (self-recomputed)" | `web/app/matters/audit/page.tsx:251` (audit row **A1**) | Matches the verifier's own vocabulary, which refuses `VALID`. One string. |
| C2 | Anchor copy made conditional | `web/app/matters/job/page.tsx:394`, `:1047` (rows **A3/A7**) | Both unconditionally say "no independent timestamp"; stale for TSA-anchored packets. |
| C3 | Pre-release anchor copy — **DECIDED**: describe the deployment's configuration | `web/app/matters/view/page.tsx:377` (row **A9**) | It sits in a *pre-release* disclosure, where the packet does not exist yet and its anchor is genuinely unknown. See the binding constraint below. |

**C3's binding constraint (owner, 2026-09-02):** configuration copy is useful to an operator *only for as long as it cannot be mistaken for completed anchoring evidence*. The string must describe an **intent** ("this deployment requests an RFC 3161 timestamp for each release packet; whether one was obtained is recorded in the packet itself"), never an achieved state, and must never appear on a surface a recipient reads as proof. This is the same discipline `tools/counselclear_verify_release_packet.py` already enforces on itself, so it belongs in the same place: extend `test_forbidden_claim_words_never_appear_as_affirmative_claims` so a pre-release surface cannot assert anchoring in the present or past tense. Without that test the copy will drift back into evidence language the first time someone tightens it for brevity.

**Dependency worth stating: C2 cannot be done properly today.** The UI has nothing to key off — `service/app/models.py` has no anchor column, and the anchor is computed inside `job_bundle` at download time and never persisted. Either (i) persist the anchor outcome on the `Release` row at bundle time and render from it, or (ii) reword to state the deployment's *configuration* ("this deployment requests an RFC 3161 timestamp; each packet records whether one was obtained") rather than a per-packet fact the UI cannot know. **(ii) is the right first move**; (i) is a schema migration that should ride Lane E.

This dependency is also why Lane A scoped `release_result.json`'s anchor field rather than deriving it from the packet: `release_result` is produced at release terminal, the packet at bundle download, and a refused release never gets a packet at all.

**Done criteria:** the three strings updated; `docs/claim-copy-audit.md` rows A1/A3/A7/A9 moved from flagged to resolved with the new text quoted.

---

## Lane D — Deployment posture (DECIDED, small)

**D1 — TSA egress is on by default.** `service/app/tsa.py:30,49-52`: an unset `COUNSELCLEAR_TSA_URL` returns `True` and defaults to `http://timestamp.digicert.com`. Zero-egress requires explicitly setting the variable to an opt-out value. The code documents this clearly and fails soft (5s timeout, one retry, falls through to unanchored with the limitation disclosed) — the gap is that it is not surfaced at deploy time.

The default is defensible: the anchor is what makes a packet externally verifiable, and it is the one claim in the system that does not rest on the operator's own key. The issue is that a privileged-matter deployment inherits an outbound call to a third party without being told.

**D1 — DECIDED (owner, 2026-09-02): the default stays on; surface the posture.** Emit `tsa_anchor: enabled|disabled` (and the resolved URL) in the startup posture log next to the existing worker-mode and clamscan warnings; document in `COUNSELCLEAR_PRODUCTION.md` that unset means DigiCert egress on every release, and that zero-egress deployments must opt out and thereby forgo external timestamps.

**Done criteria:** posture line present at startup; production doc states the trade-off in one paragraph; a test asserts the posture line reflects `anchor_enabled()`.

---

## Lane E — Durability (BACKLOG)

**E1 — Public-key durability.** `README.txt` in every packet honestly states that losing the deployment public key renders every packet issued under it unverifiable. Options, in rising order of cost: publish the key in each packet alongside a fingerprint the recipient records out of band; a signed key manifest with rotation and revocation; a durable public-key registry or organizational escrow. This is the reviewer's own "later" item and should stay later — but it is the last remaining single point of evidentiary failure.

**E2 — Schema evolution rule.** Lane A established the mechanism (archive prior bytes, resolve pins by declared version) and a test that enforces it (`test_superseded_schema_versions_stay_verifiable`). Write the rule down in `COUNSELCLEAR_DESIGN.md`: *a schema file's bytes may never change without bumping its `version` and archiving the prior bytes.* Cheap, and it prevents the next contract change from silently invalidating every issued packet.

**E3 — Persist the anchor outcome.** The migration behind C2(i). Also lets `release_result.json` eventually report the packet's real anchor instead of scoping around it.

---

## Sequencing

All three decisions are made; nothing is gated on an owner any more.

```
now        A (commit, +A7)  ──┬──►  C1, C3        ── parallel, no dependencies
                              ├──►  D1            ── parallel
                              └──►  E2            ── parallel
next       B-gate (no content mutation) ──► B2 proposal ──► B-stripper ──► B3 re-issue Aurelia
                              └──►  E3 migration ──► C2 (proper)
backlog    E1
```

**Parallelisable now:** A (commit), C1, C3, D1, E2. The only shared file is `docs/claim-copy-audit.md`, which C1 and C3 both touch — make them one commit.

**Serial:** B-gate → B2 → B-stripper → B3. The gate can start immediately, in parallel with everything in the "now" row, because it changes no bytes in any derivative. E3 → C2-proper runs alongside.

**Concurrency note:** this repo runs parallel sessions. `git status` currently shows untracked work from other sessions under `docs/legal-panel/` and `docs/counselclear-must-have-*`. Any lane commits only its own files.

## What this plan deliberately does not do

- **Does not re-issue the Aurelia packet yet.** Blocked on the stripper landing; re-issuing today would produce the same contaminated derivative under a different `reason` string.
- **Does not change `hidden_text` defaults ahead of the stripper.** The table may only name `strip` once the engine implements it; doing it in the other order would be a claim the code cannot honour.
- **Does not derive `release_result`'s anchor from the packet.** Not knowable at that point in the lifecycle without E3.
- **Does not touch `privacy_only`.** Its promise is byte fidelity apart from named identity fields; every Lane A and Lane B change is scoped away from it.

---

## Owner decisions — resolved 2026-09-02

| # | Decision | Outcome |
|---|---|---|
| **B1** | Hidden text | **Build the stripper AND gate the release.** Not alternatives — the stripper is the capability, the gate is the control, refusal is the fallback for cases the stripper cannot handle honestly. Gate ships first (mutates no content); stripper lands behind it. |
| **D1** | TSA egress default | **Stays on.** Surface the posture at startup and document the trade-off; do not change the default. |
| **C3** | Pre-release anchor copy | **Qualified yes** — describe the deployment's configuration, because it helps operators, *provided it never masquerades as completed anchoring evidence.* Enforced by test, not by care alone. |

No decisions are outstanding. Lane B is unblocked.
