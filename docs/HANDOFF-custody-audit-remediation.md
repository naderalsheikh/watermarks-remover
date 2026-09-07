# Handoff: custody-audit remediation

**To:** the engineer or agent picking this up
**From:** the 2026-09-05 session
**Repo:** `~/watermarks-remover`, branch `feat/custody-record-truthfulness`, 4 commits ahead of `main`
**Suite baseline:** 1421 passed, 1 skipped, ruff clean — **but see "State you are inheriting" first, the tree is not currently green.**

---

## Read this before touching anything

This is execution work, not a design brief. Every task below is grounded in a
verified reproduction, and the reproduction is given. **Do not re-plan, do not
re-prioritise, and do not report a task as done because it looks done — each
one names the exact command that proves it.**

Two standing rules for this repo, which govern everything below:

1. **Never let a record claim more than the code enforces.** This product is
   sold on the truthfulness of its custody record. A green check over a false
   claim is the one defect it cannot absorb. `docs/counselclear-strategy.md`
   §5: never say "clean", "safe", "removed", "verified" unless the claim is
   bound to deterministic behaviour **plus** a manifest/audit entry **plus** a
   regression test.
2. **If you cannot verify a claim, say so.** Write "not verified" in the
   commit message rather than implying you checked. A previous agent on this
   project reported coordination it had not done; that is worse than silence.

---

## State you are inheriting

Committed and green through `cc94250`. Two files are **uncommitted**, and one
of them **fails on purpose**:

| file | state |
|---|---|
| `tests/test_full_custody_chain.py` | 7 tests, all passing. Full lifecycle: upload → release → gate → strip → packet → offline verify. Commit as-is. |
| `tests/test_disposition_ledger.py` | 5 tests, **1 failing deliberately.** It asserts a `removed_unplanned` postcondition that does not exist yet. It is Task 1's specification. |

Do not "fix" the failing test by weakening the assertion. It encodes the bug.

The 4th audit (robustness/failure-paths: hostile input, resource exhaustion,
concurrency, secret leakage) **died on a rate limit before producing
findings.** Nothing in this document covers that surface. It still needs
doing — see Task 8.

---

## Where the findings came from

Three parallel adversarial audits of the 2026-09-02 → 2026-09-05 work. Each
reproduced its findings by running the engine, and I independently confirmed
the two most damning before writing this. Findings marked **(mine)** are
against code written in that same window — treat them as the highest-trust
items, because they were found by someone actively looking for reasons to
doubt them.

---

## Task 1 — `removed_unplanned` (mine, ~30 min)

**Bug.** `custody.build_dispositions` labels *any* retaining action whose
finding disappeared as `removed_confirmed` — a success. For a `keep` it is the
opposite: the operator asked for the finding to be **preserved** and the engine
destroyed it. Under `evidence_preservation` / `privacy_only`, whose entire
product is not touching things, the manifest records the violation as a
confirmed success.

**Evidence.** `service/scripts/custody.py:162-163`:
```python
elif action in _RETAINING_ACTIONS:
    postcondition = "retained_as_planned" if still_present else "removed_confirmed"
```

**Reproduced** by the audit: an ODT under `privacy_only` (policy row
`c2pa: keep`) emits
`{"subtype": "c2pa", "action": "keep", "present_after": false, "postcondition": "removed_confirmed"}`.

**Do.** Add `removed_unplanned` to the postcondition vocabulary. That means:
`custody.py` (the branch), `service/scripts/schemas/manifest.schema.json`
(the `disposition.postcondition` enum), a **schema version bump to v3 with v2's
bytes archived** under `schemas/archive/manifest.v2.schema.json` — this is
mandatory, see `docs/COUNSELCLEAR_DESIGN.md` "Schema evolution rule" — and the
certificate's `_POSTCONDITION_LABEL` map in `service/app/main.py` (~line 620),
where it should render red, not green.

**Proves it:** `.venv/bin/python -m pytest tests/test_disposition_ledger.py`
goes green with **no edit to the test's assertions**.

---

## Task 2 — the certificate's "Removed" list is not about the document (mine, ~1h)

**Bug, and the most serious §5 violation in the new surface.**
`engine_api._residual_metadata(policy_id, fmt)` takes only a policy id and a
format and returns a **fixed list** for any DOCX/PPTX under
`external_sharing`/`production`. A document that never carried a single
`w:rsid` or `w14:docId` still gets a printed custody certificate with a
`<h3>Removed</h3>` heading listing them.

**Evidence.** `service/scripts/engine_api.py:802-839`. The per-document truth
already exists and is thrown away: `container_meta.py:1967-1972` emits
`"scrub authoring exhaust: rsid attributes=N rsid session tables=N persistent docIds=N"`,
and only when a count is non-zero.

**Why it matters most here:** a printed certificate is the artifact most likely
to reach opposing counsel or an insurer with none of the surrounding UI.

**Do.** Either drive the "Removed" list from the real `exhaust_counts`, or
retitle the section to `What this policy strips` / `What this policy retains`.
The first is better. Note that `main.py:682-683`'s preamble is *already*
correct — it calls the section a policy position — so the defect is one
artifact speaking in two registers.

**Proves it:** a test in `tests/test_custody_truthfulness.py` sanitizing a
DOCX with **no** RSIDs and asserting the certificate does not claim RSIDs were
removed.

---

## Task 3 — `hidden_text_removed` prints "confirmed absent" about text that is present (mine, ~1h)

**Bug.** The content-level postcondition shares the stripper's blind spot.
`extract_docx_hidden_text` walks the same `_is_docx_body_part` set the stripper
walks, so any part the stripper skips is invisible to the check that exists to
catch the stripper skipping it.

**Evidence.** `verify.py:499-561`; `container_meta.py:2460-2498` and `:2652`
share the gate; `_is_docx_body_part` (`:1134-1147`) is far narrower than the
detector's `_is_docx_content_part` (`:1173`).

**Reproduced:** a DOCX with a `vanish` run in `word/document.xml` **and**
another in `word/glossary/header1.xml` gives
`hidden_text_removed = True: "1 concealed fragment(s) confirmed absent"` while
the glossary run survives verbatim. The job still fails overall — but only
because the byte-regex re-inspect is *broader* than the content oracle. **The
named content-level proof affirmatively certified absence of text that is still
there.**

Two adjacent cases where the backstop is also blind, so nothing fails at all:
- `w:altChunk` — a DOCX whose altChunk target is an embedded `.docx` with a
  `vanish` run and a `w:del` clause **passes verification with a clean ledger**.
- the namespace-prefix case in Task 5.

**Do.** Widen the extractor to every content part (not just body parts) while
leaving the *remover*'s scope decision alone, so a part the remover skips
becomes a loud failure rather than a false confirmation. Then decide
separately whether the remover should widen too.

**Proves it:** the glossary reproduction above must fail
`hidden_text_removed`, not pass it.

---

## Task 4 — action records silently truncate at 12 (~30 min)

**Bug.** `for m in msgs[:12]` at `service/scripts/policies.py:1207` drops every
cleaner message past the twelfth with no marker.

**Reproduced independently by two audits.** `tests/fixtures/legal/spa.docx`
produces **exactly 12** — it sits on the cap. Add 8 OLE parts and 8 customXml
parts: the derivative is fully clean, but the record stops at 12 and **all five
`authoring_props` scrubs vanish from the manifest**. The droppable messages
include the two `warning: {name} not well-formed XML; …` strings
(`container_meta.py:2646`, `:2657`), which are limitation disclosures.

**Do.** Either record all messages, or emit an explicit truncation record
naming how many were dropped. Never silently.

**Second, related defect at the same site** (`policies.py:1208-1224`): subtype
is inferred by substring-matching the cleaner's own prose with a final
`else "custom_xml"`, so dropping `word/embeddings/oleObject1.bin` is recorded
as `custom_xml|strip`. Fix both together; a prose reword in a cleaner
currently moves custody facts.

---

## Task 5 — namespace-prefix-literal detectors (**severe**, ~half a day)

**Bug.** Every DOCX legal detector matches the literal bytes `<w:ins`,
`<w:del`, `<w:delText`, `<w:vanish`. OOXML namespace **prefixes are
arbitrary** — binding the same URI to `wx:` is spec-valid and Word opens the
file identically. Such a document is reported as carrying no tracked changes,
never runs Accept All, and passes verification with a clean record.

**Evidence.** `container_meta.py:1111-1116`, `:1152-1171` (the gate deciding
whether `_docx_accept_all` runs at all), `:1488` (`_W_DELTEXT_OPEN_RE`, feeding
`extract_docx_deleted_text` — the verifier's *only* content-level oracle for
Accept All). **The XLSX and PPTX detectors are already prefix-tolerant**
(`xlsx_legal.py:24-41`, `container_meta.py:2895-2897`), so this is an internal
inconsistency, not a universal limitation.

**Reproduced:** two DOCX files differing only in prefix, each with one deleted
clause and one vanish run:

| | `w:` | `wx:` |
|---|---|---|
| findings | tracked-changes + hidden-text | *authoring_props only* |
| `accept_all_deleted_text_absent` | pass | **check never added** |
| verify | pass | **pass** |
| deleted clause in derivative | removed | **survives** |

**Do.** Make the detectors prefix-tolerant (`<(?:\w+:)?ins\b`), matching the
XLSX/PPTX dialect already in the repo. Be careful: `_DOCX_LEGAL_MARKUP_RE` is
the gate for the *whole* XML-aware pass, so widening it changes which parts get
parsed — run the full suite and watch the golden fixtures.

**Not verified by the audit:** that Word actually opens the `wx:` file
identically. The claim rests on OOXML prefix arbitrariness. **Confirm in real
Word before writing a commit message that asserts it.**

---

## Task 6 — one-format implementations behind format-blind promises (**severe**, ~1 day)

Cross-corroborated by two independent audits.

| subtype | policy says | actually implemented for |
|---|---|---|
| `embeddings_ole` | `strip` | **DOCX only** — `xl/embeddings/` and `ppt/embeddings/` are never even counted (`container_meta.py:1199-1200`) |
| `external_links` | `strip` | **XLSX only** — DOCX `attachedTemplate` + hyperlink rels survive with full UNC paths |
| `hidden_text` | `strip` | **DOCX only** — no white-font-cell, `;;;` number-format, or off-slide-shape detector exists at all |
| everything | *various* | **ODT/ODS/ODP have no legal inspector and no legal cleaner** (Task 7) |

**Reproduced:** XLSX and PPTX carrying `oleObject1.bin` pass with the payload
byte-identical and a one-row disposition ledger. An XLSX with
`<color rgb="FFFFFFFF"/>` on "SETTLEMENT FLOOR IS 2.4M" and a `;;;` cell
produces **no findings**.

**Why it is an overclaim rather than an honest gap:** the certificate's empty
state is carefully hedged and genuinely covers pure detection gaps — but
`main.py:851` shows the operator *"strips comments, external links, embedded
objects, and custom XML"* with **no format qualifier**, and the policy row says
`strip`.

**Do, in this order:** (1) make the promise honest immediately — qualify the
profile/policy descriptions by format, which is a copy change and closes the
overclaim today; (2) add the detectors; (3) add the removers. Step 1 is not
optional and should ship first.

---

## Task 7 — ODT/ODS/ODP (**severe**, ~1 day)

**Bug, and unlike Task 5 it needs no adversary — this is an ordinary
LibreOffice document.** For every non-OOXML, non-PDF container,
`apply_actions` **ignores the resolved policy entirely**, calls one generic
cleaner, and emits a single `ActionRecord("file_metadata", "strip",
"odt sharing-clean executed")`.

**Evidence.** `policies.py:1227-1239` (`mutating` is computed and never used);
`container_meta.py:2854-2885` (`inspect_odt` looks only for AI/C2PA markers —
nothing for `office:annotation`, `text:tracked-changes`,
`text:display="none"`, embedded objects, external links);
`container_meta.py:3106-3186` (`clean_odt` drops `dc:creator` **only if it
matches an AI-generator regex**).

**Reproduced:** an ODT with a tracked deletion, an `office:annotation` reading
"COMMENT: do not reveal the reserve to them" authored by "Jane Associate", and
`dc:creator` in `meta.xml`, run under `external_sharing` — **verify passes**,
limitations empty, certificate prints the policy description claiming comments
are stripped and tracked changes accepted, and **all of it survives verbatim**.
Under `privacy_only` the same file keeps `dc:creator`, for a policy whose
entire stated product is stripping PII authoring fields.

**Do.** The honest short-term fix is a **refusal**, following the
`_PDF_UNSTRIPPABLE_SUBTYPES` precedent already in the repo: if the engine has
no legal inspector for a format, an outward-facing policy must refuse rather
than emit a clean record. Build the ODF inspector/cleaner afterwards.

---

## Task 8 — the audit that never ran

The robustness sweep died on a rate limit with zero findings. Nothing in this
document covers: hostile-input handling (zip/XML budget bypasses, catastrophic
regex backtracking, recursion limits against deeply nested XML — note
`_walk_hidden_runs` is recursive and attacker-controlled), resource exhaustion
and hangs, concurrency and audit-chain races, partial-write/data-loss paths, or
secret leakage in logs and error messages.

Two concurrency leads already surfaced elsewhere, both **verified by reading,
not reproduced**:
- `main.py:3730-3732` writes `releases.last_anchor_*` with no locking or
  compare-and-set. Two concurrent bundle downloads each produce a validly
  anchored packet, but the row records one digest — inverting the column's
  stated purpose ("lets a reader tie this row to a specific packet they hold").
- `main.py:2974-2990` — `cancel_batch` is the only route that checks existence
  **before** permission, giving an unauthorised principal a 403/404
  id-existence oracle. No ACL test covers it.

---

## Task 9 — verifier and coverage gaps (~half a day)

- **The verifier passes a packet containing undeclared extra files.**
  Reproduced: adding `derivative/SECRET-second-document.docx` to a valid packet
  yields `report.valid == True` and the filename appears nowhere in the report.
  `tools/counselclear_verify_release_packet.py:1855` checks declared names
  against declared hashes and never enumerates what else is in the archive.
  **Fix: make packet membership closed.**
- **`audit_refs` is never cross-checked against `--audit-csv`**
  (`:1015` pulls only `manifest_sha256`/`derivative_sha256`).
- **No migration is ever run against a populated database, and no
  `downgrade()` is ever executed** — every `downgrade` body is 0% covered. The
  chain is currently sound (hand-verified: 0009→head on populated data, and
  head→0009→base, preserve rows, FKs, indexes and
  `uq_audit_events_matter_seq`). The risk is the *next* `batch_alter_table`
  migration, which on SQLite is create-copy-drop-rename: losing that unique
  constraint is a silent loss of audit tamper-evidence, and 1421 tests would
  still pass.
- **No PDF ever reaches a release packet, certificate, or verifier in any
  test.** Format skew across the suite: docx 365 fixture mentions, pdf 85,
  pptx 6, odt 0. There is no PPTX fixture in the legal corpus at all.

---

## Task 10 — claim-copy increment 2

A full row-by-row audit of the new copy surface exists in the session
transcript and should be transcribed into `docs/claim-copy-audit.md` as
sections F–J, in the same format as the existing rows. The three highest-value
items:

- **`"VERIFIED under a SELF-PUBLISHED key (provenance unconfirmed)"`**
  (`verify script:418`) leads with the green word; every other verdict in that
  tool leads with the negation (`NOT VERIFIED`, `NOT EXTERNALLY ANCHORED`,
  `UNSIGNED`). Proposed: `"SELF-PUBLISHED KEY — signature checks out,
  provenance unconfirmed"`.
- **`"Externally anchored (RFC 3161)"`** (`page.tsx:376`) means *a token was
  obtained*, not *a token was verified* — the distinction lives in a sentence
  above the pill that no screenshot includes. Proposed:
  `"Timestamp obtained (RFC 3161) — not verified here"`.
- **`"removed — confirmed absent on re-inspect"`** (`main.py:625`) asserts a
  content-level fact that only `hidden_text` actually has an oracle for.
  Everything else rests on a detector going quiet — which `verify.py:483-489`
  says in its own words. Proposed: `"no longer observed by the post-sanitize
  re-inspect"`.

---

## Order of work

Ship in this order. It is chosen so the record stops overclaiming as early as
possible, not so the easy things go first.

1. **Task 1** — commit the two pending test files with it.
2. **Task 6 step 1** — qualify the format-blind promises. Copy change, closes a
   severe overclaim today.
3. **Task 7** — ODF refusal. Same reasoning: honest refusal beats a false clean
   record, and it is far cheaper than the inspector.
4. **Task 2, Task 4** — certificate truthfulness.
5. **Task 3, Task 5** — the two places a *content-level proof* is
   circumventable. Task 5 needs real-Word confirmation first.
6. **Task 9** — verifier packet-closure, then migration tests.
7. **Task 8** — the missing audit. Re-run it as its own pass.
8. **Task 10** — copy, once the code it describes has settled.

## Definition of done, per task

- `.venv/bin/python -m pytest` green (~7 min; do not run it per-edit)
- `.venv/bin/python -m ruff check service tools tests engine` clean —
  **scope it to those four paths**; a previous run included `docs/` and
  modified another session's untracked files
- a regression test that fails without the fix, in the file the task names
- a commit message stating what was verified and what was not
- `git status` shows only your own files staged; this repo runs parallel
  sessions and carries untracked work from others under `docs/legal-panel/`
  and `docs/counselclear-must-have-*` — **never commit those**
