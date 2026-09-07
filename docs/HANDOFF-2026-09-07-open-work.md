# Handoff: open work after the custody-audit remediation

**To:** the engineer or agent picking this up — including one arriving with no
history on this repo
**From:** the 2026-09-07 session
**Repo:** `~/watermarks-remover`, branch `feat/custody-record-truthfulness`,
HEAD `51c6b3f`, 36 commits ahead of `main`, pushed to the `fork` remote
(`github.com/naderalsheikh/watermarks-remover`). `origin` is the upstream
project and is not ours to push to.
**Suite baseline:** `1419 passed, 1 skipped, 1 failed` in ~8 min. **The one
failure is a flake and it is Task 1 below.** Read "State you are inheriting"
before concluding the tree is broken.

---

## Read this before touching anything

This product is sold on the truthfulness of its custody record. It sanitizes
legal documents and issues a signed packet asserting what was removed and what
remains. A green check over a false claim is the one defect it cannot absorb —
it is worse than a crash, because a crash is visible and a false certificate
travels to opposing counsel.

Two standing rules govern everything below. They are not style preferences.

1. **Never let a record claim more than the code enforces.**
   `docs/counselclear-strategy.md` §5: never say "clean", "safe", "removed",
   "verified" unless the claim is bound to deterministic behaviour **plus** a
   manifest/audit entry **plus** a regression test. A claim bound to a missing
   test is worse than an uncommented one, because it stops the next reader
   checking. This has already happened here twice: a comment cited a test file
   that did not exist, and a README asserted three isolation properties nothing
   enforced.

2. **If you cannot verify a claim, say so.** Write "not verified" in the commit
   message rather than implying you checked. A previous agent on this project
   reported coordination it had not done; that is worse than silence. The
   commits that follow this rule well are `996b3e1` (states plainly that real
   Microsoft Word was never used to confirm its central premise) and `8937851`
   — read both before writing your first commit message here.

A third rule, learned the hard way in the session that wrote this document:

3. **Do not pipe `pytest` into `tail` and then read the exit code.** The shell
   reports the *last* command in a pipeline, so `pytest … | tail -2` exits 0
   even when tests fail. This session reported "full suite green, exit 0" twice
   on that basis and was wrong both times; the failure in Task 1 had been there
   the whole time. See "Running things" for the correct invocations.

**Do not re-plan and do not re-prioritise.** Every task below is grounded in a
reproduction that was actually executed, and the reproduction is given so you
can re-run it rather than trust it. Do not report a task as done because it
looks done — each names the command that proves it.

---

## State you are inheriting

The tracked tree is clean. `ruff check service tools tests engine` passes.
Frontend `npm run lint` passes and `vitest` is 109 green.

**The suite baseline dropped from 1478 to 1420 and no tests were lost.**
Commit `7278848` moved the research harnesses to `research/`, and `pytest.ini`
sets `testpaths = tests`, so `research/tests`' **79 tests are no longer
collected**. 1478 − 79 = 1399, plus 21 added since = 1420, which is what the
suite now reports. If you want them, run `pytest research/tests` explicitly.
Do not "fix" this by widening `testpaths`; the quarantine is deliberate and
Task 9 explains why.

**`git status` carries untracked work from other sessions** under
`docs/legal-panel/` and `docs/counselclear-must-have-*`, plus `.DS_Store`
noise. This repo runs parallel sessions. **Never commit those files.** Stage
your own paths explicitly; never `git add -A` from the repo root.

---

## Running things

```bash
.venv/bin/python -m pytest                                   # full suite, ~8 min
.venv/bin/python -m pytest tests/test_foo.py                 # one file
.venv/bin/python -m ruff check service tools tests engine    # scope to these four
cd web && npm run lint && npx vitest run                     # frontend
```

Three gotchas that cost this session real time:

- **Do not add `-q`.** `pytest.ini` already sets `addopts = -q`; your second
  `-q` makes it `-qq`, which suppresses the summary line entirely. You get
  progress dots, no counts, and no list of failures.
- **Do not pipe to `tail`** if you intend to read the exit code (rule 3 above).
  Redirect to a file and read it, or let the command print in full.
- **Scope ruff to those four paths.** A previous run included `docs/` and
  modified another session's untracked files.

The full suite takes ~8 minutes. Do not run it per-edit; run the file your
change touches, and the full suite once before you commit.

---

## Task 1 — the F3.2 regression test is flaky, so the fix it guards is unproven (~2h)

**Start here.** It is small, fully reproduced, and it is the reason the suite
is not green.

**Bug.** `tests/test_release_anchor_record.py::test_concurrent_anchor_write_race_guarded_by_cas`
fails intermittently. It is the regression test added by `8937851` for
robustness finding F3.2 (concurrent bundle downloads losing an anchored
packet's digest). **A flaky regression test does not guard anything** — the
next person to see it red will re-run it, watch it pass, and move on.

**Evidence.** `tests/test_release_anchor_record.py:280-292`. Two threads meet
at a `threading.Barrier(2)` and each downloads the same bundle:

```python
def hit(tag):
    barrier.wait()
    r = orig_get(f"/v1/matters/{mid}/jobs/{jid}/bundle")
    z = zipfile.ZipFile(io.BytesIO(r.content))          # <-- raises here
    packet = json.loads(z.read("release_packet.json"))
    results[tag] = (packet.get("anchor") or {}).get("digest")
```

`threading.Thread` **swallows the exception**. When thread B raises, `results`
never gets a "B" key, and the assertion at `:292` reports:

```
assert results.get("A") and results.get("B")
AssertionError: assert ('0000…0001' and None)
```

**The test cannot distinguish "thread B lost a race" from "thread B crashed",**
and the failure message points at neither.

**Reproduced.** Isolated, it failed on iteration 2 of 3 and again on iteration
8 of 15; the failing run took 7.68s against a normal 1.4–2.3s, which points at
lock contention rather than logic. It did **not** reproduce in 15 runs under
`-s`, nor in 4 whole-file runs — unbuffered output shifts the timing enough to
hide it. Budget for a heisenbug; do not assume one clean run means fixed.

```bash
for i in $(seq 1 15); do .venv/bin/python -m pytest \
  tests/test_release_anchor_record.py::test_concurrent_anchor_write_race_guarded_by_cas \
  --no-header -p no:warnings 2>&1 | tail -1; done
```

**Do, in this order.**

1. **Make the failure legible first, before diagnosing.** Capture each thread's
   exception (`results[tag] = ("raised", exc)` or a `threading.excepthook`) and
   assert on it. You cannot fix what the test refuses to tell you.
2. **Then find out what thread B actually gets.** The likely candidate is the
   409 path in `job_bundle` (`service/app/main.py`) — a concurrent download
   returning a JSON error body, which `zipfile.ZipFile` then rejects as
   `BadZipFile`. Print `r.status_code` and `r.content[:200]` to confirm before
   assuming.
3. **Now the real question, and it is a design question, not a test question:**
   is a 409 to the second concurrent downloader **correct behaviour**? If it
   is, the test's premise — "both downloads succeed and acquire distinct
   digests" — is wrong and the test should assert first-writer-wins with the
   loser getting a clean 409. If it is not, F3.2's CAS fix has a gap and the
   *code* changes.

**Do not** paper over it with a retry, a `sleep`, a `@pytest.mark.flaky`, or by
loosening the assertion to `results.get("A") or results.get("B")`. The
assertion encodes what F3.2 claims to have fixed. If the claim is wrong, change
the claim in the open, in the commit message.

**Proves it:** the reproduction loop above, 30 consecutive iterations green,
**and** a stated answer to question 3 in the commit message.

---

## Task 2 — B3-D1: white-only hidden text falls past its own refusal (~2h)

**Bug.** `WHITE_ONLY_HIDDEN_REFUSAL` exists so a document whose only
concealment is white-on-white is refused with a named remedy, rather than
letting `strip` silently no-op and die later at the re-inspect gate. Its
condition misses the case where white-font rules are **declared but never
applied**, and that case then produces exactly the outcome the refusal was
written to prevent.

**Evidence.** `service/scripts/policies.py:513-533`:

```python
if int(legal.get("hidden_vanish") or 0) == 0 and int(
    legal.get("hidden_white_applied_runs") or 0
):
    raise PolicyError(f"{WHITE_ONLY_HIDDEN_REFUSAL}: …")
```

With `hidden_white_applied_runs == 0` and `hidden_white > 0`, the document
falls past the refusal into a strip with nothing to strip. The detector still
reports `hidden_white`, and the job dies at the verify gate with a generic
message naming no remedy.

**Reproduced on a real document** — the Aurelia matter that motivated this
whole lane (`data/counselclear-sjo/`, matter `03b44ae916864d4d`,
`sjo_agreement.docx`, 54,828 bytes). Read-only; write nothing into
`data/counselclear-sjo/`:

```python
import sys, pathlib; sys.path.insert(0, "service/scripts")
import engine_api
src = pathlib.Path("data/counselclear-sjo/local/matters/03b44ae916864d4d"
                   "/docs/a24123df26de4167/original/sjo_agreement.docx")

r = engine_api.inspect_path(src)
print((r.report["details"]["docx_legal"]))
# hidden_vanish: 0
# hidden_white: 119
# hidden_white_rule_parts: {"word/styles.xml": 119}
# hidden_white_applied_runs: 0
# hidden_white_applied_parts: []

engine_api.clean_to_bundle(src, pathlib.Path("/tmp/scratch"),
                           policy_id="external_sharing")
# CustodyError: verification failed: reinspect_targeted_gone
```

Passing `decisions={"hidden_text": "keep"}` succeeds — but that is the operator
knowing to hand-feed an acknowledgement flag to get past a gate that should
have refused with instructions.

**Do.** Widen the condition to `hidden_vanish == 0 and hidden_white > 0`, or
give the declarations-only case its own message. Either way the operator must
end up with a named remedy instead of `verification failed:
reinspect_targeted_gone`.

**Proves it:** a test in `tests/` building a DOCX with white-font rules in
`word/styles.xml` and **no** run applying them, asserting `PolicyError`
carrying `WHITE_ONLY_HIDDEN_REFUSAL` — not `CustodyError`.

**Read `docs/counselclear-custody-truthfulness-plan.md` §B3 first.** It records
the full finding, including why this document's "119 hidden things" turned out
to be 119 unused style declarations concealing nothing.

---

## Task 3 — migrations are never executed against data (~half a day)

**Gap, inherited from Task 9 of the previous handoff and still open.** No
migration is ever run against a populated database and **no `downgrade()` body
is ever executed** — every one is 0% covered. `tests/test_postgres_support.py`
is the only file that mentions alembic at all.

The chain is currently sound; it was hand-verified (0009→head on populated
data, and head→0009→base, preserving rows, FKs, indexes and
`uq_audit_events_matter_seq`). **The risk is the next migration.** On SQLite,
`batch_alter_table` is create-copy-drop-rename, and silently losing
`uq_audit_events_matter_seq` would remove the database-level backstop against a
forked audit chain — the tamper-evidence the whole product rests on — while
1,419 tests still passed.

**Do.** A test that seeds a populated database, runs `upgrade head`, then
`downgrade` back and `upgrade` forward again, asserting rows, foreign keys,
indexes and **`uq_audit_events_matter_seq` specifically** survive the round
trip.

**Proves it:** delete `uq_audit_events_matter_seq` from a migration locally and
watch your test go red. If it stays green it is not testing what it claims.

---

## Task 4 — format-blind promises: the detectors and removers (~1 day)

**Only step 1 of three shipped.** Commit `a093878` qualified the *copy* by
format, which closed the overclaim. The capability gaps are still open, and the
policy table still says `strip`:

| subtype | policy says | actually implemented for | evidence |
|---|---|---|---|
| `embeddings_ole` | `strip` | **DOCX only** | counted at `container_meta.py:1262` (`word/embeddings/`), removed at `:2747`. `policies.py:1167-1168` maps `xl/embeddings/` and `ppt/embeddings/` to the subtype, so the *ledger* knows about them while no inspector counts and no cleaner removes them. |
| `external_links` | `strip` | **XLSX only** | stripped at `container_meta.py:2893` (`xl/externallinks`). DOCX `attachedTemplate` and hyperlink rels survive with full UNC paths. |
| `hidden_text` | `strip` | **DOCX only** | no white-font-cell, `;;;` number-format, or off-slide-shape detector exists for XLSX/PPTX. |

**Reproduced by the 2026-09-05 audit** (re-verify before you start, do not take
it from this document): XLSX and PPTX carrying `oleObject1.bin` pass with the
payload byte-identical and a one-row disposition ledger; an XLSX with
`<color rgb="FFFFFFFF"/>` on "SETTLEMENT FLOOR IS 2.4M" and a `;;;` cell
produces **no findings**.

**Do.** Detectors first, then removers, one format at a time, each with its own
regression test. **Detectors before removers, always** — a remover without a
detector removes nothing and reports success. Follow the existing dialect: the
XLSX and PPTX detectors are already namespace-prefix-tolerant
(`xlsx_legal.py:24-41`), and the DOCX side was brought into line by `996b3e1`.

---

## Task 5 — ODF has a refusal but no capability (~1 day)

`0b5c597` shipped the honest refusal: under an outward-facing policy the engine
refuses ODT/ODS/ODP rather than emitting a clean record it cannot support
(`policies.py:859` `_ODF_UNSTRIPPABLE_SUBTYPES`, `:875`
`ODF_CONTENT_REFUSAL_MARKER`). That closed the false-clean-record defect and
left the capability unbuilt.

`container_meta.inspect_odt` still looks only for AI/C2PA markers — nothing for
`office:annotation`, `text:tracked-changes`, `text:display="none"`, embedded
objects or external links — and `clean_odt` drops `dc:creator` only when it
matches an AI-generator regex.

**Do.** Build the ODF legal inspector, then the cleaner, then narrow the
refusal to what genuinely remains unsupported. **Do not narrow the refusal
first.** There is no ODT/ODS/ODP fixture in `tests/fixtures/legal/` — you will
add the first one (see Task 7).

---

## Task 6 — the open robustness findings (~half a day)

`docs/robustness-audit-2026-09-06.md` is the full audit. Its three High
findings were fixed in `8937851`. Three remain, none of them High:

- **F1.2 (Medium)** `:29` — tempered-quadratic regexes over attacker-controlled
  bytes in the hot DOCX scan path. Suggested fix at `:38`: convert the four to
  `_iter_tag_blocks`-style two-regex scans, matching the linear helpers already
  in the file. **The audit did not run the blow-up to completion** — it
  established pattern shape only, and says so. Confirm the cost before you
  spend a day on it.
- **F2.3 (Medium)** `:65` — CPU amplification inside the worker, bounded only
  by the per-job wall clock. Verified by reading, not executed.
- **F5.4 (Low)** `:157` — worker stderr tail stored in `job.error` and surfaced
  to API consumers. Suggested fix at `:160`.

The audit's own coverage statement (`:168`) lists what it did **not** examine —
`xlsx_legal.py`, `av_meta.py`, `pdf_legal.py` regex inventories, the verifier's
2,528-line parser beyond its key-handling surfaces, `web/`, `deploy/`,
migration contents, `storage.py`'s S3 path, `oidc.py`, `dispatcher.py`. Read
that list before claiming a surface is covered.

---

## Task 7 — test corpus format skew (~half a day)

`tests/fixtures/legal/` holds `spa.docx`, `spa.txt`, `hidden.xlsx`,
`macro.docm`, `incremental.pdf`, `signed.pdf`, `gps.jpg` — **no PPTX and no
ODF at all.** Combined with Task 4 and Task 5, the two formats with the largest
capability gaps are also the two with the least fixture coverage.

Previously noted and still true: no PDF ever reaches a release packet,
certificate, or verifier in any test.

**Do.** Add a PPTX and an ODT to the legal corpus via
`tests/fixtures/legal/generate.py` (fixtures here are generated, not
committed as opaque binaries — follow that), and one end-to-end test carrying a
PDF through to the verifier.

---

## Task 8 — claim-copy audit, sections G onward (~half a day, do it last)

`docs/claim-copy-audit.md` now runs A–F. Rows F1–F3 were applied in `73f4a50`;
F4–F5 were found and closed in `3c1cce1`. The previous handoff called for a
full row-by-row audit of the increment-2 copy surface as **sections F–J**; only
F exists, and the transcript the rest was to be drawn from is gone.

**Do.** Re-audit the current copy surface from the code, in the format sections
A–F use. Two surfaces have no rows at all and both are outward-facing:

- **the privilege-log CSV/JSON export** (`main.py`, `GET
  /v1/matters/{id}/privilege-log`) — a new artifact whose entire purpose is to
  be read by opposing counsel. Its docstring overclaimed FRCP compliance until
  `3c1cce1`; the column headers and any UI copy around it have never been
  audited.
- **the `/verify` browser verifier** (`211e591`) — a verdict surface, which is
  the highest-risk copy category in this product.

**Do this last.** Copy should settle after the code it describes.

---

## Decisions that are not yours to make

Three open questions. Each has a real argument on both sides, and a wrong
unilateral answer is expensive. Surface them; do not settle them in a commit.

1. **B3-D2 — should `hidden_text_formatting` fire at all when
   `hidden_white_applied_runs == 0`?** A style declaration nothing uses conceals
   nothing, and raising it forces every such document through an
   acknowledgement whose recorded basis will always be "there was nothing
   there". But suppressing it is a detector-semantics change across every DOCX
   built from a Word template, and it trades a false positive for a possible
   false negative. **Keep it out of Task 2's commit**, whatever you think.

2. **Issuing a superseding Aurelia release.** The engine work is unblocked and
   the record would be materially better than the 2026-09-02 one — schema v3, a
   real disposition ledger, and 2,122 `w:rsid*` edit-session attributes
   stripped that the shipped derivative still carries. But issuing a custody
   packet to a live counterparty is an outward-facing legal act, and the path
   requires a `legal_justification` a person writes. **Owner's call.** Do not
   write to `data/counselclear-sjo/`.

3. **Whether `research/README.md`'s "product spine" should be widened.** It
   names `service/app/`, `web/` and `tools/`, but the commercial image also
   copies `service/scripts/`, which mentions the quarantined projects via
   `--synthid-dir` and `--ctrlregen-dir` flags inherited from upstream. This is
   **not** a licensing breach — those flags resolve an operator-supplied path,
   and the shipped code neither imports a harness nor hardcodes a `research/`
   path; `tests/test_research_isolation.py` pins exactly that. It is a
   documentation gap. Widening the README's wording is safe; widening the
   *test's* no-mention assertion to `service/scripts/` would fail today and is
   a scope decision.

---

## Order of work

Chosen so the suite becomes trustworthy first and the record stops overclaiming
early — not so the easy things go first.

1. **Task 1** — the flaky test. Nothing else is verifiable while the suite lies.
2. **Task 2** — B3-D1. Small, reproduced, unblocks the Aurelia decision.
3. **Task 3** — migration tests. Guards the audit chain before the next schema change.
4. **Task 4** — detectors, then removers.
5. **Task 5** — ODF capability.
6. **Task 6** — remaining robustness findings.
7. **Task 7** — fixture coverage. Can run in parallel with 4 and 5; it feeds them.
8. **Task 8** — copy, last.

---

## Definition of done, per task

- `.venv/bin/python -m pytest` green — **read the summary line, not the exit
  code of a pipeline** (rule 3)
- `.venv/bin/python -m ruff check service tools tests engine` clean — scope it
  to those four paths
- frontend touched? `cd web && npm run lint && npx vitest run`
- a regression test that **fails without your fix**, in the file the task names.
  Verify this by reverting your fix and watching it go red. A test that has
  never failed has not been shown to test anything.
- a commit message stating what you verified **and what you did not**
- `git status` shows only your own files staged
- if you found something the task did not predict, write it down where the next
  reader will find it — a doc commit is a legitimate deliverable here, and
  `51c6b3f` is the worked example
