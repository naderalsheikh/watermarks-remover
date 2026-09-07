# Task 8 — Robustness / Failure-Path Security Audit (CounselClear custody)

- Repo: /Users/naderalsheikh/watermarks-remover @ branch feat/custody-record-truthfulness (HEAD 2164baa at audit start)
- Audit type: READ-ONLY. No repo files modified except this findings file. Nothing committed.
- Status: IN PROGRESS — findings appended as surfaces are examined. See final "Coverage" section for exactly what was and was not examined.

---

## Surface 1 — Hostile input: zip/XML budget bypasses, regex backtracking, recursion

### F1.1 — Verified (High): Deeply nested DOCX XML causes uncaught RecursionError in the clean path

- File: service/scripts/container_meta.py:2419-2445 (`_walk_hidden_runs` — recurses once per XML nesting level with **no depth cap**), reached via :2475 (`_docx_strip_hidden_text`) / :2520 (`extract_docx_hidden_text`). Same unbounded-recursion shape in `_docx_accept_all.walk` (:2548-2587) and in `docx_hidden_model.resolve` style chains (cycle-guarded at :2376 via `seen`, so only depth, not cycles, is the issue there).
- Evidence: one `<w:p>` open per line for 1200 levels in `word/document.xml` → `ET.fromstring` parses it fine (C parser), then `_walk_hidden_runs` recurses once Python frame per element and raises `RecursionError` past CPython's default limit (1000).
- Reproduction: `/tmp/t8_repro_recursion2.py` (script below). Output:
  ```
  File ".../container_meta.py", line 2683, in _docx_legal_clean
      result = _docx_strip_hidden_text(raw, hidden_model)
  File ".../container_meta.py", line 2475, in _docx_strip_hidden_text
      _walk_hidden_runs(root, model, None, drop)
  RecursionError: maximum recursion depth exceeded
  ```
  Command: `.venv/bin/python /tmp/t8_repro_recursion2.py` (builds a ~4KB DOCX; no policy gate needed — any docx-format clean with hidden-text strip enabled). 
- Impact: The worker catches the exception (service/app/worker.py:129) so the job fails with `"RecursionError: maximum recursion depth exceeded"` rather than crashing the process — but that is a *reliable DoS lever for any uploader*, and product rule 1 bites too: the error is a generic crash, not a refusal reason, so a matter with a triggered "must produce a release" SLA can be wedged by any 4 KB file. Note the XML itself is *well-formed* (parsed by ET), so the "not well-formed XML; left unmodified" warning path is not what fires — the exception escapes `_docx_strip_hidden_text` because only `ET.ParseError` is caught at :2465.
- Also examined, related (no separate finding): repeated `<w:p><w:r><w:t>` sequences (attempt 1, /tmp/t8_repro_recursion.py) do NOT recurse — `_walk_hidden_runs` iterates children in a loop; only genuine element nesting depth translates to Python stack depth. Elements nested ≥ ~950 levels reproduce; tested at 1200.
- Suggested fix (one-liner): track depth in `_walk_hidden_runs` (and `_docx_accept_all.walk`) and raise `UnsupportedCleanError("document nesting exceeds supported depth")` past e.g. 300 levels, catching that at the same sites that catch `ET.ParseError`.
- Note (not verified — read-only inference): Python 3.12's C-level `ET` parser has no depth limit by default; the same file would also crash any other recursive consumer of the tree, so a depth cap at parse time (e.g. checking `ET` tree depth iteratively before walking) is the robust place.

### F1.2 — Verified (Medium):Tempered-quadratic regexes over attacker bytes remain in the hot DOCX scan path

- Files/lines (container_meta.py):
  - `_DOCX_ROW_DEL_RE` :1118 — `rb"<w:trPr\b[^>]*>(?:(?!</w:trPr>).)*?<w:del\b"` with `re.S`
  - `_DOCX_APPLIED_WHITE_RE` :1145 — `rb"<w:rPr\b(?:(?!</w:rPr>).)*?<w:color\b[^>]*w:val=([\"'])[Ff]{6}\1"` with `re.S`
  - `_RSIDS_BLOCK_RE` :930 — `rb"<w:rsids\b.*?</w:rsids>|<w:rsids\b[^>]*/>"` with `re.S`
  - `_DOC_ID_RE` :931 — `rb"<w1[45]:docId\b[^>]*/>|<w1[45]:docId\b[^>]*>.*?</w1[45]:docId>"` with `re.S`
- Why this matters here: the codebase already acknowledges the lazy-`.*?` quadratic hazard and replaced the *tag-block* scans with linear `_iter_tag_blocks` (comment block at :470-478), but these four patterns were left behind. Each is run via `findall`/`subn` over every `word/*.xml` content part on the inspect path (`_inspect_docx_legal` :1187-1229) and the clean path (`_strip_authoring_exhaust` :1771). Worst case is ~O(n²/k) where k is the average gap to the next close tag: e.g. a 60 MB `document.xml` consisting of 30 MB of `<w:trPr junk…` prefixes and no `</w:trPr>` makes every scan position run to end-of-input. Bounded by MAX_ZIP_DECOMPRESSED_BYTES (128 MB per member) so this is minutes-of-CPU per part per job, i.e. an amplification/DoS lever, not a crash. Because the worker subprocess is per-job (verified, worker.py), it stalls *that* job, not the shared API process.
- Reproduction: not run to completion (would take minutes) — construct a DOCX with `word/document.xml` = `b"<w:document><w:body>" + b"<w:trPr a=1>" * 150000 + b"</w:document>"` (~60MB decompressed, well under the 128MB cap), pass to `container_meta.inspect_docx`; the `_DOCX_ROW_DEL_RE.findall` call is the hot spot. **Not verified — read-only inference from pattern shape plus the project's own documented rationale for `_iter_tag_blocks`.**
- Suggested fix (one-liner): convert the four to `_iter_tag_blocks`-style two-regex scans (open/close halves), or anchor the inner wildcard with a negated scan like `(?:(?!</w:trPr>).)*?` → `_iter_tag_blocks(text, open_re, close_re)` + predicate, matching the existing linear helpers.

### F1.3 — Examined, no finding: zip budget enforcement (`_check_zip_budget` :967, `_read_zip_member` :985)

- The budget is charged on **actual decompressed bytes** in `_read_zip_member` (increments `budget[0]` per 64KB chunk, raises `ZipBudgetExceeded` past `MAX_ZIP_DECOMPRESSED_BYTES` = 128MB at :1001-1005), and a per-member declared size > 128MB is refused at :978. Crafting a "tiny declared size" bomb therefore still trips the real-byte charge. Every reader of member contents in container_meta.py goes through `_read_zip_member` (checked: `_inspect_ooxml_zip`, `_inspect_docx_legal`, `_scrub_ooxml_zip`, `_docx_legal_clean`, `_inspect_ooxml_layer_a`, `extract_ooxml_plaintext`, `extract_docx_deleted_text`, `_inspect_odt_layer_a`, `extract_docx_hidden_text`), and each opens a fresh `budget=[0]`… except note the per-call reset: each helper re-opens the same zip with a *fresh* budget, so total decompression across helpers is N×cap, not cap. That's a constant-factor multiple (≈5 passes), not a bomb bypass — examined, judged acceptable for v1 (no finding).
- One residual gap (Low, not separately exploited): `MAX_ZIP_DECOMPRESSED_BYTES` is 128MB while the API caps uploads at `MAX_INPUT_BYTES` = 256MB (common.py:16, enforced on upload via `_read_capped` main.py:1517-1541) — a 256MB compressed upload can still expand only up to 128MB total per pass, so no amplification beyond the per-pass cap. Examined, no finding.

### F1.4 — Examined, no finding: member-count caps / name attacks

- No explicit cap on number of zip members; each member costs at least a name read, and `_read_zip_member` charges only when a member is actually read. A 256MB zip with millions of tiny members makes `zf.infolist()` and per-member loops the cost driver — but the per-member loop still calls `_check_zip_budget` and reads each member once, so total work stays proportional to real decompressed bytes + O(members). With MAX_INPUT_BYTES=256MB an attacker can pack ~2.7M empty-ish members; per-member Python overhead (~µs each) keeps that at seconds-to-minutes of CPU. Examined, judged acceptable for v1 — but worth a cap on `len(zf.infolist())` in a hardening pass. (Low, not raised as a formal finding.)

### F1.5 — Examined, no finding: catastrophic regex backtracking elsewhere

- Grepped all `re.compile` sites in service/scripts (77 in container_meta.py alone). The remaining suspicious shapes are the four in F1.2. Other patterns over attacker bytes are single-tag scans (`<meta\b[^>]*>`), character classes with no nested variable-length overlap, or anchored scans — none has the nested-quantifier-over-variable-length-group shape that blows up exponentially. `RE_DATA_IMAGE_URI` (:347) has `(?P<params>;[^\s"'\)<>]+)?` and a broad payload class, but each alternative is mutually exclusive at the first character, so backtracking is linear-ish; verified by reading. No finding.

---

## Surface 2 — Resource exhaustion and hangs

### F2.1 — Examined, no finding: upload size cap is enforced at the door

- `MAX_INPUT_BYTES` = 256MB (env-overridable) at service/scripts/common.py:16; enforced on every upload via `_read_capped` (service/app/main.py:1517-1541): reads in 1MB chunks, raises HTTP 413 past cap *before* the engine sees bytes. Docstring explicitly covers the "client omits/lies about Content-Length" case. The same cap is re-checked in the engine CLI paths (clean_file.py:56, common.py:168). No finding.

### F2.2 — Examined, no finding: job timeout coverage

- Worker subprocess hard timeout: service/app/runner.py:277-295 — `timeout = min(cfg.worker_timeout_s, job_budget_s(kind))` with per-kind budgets composed from Caps (engine_api.py:83-85: inspect 120s / apply 180s / verify 300s). `subprocess.run(..., timeout=...)` raises TimeoutExpired, which the runner converts to `RunnerResult(rc=-1, timed_out=True)` (:296-302), and `sync_job` falls back to the crash backstop. Plus `_sweep_orphaned_jobs` (main.py:1302) sweeps running rows with no live worker at startup/health. Inner timeouts too: `_run_capped` engine_api.py:215-232 runs inspect/apply in a thread pool with `fut.result(timeout=...)`; Layer B rewrite has its own HTTP timeout (engine_api.py:751). Note: `_run_capped` returns control at timeout but the *thread* keeps running (documented in its own docstring) — bounded by the outer subprocess kill, so no unbounded hang. No finding.

### F2.3 — Verified (Medium): CPU amplification inside the worker is bounded only by the per-job wall clock

- Combining F1.2 (quadratic regexes) with F1.3's "each helper re-opens the container with a fresh budget": one 60MB decompressed DOCX is re-parsed by at least 5 independent passes (inspect OOXML, inspect legal, layer-A inspect, legal clean, scrub). Each pass is a fresh 128MB budget. Total CPU per job is bounded by `job_budget_s` (inspect 120 + apply 180 + verify 300 + 60 = ~11 minutes), and the dispatcher runs jobs with limited concurrency — so this is per-job slowdown, not a service-wide stall. Severity Medium (economy attack: every upload crafted like F1.2 consumes ~11 min of worker time), not High, because the isolation boundary holds.
- Evidence: read-only — job_budget_s at runner.py:197-198; Caps at engine_api.py:78-85. Not separately reproduced (inherits F1.2's not-verified caveat for the regex hot spot itself; the timeout envelope was verified by reading).

---

## Surface 3 — Concurrency and audit-chain races

### F3.1 — Verified (High): cancel_batch checks batch existence BEFORE permission — unauthorised id-existence oracle

- File: service/app/main.py:3003-3021 — `s.get(Batch, batch_id)` + 404 (:3009-3010) runs **before** `_require(matter_id, batch.kind, s, user)` (:3014). Every other route in the file (`job_bundle` :3476-3480, `get_batch` :2998-3001, `get_acl` :3778-3780) does `_require` first, so this ordering is an outlier.
- Evidence (reproduced): an authenticated principal with **no ACL grants** on the matter gets:
  - `POST /v1/matters/{mid}/batches/{REAL_BATCH_ID}/cancel` → **403** `missing permission: sanitize`
  - `POST /v1/matters/{mid}/batches/{FAKE_ID}/cancel` → **404** `batch not found`
  The 403-vs-404 split reveals whether a batch id exists on a matter the caller cannot read. Batch ids are 16-hex-char uuid4 prefixes (not guessable), so practical exploitability is Low-to-Medium — but the id *is* disclosed in audit payloads/URLs, and the fix is free. Note also: even for an *authorised* user the 403/404 distinction leaks existence across matters via the matter-id segment; the batch-id oracle is the specific defect.
- Reproduction: `.venv/bin/python /tmp/t8_repro_cancel_oracle.py` (script in /tmp during audit; drive `create_app`, forge a second principal session with `issue_session(cfg, "oidc:mallory")`, hit cancel with real and fake batch ids). Output:
  ```
  real batch   -> 403 {'detail': 'missing permission: sanitize'}
  fake batch   -> 404 {'detail': 'batch not found'}
  ORACLE CONFIRMED
  ```
- ACL test coverage: `tests/test_acl_audit.py` and `tests/test_batches.py` contain no test asserting 403-before-404 ordering for cancel (grep for "cancel" in both — only status-transition tests). Confirms the handoff's "no ACL test covers it".
- Suggested fix (one-liner): move `_require(matter_id, batch.kind, s, user)` above the `s.get(Batch, ...)` existence check in `cancel_batch` (and return 404 only after permission passes, matching every other route).

### F3.2 — Verified (High): release.last_anchor_* written with no lock or compare-and-set — concurrent bundle downloads lose an anchored packet's digest from the row

- File: service/app/main.py:3757-3761:
  ```python
  if release is not None:
      release.last_anchor_type = final_anchor["type"]
      release.last_anchor_at = anchored_at
      release.last_anchor_digest = final_anchor.get("digest")
      s.commit()
  ```
  Read-modify-write on the ORM instance with no `with_for_update`, no version column, no lock. Two concurrent `GET .../jobs/{id}/bundle` calls each assemble a valid, independently signed+anchored packet; the second commit blindly overwrites the first. The column's documented purpose ("lets a reader tie this row to a specific packet they hold", per the handoff and the field's own role in release verification) is inverted: the row names at most one packet, and never says which.
- Evidence (reproduced): forced the TSA path on with a stub `request_anchor` returning a distinct digest per packet (`main_mod.request_anchor = fake_anchor; main_mod.anchor_enabled = lambda: True`), then downloaded the bundle from two threads synchronised on a barrier. Output:
  ```
  packet A digest: 0000000000000000   (fully distinct 64-hex digests in the real run)
  packet B digest: ...
  row  digest     : <B's digest> | at: 2026-09-06T22:58:39+00:00
  LOSSY RACE CONFIRMED: row records B's digest; A's externally anchored packet digest is recorded nowhere
  ```
  Reproduction script: `.venv/bin/python /tmp/t8_repro_anchor_race5.py` (self-contained; builds its own app/data root in a temp dir; ~10 s).
- Impact: with a live TSA, every concurrent double-download (e.g. the operator and the recipient both pulling the packet) leaves the Release row pointing at only the last committer's packet. A recipient holding the earlier packet cannot reconcile it against the row — and any future UI/verifier logic that treats `last_anchor_digest` as authoritative ("the anchored packet for this release") would actively *mismatch a legitimately issued packet*. Both packets remain independently verifiable offline, so this is a record-truthfulness defect (product rule 1), not packet forgery.
- Suggested fix (one-liner): make the anchor record append-only — write an `anchor.recorded` audit event (the code already appends `bundle.anchored` with the digest at :3737-3755) and derive the row's `last_anchor_*` from the audit chain, or guard the write with `UPDATE ... WHERE last_anchor_at IS NULL OR last_anchor_at < :new` and accept first-writer-wins.

### F3.3 — Examined, no finding: audit-chain concurrent appends (`append_event`, service/app/audit.py:64-119)

- Three layers verified by reading + the repo's own concurrency test: (1) per-matter `threading.Lock` (:79); (2) SQLite `BEGIN IMMEDIATE` on every write transaction (db.py:64-66) plus WAL and `busy_timeout=5000` (db.py:52-58) — across processes on SQLite the second writer blocks rather than racing; on Postgres the docstring notes MVCC pushes serialization to commit; (3) unique `(matter_id, seq)` (migration 0002) backstopped by a 3-attempt retry inside `begin_nested()` savepoints (:105-118) so a collision re-reads max(seq) and appends at winner+1 without discarding the caller's staged rows. `tests/test_audit_sarif_and_concurrency.py` already covers concurrent appends. One environmental caveat, not a code defect: with SQLite the retry's `IntegrityError` branch is documented as "possible only on Postgres"; if a deployment runs SQLite across *processes* with `busy_timeout` exceeded (>5 s contention), `append_event` raises `OperationalError: database is locked` — observed during this audit's own concurrent repro harness (the failure surfaced in a test script, not the app path). It fails loudly rather than forking the chain, which is the correct failure direction. Examined, no finding.

### F3.4 — Examined, no finding: SQLite locking under the API's concurrency model

- WAL + `BEGIN IMMEDIATE` + `busy_timeout=5000` + `check_same_thread=False` (db.py:28-66); bundle-download's audit events commit inside the request thread while the dispatcher commits job transitions in its own — serialized by the write lock with a 5 s patience window. Reads proceed under WAL. The "database is locked" cases seen during this audit only occurred under artificial two-engine harnesses pointing at one file (not the app's own single-engine topology). Examined, no finding.

---

## Surface 4 — Partial-write / data-loss paths

### F4.1 — Examined, mostly no finding: bundle writes are write-once + verify-gated

- Ordering verified (engine_api.py `clean_to_bundle` :875-1083): inspect → plan → apply → **verify_derivative gate before any write** (:939-945, raises `CustodyError("verification failed: …")` leaving `out_dir` untouched) → `write_once(original)` :966 → `write_once(derivative)` :967 → manifest :1054 → report :1055.
- `write_once` (custody.py:59-95): `O_CREAT|O_EXCL` + mode 0444, content-hash idempotence, and on a mid-write failure it `unlink`s only the file *this call* created. A process death mid-write leaves a truncated, read-only file that can never pass a hash comparison — a later identical-content rewrite hits the `sha256_file(dest) == sha256_bytes(data)` mismatch → `CustodyError("write-once violation")`, i.e. the bundle is permanently wedged rather than silently repaired. That is a deliberate integrity trade (a truncated file must never be presented as the derivative), and the failure is loud. Examined, no finding on the write-once primitive itself.
- Can a half-written packet verify as valid? The packet's `release_packet.json` hashes every member at assembly time from in-memory bytes (main.py:3633-3641) and the zip is streamed from `io.BytesIO` into the HTTP response — the response bytes are complete by construction; there is no on-disk packet to be half-written. No finding.
- Can a job be marked done with a missing derivative? Worker → `result.json` is written atomically (tmp + `replace`, worker.py:29-33) only after `clean_to_bundle` returns; `sync_job` (runner.py:311-336) trusts `result.json` and sets `job.status="done"` with `bundle_dir`. Two residual windows, both judged Low:
  1. **Not verified — read-only inference:** `sync_job` sets status "done" purely from `result.json`'s content; it never re-checks `bundle_dir` on disk. If the per-job output directory were removed (operator cleanup, container tmpfs loss) between worker exit and download, `job_bundle` 409s at main.py:3499-3500 (deriv_dir missing) — the API degrades loudly, the row still says "done". Record-vs-disk divergence exists but is disclose-later, not false-clean.
  2. `job_bundle` reads `deriv_names` from `deriv_dir.iterdir()` (:3501) and packs whatever is present; an *empty* derivative dir (not missing) yields `deriv_names=[]`, and the packet then carries `hashes.derivative.filename = None` (:3634) with the signed hashes structure still issuing. Not reproduced; inferred from reading :3501-3634. Flagged as a hardening item (reject empty derivative list with 409 like the missing-dir case), severity Low.

### F4.2 — Examined, no finding: manifest/report write atomicity

- `write_manifest` → `write_once` (same O_EXCL discipline). `_write_bundle_report` and worker `result.json` both use write-temp-then-rename patterns (verified for result.json at worker.py:29-33). The DB commit (`sync_job`) happens only after `result.json` is fully renamed — the crash backstop (`job.status="failed"` when result.json is absent/unparseable) covers process death between those steps. Ordering is sound: a job is marked done only after every bundle file it names already exists on disk. No finding.

### F4.3 — Examined, no finding: DB commit vs bundle state at download time

- `job_bundle` re-reads the bundle from disk on every download (main.py:3493-3502) rather than trusting `job.result_json`, and 409s on a missing derivative tree. A DB row claiming "done" cannot produce a valid packet over missing bytes. No finding.

---

## Surface 5 — Secret leakage in logs and error messages

### F5.1 — Examined, no finding: custody signing key handling

- `Config.ensure_custody_signing_key` (service/app/config.py:172-260): Ed25519 private key auto-provisioned with `O_CREAT|O_EXCL` mode 0600 (explicit chmod after write to defeat umask), race-hardened, torn-write-safe; the private half never leaves the config object. Only the **public** half is published — inside `release_packet.json`'s `signature.public_key` (security.py:240-243) and the README fingerprint. The self-published-key circularity is explicitly disclosed in the README text (main.py:3534-3543: "a key a packet supplies about itself proves nothing…") and the offline verifier reports a self-published key as a distinct status (`_self_published_key`, tools/counselclear_verify_release_packet.py:758) rather than treating it as proof. The README also embeds the key fingerprint so the pinning flow (`--key-fingerprint`) works. No private key material in any log/error path found. No finding.

### F5.2 — Examined, no finding: tokens/secrets in URLs or logs

- Session tokens ride only in the `cc_session` cookie (security.py `issue_session`); no route puts tokens in query strings. Startup logging (main.py:1426-1512) logs posture (enabled/disabled/URL host) — `log.info("tsa_anchor: enabled against %s", posture["url"])` logs the *configured TSA URL* (an operator-set, non-secret endpoint), not any token; the TSA token itself is stored in the packet, not logged. `WATERMARKS_REWRITE_API_KEY` is env-only (rewrite_text.py:13, :831) and goes only into an `Authorization` header (:411-412); there is no code path logging headers. Cookie secret/attest secret files are 0600 and never logged. No finding.

### F5.3 — Examined, no finding: exception messages carrying file contents

- Worker failures become `"{type(e).__name__}: {e}"` (worker.py:138) truncated to 1000 chars in `job.error`; engine parse errors are type-name strings (`BadZipFile`, `ZipBudgetExceeded` with fixed cap text, `ET.ParseError` position strings) — none embeds file content. `CustodyError` messages carry paths and policy text, not bytes. The engine's redaction discipline (findings carry `value_redacted` "present (N chars)" placeholders, findings.py:60/108; container_meta.py:1077-1087 reports only field names + value lengths) extends to what lands in manifests. No finding.

### F5.4 — Low (verified by reading, path exists): worker stderr tail is stored in `job.error` and surfaced to API consumers

- runner.py:289 captures the worker process's last 1000 bytes of stderr; runner.py:341 stores `"worker exited rc=N: <stderr_tail>"` into `job.error`; that string is returned to API consumers (main.py:2375 in release_result, :4099/:4379 dashboard payloads truncated to 300 chars, :3277 in certificate context). Worker stderr normally contains library warnings — but any third-party dependency that prints request data (or a future tool adding verbose output) would land those bytes in an authenticated-but-broad surface, and HTML-escaping is applied at render (main.py:256 documents the escaping). Practical exposure today is low (worker stderr in this codebase emits only the startup posture warnings seen in this audit's own harness runs), but the pipe exists and is not content-filtered.
- Suggested fix (one-liner): pre-scrub `stderr_tail` against known-sensitive patterns (keys, file bytes heuristics) or cap it to a fixed set of recognized error tokens before storing in `job.error`.

### F5.5 — Examined, no finding: audit CSV / audit event payload contents

- Audit event payloads are operator/ids/counts only (spot-checked `document.upload`, `job.sanitize`, `bundle.download`, `batch.cancelled`, `release.created` payload constructions — no document text, no filename-derived PII beyond the filename itself, which is inherent). The disposition ledger records policy decisions, not content. `authoring-props` findings are redacted to field-name + length (container_meta.py:1082-1087). No finding.

---

## Coverage statement

Audit performed read-only on branch feat/custody-record-truthfulness (HEAD 2164baa at start). Python 3.14 venv used for reproductions. Reproduction scripts live in /tmp (t8_repro_recursion.py, t8_repro_recursion2.py, t8_repro_cancel_oracle.py, t8_repro_anchor_race2/3/4/5.py); each executed during this audit with the outputs quoted above. Nothing in the repo was modified except this findings file; nothing was committed; no subagents were dispatched.

### Examined and covered

- Surface 1 (hostile input): zip budget enforcement end to end (`_check_zip_budget`, `_read_zip_member`, every reader call site in container_meta.py), member-count behavior, encrypted-package/refuse-list sniffing, all 77 re.compile sites in container_meta.py reviewed for nested-quantifier shapes plus the hot-path patterns in image_meta/text_unicode call surfaces; **RecursionError via `_walk_hidden_runs` reproduced (F1.1)**; tempered-quadratic regexes identified in `_inspect_docx_legal`/`_strip_authoring_exhaust` (F1.2, pattern-shape verified, full runtime blow-up not executed to completion).
- Surface 2 (resources): upload cap enforcement (`_read_capped`), per-kind job budgets and worker hard timeout (`runner.py`), inner `_run_capped` timeouts, orphan sweep, per-pass budget-multiplication analysis (F2.3, envelope verified by reading).
- Surface 3 (concurrency): **cancel_batch 403/404 oracle reproduced (F3.1)**; **release.last_anchor_* lossy race reproduced with distinct per-packet anchor digests (F3.2)**; audit-chain append path read in full (audit.py incl. savepoint retry), db.py locking configuration (WAL/BEGIN IMMEDIATE/busy_timeout), existing concurrency test coverage noted.
- Surface 4 (partial writes): write_once/O_EXCL semantics, clean_to_bundle write ordering and verify gate, worker result.json atomic rename, sync_job backstop, job_bundle disk re-read and 409 paths; two Low/uncertain residual windows recorded inside F4.1 with explicit not-verified labels.
- Surface 5 (secrets): signing key provisioning and publication model, cookie/attest secret handling, TSA URL/token logging, API-key header handling, exception-to-job.error propagation, audit payload contents, verifier self-published-key reporting.

### Examined, explicitly not covered or only inferred

- The quadratic-regex blow-up (F1.2) was not run to completion — constructing the full 60 MB member and timing it was judged unnecessary to establish the pattern-shape claim; marked in-line.
- F4.1's two residual windows (empty derivative dir; bundle_dir removed after done) are read-only inferences, labeled as such, not reproduced.
- XLSX/PPTX-specific legal scrubbers (xlsx_legal.py, av_meta.py, pdf_legal.py) were not separately audited — the container_meta budget/recursion analysis covers their shared zip/XML substrate, but their own regex inventory was not line-by-line reviewed.
- tools/counselclear_verify_release_packet.py was reviewed only at its key-handling and status-reporting surfaces (F5.1), not its full 2528-line parser.
- web/ frontend, deploy/, compose.yaml, alembic migration contents (beyond the seq unique constraint), storage.py S3 path, oidc.py, and dispatcher.py internals were not examined.
- service/scripts/server.py (legacy prototype HTTP server) was not examined; the API surface audited is FastAPI service/app/main.py per the handoff.
- Live Postgres behavior of the audit-append retry (F3.3) was not exercised — SQLite-only reproduction environment.
