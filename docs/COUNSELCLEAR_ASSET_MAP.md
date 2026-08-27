# CounselClear Asset Map

**Status:** inventory and doctrine clarification only. Written 2026-08-27, current as of commit `0f4d69f` (PR 44). This document does not move code, rewrite license headers, or change what ships — it records what already exists and how it's licensed/positioned, so that decision stays traceable to real files rather than memory.

**How to keep this current:** re-derive from the repo, don't hand-edit stale facts forward. Each bucket below cites real paths; if a path moves, this doc is wrong until updated alongside it.

---

## 1. Engine

Byte/document-level inspection and sanitization. Lives entirely in `service/scripts/`, isolated from the control plane by design (PR 17: the control plane in `service/app/` never imports these modules directly except through `engine_api`/`runner.py`'s subprocess boundary; `service/scripts/` never imports `service/app/`). Statically enforced by `tests/test_worker_isolation.py`.

### Core, always-on engine (CounselClear-original, built on an upstream base)

| Area | Files | Notes |
|---|---|---|
| Engine entrypoint / boundary | `engine_api.py`, `counselclear.py` (CLI), `format_dispatch.py` | `engine_api.py` was extracted from pre-existing inspect/clean logic in PR 1 (`07c6ee2`) — a refactor of upstream code into an explicit API surface, not a rewrite from nothing. |
| Format parsers | `inspect_file.py`, `inspect_text.py`, `inspect_image.py`, `pdf_legal.py`, `xlsx_legal.py`, `container_meta.py`, `image_meta.py`, `av_meta.py`, `authoring_identity.py`, `text_unicode.py` | DOCX/PDF/XLSX/PPTX/image/audio-video metadata + legal-specific inspectors (hidden sheets, tracked changes, comments, GPS, authoring identity). CounselClear-original — added PR 3 onward (`d981a4c` GPS/JPEG/TIFF, PR 5 PDF legal inspectors, PR 6 DOCX, PR 7 XLSX, PR 8 PPTX). |
| Sanitization / cleaning | `clean_file.py`, `clean_text.py`, `clean_image.py` | The "strip" side matching the inspectors above. CounselClear-original, same PR lineage. |
| Policy engine | `policies.py` | `plan_actions`/`apply_actions`, four frozen v1 policies (PR 11, `7972c2e`). CounselClear-original. |
| Findings schema | `findings.py` | Canonical `Finding` schema (PR 3). CounselClear-original. |
| Verification gate | `verify.py`, `verify_file.py`, `verify_render.py` | Derivative-vs-original verification (PR 13, `3926ecd`): confirms a sanitize job's own output actually matches what it claims. CounselClear-original. |
| Custody / WORM storage | `custody.py` | Write-once storage, SHA-256 manifests (PR 12, `ef8a897`). CounselClear-original. |
| Reporting | `report_html.py` | Reviewer-facing plain-language report groundwork (predates the CounselClear rename — see IP section). |
| Refuse list | (wired through `policies.py`/`engine_api.py`) | Macro-enabled files, digitally signed documents, encrypted packages — PR 4 (`8ebb084`). |
| Stylometry | `score_stylometry.py` | Referenced by `text_detectors.py`; scope not fully re-audited for this map — see Unknowns. |
| Legal test corpus | `tests/fixtures/legal/`, `tests/test_legal_corpus.py` | Regression fixtures (PR 10, `267a791`). CounselClear-original. |

### Upstream-derived (pre-CounselClear, `watermarks-remover` origin)

The commit immediately before the CounselClear layer begins is `aeaa97a` ("docs: CounselClear sanitization + custody design spec"). Everything before it in `git log --oneline --reverse` is the original `watermarks-remover` project: text/pixel watermark detection and removal (Unicode "Layer A" hygiene, statistical "Layer B" rewrite, KGW/Gumbel detectors, a UI report view). PR 1 (`07c6ee2`) explicitly *refactors* — not rewrites — that existing inspect/clean logic into `engine_api.py`. Practically: the byte-level parsing/mutation primitives these modules build on (docx/pdf/xlsx zip-part manipulation, image pixel access) trace back to the upstream project; the *legal-inspection and policy layer* built on top of them (hidden content, tracked changes, custody, verification, policy engine) is CounselClear-original. The two are not cleanly separable file-by-file without a real line-level audit — see Unknowns.

### Text/image watermark detection & rewrite (upstream-origin capability, gated)

`detect_kgw.py`, `detect_gumbel.py`, `detect_text_watermark.py`, `text_detectors.py`, `rewrite_text.py`, `score_synthid.py`, `synthid_score_server.py`, `bench_synthid_text.py`, `markdiffusion_harness.py`, `clean_ctrlregen.py`. This is the original `watermarks-remover` capability (AI-text/image watermark detection and "Layer B" rewrite), carried forward and explicitly **gated, off by default** (PR 20, per `docs/COUNSELCLEAR_DESIGN.md`) — never the product spine, per that same doc's own stated positioning (`"Watermark removal ... is a gated, high-risk add-on — never the product spine, never a completeness claim, and never the default legal engine."`). See §4 and the IP section for what is and isn't bundled here — most of this area is an *integration harness* pointing at externally-checked-out third-party research code, not vendored source.

### Manifests the verifier cares about (engine output, consumed downstream)

`manifest.json` (per-job custody manifest: policy, hashes, actions, findings), `report.json` (verification result + pre-sanitize findings extract) — both produced by the engine, consumed by the control plane (`job_bundle`) and the offline verifier. Schema is implicit (no formal JSON Schema file found for these two — see Unknowns); `service/scripts/schemas/` exists but its exact coverage wasn't re-verified for this map.

---

## 2. Receipt

The evidentiary layer: what a release proves, and is careful never to overclaim.

| Artifact | Produced by | Proves | Does NOT prove |
|---|---|---|---|
| `release_packet.json` | `job_bundle` route, `service/app/main.py` | Content hashes of every file in a *done* release's packet (derivative, manifest, report, certificate, README); policy/profile/recipient context (`release` sub-object, PR 42); `original_sha256` at top level (PR 39) | External timestamping, authenticity, or that the document was actually transmitted anywhere. `anchor.type` is always `"none"` — no TSA, no transparency log, no customer-held WORM copy exists yet. |
| `release_result.json` | `_build_release_result`, `service/app/main.py` | The lightweight, always-present outcome record for *every* terminal release — done, refused, or failed alike (PR 39/43) — status, reason, `original_sha256`, `audit_refs`, limitations, `certificate_html_sha256` | Same anchoring limits as above. `audit_refs` for a refused/failed release never includes `certificate_issued_seq` (that certificate is fetched in a separate call after the result is built) — a real, documented asymmetry (milestone audit, PR 44). |
| `certificate.html` | `_render_job_certificate_html`/`_build_certificate_html`, `service/app/main.py` | This system's own recorded state for one job/release: what ran, what was verified, what's disclosed as a limitation, and (since PR 44) who it was prepared for under which profile | Never "clean," "safe," or a legal opinion — the certificate's own disclaimer says so explicitly. "Prepared for release," never "sent" or "delivered" (PR 44's own careful-language requirement, tested). |
| Verifier CLI | `tools/counselclear_verify_release_packet.py` | Offline, stdlib-only, recomputes every declared hash independently of the system that produced it; as of PR 44, cross-checks `release_packet.json` and `release_result.json` against each other when both exist, failing loudly on disagreement rather than silently picking one | Never prints "verified" as a bare claim, "unforgeable," "independently timestamped," "court-proof," or "unimpeachable" as affirmative claims — enforced by its own test suite (`test_forbidden_claim_words_never_appear_as_affirmative_claims`). Certificate content is hash-checked only, never re-parsed for meaning (the substring cross-check it used to do was removed as unreliable, PR 39). |
| `audit_refs` | Embedded in both JSON artifacts | Real `seq` numbers in the matter's own tamper-evident hash chain | The seq numbers are *declared*, not independently checkable by the offline verifier (no database access) — the verifier says so explicitly in its own output (PR 41). Cross-checking them requires the live `GET /v1/matters/{id}/audit` route. |
| Custody / audit chain | `service/app/audit.py`, `AuditEvent` model | Gapless, per-matter, hash-chained (`sha256(prev_hash \| seq \| actor \| action \| payload)`); `release.created`/`release.terminal` live in the *same* chain as every other event — no parallel chain (PR 39) | Nothing about the chain is externally anchored either — it's this system's own tamper-*evident* (detects post-hoc tampering) record, not tamper-*proof* in a cryptographic-notary sense. |

---

## 3. Gate

The user-facing product surface — what a person or script actually interacts with, versus what's execution detail underneath.

### User-facing product

- **Web Release flow** (`web/app/matters/view/page.tsx`'s `ReleasePanel`, `web/app/matters/job/page.tsx`) — "Prepare Release Packet" is the primary document action (PR 40); a release profile selector, not a raw policy dropdown, is the primary choice (`policy_id` demoted to a "Technical details" disclosure). Recipient/purpose/intent context is captured at creation and shown back at review time (certificate + job page, PR 44).
- **Airlock CLI** (`tools/counselclear_airlock.py`) — Release-native since PR 43 (`Client.release()`, `--profile`, required `--recipient-type`). The legacy `Client.sanitize()` / `--policy` path is retained for compatibility but is not the primary path.
- **Batch/folder release flow** — two distinct mechanisms, not one: (a) the web UI's `POST /v1/matters/{id}/releases`, an async server-side batch riding the existing `Batch`/dispatcher machinery (PR 39); (b) the Airlock CLI's own client-side sequential loop over `--folder`/`--files` (PR 38, migrated to Release calls in PR 43) — never calls the server batch route. Both exist; they were deliberately not unified.
- **Release profiles** (`RELEASE_PROFILES`, `service/app/main.py`) — `counterparty_deal_room`, `public_filing_anonymized`, `ediscovery_production`. Presentation-layer resolution to a stable internal `policy_id`; never a reinterpretation of what a policy does.
- **Recipient/context capture** — `recipient_type` (required, controlled vocabulary), `recipient_name`/`purpose` (optional, free text), `intended_external` (worded as stated intent, never a delivery claim, everywhere it appears).

### Internal execution mechanism (not the product surface)

- **`Job`** (`service/app/models.py`) — the execution record. Always present; a `Release` wraps it 1:1 but a `Job` can exist without one (legacy `/sanitize-jobs` path, still functional, no longer primary).
- **`Batch`** (`service/app/models.py`, `service/app/dispatcher.py`) — the grouping/execution envelope only. "Batch completed" and "each release completed" are deliberately different events (PR 39).
- **Legacy routes** — `POST .../sanitize-jobs`, `POST .../batches` (raw, non-Release). Explicitly retained compatibility, not removed, not deprecated with a warning; see §4.
- **`GET /v1/policies`** — still exists, still the source of truth `RELEASE_PROFILES` resolves to; not the primary UI selection surface anymore.

---

## 4. Explicitly Not Included

Stated plainly so the product's own claims never outrun what's actually shipped and tested.

- **External anchoring or signing** — no TSA, transparency log, or customer-held WORM copy. Every artifact's `anchor.type` is `"none"`, honestly, everywhere. A design proposal exists (`docs/release-packet-verification-and-anchoring-proposal.md`); nothing from it is implemented.
- **Legal certification / "court-proof" / "unforgeable" claims** — actively enforced, not just avoided. The verifier's own test suite asserts these words never appear as affirmative claims anywhere in generated output.
- **Insurance, warranty, or risk-transfer product** — CounselClear records what it did; it does not indemnify, warrant, or transfer risk for what happens to a document after release.
- **Unattended watch mode or desktop app** — explicitly scoped out of every pass to date (PR 38, PR 40, PR 43 proposals all named this as out of scope). Nothing resembling folder-watching or an unattended trigger exists in the codebase.
- **Restricted or proprietary watermark research code** — see the IP section below in full; the short version is that the optional watermark-detection/removal harnesses (`detect_text_watermark.py`, `markdiffusion_harness.py`, `clean_ctrlregen.py`, `score_synthid.py`) explicitly do not vendor third-party code, by their own docstrings, and are architecturally isolated (separate `Dockerfile.*`, separate `requirements-*.txt`, off by default).
- **Model-provider-specific circumvention claims** — `skills/remove-ai-marks/references/vendor-notes.md` is deliberately scoped to "mark classes... not reverse-engineered private detectors," sourced from public docs and literature, explicit that production keys for vendor watermarks (SynthID etc.) are not public and not reproduced here.
- **Anything not backed by tests/manifests/verifier output** — the discipline this whole Release-native effort has run under (PR 39-44): every claim in a certificate, packet, or result JSON traces to a real computed value, checked by a real test, and the verifier CLI exists specifically to let a third party confirm that independently of trusting this system's own UI.

---

## IP / Licensing

**This section records what the license situation appears to be from the files present. It is not a legal opinion and has not been reviewed by counsel — see Unknowns for what still needs real diligence.**

### Repository license

`LICENSE` (root): MIT, copyright "watermarks-remover contributors." One license file covers the entire repository — there is no separate license carve-out for CounselClear-original code today; everything added since the fork point is licensed under the same MIT terms as the upstream project it extends.

### Upstream (`guillaumemeyer/watermarks-remover`) components

Everything at and before commit `aeaa97a` (the last pre-"CounselClear" commit) — text/pixel watermark detection and removal (Layer A Unicode hygiene, Layer B statistical rewrite, KGW/Gumbel detection, the original UI). `origin` remains this upstream repo, read-only per this project's own standing rule (never push there). MIT-licensed, same as the rest of the repo.

### CounselClear-original components

Everything from PR 1 (`07c6ee2`) onward: `engine_api.py`'s extraction, the legal-inspection layer (`pdf_legal.py`, `xlsx_legal.py`, `authoring_identity.py`, etc.), the policy engine, custody/WORM storage, the verification gate, the entire control plane (`service/app/`), the entire frontend (`web/`), the Airlock CLI, the offline verifier, and the Release object work (PR 39-44). Also MIT-licensed (same repo, same LICENSE file) — "CounselClear-original" here is an attribution/architecture distinction, not a distinct license grant.

### Third-party dependencies (high level, not an exhaustive audit)

**Backend, always-installed** (`service/requirements-app.txt`, `requirements-dev.txt`): FastAPI, Uvicorn, SQLAlchemy, Alembic, argon2-cffi, python-multipart, httpx, psycopg, PyJWT, cryptography, boto3 — all standard, permissively-licensed (MIT/Apache-2.0/BSD-family) infrastructure libraries. Version-pinned.

**Frontend** (`web/package.json`): Next.js, React, React DOM (MIT) plus standard dev tooling (TypeScript, ESLint, Tailwind, Vitest — all MIT/permissive).

**Optional, off-by-default watermark-research harnesses** — each is an *integration point*, not vendored code, confirmed by reading each script's own docstring:

| Harness | Upstream project | License (as stated in this repo's own references) | Vendored here? |
|---|---|---|---|
| `detect_text_watermark.py` | `THU-BPM/MarkLLM` | Apache-2.0 | **No.** `detect_text_watermark.py`'s own docstring: "does NOT vendor upstream code... imports `AutoWatermark` from a user-provided checkout at runtime." |
| `markdiffusion_harness.py` | `THU-BPM/MarkDiffusion` | Apache-2.0 | **No.** Same disclaimer, imports from a user checkout or `pip install markdiffusion`. |
| `clean_ctrlregen.py` | `mertizci/noai-watermark` (CtrlRegen) | **No LICENSE file in the upstream repo** — per `vendor-notes.md`, treated as all-rights-reserved | **No.** Script's own docstring: "does NOT vendor upstream code... imports `CtrlRegenEngine` from a user-provided checkout at runtime." |
| `score_synthid.py` / `synthid_score_server.py` | `aloshdenny/reverse-SynthID` | Non-commercial Research License, per `vendor-notes.md` | **No.** Same disclaimer pattern; this is an unofficial, best-effort, reverse-engineered scorer — explicitly not the official Google detector. |

Each harness ships its own `requirements-<harness>.txt` (ML dependencies for the *harness's own runtime*, not the upstream project's source) and its own `Dockerfile.<harness>` — architecturally isolated from the main product image (`Dockerfile.counselclear`). `service/scripts/setup_<harness>.sh`/`.ps1` scripts clone the relevant upstream checkout at a pinned commit at install time; none of that checked-out code is committed to this repository.

### Statement on restricted/non-redistributable code

**No restricted research code or non-redistributable watermark-removal implementation is included in this repository's committed, licensed surface**, based on the docstring-level "does NOT vendor upstream code" declarations in every one of the four optional harness scripts, cross-checked against the actual repository contents (no vendor source trees found under `service/scripts/` or anywhere else in the tracked tree). This statement is **as good as those docstrings are accurate** — none of the four claims was verified against the actual upstream projects' own license files by this pass (see Unknowns).

### Unknowns requiring follow-up diligence

- **The four "does not vendor" claims above were not independently verified** against the actual upstream `THU-BPM/MarkLLM`, `THU-BPM/MarkDiffusion`, `mertizci/noai-watermark`, and `aloshdenny/reverse-SynthID` repositories' own current license files — they were taken from this repo's own docstrings and `vendor-notes.md`, which could be stale or wrong. Worth an actual `git log`/checkout diff confirmation before any redistribution decision.
- **No line-level audit separates upstream-derived code from CounselClear-original code within a single file** — the commit-boundary analysis above (`aeaa97a` and PR 1's refactor) is a reasonable approximation, not a clean-room provenance audit. A file like `engine_api.py` demonstrably contains both upstream logic (refactored, not rewritten) and CounselClear additions layered on top since; attributing individual functions/lines wasn't attempted here.
- **No formal JSON Schema found for `manifest.json`/`report.json`** (the engine's own output format the verifier and control plane both depend on) — `service/scripts/schemas/` exists but its exact coverage of these two files wasn't confirmed for this map.
- **`score_stylometry.py`/`text_detectors.py`'s exact scope and provenance** (upstream vs. original) wasn't re-audited for this pass — flagged, not resolved.
- **No `pyproject.toml`/`setup.py`/single base `requirements.txt`** was found defining the core engine's own document-parsing dependencies (as distinct from the control-plane and optional-harness requirement files enumerated above) — likely a mix of stdlib and system CLI tools (qpdf, exiftool, per scattered design-doc mentions), but this wasn't confirmed against an actual manifest, because none appears to exist. Worth resolving before any formal SBOM/license-compliance exercise.
- **No independent legal review** of the MIT license's adequacy for a product with CounselClear's actual use case (legal-document handling, custody claims) has been recorded anywhere in this repository's history that this pass found.
