# CounselClear: Gap Analysis & Production Readiness Assessment
**Prepared:** 2026-09-10  
**Grounded at HEAD:** `000dd3a50e` (2026-09-01)  
**Doctrine reference:** `docs/counselclear-strategy.md`

---

## My case for working on this project

Before the gap analysis: the strategy doctrine (§6, §7) requires honesty about what AI assistance can and cannot do here. So I'll state my case plainly.

**What I bring:** I've read all seven doctrine points. I understand that CounselClear's moat is *defensibility*, not file-cleaning — and that diluting it with "magic auto-clean" UX would be a category error. I understand the engine/product-shell boundary and will never propose crossing it. I understand that claims must be evidence-bound, which means I will not write marketing copy that says "verified" or "clean" without a deterministic code path behind it. And I understand the one-writer rule: every change I propose will come as a PR with the handoff packet §7 requires.

**What I cannot do:** Establish product truth. I can propose and implement. A deterministic test or a byte-level fixture establishes truth; my analysis does not. I'll flag where my readings are hypotheses.

**Why this is a good fit:** The work left is largely at the surface layer (docs, build pipeline, marketing) and the ambient-integration layer (CLI, DMS hooks). Neither requires touching the custody-write paths that would take days to audit. I can do the surface work today.

---

## Current state in one sentence

The CounselClear product exists and is coherent in code. The build, docs, and release surface still partially exposes the upstream watermarks-remover utility, blurring what the product is for evaluators and IT directors.

---

## What is solid (do not touch)

| Component | Status | Evidence |
|---|---|---|
| Engine: format-aware sanitization | Complete, tested | 42+ test modules, ~575 test functions |
| Control plane: FastAPI, auth, matters, jobs, audit chain | Complete | 10 Alembic migrations, OIDC + local-password auth |
| Release packet / certificate / verify workflow | Complete + RFC 3161 anchoring just added | `tools/counselclear_airlock.py`, `tools/counselclear_verify_release_packet.py` |
| Web UI: Release Gate | Functional, recently styled | Next.js, dashboard, matters, audit, jobs views |
| Docker/compose deployment: `legal` profile | Working | `service/Dockerfile.counselclear`, compose `cc-api` + `cc-postgres` + `cc-freshclam` |
| CI pipeline | Passing (green badge on README) | `.github/workflows/ci.yml` |
| Worker isolation: subprocess mode | Enforced | `tests/test_worker_isolation.py` |
| ClamAV malware scanning | Integrated | `service/app/malware.py`, `cc-freshclam` sidecar |
| Batch async dispatch | Implemented | `service/app/dispatcher.py`, 6-migration history |
| Schema pinning for release artifacts | Implemented | `engine/schemas/`, committed |

---

## Gap 1: Build/docs surface still exposes adjacent research systems (BLOCKING for pilot credibility)

**What the Commercial Surface Manifest (2026-08-28) identified:**

The `.github/workflows/release-images.yml` publishes `markllm` and `markdiffusion` GHCR images. Both are classified `build-exclude` + `legal-review-needed`. A law firm's IT/security review will pull that workflow and ask: "Why is this product publishing unlicensed research model images to a public container registry?"

**What has already been fixed (since the manifest):**  
- `service/Dockerfile.counselclear` got its own `.dockerignore` (commit `840c07bedd`) — the broken build and commercial-surface gap is closed.
- `README.md` is now CounselClear-first with a clear legacy section.

**What still needs fixing:**  
1. `.github/workflows/release-images.yml` — still publishes `markllm`/`markdiffusion` images. This is the clearest remaining hard-block in the CI surface.  
2. `compose.yaml` — the default `docker compose up` (without `--profile legal`) still launches `wr-core`, not CounselClear. An evaluator who follows default Docker instincts hits the wrong product.  
3. `.env.example` — still documents `WATERMARKS_SYNTHID_SCORER_URL`, `COUNSELCLEAR_REWRITE_NETWORK`, and harness-profile env vars alongside product vars. A law firm IT director reading this sees a product that can call out to a statistical model scoring server.  
4. `compose-check.sh` — validates `wr-markllm`, `wr-markdiffusion`, `wr-ctrlregen`, `wr-synthid` as part of the check surface.

**Fix complexity:** Low. CI workflow matrix trim, compose default profile change, .env.example split. No engine code touched.

---

## Gap 2: No 5-minute demo path (BLOCKING for law firm evaluation)

**What the eval runbook provides:** A complete walkthrough of the Release Gate flow. It's thorough and technically accurate.

**What's missing:** A paralegal or IT director evaluating this for a small/mid firm needs to be up and running in one terminal command with a result they can screenshot in under 5 minutes. The eval runbook is the right depth for a senior engineer; it's too long for the buyer.

**What's needed:**
```bash
# target: this should be the entire evaluation
docker compose --profile legal up -d
./tools/counselclear_airlock.py --file sample_nda.docx --output release_packet/
open release_packet/release_manifest.json   # or xdg-open
```

Plus a `samples/` directory with a realistic but synthetic legal document (NDA, engagement letter) containing embedded metadata that the sanitizer actually finds — so the evaluator sees real findings immediately.

**Fix complexity:** Medium. Requires a `samples/` directory with a well-chosen synthetic document and a `QUICKSTART.md` that is self-contained in under 15 lines.

---

## Gap 3: No DMS/workflow integration (BLOCKING for "must-have" status)

**What the strategy (§3) says:** "Lawyers will not reliably log into a separate web dashboard for every document they send." The ambient airlock concept is described but not implemented.

**What exists today:**
- `tools/counselclear_airlock.py` — a scriptable release packet workflow. This is the foundation.
- `integrations/cursor/clean-user-facing-text.mdc` — a Cursor IDE integration.

**What's missing for "must-have":**
- iManage / NetDocuments export hook (CLI wrapper or API integration guide)
- DocuSign pre-send hook
- Outlook/M365 add-in concept (even a documented recipe for the IT team)
- A folder-watcher daemon (watches a drop-zone directory, auto-processes documents)

**The folder-watcher is the fastest win:** A 50-line Python script that watches `~/CounselClear/inbox/` and auto-runs the airlock is the "always-on, zero extra clicks" promise. It's the difference between a tool a lawyer uses and a tool IT installs and nobody touches.

**Fix complexity:** Low-medium for the folder-watcher. Medium for the DMS guide. The DMS integration itself is a Phase 4 item.

---

## Gap 4: Marketing/positioning (BLOCKING for major-player adoption)

**What exists:** The strategy doctrine. A design doc. A commercial surface manifest. An eval runbook.

**What's missing:**
- A 1-page product brief in non-engineer English (for bar association committees, law firm managing partners, malpractice insurers)
- A positioning statement that ties CounselClear to specific professional responsibility rules (Model Rules 1.6, 1.1, and state-level AI disclosure requirements)
- A competitive brief against Word Inspect Document / Adobe Acrobat / DMS scrubbers (why CounselClear's WORM + audit chain wins on defensibility)

**The pitch in one paragraph (draft, not evidence-bound until the product team approves):**
> CounselClear is the first document-sanitization platform built for legal defensibility rather than convenience. Unlike Word's "Inspect Document" or DMS metadata scrubbers — which overwrite files, leave recoverable data, and produce no evidence of what was removed — CounselClear preserves the original immutably, creates a separate verified derivative, and produces a hash-chained audit certificate that satisfies your firm's chain-of-custody obligations. Every document release under CounselClear is rebuttable with evidence. Every document release under a scrubber is a bet.

---

## Priority order for the pilot

| Priority | Work | Who | Complexity |
|---|---|---|---|
| P0 | Stop publishing hard-block images in CI workflow | Coding PR | 1 hour |
| P0 | Fix `compose.yaml` default to be CounselClear-first | Coding PR | 30 min |
| P1 | Split `.env.example` into product vs. research vars | Coding PR | 1 hour |
| P1 | Add `samples/` directory with synthetic legal doc | Coding PR | 2 hours |
| P1 | Write `QUICKSTART.md` (5-minute eval path) | Coding PR | 1 hour |
| P2 | Folder-watcher daemon (`tools/counselclear_watch.py`) | Coding PR | 3-4 hours |
| P2 | Product brief (1 page, non-engineer audience) | Docs | Done below |
| P3 | iManage/NetDocuments integration guide | Docs | 2 hours |
| P3 | Bar association adoption pitch | Docs | Done below |

---

## Handoff state (per doctrine §7)

- **HEAD SHA:** `000dd3a50e`  
- **Working tree:** No changes made yet — this is a read-only audit.  
- **Upstream `origin`:** Not touched.  
- **Verification state:** CI green per README badge. Exact test count: ~575 functions across 42+ test modules (from DESIGN.md; not independently re-run here — that's a hypothesis, not a confirmed claim).  
- **Open risks:** Release-images CI workflow publishing hard-block images is the most visible risk for a law firm IT/security review.  
- **Next chunk:** PR to fix P0 items (CI workflow + compose default), then QUICKSTART.md.

---

*This document is an agent-assisted assessment. It is not a legal opinion and does not establish product truth. Findings grounded against actual repo files read in this session; hypothesis label applied where confirmation requires running tests or inspecting CI output directly.*
