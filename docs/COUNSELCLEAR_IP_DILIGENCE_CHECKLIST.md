# CounselClear Dependency/IP Diligence Checklist
## Pre-Commercial Distribution Verification

**Document Date:** 2026-08-27  
**Base Reference:** `docs/COUNSELCLEAR_ASSET_MAP.md` (commit 0f4d69f, PR 44)  
**Purpose:** Track verification status for upstream projects, optional harnesses, package licenses, model/API terms, and generated fixtures before any commercial distribution decision.

**This is a diligence-planning checklist, not a legal opinion or sign-off.** No license headers, attributions, or code have been changed as part of producing this document.

### ⚠️ How to read the status marks in this document

A license **label** (MIT, Apache-2.0, BSD) identifies the stated terms of a package as declared by its maintainers — it is a starting point for review, not a clearance. A "✓ License label: permissive" mark in this document means only that: *the declared license family is generally redistribution-friendly.* It does **not** by itself establish:

- that attribution/notice files are complete and correctly reproduced downstream
- that the upstream code's own provenance is clean (i.e., that upstream didn't itself incorporate something restricted)
- that commercial custody/verification claims built on top of this code create no separate warranty or liability exposure
- that any given component — especially the optional watermark harnesses — is actually clear to ship, invoke, or even document in a commercial product surface
- that generated fixtures, copied snippets, or reference test data have clean provenance independent of their producing code's license

Wherever this document previously used "✓ Verified" for a package license, it has been revised to "✓ License label identified" — **notice completeness and provenance review are separate, still-open action items**, tracked in §8.

---

## 1. UPSTREAM PROJECTS

### 1.1 Primary Upstream: `guillaumemeyer/watermarks-remover`

| Item | Status | Verification | Notes |
|------|--------|---|---|
| **Repository** | ✓ Identified | Read from git history | Everything before commit `aeaa97a` (pre-CounselClear layer) |
| **License** | ✓ Identified | MIT (root LICENSE) | Same as current repo; covers all watermark detection/removal ("Layer A" and "Layer B") |
| **Commit Range** | ✓ Identified | git log | All commits before `aeaa97a` are upstream-origin |
| **Capabilities Included** | ✓ Identified | Codebase audit | Text/pixel watermark detection (KGW/Gumbel detectors), statistical rewrite, original UI view |
| **Licensing Adequacy** | ⚠️ **Pending** | Legal review | MIT may or may not be adequate for CounselClear's legal-custody use case; no prior review found in repo history |
| **No Pending Obligations** | ⚠️ **Pending** | Upstream communication | Confirm with `guillaumemeyer` no upstream obligations exist (attribution, contribution-back, disclosure requirements) |

---

## 2. OPTIONAL WATERMARK-RESEARCH HARNESSES

**🚫 OUTSIDE THE LICENSED/COMMERCIAL SURFACE UNTIL INDEPENDENTLY CLEARED.** All four harnesses below remain off-by-default and must stay excluded from any commercial build, commercial documentation, marketing claim, or customer-facing feature list until each is independently cleared per §8. This applies regardless of the "does NOT vendor" docstring claims, which describe architecture (no committed source) — they are not a license clearance and do not resolve whether *invoking* the upstream project at runtime is itself permitted for commercial use.

Each harness is an **integration point, not vendored code** — this is a claim taken from each script's own docstring, not yet independently confirmed by comparing against the actual upstream repositories. The "does NOT vendor" claims require independent verification (see §8).

### 2.1 MarkLLM Text Watermark Detection

| Item | Status | Verification | Notes |
|------|--------|---|---|
| **File(s)** | ✓ Identified | `service/scripts/detect_text_watermark.py` | Integration harness only |
| **Upstream Project** | ✓ Identified | `THU-BPM/MarkLLM` | GitHub project exists (Apache-2.0 licensed) |
| **Upstream License** | ✓ Identified | Apache-2.0 | Per vendor-notes.md and upstream repo |
| **Vendored Code?** | ⚠️ **Pending** | Direct repo comparison | Docstring claims "does NOT vendor upstream code"; must verify no upstream source tree committed here |
| **Installation Method** | ✓ Identified | User-provided checkout or pip | `setup_detect_text_watermark.sh` clones upstream at pinned commit; not committed to this repo |
| **Requirements File** | ✓ Identified | `service/scripts/requirements-detect_text_watermark.txt` | Separate from main product requirements |
| **Docker Isolation** | ✓ Identified | `Dockerfile.detect_text_watermark` | Separate build artifact; not included in main `Dockerfile.counselclear` |
| **Default Status** | ✓ Off by default (PR 20) | Code inspection | Gated, not part of default release flow |
| **Transitive Deps Audit** | ⚠️ **Pending** | ML dependency tree | `requirements-detect_text_watermark.txt` may pull additional third-party packages; full tree not audited here |
| **Commercial Surface Status** | 🚫 **Excluded** | — | Not to be shipped, invoked by default, or referenced in commercial documentation/marketing until independently cleared (§8) |

### 2.2 MarkDiffusion Image Watermark Detection

| Item | Status | Verification | Notes |
|------|--------|---|---|
| **File(s)** | ✓ Identified | `service/scripts/markdiffusion_harness.py` | Integration harness only |
| **Upstream Project** | ✓ Identified | `THU-BPM/MarkDiffusion` | GitHub project exists (Apache-2.0 licensed) |
| **Upstream License** | ✓ Identified | Apache-2.0 | Per vendor-notes.md and upstream repo |
| **Vendored Code?** | ⚠️ **Pending** | Direct repo comparison | Same "does NOT vendor" claim; verify no source committed here |
| **Installation Method** | ✓ Identified | User-provided checkout or pip | `setup_markdiffusion_harness.sh` clones upstream; not committed |
| **Requirements File** | ✓ Identified | `service/scripts/requirements-markdiffusion_harness.txt` | Separate from main product |
| **Docker Isolation** | ✓ Identified | `Dockerfile.markdiffusion_harness` | Separate build artifact |
| **Default Status** | ✓ Off by default (PR 20) | Code inspection | Gated add-on |
| **Transitive Deps Audit** | ⚠️ **Pending** | ML dependency tree | Full transitive dependencies not audited |
| **Commercial Surface Status** | 🚫 **Excluded** | — | Not to be shipped, invoked by default, or referenced in commercial documentation/marketing until independently cleared (§8) |

### 2.3 CtrlRegen Watermark Removal

| Item | Status | Verification | Notes |
|------|--------|---|---|
| **File(s)** | ✓ Identified | `service/scripts/clean_ctrlregen.py` | Integration harness only |
| **Upstream Project** | ✓ Identified | `mertizci/noai-watermark` (CtrlRegen) | GitHub project exists |
| **Upstream License** | ⚠️ **Critical** | No LICENSE file in upstream | Per vendor-notes.md: treated as all-rights-reserved (likely proprietary research code) |
| **Vendored Code?** | ⚠️ **Pending** | Direct repo comparison | Docstring claims "does NOT vendor"; verify confirmed, given license uncertainty |
| **Installation Method** | ✓ Identified | User-provided checkout only | `setup_clean_ctrlregen.sh` clones upstream; not pip-installable (proprietary) |
| **Requirements File** | ✓ Identified | `service/scripts/requirements-clean_ctrlregen.txt` | May include proprietary research ML packages |
| **Docker Isolation** | ✓ Identified | `Dockerfile.clean_ctrlregen` | Separate build artifact |
| **Default Status** | ✓ Off by default (PR 20) | Code inspection | Gated add-on |
| **Licensing Risk** | 🔴 **HIGH** | Contact upstream author | No public license = no clear redistribution rights; must obtain explicit written permission before any commercial distribution if this harness is ever enabled |
| **Commercial Surface Status** | 🚫 **Excluded — hard block** | — | Absent a LICENSE file, default legal posture is all-rights-reserved; this harness must not be shipped, invoked, or documented commercially under any circumstance until written permission is obtained (§8) |

### 2.4 Reverse-Engineered SynthID Scorer

| Item | Status | Verification | Notes |
|------|--------|---|---|
| **File(s)** | ✓ Identified | `service/scripts/score_synthid.py`, `service/scripts/synthid_score_server.py` | Integration harness and scorer service |
| **Upstream Project** | ✓ Identified | `aloshdenny/reverse-SynthID` (unofficial) | GitHub project; NOT the official Google SynthID detector |
| **Upstream License** | ⚠️ **Critical** | Non-commercial Research License | Per vendor-notes.md; explicitly unofficial and reverse-engineered |
| **Official Google SynthID** | 🔴 **Not Used** | Code inspection | CounselClear does NOT use the official Google SynthID detector; this is a best-effort reverse-engineered alternative |
| **Vendored Code?** | ⚠️ **Pending** | Direct repo comparison | Docstring claims "does NOT vendor"; verify confirmed |
| **Installation Method** | ✓ Identified | User-provided checkout | `setup_score_synthid.sh` clones; not pip-installable from official source |
| **Requirements File** | ✓ Identified | `service/scripts/requirements-synthid_score.txt` | Separate dependencies |
| **Docker Isolation** | ✓ Identified | Separate server/container | `synthid_score_server.py` runs as isolated service |
| **Default Status** | ✓ Off by default (PR 20) | Code inspection | Gated add-on; not part of default release flow |
| **Licensing Risk** | 🔴 **HIGH** | Legal review required | Non-commercial Research License, on its face, prohibits commercial use; explicit license audit needed before any commercial offering that includes this scorer. Cannot be advertised as "Google SynthID" detection — that would be a false/misleading provider claim independent of the license issue (see §2.5). |
| **Vendor Lock-in Risk** | Low — architecturally optional | Script design | CounselClear contains no hard dependency on this harness; is gated and optional. Does not by itself resolve the licensing block above. |
| **Commercial Surface Status** | 🚫 **Excluded — hard block** | — | Non-commercial license term is explicit; must not be shipped, invoked, or documented commercially until either (a) upstream grants a commercial license, or (b) the scorer is replaced with a properly licensed alternative (§8) |

### 2.5 Provider-Specific Watermark Circumvention Claims

**🚫 EXCLUDED FROM COMMERCIAL SURFACE — separate issue from licensing, above.**

| Item | Status | Notes |
|---|---|---|
| **Scope per `vendor-notes.md`** | ✓ Identified, as documented | Deliberately scoped to "mark classes... not reverse-engineered private detectors," sourced from public docs/literature |
| **Vendor production keys** | ✓ Not included, as documented | SynthID and similar vendor watermark production keys are stated as not public and not reproduced here |
| **Marketing/claims risk** | ⚠️ **Pending review** | Any commercial documentation, sales material, or product surface must not claim CounselClear can detect or circumvent a *named vendor's* specific watermark (e.g., "defeats Google SynthID," "bypasses OpenAI watermarking") — this is a truth-in-advertising and potential vendor-relations issue independent of the code license questions above |
| **`vendor-notes.md` accuracy** | ⚠️ **Not independently verified** | The scoping claims in this file are self-reported, same as the harness "does not vendor" docstrings — see §8 |

---

## 3. CORE PACKAGE DEPENDENCIES

### 3.1 Backend - Always-Installed (Application)

**Source:** `service/requirements-app.txt`, `requirements-dev.txt`

| Package | License | Version | Status | Notes |
|---------|---------|---------|--------|-------|
| **FastAPI** | MIT | Pinned | ✓ License label identified | Standard async web framework |
| **Uvicorn** | BSD-3-Clause | Pinned | ✓ License label identified | ASGI server |
| **SQLAlchemy** | MIT | Pinned | ✓ License label identified | ORM; critical for job/release data |
| **Alembic** | MIT | Pinned | ✓ License label identified | DB migrations |
| **argon2-cffi** | MIT | Pinned | ✓ License label identified | Password hashing |
| **python-multipart** | Apache-2.0 | Pinned | ✓ License label identified | Form/file upload handling |
| **httpx** | BSD | Pinned | ✓ License label identified | Async HTTP client |
| **psycopg** | BSD-3-Clause | Pinned | ✓ License label identified | PostgreSQL driver |
| **PyJWT** | MIT | Pinned | ✓ License label identified | JWT token handling |
| **cryptography** | Apache-2.0/BSD | Pinned | ✓ License label identified | Crypto primitives; critical for SHA-256, key handling |
| **boto3** | Apache-2.0 | Pinned | ✓ License label identified | AWS S3 client (for custody/WORM storage) |
| **All others** | MIT/Apache-2.0/BSD | Pinned | ✓ License label identified | Standard dev tooling (pytest, black, etc.) |

**Status:** License labels across core backend dependencies are permissive (MIT, Apache-2.0, BSD-family) — this identifies the declared terms only. Notice/attribution completeness (e.g., a consolidated third-party-notices file bundled with the distributed product) has **not** been separately verified. See §8.

### 3.2 Frontend - Web UI

**Source:** `web/package.json`

| Package | License | Version | Status | Notes |
|---------|---------|---------|--------|-------|
| **Next.js** | MIT | Pinned | ✓ License label identified | React framework |
| **React** | MIT | Pinned | ✓ License label identified | UI library |
| **React DOM** | MIT | Pinned | ✓ License label identified | DOM rendering |
| **TypeScript** | Apache-2.0 | Pinned | ✓ License label identified | Type system |
| **ESLint** | MIT | Pinned | ✓ License label identified | Linting |
| **Tailwind CSS** | MIT | Pinned | ✓ License label identified | Utility CSS; critical for UI styling |
| **Vitest** | MIT | Pinned | ✓ License label identified | Test runner |
| **All others** | MIT/permissive | Pinned | ✓ License label identified | Standard frontend tooling |

**Status:** License labels across frontend dependencies are permissive — declared terms only, not a notice/provenance clearance. See §8.

### 3.3 Missing Dependency Manifest

| Item | Status | Issue | Impact |
|------|--------|-------|--------|
| **`pyproject.toml` / `setup.py`** | ❌ Not found | No single base requirement file for core engine | Cannot generate complete SBOM without manual audit of `service/scripts/` |
| **System CLI tools** | ⚠️ **Undocumented** | Scattered references only (qpdf, exiftool mentioned in design docs, not confirmed) | License status of these tools unknown; may be proprietary or GPL-licensed |
| **Core engine dependencies** | ⚠️ **Undocumented** | No formal manifest for document-parsing libraries | Need to verify what's stdlib vs. third-party (PIL, pypdf, python-pptx, openpyxl, etc.) |

---

## 4. MODEL/API TERMS & VENDOR AGREEMENTS

### 4.1 AI Model Usage

| Model/Service | Used For | License/Terms | Status | Notes |
|---|---|---|---|---|
| **Claude API** (if used) | Not identified in code | Depends on Anthropic Terms | ⚠️ Check if integrated | No references found to Claude API in codebase |
| **OpenAI API** (if used) | Not identified in code | OpenAI Terms of Service | ⚠️ Check if integrated | No references found to OpenAI API |
| **Google SynthID** | NOT used (reverse-engineered scorer only) | Google Terms | ✓ Not applicable | CounselClear does NOT use official Google detector; cannot claim "Google SynthID detection" |
| **Reverse-SynthID** (unofficial) | Scorer service (optional, gated) | Non-commercial Research License | 🔴 HIGH RISK | See §2.4; commercial use may violate upstream license |
| **Local/LLM models** | Not identified in scope | Depends on model origin | ⚠️ Verify if used | Confirm whether any bundled or recommended LLMs have restrictions |

### 4.2 Third-Party Service Integrations

| Service | Used For | Agreement Required | Status | Notes |
|---|---|---|---|---|
| **AWS S3** | Custody storage (boto3) | AWS Terms of Service | ✓ Standard | Customer controls bucket/billing; no special license agreement needed |
| **PostgreSQL** | Data persistence | PostgreSQL License (permissive) | ✓ Standard | Dependency only; no special agreement |
| **Email/SMTP** | Not identified | Depends on provider | ✓ Not in scope | No email integration found in code |

---

## 5. GENERATED FIXTURES & TEST ASSETS

### 5.1 Legal Test Corpus

| Asset | Location | Source | License/Rights | Status |
|---|---|---|---|---|
| **Legal test fixture documents** | `tests/fixtures/legal/` | CounselClear-original (PR 10, 267a791) | MIT (repo license) | ✓ Authored in-repo; no third-party source identified in this pass |
| **Regression test suite** | `tests/test_legal_corpus.py` | CounselClear-original | MIT | ✓ Authored in-repo; test coverage present |

### 5.2 Release/Verification Output Schemas

| Artifact | Produced By | Schema Defined? | License | Status |
|---|---|---|---|---|
| **`release_packet.json`** | `job_bundle`, `service/app/main.py` | ⚠️ No formal JSON Schema | MIT (generated output) | ⚠️ Pending: formal schema definition or docstring specification |
| **`release_result.json`** | `_build_release_result`, `service/app/main.py` | ⚠️ No formal JSON Schema | MIT (generated output) | ⚠️ Pending: formal schema definition |
| **`certificate.html`** | `_render_job_certificate_html`, `service/app/main.py` | ⚠️ Template-based, no schema | MIT (generated output) | ✓ HTML template generated by system; no third-party source identified in this pass |
| **`manifest.json`** (per-job) | Engine output | ⚠️ Coverage unclear (`service/scripts/schemas/` may exist but not verified) | MIT (generated output) | ⚠️ Pending: verify schema coverage |
| **`report.json`** (verification result) | Engine output | ⚠️ Coverage unclear | MIT (generated output) | ⚠️ Pending: verify schema coverage |

---

## 6. CODE PROVENANCE & LICENSING GAPS

### 6.1 Upstream vs. CounselClear Boundary

| Area | Boundary | Verification Status | Impact |
|---|---|---|---|
| **Engine API layer** | PR 1 (`07c6ee2`): refactored, not rewritten | ⚠️ **Pending** | File contains both upstream logic (refactored) and CounselClear additions; no line-level audit performed |
| **Legal inspectors** | PR 3+ onward: entirely CounselClear-original | ✓ Identified | `pdf_legal.py`, `xlsx_legal.py`, `authoring_identity.py`, etc. are new in CounselClear scope |
| **Control plane** | PR 1+ onward: entirely CounselClear-original | ✓ Identified | `service/app/` is new work; no upstream origin |
| **Frontend** | PR 1+ onward: entirely CounselClear-original | ✓ Identified | `web/` is new work |
| **Verify/custody layers** | PR 12-13: entirely CounselClear-original | ✓ Identified | `verify.py`, `custody.py` are new in CounselClear scope |

### 6.2 Unaudited Provenance

| Item | Location | Status | Risk | Notes |
|---|---|---|---|---|
| **Stylometry scoring** | `service/scripts/score_stylometry.py` | ⚠️ **Not re-audited** | Unknown | Referenced by `text_detectors.py`; scope and provenance not verified for this pass |
| **Text detectors** | `service/scripts/text_detectors.py` | ⚠️ **Not re-audited** | Unknown | Upstream vs. original mix not confirmed |
| **Rewrite implementations** | `service/scripts/rewrite_text.py`, `clean_ctrlregen.py`, etc. | ⚠️ **Partially audited** | Medium | Some upstream-derived, some original; no line-level breakdown |

---

## 7. EXPLICIT OUT-OF-SCOPE ITEMS (No Code Path Found)

These are **intentionally excluded from the codebase per the asset map** — recorded here so the diligence process doesn't have to re-derive that fact, not as a legal determination that they carry no risk:

| Item | Reason | Basis (feature absent / scoped out) |
|---|---|---|
| **External timestamping (TSA)** | Not implemented | Design proposal exists but code does not; `anchor.type` is always `"none"` |
| **Legal certification claims** | Actively avoided in generated output | Verifier test suite enforces words like "court-proof" never appear as affirmative claims |
| **Insurance/warranty product** | Out of scope | Per asset map, CounselClear records actions and does not itself indemnify or warrant outcomes — this is a product-positioning fact, not a legal risk-transfer assessment |
| **Unattended watch mode** | Explicitly scoped out | PR 38/40/43 all named this as out of scope; no folder-watching code found in this pass |
| **Proprietary vendor watermark keys** | Not present, per asset map | SynthID production keys etc. are stated as not public and not reproduced here — not independently re-verified in this pass |

---

## 8. CRITICAL DILIGENCE ITEMS - MUST RESOLVE BEFORE COMMERCIAL DISTRIBUTION

### 🔴 HIGH PRIORITY

| Item | Action | Owner | Deadline |
|---|---|---|---|
| **CtrlRegen license status** | Contact `mertizci/noai-watermark` upstream author for written redistribution permission | Legal + eng | Before any release including this harness |
| **SynthID scorer commercial use** | Confirm reverse-SynthID's Non-commercial Research License permits commercial use of CounselClear (likely no) | Legal | Before marketing as AI-watermark detection product |
| **MIT license adequacy** | Legal review: is MIT sufficient for a product handling legal documents and making custody claims? | General Counsel | Before commercial go-live |
| **Upstream obligations** | Confirm with `guillaumemeyer` no contribution-back or attribution obligations exist | Legal | Before commercial go-live |
| **System CLI tool licenses** | Audit all system CLI tool dependencies (qpdf, exiftool, others) for restrictive licenses (GPL, proprietary) | Eng + Compliance | Before packaging for distribution |

### ⚠️ MEDIUM PRIORITY (Needed for Complete SBOM/Compliance)

| Item | Action | Owner | Deadline |
|---|---|---|---|
| **Harness "does not vendor" claims** | Independently verify no source code from THU-BPM/MarkLLM, THU-BPM/MarkDiffusion, mertizci/noai-watermark committed to this repo | Eng | Before public release |
| **Line-level code audit** | For `engine_api.py` and other files with mixed provenance, confirm upstream vs. original boundaries | Security/Eng | Before commercial distribution |
| **JSON Schema formalization** | Document or generate formal schemas for `manifest.json`, `report.json` | Eng | Before public release |
| **Core engine dependency manifest** | Create `pyproject.toml` or formal requirements file for document-parsing libraries (PIL, pypdf, python-pptx, openpyxl, etc.) | Eng | Before SBOM generation |
| **Transitive dependency audit** | Full tree audit of ML/watermark harness transitive dependencies (MarkLLM → *, MarkDiffusion → *, etc.) | Compliance | Before bundling optional harnesses |
| **Stylometry/text_detectors audit** | Confirm provenance (upstream vs. original) and audit for any restricted research dependencies | Eng | Before public release |

### ✅ NICE-TO-HAVE (Best Practices, Not Blockers)

| Item | Action | Owner | Deadline |
|---|---|---|---|
| **SBOM generation** | Auto-generate SBOM (cyclonedx, SPDX) from pinned requirements files + system tool audit | DevOps | Post-release |
| **CIP separation** | Consider separate LICENSE.COUNSELCLEAR for CounselClear-original code (from PR 1 onward) for clarity | Legal | Post-release |
| **Upstream sync policy** | Document formal policy for syncing future upstream patches from guillaumemeyer/watermarks-remover | Eng + PM | Post-release |
| **Harness licensing docs** | Add explicit README to `service/scripts/` documenting each harness's upstream license and restrictions | Eng | Post-release |

---

## 9. VERIFICATION CHECKLIST FOR GO/NO-GO

**Use this section to track final sign-off before commercial distribution.**

### Prerequisites (Must All Be ✓)

- [ ] **MIT License Adequacy** — General Counsel confirms MIT is sufficient for CounselClear's use case (legal custody, claims)
- [ ] **Upstream Obligations** — Confirmed no contribution-back/attribution obligations with `guillaumemeyer`
- [ ] **CtrlRegen Permission** — Written permission obtained from upstream author (if harness is enabled) OR harness confirmed disabled by default and never bundled
- [ ] **SynthID Commercial Use** — Legal opinion: can CounselClear market this product with optional SynthID reverse-engineer scorer? (Likely: no, unless license permits commercial derivative use)
- [ ] **System CLI Tools** — Complete audit of qpdf, exiftool, and all other system tool dependencies; confirm none are GPL or proprietary
- [ ] **Harness Vendoring** — Verified independently: no THU-BPM/MarkLLM, THU-BPM/MarkDiffusion, mertizci/noai-watermark, or aloshdenny/reverse-SynthID source code committed to this repo
- [ ] **Core Engine Dependencies** — `pyproject.toml` or formal manifest created; all document-parsing libraries (PIL, pypdf, python-pptx, openpyxl, etc.) identified and licensed
- [ ] **No Proprietary Code** — Search performed: no restricted research code, vendor watermark keys, or non-redistributable implementations found in committed tree

### Risk Acceptance (If Prerequisite Cannot Be Met)

- [ ] **Harness Opt-Out** — If SynthID or CtrlRegen cannot be licensed for commercial use, they are disabled or removed entirely before distribution
- [ ] **Upstream Sync Limitation** — If upstream obligations cannot be confirmed, fork remains read-only (current policy) and stated in public docs
- [ ] **Dependencies Unknown** — If complete dependency audit is impossible, legal team accepts residual risk and provides written exception

### Sign-Off

- **Prepared by:** ________________  **Date:** ________
- **Reviewed by (Legal):** ________________  **Date:** ________
- **Reviewed by (Engineering):** ________________  **Date:** ________
- **Approved by (Executive):** ________________  **Date:** ________

---

## Appendix: References & Citation

| Reference | Location | Purpose |
|---|---|---|
| Asset Map | `docs/COUNSELCLEAR_ASSET_MAP.md` | Base inventory (commit 0f4d69f, PR 44) |
| Design Spec | `docs/COUNSELCLEAR_DESIGN.md` | Positioning of watermark removal as gated add-on |
| Verification Proposal | `docs/release-packet-verification-and-anchoring-proposal.md` | Out-of-scope features (TSA, transparency log) |
| Vendor Notes | `skills/remove-ai-marks/references/vendor-notes.md` | Watermark harness upstream license summary |
| Core Requirements | `service/requirements-app.txt` | Application dependencies |
| Dev Requirements | `requirements-dev.txt` | Development tooling |
| Frontend Requirements | `web/package.json` | Frontend dependencies |
| Worker Isolation Test | `tests/test_worker_isolation.py` | Confirms engine/control-plane boundary |
| Legal Corpus | `tests/fixtures/legal/` | Test corpus source |

---

**Last Updated:** 2026-08-27  
**Status:** Checklist created from COUNSELCLEAR_ASSET_MAP.md  
**Next Action:** Assign owners and set deadlines for §8 critical items
