# CounselClear Commercial Surface Manifest

**Status:** inventory and classification only. No code or release automation changed by this document.  
**Document date:** 2026-08-28  
**Grounded at commit:** `12d6cdb`  
**Purpose:** define the current CounselClear commercial surface from actual repo paths, and classify adjacent research/build/docs surfaces as keep, quarantine, build-exclude, docs-remove, or legal-review-needed.

This document is intentionally narrower than the asset map and the IP checklist:

- The asset map says what exists.
- The IP checklist says what still needs diligence.
- This manifest says what belongs in the **CounselClear commercial product surface** versus what must stay outside it.

It is not a legal opinion. It is a repo-grounded engineering classification.

---

## 1. Classification keys

| Classification | Meaning |
|---|---|
| `safe-to-keep` | In the CounselClear commercial product surface as it exists today. |
| `quarantine` | May remain in the repo for research or internal evaluation, but must stay outside commercial packaging, default runtime, and customer-facing claims. |
| `build-exclude` | Must not be built, published, or promoted as part of a commercial release path. |
| `docs-remove` | Current user-facing or operator-facing documentation/config copy that should not be used as commercial product positioning. |
| `legal-review-needed` | Not a ship/no-ship conclusion by itself, but not cleared for commercial inclusion. |
| `hard-block` | Known licensing or claim-risk problem; keep out of the commercial surface unless separately cleared and deliberately reintroduced. |

---

## 2. The actual CounselClear commercial surface

These are the repo areas that define the Release Gate product rather than the upstream watermark-removal utility.

| Path / area | Current role | Classification | Why |
|---|---|---|---|
| `service/app/` | Control plane: auth, matters, jobs, releases, audit chain, certificates, batches | `safe-to-keep` | Core CounselClear product surface. |
| `service/Dockerfile.counselclear` | Main CounselClear API/worker image | `safe-to-keep` | This is the product container, not a research harness. |
| `web/` | Release Gate UI | `safe-to-keep` | Primary human-facing product surface. |
| `tools/counselclear_airlock.py` | Scriptable release packet workflow | `safe-to-keep` | Adoption surface for ambient/document workflow. |
| `tools/counselclear_verify_release_packet.py` | Offline verifier for release artifacts | `safe-to-keep` | Part of the evidence/receipt story, not a research add-on. |
| `docs/counselclear-eval-runbook.md` | Demo/evaluation instructions for the Release flow | `safe-to-keep` | Product-facing operational doc. |
| `compose.yaml` `cc-api`, `cc-worker`, `cc-postgres`, `cc-freshclam` under `legal`/`pg` profiles | CounselClear deployment surface | `safe-to-keep` | This is the deployable product path inside compose. |

Two important boundary notes:

1. `compose.yaml` still defaults to the upstream `wr-core` utility when run without the `legal` profile. That is a **real packaging/coherence mismatch**, not just documentation noise.
2. The repo still contains the upstream `watermarks-remover` service and its harness ecosystem. This manifest does not erase that history; it classifies it.

---

## 3. Research/runtime adapters outside the commercial surface

### 3.1 Hard-block surfaces

| Path / area | What it does | Classification | Reason |
|---|---|---|---|
| `service/scripts/clean_ctrlregen.py` | CtrlRegen adapter over `mertizci/noai-watermark` | `hard-block` | Upstream has no LICENSE per existing repo notes. |
| `service/Dockerfile.ctrlregen` | Builds local CtrlRegen image from upstream checkout | `hard-block` | Pulls all-rights-reserved research code at build time. |
| `service/scripts/setup_ctrlregen.sh` | Clones upstream CtrlRegen checkout | `hard-block` | Explicit bootstrap path for restricted code. |
| `service/scripts/setup_ctrlregen.ps1` | Windows bootstrap for CtrlRegen | `hard-block` | Same reason as shell bootstrap. |
| `service/scripts/requirements-ctrlregen.txt` | CtrlRegen-specific deps | `hard-block` | Supports a blocked harness. |
| `service/scripts/score_synthid.py` | reverse-SynthID scorer adapter | `hard-block` | Existing repo diligence says non-commercial research license. |
| `service/scripts/synthid_score_server.py` | HTTP sidecar for reverse-SynthID scoring | `hard-block` | Same license block; also provider-claim risk. |
| `service/Dockerfile.synthid` | Builds local reverse-SynthID image from upstream checkout | `hard-block` | Pulls non-commercial research code at build time. |
| `service/scripts/setup_synthid.sh` | Clones reverse-SynthID checkout | `hard-block` | Explicit bootstrap path for blocked scorer. |
| `service/scripts/setup_synthid.ps1` | Windows bootstrap for reverse-SynthID | `hard-block` | Same reason as shell bootstrap. |
| `service/scripts/requirements-synthid-scorer.txt` | SynthID scorer deps | `hard-block` | Supports a blocked harness. |
| `compose.yaml` `wr-ctrlregen`, `wr-synthid`, `wr-synthid-score` | Local-only heavy-profile services | `build-exclude` | Already local-only in intent; must remain outside commercial release paths. |

### 3.2 Quarantined / legal-review-needed surfaces

| Path / area | What it does | Classification | Reason |
|---|---|---|---|
| `service/scripts/detect_text_watermark.py` | MarkLLM adapter | `quarantine` + `legal-review-needed` | Apache-2.0 upstream appears better than the blocked harnesses, but this is still research verification, not the CounselClear product spine. |
| `service/scripts/text_detectors.py` | Optional detector orchestration | `quarantine` + `legal-review-needed` | Exposes MarkLLM and provider-specific seams. |
| `service/scripts/rewrite_text.py` | Layer B rewrite path | `quarantine` + `legal-review-needed` | Strategically gated; not part of the commercial Release Gate surface. |
| `service/scripts/markdiffusion_harness.py` | MarkDiffusion adapter | `quarantine` + `legal-review-needed` | Research harness, not product-core. |
| `service/Dockerfile.markllm` | Builds MarkLLM image | `build-exclude` + `legal-review-needed` | Currently publishable by workflow, but should not define the commercial surface. |
| `service/Dockerfile.markdiffusion` | Builds MarkDiffusion image | `build-exclude` + `legal-review-needed` | Same issue as MarkLLM. |
| `service/scripts/setup_markllm.sh` | Clones MarkLLM checkout | `quarantine` + `legal-review-needed` | Internal/research bootstrap only. |
| `service/scripts/setup_markdiffusion.sh` | Bootstraps MarkDiffusion | `quarantine` + `legal-review-needed` | Internal/research bootstrap only. |
| `service/scripts/requirements-markllm.txt` | MarkLLM-specific deps | `quarantine` + `legal-review-needed` | Supports research harness. |
| `service/scripts/requirements-markdiffusion.txt` | MarkDiffusion-specific deps | `quarantine` + `legal-review-needed` | Supports research harness. |
| `compose.yaml` `wr-markllm`, `wr-markdiffusion` | Harness-profile services | `build-exclude` + `legal-review-needed` | Optional research services; not the CounselClear product image path. |
| `.github/workflows/release-images.yml` harness matrix | Publishes `markllm` and `markdiffusion` GHCR images | `build-exclude` | This is the clearest current commercial-surface mismatch in automation. |

---

## 4. Documentation and config surfaces that are not CounselClear product positioning

These files may remain as source history or research reference, but they should not be treated as the commercial product surface without rework.

| Path / area | Current issue | Classification |
|---|---|---|
| `README.md` | Still centered on the upstream `watermarks-remover` utility, vendor watermark detection/removal, published harness images, and model-specific claims. | `docs-remove` |
| `.env.example` | Still documents MarkLLM, SynthID scorer, rewrite, and harness/heavy profile env vars alongside the repo’s product envs. | `docs-remove` |
| `compose.yaml` default `wr-core` path | Default `docker compose up` launches the upstream utility, not CounselClear. | `docs-remove` + `build-exclude` |
| `compose-check.sh` | Treats `wr-markllm`, `wr-markdiffusion`, `wr-ctrlregen`, and `wr-synthid` as part of the validation surface. | `build-exclude` |
| `benchmarks/README.md` | Benchmark-facing research doc. | `quarantine` |
| `docs/synthid-text-benchmark.md` | Research benchmark instructions and claims boundary for MarkLLM/SynthID-text. | `quarantine` |
| `docs/legal-panel/` | Legal panel raw memos and synthesis. Useful internally, not product documentation. | `quarantine` |
| `docs/plans/ideas/` | Internal planning docs, including watermark-removal deployment ideas. | `quarantine` |

Two specific documentation mismatches matter:

1. The current `README.md` still advertises published `markllm` and `markdiffusion` images, even though the product strategy has already moved away from watermark-removal as the spine.
2. The current repo has **two parallel narratives**: CounselClear Release Gate in `service/app/`, `web/`, and the Airlock/verifier tools; and upstream watermark removal in `README.md`, `wr-core`, harness images, and benchmark docs. That split is now explicit technical debt, not just branding drift.

---

## 5. Test and benchmark surfaces

| Path / area | Classification | Notes |
|---|---|---|
| `tests/` covering CtrlRegen / SynthID / MarkLLM / MarkDiffusion adapters | `quarantine` | Keep as regression coverage for research paths if those remain in-repo, but they are not evidence that the commercial product should expose them. |
| `service/scripts/bench_synthid_text.py` | `quarantine` | Benchmark tooling, not commercial release workflow. |
| `benchmarks/` corpus and outputs | `quarantine` | Research/evaluation material only. |

Tests and benchmark code are not a distribution problem by themselves. The issue is whether build, docs, and publish paths make those capabilities part of the product surface.

---

## 6. Current-state verdict

As of commit `12d6cdb`, the repo is **not yet aligned** to a single commercial surface.

What is true today:

- The **CounselClear product** exists and is coherent in code: `service/app/`, `web/`, `Dockerfile.counselclear`, Airlock, verifier, release packet, certificate, audit chain.
- The **upstream watermark-removal utility** also still exists as an active build/runtime/docs path: `wr-core`, `README.md`, harness profiles, published harness images.
- `CtrlRegen` and `reverse-SynthID` are already partially fenced off as local-only, but they still exist as bootstrap/build/runtime paths in the repo.
- `MarkLLM` and `MarkDiffusion` are less restricted on paper, but they are still research harnesses and are currently wired into a **published image workflow**, which means they are not merely “source-only.”

So the immediate engineering conclusion is:

> The repo has a usable commercial product surface, but the build/docs/release surface still exposes adjacent research systems strongly enough to blur what the product actually is.

---

## 7. Minimum enforcement pass implied by this manifest

This document does not itself change code, but it implies a bounded next pass:

1. Stop treating `markllm` and `markdiffusion` as published release artifacts in `.github/workflows/release-images.yml`.
2. Split CounselClear-facing documentation from upstream/research documentation, starting with `README.md`.
3. Make the default operator/deploy path CounselClear-first, not `wr-core`-first.
4. Keep `CtrlRegen` and `reverse-SynthID` explicitly local-only and outside any commercial packaging path.
5. Move benchmark/legal/research materials under an internal or clearly-non-product documentation boundary if they stay in-repo.

That is the smallest pass that would make the repo’s commercial surface match the product strategy already expressed elsewhere.
