# Commercial Surface Manifest — CtrlRegen / Reverse-SynthID / MarkLLM / MarkDiffusion

**Status:** audit deliverable only. No file, path, flag, or doc-string listed here was
deleted, moved, or modified by this document. No code changes were made in this pass.
**Document date:** 2026-08-31
**Grounded at commit:** `d9d1eeb` (`d9d1eeb381ec235342f0c36c1e3ffd1be3b2edae`, 2026-08-31, branch `main`)
**Search method:** `grep -rniIE` over the tree excluding `.git`, `node_modules`, `.venv`,
`__pycache__`, and `graphify-out/` (git-ignored analysis output, not source), with the
patterns `ctrlregen`, `reverse-synthid`, `synthid-scorer`, `wr-synthid`, `markllm`,
`markdiffusion` (case-insensitive; hyphen/underscore variants `ctrl[-_.]?regen`,
`mark[-_.]?llm`, `mark[-_.]?diffusion` were also swept to catch alternate spellings).

---

## 0. Headline verdicts

1. **The adapter code ships inside the published commercial image.** Both
   `service/Dockerfile.counselclear` (the product image, published to GHCR by
   `.github/workflows/release-images.yml` on `v*` tags) and `service/Dockerfile` (the legacy
   `wr-core` image) do `COPY scripts /app/scripts` — the whole `service/scripts/` tree,
   including `clean_ctrlregen.py`, `score_synthid.py`, `synthid_score_server.py`,
   `markdiffusion_harness.py`, `detect_text_watermark.py` (the MarkLLM harness),
   `bench_synthid_text.py`, and the four harness `requirements-*.txt` pin files. None of
   this is vendored upstream code (every adapter is a thin CLI wrapper that imports from a
   user-provided checkout at runtime), but **the references to the restricted-licensed
   upstream tools are baked into the commercial image**.
2. **The compose `heavy`/`harness` profiles exclude the flagged *services* from the default
   stack — but that is a runtime opt-in, not a build- or publish-time exclusion.** The
   adapters, their env-gated call paths, and the legacy CLIs that invoke them are all
   present inside the built image regardless of profile.
3. **The release workflow has never published anything.** `release-images.yml` builds and
   pushes only the CounselClear image, and only on `v*` tags — but no tag contains commit
   `8b05733` (which introduced the workflow on 2026-08-29; the latest tag `v0.6.0` is dated
   2026-08-26). The published-image surface it defines has never executed.
4. **Prose vs. build config (verified against config, not prose):** the compose header
   comments and setup-script docstrings claim the flagged tools are "local-only", "not
   redistributed", "never pushed to GHCR" — and for the *upstream code itself* that is
   true: the four harness Dockerfiles fetch upstream from GitHub at build time (pinned
   commit SHAs) and never bundle it. But the *this-repo* adapter scripts that reference
   them are not excluded from any image build; no doc claims they are, and the README's
   "you can ignore that document" boundary is docs-level only. Full verdict in §3.

---

## 1. Classification key

| Class | Meaning |
|---|---|
| **REMOVE** | Must not exist in a commercial branch/build — delete the path/flag/doc-string when the commercial split happens. |
| **QUARANTINE** | Move to a clearly-labeled `research/` subtree, excluded from default build and published images. |
| **EXCLUDE** | Docs/marketing copy only — reword or delete the reference; no code motion involved. |

Application notes: upstream code itself is never vendored, so nothing must be deleted for
licensing reasons. What a commercial branch must not do is *carry the adapters and their
option surfaces* in the product path; for items with ongoing research value outside the
product image, QUARANTINE is the proportionate class. REMOVE is reserved for artifacts whose
only purpose is to reach the flagged tool. For shared engine modules (§2.3), the class
applies to the flagged **members/flags only** — the file itself is product code and stays;
"quarantine" means moving those members out during the split.

---

## 2. The manifest table

### 2.1 Dedicated adapter/harness scripts (`service/scripts/`)

| Path | What it is | Class | Notes |
|---|---|---|---|
| `service/scripts/clean_ctrlregen.py` | CtrlRegen pixel-removal adapter CLI | **QUARANTINE** | Imports `CtrlRegenEngine` from a user checkout; no vendoring. |
| `service/scripts/score_synthid.py` | reverse-SynthID scorer adapter CLI | **QUARANTINE** | Upstream under a non-commercial Research License; adapter is this-repo code. |
| `service/scripts/synthid_score_server.py` | HTTP sidecar wrapping the scorer | **QUARANTINE** | The `wr-synthid-score` sidecar entry point; stdlib-only. |
| `service/scripts/markdiffusion_harness.py` | MarkDiffusion image-harness adapter CLI | **QUARANTINE** | Apache-2.0 upstream, imported from PyPI/checkout; never bundled. |
| `service/scripts/detect_text_watermark.py` | MarkLLM text-harness adapter CLI | **QUARANTINE** | Apache-2.0 upstream, runtime checkout import. |
| `service/scripts/bench_synthid_text.py` | Layer B rewrite benchmark driver | **QUARANTINE** | MarkLLM-dependent; fed by the `bench-synthid-text` make target and the `harness` profile. |
| `service/scripts/requirements-ctrlregen.txt` | Harness pin file (CtrlRegen ML deps) | **QUARANTINE** | Research-era pins with known advisories, per its own header. |
| `service/scripts/requirements-synthid-scorer.txt` | Harness pin file (scorer deps) | **QUARANTINE** | pip-audited by CI (see §2.7). |
| `service/scripts/requirements-markllm.txt` | Harness pin file (MarkLLM deps) | **QUARANTINE** | Watched by dependabot (see §2.7). |
| `service/scripts/requirements-markdiffusion.txt` | Harness pin file (MarkDiffusion deps) | **QUARANTINE** | Watched by dependabot (see §2.7). |
| `service/scripts/setup_ctrlregen.sh` / `.ps1` | Host bootstrap for noai-watermark | **QUARANTINE** | `.ps1` parsed by CI; `.sh` pinned to the same upstream commit as the Dockerfile. |
| `service/scripts/setup_synthid.sh` / `.ps1` | Host bootstrap for reverse-SynthID | **QUARANTINE** | Same pattern; `.ps1` parsed by CI. |
| `service/scripts/setup_markllm.sh` | Host bootstrap for MarkLLM | **QUARANTINE** | Referenced by the `bootstrap-markllm` make target. |
| `service/scripts/setup_markdiffusion.sh` | Host bootstrap for MarkDiffusion | **QUARANTINE** | Referenced by the `bootstrap-markdiffusion` make target. |

### 2.2 Harness Dockerfiles (`service/`)

| Path | What it is | Class | Notes |
|---|---|---|---|
| `service/Dockerfile.ctrlregen` | Local-only image; clones noai-watermark @ pinned SHA at build | **QUARANTINE** | Upstream ships no LICENSE → all-rights-reserved; tagged `watermarks-remover-ctrlregen:local`, never pushed. |
| `service/Dockerfile.synthid` | Local-only image; clones reverse-SynthID @ pinned SHA | **QUARANTINE** | Upstream non-commercial Research License; tagged `watermarks-remover-synthid-scorer:local`, never pushed. |
| `service/Dockerfile.markllm` | MarkLLM harness image | **QUARANTINE** | Apache-2.0 upstream; compose names a GHCR ref (`ghcr.io/…:markllm-latest`) that no workflow in this repo builds. |
| `service/Dockerfile.markdiffusion` | MarkDiffusion harness image | **QUARANTINE** | Apache-2.0 upstream; same stale-GHCR-ref note as markllm. |
| `service/Dockerfile` | Legacy `wr-core` upstream-utility image | **QUARANTINE** | `COPY scripts /app/scripts` blanket-includes the adapters; runs under the `upstream` compose profile. |
| `service/Dockerfile.counselclear` | The product image | — (see §0.1/§3) | Not itself flagged, but its `COPY scripts /app/scripts` line is the vehicle that carries every §2.1 adapter into the published image. |

### 2.3 Flagged members and flags inside shared engine modules

These are member-level classifications: the module is shared product code and stays; the
flagged member/flag is the quarantine candidate. The app layer has **zero** direct
references: grep returns no hits in `service/app/`, `service/app_launcher.py`, `tools/`,
or `engine/`. All reachability runs through the engine, gated by env vars that are off by
default.

| Path | Flagged surface | Class | Notes |
|---|---|---|---|
| `service/scripts/image_meta.py` | `run_synthid_score()` (HTTP sidecar via `WATERMARKS_SYNTHID_SCORER_URL`, else `REVERSE_SYNTHID_DIR` subprocess), `run_ctrlregen_clean()` + `ctrlregen_preexec_fn` / `_ctrlregen_python` | **QUARANTINE** (members only) | `ImageInspectReport.synthid` field and `"synthid"` in the AI-marker byte/regex lists are detection heuristics, not tool references (§2.8). |
| `service/scripts/engine_api.py` | `detect_bytes`/`inspect_http` calling `run_synthid_score`; `clean_bytes` option `remove_pixel ∈ {ctrlregen, diffusion}` (lines ~592-604) | **QUARANTINE** (members only) | Not reachable from the product path: the app worker calls `inspect_bytes` and `clean_to_bundle`, whose signatures have no `remove_pixel`. Flagged members are reachable only via the legacy CLIs / `server.py` HTTP surface. |
| `service/scripts/text_detectors.py` | `MarkLLMTextDetector` class; `run_all_text_detectors(include_markllm=…)` | **QUARANTINE** (member only) | Env-gated (`MARKLLM_DIR` etc.), off by default; the `include_markllm=False` path is tested. The gumbel/kgw/claude-text detectors in the same module are product surface. |
| `service/scripts/rewrite_text.py` | `--markllm-scheme` / `markllm_dir` / `markllm_model` / `markllm_timeout` params; `MarkLLMTextDetector` evaluator hook | **QUARANTINE** (flags only) | Layer B rewrite itself is product surface (`clean_to_bundle(layer_b_strength=…)` is passed by the app worker); only the MarkLLM hook flags are research. |
| `service/scripts/clean_image.py` | `--synthid-dir`, `--remove-pixel {ctrlregen,diffusion}`, `--ctrlregen-*` flag family, SynthID before/after prints | **QUARANTINE** (flags/strings only) | Legacy CLI; help strings name CtrlRegen/MarkDiffusion. |
| `service/scripts/inspect_image.py` | `--synthid-dir`, SynthID score prints, the "run clean_image.py --remove-pixel ctrlregen" advice line | **QUARANTINE** (flags/strings only) | Legacy CLI. |
| `service/scripts/server.py` | `/capabilities` advertising `ctrlregen`/`diffusion`/`markllm`/`synthid_http` (each gated on `NOAI_WATERMARK_DIR`/`MARKDIFFUSION_DIR`/`MARKLLM_DIR`/`WATERMARKS_SYNTHID_SCORER_URL`); OpenAPI schema entries; `synthid_http` env flag | **QUARANTINE** (flagged members only) | Legacy `wr-core` HTTP server — the whole file is upstream-utility surface, but it ships in both core images via `COPY scripts`. |
| `service/scripts/ui.html` | One skip-label: "MarkLLM research harness … not installed" | **QUARANTINE** (string only) | Legacy `wr-core` UI; moves with `server.py`. |
| `service/scripts/detect_gumbel.py` | Doc-string honesty caveat: "same as the MarkLLM harness" | **EXCLUDE** | Doc-string only; the gumbel detector itself is product detection surface — reword, don't move. |

### 2.4 App layer / product surface — clean

| Path | Finding | Class |
|---|---|---|
| `service/app/` (all files), `service/app_launcher.py`, `tools/counselclear_airlock.py`, `tools/counselclear_verify_release_packet.py`, `engine/` | **Zero grep hits** for any flagged term | — (no action) |

The commercial product surface is clean of direct references. The contamination path into
the product image is `Dockerfile.counselclear`'s blanket `COPY scripts`, not the app code.

### 2.5 Tests (`tests/`)

| Path | What it is | Class | Notes |
|---|---|---|---|
| `tests/test_ctrlregen_clean.py` | Adapter tests (fake upstream checkout) | **QUARANTINE** | Follows the adapter. |
| `tests/test_synthid_score.py` | Scorer adapter tests | **QUARANTINE** | Follows the adapter. |
| `tests/test_synthid_stdout_purity.py` | Sidecar stdout-purity tests | **QUARANTINE** | Follows the sidecar. |
| `tests/test_markllm_detect.py`, `tests/test_markllm_schemes.py` | MarkLLM adapter tests | **QUARANTINE** | Follows the adapter. |
| `tests/test_markdiffusion_harness.py` | MarkDiffusion adapter tests | **QUARANTINE** | Follows the adapter. |
| `tests/test_bench_synthid_text.py` | Benchmark driver tests | **QUARANTINE** | Follows the driver. |
| `tests/test_text_detectors.py`, `test_rewrite_text.py`, `test_gumbel_detector.py`, `test_detect_endpoint.py` | Tests of shared modules exercising the flagged members | **QUARANTINE** (flagged test functions only) | Only the tests that construct `MarkLLMTextDetector`, call `run_synthid_score`/`run_ctrlregen_clean`, or assert on their strings move; the rest of each file stays with the product modules. |
| `tests/test_json_exit_code.py:74-75` | Fixture dict fields `synthid_before`/`synthid_after` | **EXCLUDE** | Test-fixture strings; rename/delete with the flag family. |
| `tests/test_worker_isolation.py:107-109` | Comment citing the synthid sidecar / MarkLLM workers as the allowed egress exception | **EXCLUDE** | Comment only. |
| `tests/fixtures/legal/golden/gps.jpg.json:49` | `"synthid": null` key in a golden inspect report | **EXCLUDE** | Golden output of the shared image inspect — the key exists because `ImageInspectReport.synthid` does; regenerates when that field moves. |

### 2.6 Benchmarks, skills, docs

| Path | What it is | Class | Notes |
|---|---|---|---|
| `benchmarks/benchmark-smoke.sh`, `benchmarks/benchmark-full.sh` | Benchmark drivers exporting `MARKLLM_DIR`, passing `--markllm-dir` | **QUARANTINE** | Move with `bench_synthid_text.py`. |
| `benchmarks/README.md` | Doc line: benchmark "extends it with MarkLLM's `facebook/opt-1.3b`" | **QUARANTINE** | Research doc for the same driver. |
| `benchmarks/corpus/*` | Seed corpus (plain text) | — (no flagged refs) | Can stay or move with the research subtree; no flagged terms inside. |
| `docs/synthid-text-benchmark.md` | Benchmark methodology doc | **QUARANTINE** | Research doc; follows the driver. |
| `skills/remove-ai-marks/SKILL.md` + `references/{markdiffusion,vendor-notes,removal-matrix,how-word-choice-watermarks-work,ethics}.md` | Skill copy describing the optional harnesses (`remove_pixel: ctrlregen`, MarkLLM/MarkDiffusion harnesses, reverse-SynthID scorer caveats) | **EXCLUDE** | Docs copy of the upstream-utility client; reword/delete the harness references in a commercial branch. The skill as a whole is upstream-utility surface. |
| `docs/UPSTREAM_UTILITY_LEGACY.md` | Designated legacy-surface documentation (harness docs, env tables incl. `WATERMARKS_SYNTHID_SCORER_URL`) | **EXCLUDE** | This is the README-designated "ignore this" doc; delete or trim in a commercial branch — no code motion. |
| `docs/COUNSELCLEAR_ASSET_MAP.md`, `docs/COUNSELCLEAR_IP_DILIGENCE_CHECKLIST.md`, `docs/COUNSELCLEAR_COMMERCIAL_SURFACE.md`, `docs/COUNSELCLEAR_DESIGN.md` | Diligence/asset-map docs that *inventory* the flagged tools | **EXCLUDE** | Diligence records, not product claims; keep for the record. `COUNSELCLEAR_DESIGN.md`'s hits include the §"Deliberately not a blanket network ban" note documenting the gated sidecar exception. |
| `docs/counselclear-strategy.md` | Strategy memo naming the gated sidecar/tool-call exception | **EXCLUDE** | Strategy record. |
| `docs/plans/ideas/deployment-docker-cli-api.md` | Parked plan idea (CtrlRegen GPU worker, MarkLLM exclusion) | **EXCLUDE** | Parked idea; not product copy. |
| `docs/legal-panel/*` (round1/, round2/, memos, orchestrator/regen scripts) | Model-generated advisory memos citing the flagged tools — **untracked** | **EXCLUDE** | Not in git history, not in any build context (root `.dockerignore` denies everything). `docs/legal-panel/README.md` (tracked banner) is unflagged. |
| `docs/counselclear-eval-runbook.md`, `docs/COUNSELCLEAR_PRODUCTION.md` | Product docs | — (no hits) | Clean. |

### 2.7 CI / dependabot / compose / Makefile / env

| Path | Flagged surface | Class | Notes |
|---|---|---|---|
| `.github/workflows/ci.yml` | Windows step parsing `setup_ctrlregen.ps1` + `setup_synthid.ps1` (incl. a CUDA-check assertion on the ctrlregen script); pip-audit of `requirements-synthid-scorer.txt` | **QUARANTINE** (steps only) | Keeps research paths testable; follows the quarantined files. |
| `.github/dependabot.yml` | pip-ecosystem watch on `/service/scripts` (comments tie it to the synthid pins); docker-ecosystem entry tracking the synthid base image | **QUARANTINE** (entries only) | Re-scope if the research subtree moves. |
| `compose.yaml` | `wr-markllm`, `wr-markdiffusion` (`harness` profile); `wr-ctrlregen`, `wr-synthid`, `wr-synthid-score` (`heavy` profile); `wr-core`'s `WATERMARKS_SYNTHID_SCORER_URL`/`API_KEY` env; `markllm-cache`/`markdiffusion-cache`/`ctrlregen-cache`/`synthid-cache` volumes; header comments | **QUARANTINE** (services/entries only) | The `legal`-profile services (cc-api, cc-worker, cc-postgres, cc-freshclam) are clean. |
| `Makefile` | `smoke-*` / `bootstrap-*` / `docker-*-build` / `docker-*-help` targets for all four tools; `bench-synthid-text`; `compose-up-heavy`; the matching `.PHONY` entries | **QUARANTINE** (targets only) | Product targets (`test`, `lint`, `compose-up`, `compose-check`) are clean. |
| `.env.example` | `WATERMARKS_MARKLLM_DIR`/`SCHEME`, `WATERMARKS_SYNTHID_SCORER_URL`/`API_KEY`, the HF_TOKEN comment naming CtrlRegen/MarkLLM/MarkDiffusion | **QUARANTINE** (lines only) | These wire to quarantined members; delete the lines when the members move. |
| `README.md` | "Legacy upstream utility and research surfaces" section pointing at the harness docs | **EXCLUDE** | Already tells commercial evaluators to ignore it; reword/delete in a commercial branch. |

(`.github/workflows/release-images.yml` contains no flagged references — its role in the
publish question is covered in §3.)

---

## 2.8 The "synthid" strings that are NOT flagged-tool references

`service/scripts/container_meta.py:93,108,668,742` and `service/scripts/image_meta.py:104`
match the flag patterns but are **detection heuristics** — regexes/constants listing
`synthid` alongside `claude`, `gemini`, `openai`, etc. as AI-metadata markers to *find* in
files. They are product code (CounselClear detects SynthID-tagged metadata), not references
to reverse-SynthID/CtrlRegen/MarkLLM. Not QUARANTINE/REMOVE — listed so the next sweep
doesn't misclassify them. Same for the `synthid` field name in golden/fixture JSON (§2.5).

---

## 3. The Docker/compose/CI build-config verdict (verified against config, not prose)

**Question:** do the actual Dockerfiles/compose/CI build config already exclude the flagged
tools from published images, or does the README merely claim they're local-only?

**Answer: the build config excludes the flagged *upstream code* from every image — but does
NOT exclude the flagged *adapter scripts and option surfaces* from the published commercial
image. The prose claims are true for upstream code and silent on the adapters.**

Verified facts, config line by line:

1. **Upstream code never ships in any image** — true, and not merely prose:
   - `Dockerfile.ctrlregen` / `.synthid`: `git clone` of noai-watermark / reverse-SynthID
     at pinned SHAs **at build time**; the repo's comments ("NOT redistributed by this
     repository") match the config — nothing from those upstreams is committed.
   - `Dockerfile.markllm` / `.markdiffusion`: sparse clone of THU-BPM/MarkLLM / PyPI
     `markdiffusion==1.0.2` install at build time. Not committed.
   - The ctrlregen/synthid images are tagged `:local` and the compose comments ("never
     pushed to GHCR") match reality: the only publish workflow builds `Dockerfile.counselclear`
     exclusively. The markllm/markdiffusion compose `image:` lines name GHCR refs that no
     workflow in this repo builds — stale references, not a publish path.
2. **The product image DOES carry the adapter code.** `service/Dockerfile.counselclear:43`
   and `service/Dockerfile:51` both do `COPY scripts /app/scripts` — blanket copies of the
   whole scripts tree, flagged adapters included. `service/.dockerignore` whitelists only
   `scripts/**` (deny-by-default `*` + `!scripts/` + `!scripts/**`), so nothing filters
   *within* the tree; every flagged adapter ships in both core images.
3. **Compose profiles are runtime opt-in, not build exclusion.** `wr-markllm`/
   `wr-markdiffusion` are `profiles: [harness]`, `wr-ctrlregen`/`wr-synthid`/
   `wr-synthid-score` are `profiles: [heavy]` — `docker compose up` without `--profile`
   never starts them. But the default stack builds `cc-api`/`cc-worker` from
   `Dockerfile.counselclear`, whose image contents include the adapters. Profiles control
   what *runs*, not what *ships*.
4. **CI never publishes any flagged image** — true: `ci.yml` runs tests/lint/pip-audit only;
   `codeql.yml` is analysis; `release-images.yml` publishes only the CounselClear image on
   `v*` tags — and has never run (no tag contains `8b05733`; latest tag `v0.6.0` predates
   the workflow).
5. **The flagged call paths ship inside the product image but are NOT reachable from the
   product API.** `engine_api.clean_to_bundle` (the sanitize path the app worker calls)
   has no `remove_pixel` parameter, and `inspect_bytes` (the app inspect path) runs no
   detectors or scorers. `run_synthid_score` / `remove_pixel` / `MarkLLMTextDetector` are
   reachable only from the legacy CLIs and `server.py`'s `/detect`-family surface — code
   that is *present in the image* (and executable by anyone who execs into the container or
   overrides the entrypoint) but never invoked by the CounselClear ASGI app. Env gates
   (`WATERMARKS_SYNTHID_SCORER_URL`, `REVERSE_SYNTHID_DIR`, `NOAI_WATERMARK_DIR`,
   `MARKLLM_DIR`, `MARKDIFFUSION_DIR`) are all unset by default and the members degrade to
   "unavailable"/`None` without them.
6. **Research pin files are actively maintained by commercial CI.** `ci.yml` pip-audits
   `requirements-synthid-scorer.txt` and parses the two `.ps1` setup scripts on every
   Windows run; `.github/dependabot.yml` watches `/service/scripts` (all four pin files)
   weekly plus the synthid base image monthly. The research surface is live config, not
   dormant.
7. **Prose verified accurate where it makes claims.** `compose.yaml` header ("never pushed
   to GHCR", "not publicly redistributable"), the Dockerfiles' comments, and the setup
   scripts' docstrings all match the build config **for upstream code**. The gap: no
   document claims the adapters are excluded from the product image — and they are not.

**Bottom line:** "these are local-only" is half-true, and the build config proves the
better half: upstream code never ships, and no automation publishes a flagged image. The
false comfort is that the adapters and their env-gated call paths ship inside the
CounselClear image via the blanket `COPY scripts`. If the commercial split wants the
product image free of these references, the fix is a filtered scripts COPY or a
`research/` subtree move — a code change this audit explicitly does not make.

---

## 4. Build defect found during the audit (out of scope to fix here)

`service/.dockerignore` deny-by-default rules are `*` with only `!scripts/` +
`!scripts/**` whitelisted, but `service/Dockerfile.counselclear` COPYs
`requirements-app.txt` (line 38) and `app` (line 44) — both outside the whitelist. Since
the build context for every image is `service/`, the context-root `.dockerignore` applies,
and those COPY sources would be excluded from the context — the CounselClear image build
(`release-images.yml` and local `docker build -f service/Dockerfile.counselclear`) would
fail at the first out-of-whitelist COPY. This is a config contradiction, not a licensing
issue; it is derived from the ignore rules as written (Docker was not available on the
audit machine for a live confirmation), and it predates nothing: the whitelist came from
upstream (`d5563d2`) and the counselclear Dockerfile from the fork. Flagged for the
maintainers; not fixed by this pass per its no-code-changes mandate.

> If fixed by widening `service/.dockerignore` (e.g. `!app/`, `!requirements-app.txt`),
> coordinate with the QUARANTINE items above — that edit is the natural moment to also
> filter the flagged adapters out of the product image.

---

## 5. Deviations and scoped notes

- **No files were changed, moved, or deleted.** The deliverable is this manifest only,
  committed to `agent/z-commercial-surface-manifest` (off `main` @ `d9d1eeb`), pushed to
  the fork. `main` untouched.
- `docs/legal-panel/*` contents other than `README.md` remain untracked and unstaged, per
  the standing instruction for that directory.
- The brief's QUARANTINE wording ("research/ subtree") matches the existing
  `docs/COUNSELCLEAR_COMMERCIAL_SURFACE.md` vocabulary (quarantine/build-exclude, grounded
  at `12d6cdb`); this manifest is compatible with it and finer-grained (per-file,
  per-flag, per-member).
- `graphify-out/` (git-ignored analysis output whose cached AST/label JSON contains
  flagged-term hits) is generated tooling output — not tracked, not in any build context,
  excluded from the table and noted here for completeness.
- Terminology: "reverse-SynthID" (the upstream project) vs "SynthID" (Google's watermark
  family — a detection heuristic in product code) are distinct. This manifest targets the
  upstream tool only; the `synthid` detection regexes in `container_meta.py`/`image_meta.py`
  are product code and explicitly out of scope (§2.8).
