# CounselClear Strategy Doctrine

Strategy doctrine set by the product owner on 2026-08-26, following the defensibility-wedge review. Apply this to every feature, roadmap, architecture, and upstream-code decision in the CounselClear fork.

(Tracked here rather than only in the root-level `counselclear-strategy.md` — that file sits outside this repo's allowlisted `.gitignore` tree and isn't visible to `git status`/`git log`/collaborators. This copy is the one that ships with the repo.)

## 1. Protect the Wedge: Defensibility, Not File Cleaning

Do not compete with Microsoft Word's "Inspect Document," Adobe Acrobat's "Remove Hidden Information," or DMS-native scrubbers on convenience alone. Those tools are destructive and weakly evidenced: they overwrite files, can break formatting, can leave recoverable incremental updates in PDFs, and provide limited evidentiary proof of what occurred.

CounselClear's moat is mathematical and procedural defensibility: the "Black Box of Legal Custody." The product should double down on WORM originals, SHA-256 manifests, policy versioning, cryptographic audit chains, and honest disclosures of unreviewed, kept, refused, or out-of-scope content.

Never dilute this with "magic auto-clean" features that obscure what actually happened to the document.

## 2. Upstream Decoupling: CounselClear Has Outgrown the Fork

Upstream (`guillaumemeyer/watermarks-remover`) is a consumer utility for stripping marks from downloaded files. CounselClear is an enterprise document-hygiene and evidentiary-custody platform with different security constraints, data models, trust boundaries, and product obligations.

Treat upstream strictly as an external reference source for obscure format parsers, research leads, or adversarial fixtures. Never treat upstream as a parent branch to sync, rebase, or cherry-pick from blindly. A parser idea borrowed from upstream is ported only through a native in-tree implementation, reviewed and covered by CounselClear's own tests — never by merging or cherry-picking upstream's diff directly.

PR 31's decision to build native in-tree features rather than force-merging divergent upstream diffs was the turning point. Keep that discipline permanently.

## 3. Integration Over Destination: The Invisible Airlock

Lawyers will not reliably log into a separate web dashboard for every document they send. In high-pressure deal closings, four extra clicks in a separate tab means the tool will be skipped and metadata will leak.

The next product horizons should emphasize ambient integration:

- Airlock drop-zones and desktop/folder-watcher workflows that output a sanitized bundle with minimal operator friction.
- CLI/API hooks in front of email attachments, DocuSign packets, iManage/NetDocuments exports, and VDR batch uploads.
- One-click handoff reports: self-contained, printable HTML/PDF custody packets filed alongside closing binders, production logs, or regulator responses.

The dashboard remains useful as an operator console, review workspace, and administrative surface. It should not become the primary product thesis.

## 4. Keep the Core Library Pristine

Never leak API, database, ORM, auth, queue, or network dependencies into the sanitization engine.

The test velocity and reliability come from the strict Engine vs. Product Shell isolation boundary: `service/scripts/engine_api.py` operates on pure bytes with no DB or control-plane access. Keep the engine stateless, functional, deterministic, and offline-runnable on a single laptop.

Keep multi-user identity, queuing, database persistence, deployment topology, audit routing, and auth strictly in the control plane (`service/app/`). The same core legal guarantees should hold whether CounselClear runs as a local CLI tool, a single-tenant Docker container, or an enterprise SaaS cluster.

`tests/test_worker_isolation.py` enforces this boundary in both directions: `test_api_module_never_imports_parsers` bans the control plane from importing the engine's parsers, and `test_engine_scripts_never_import_control_plane_or_orm_or_web_framework` bans the engine from importing the control plane, an ORM/session library, a web framework, or a control-plane-style HTTP client. This is not a blanket ban on the engine's own network I/O — several modules make outbound calls to their own optional, config-gated sidecar services (the SynthID scorer HTTP sidecar, the watermark-rewrite network, the MarkLLM/KGW detector workers), and every one degrades gracefully when unconfigured. That is a pre-existing, intentional engine capability, not control-plane leakage.

## 5. Claims Must Be Evidence-Bound

CounselClear should never say "clean," "safe," "removed," "verified," or similar unless the claim is bound to deterministic behavior, a manifest or audit entry, and a regression test or fixture.

Preferred product language:

- "Cleared under policy X."
- "Stripped under policy X."
- "Kept because reason Y."
- "Refused by policy."
- "Out of scope for this policy."
- "Verification passed for these checks."

A green UI state must never erase yellow or red limitations. Disclosure is part of the product, not a UX failure.

## 6. Model Assistance Is Not Authority

Claude, Z Code, DeepSeek, or any model may propose code, parser ideas, reviews, or implementation plans. No model self-report establishes product truth.

Product truth comes from deterministic code paths, byte-level tests where relevant, hashes, manifests, audit chains, fixtures, and independent verification. This matters especially for provenance and watermark handling, where provider incentives or policy constraints may not align perfectly with the user's goal.

Use models as builders and reviewers. Do not use model goodwill as an evidentiary guarantee.

## 7. One Writer, Explicit Handoffs

Only one agent or session may have write authority at a time. Other agents are read-only reviewers or researchers unless the user explicitly transfers write authority.

Every major handoff should include:

- Current SHA.
- Dirty/clean working-tree status.
- Pushed remote and confirmation that upstream `origin` was not touched.
- Verification state and exact test counts when available.
- Open risks or review findings.
- Next intended implementation chunk.

No blind sync, rebase, or cherry-pick from upstream. No overlapping writers.

## Why This Overrides Feature Drift

These rules are the user's corrections and confirmations of product direction. They override drift toward scrubber-UX parity, dashboard-first thinking, model self-certification, and fork-following.

Before proposing any feature, accepting upstream code, or changing architecture, check it against all seven points above.
