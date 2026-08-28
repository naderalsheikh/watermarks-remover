# CounselClear evaluation runbook

Minimal operator note for reproducing a live, browser-evaluable CounselClear
session locally. Assumes this repo checkout, a `.venv` with
`service/requirements-app.txt` installed, and `web/node_modules` installed
(`npm install` in `web/`). Also assumes `exiftool` and `qpdf` are on `PATH`
(`brew install exiftool qpdf` on macOS) — both are required for the real
metadata-strip and structural-rewrite paths; without them the product still
runs but falls back to degraded modes that are honestly flagged in the UI,
not silently skipped.

## 1. Start the backend

```bash
cd /Users/naderalsheikh/watermarks-remover
source .venv/bin/activate
COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 \
COUNSELCLEAR_DATA_ROOT=/tmp/cc-eval-data \
uvicorn app_launcher:app --app-dir service --host 127.0.0.1 --port 8443
```

`COUNSELCLEAR_DATA_ROOT` isolates eval data (sqlite DB + document blobs)
from any other local run — delete that directory for a fully clean slate.
The password is whatever you set `COUNSELCLEAR_LOCAL_PASSWORD` to; there is
no default. A `429` on login is the built-in per-peer brute-force throttle
firing, not a bug — restart the backend process to clear its in-memory
state, or just wait.

Health check: `curl http://127.0.0.1:8443/health` should return `{"ok":true}`.

## 2. Start the frontend

```bash
cd web
npm run dev
```

Open **http://localhost:3000**. `next dev`'s own rewrite forwards `/v1/*`
to `http://127.0.0.1:8443` (override with `COUNSELCLEAR_API_ORIGIN`); this
proxy only exists in dev — production serves the static export behind
nginx instead (see `deploy/nginx-counselclear.conf.example`).

## 3. Seed a demo matter (optional but recommended)

**Easiest: click it.** Once logged in, the **Matters** page (an
instance with no matters especially) shows a "Load sample matter" button
next to the "New matter" form — local-password mode only. Click it and
you land directly on a populated matter; skip to §4.

**Or from the CLI** (same result, useful for scripting/CI or a headless
check before opening a browser at all):

```bash
source .venv/bin/activate
COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 \
python3 tools/seed_eval_matter.py --base-url http://127.0.0.1:8443
```

Creates (or reuses) a matter carrying three synthetic legal-document
fixtures and prepares a real release on each, under the
`counterparty_deal_room` profile — through `POST .../documents/{id}/releases`,
the same Release-native route the web UI's "Prepare Release Packet" button
and the Airlock CLI both use. Three fixtures, three real outcomes, deliberately
under one profile so the walkthrough is "one profile, three outcomes" rather
than also requiring you to reason about profile choice:

| Fixture | Outcome | What it shows |
|---|---|---|
| `Sample - Stock Purchase Agreement.docx` | **done** | A comment strips, tracked changes get Accept-All'd, and a hidden (`w:vanish`) "ATTORNEY WORK PRODUCT" paragraph survives **flagged, not stripped** — one document, both behaviors. |
| `Sample - Macro-Enabled Draft.docm` | **refused** | Macro-enabled files are refused outright by this policy — deterministic, no attestation ambiguity. This is the gate working as intended, not an error. |
| `Sample - Deal Terms Workbook.xlsx` | **done, with a kept finding** | A comment and an external link strip; a hidden sheet is flag-only under this policy and survives — visible under "What was found" on the job page but absent from "Actions taken". |

Idempotent: safe to rerun — reuses the matter, skips documents already
uploaded by filename, and skips releasing a document that already has one.
`--no-releases` uploads without preparing releases; `--help` for all options.
No Layer B / watermark-rewrite sample is included — that capability is
gated, off by default, and not what this walkthrough demonstrates.

## 4. Tested evaluation flow

1. Log in with the password above.
2. **Matters** — click "Load sample matter", or open the seeded matter from
   the list. Demo matters carry a visible "Demo" badge, both in the list and
   on the matter page itself — never confusable with a real client matter.
3. Open the **done** document (the SPA) — its job page shows: custody
   (original vs. derivative filename/bytes/sha256), "What was found" vs.
   "Actions taken" (with a one-line explainer for why an item can appear in
   one list and not the other), verification checks, and the release context
   (profile, recipient, purpose, intent — never a "sent"/"delivered" claim).
   Download the release packet.
4. Open the **refused** document (the macro-enabled draft) — the job page
   reads "Refused by policy — this is expected, not an error," with the
   specific reason. No derivative, but `release_result.json` is still
   downloadable on its own.
5. Open the **kept-finding** document (the workbook) — same as step 3, but
   "What was found" lists the hidden sheet while "Actions taken" doesn't:
   a real, visible limitation, not a hypothetical one.
6. **Verify offline** — every job page with a release now shows a copy-paste
   command next to "Download release result (JSON)":
   ```bash
   python3 tools/counselclear_verify_release_packet.py <downloaded-file-or-folder>
   ```
   Run it against the downloaded packet (unzip first) or the standalone
   `release_result.json` for the refused case — expect `INTERNALLY CONSISTENT`
   for both, plus the explicit "NOT EXTERNALLY ANCHORED" disclosure.
7. **Audit log** (top-right of the matter view) — event history for the
   matter. A demo matter's activity does **not** appear in the cross-matter
   **Dashboard** totals/attention feed — that aggregation deliberately
   excludes `is_demo` matters so seeding one never pollutes an operator's
   real caseload view.
8. Try your own document — create a **new** matter (not the demo one; it
   warns you why in-app) and upload it there, then prepare a release, to
   confirm the same loop works on real content, not just the seeded
   fixtures.
9. **Sign out**.

Empty/loading/error states are exercised automatically: a fresh matter
shows friendly empty states, all list views show skeleton loading, and
failed uploads/releases/matter-creates surface an inline error instead of
failing silently.

## 5. Verification commands actually run for this pass

State exact scope — narrow runs are labeled narrow, not "verified":

```bash
# frontend, from web/
npx tsc --noEmit          # clean
npm run lint               # clean
npm run test                # vitest — pure-logic unit tests (web/lib/**/*.test.ts)
NODE_ENV=production npx next build   # clean static export

# backend, from repo root with .venv active
ruff check service/ tools/           # clean
python3 -m pytest -q                 # full suite — see PR/commit notes for pass count
```

`npm run test` runs Vitest against `web/lib/**/*.test.ts` only — pure logic
(e.g. `productionReview.ts`'s per-finding-review gate), not component
rendering. There's no jsdom/React Testing Library setup; page/component
behavior is verified live in the browser instead, per this project's
standing practice, not through a rendering test harness.

## 6. Known, documented limitations (not bugs)

- `privacy_only` PDF sanitize jobs remove GPS/EXIF location from embedded
  images (`exiftool -gps:all=`, byte-preserving) while leaving other
  embedded metadata and any C2PA/JUMBF provenance untouched — both
  outcomes are disclosed as explicit manifest actions. See
  `docs/pdf-deep-image-metadata.md` ("`privacy_only` embedded-image
  handling — resolved in two stages").
- The indirect-`/Length` embedded-image "skip" case is real and unit
  tested, but unreachable through `external_sharing`/`production` sanitize
  jobs in a deployment with qpdf installed — qpdf's own structural rewrite
  normalizes indirect references to direct ones as a side effect before
  the strip step runs. Full mechanism in `docs/pdf-deep-image-metadata.md`.
