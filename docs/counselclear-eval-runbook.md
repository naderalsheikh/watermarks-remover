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

```bash
source .venv/bin/activate
COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 \
python3 tools/seed_eval_matter.py --base-url http://127.0.0.1:8443
```

Creates (or reuses) a matter named **"PDF Embedded-Image Metadata Demo"**,
uploads a synthetic PDF carrying real EXIF metadata inside an embedded JPEG
image, and runs a real inspect job then a real `external_sharing` sanitize
job against it — so the matter you land on already has populated findings
and a manifest showing the "embedded-image metadata removed" notice,
instead of an empty matter. Idempotent: safe to rerun. `--no-jobs` uploads
without triggering jobs; `--help` for all options. See the script's
docstring for why it seeds one fixture, not two — it explains, with the
actual mechanism, why the indirect-`/Length` "not cleared" UI state can't
be honestly demoed through the real product pipeline in a deployment that
has qpdf installed (which this one does).

## 4. Tested evaluation flow

1. Log in with the password above.
2. **Matters** — see the seeded matter (or create a new one).
3. Open the matter — see document count / jobs-done stats, upload a file.
4. **Inspect** a document — findings render grouped by category, with a
   risk-count summary (e.g. "3 findings · 2 high · 1 medium") at the top.
5. **Sanitize** a document — pick a policy, optionally attest to breaking a
   signature, run it. The job page shows: custody (original vs. derivative
   filename/bytes/sha256), what was found, actions taken, verification
   checks, and — for PDFs with embedded-image metadata — a dedicated
   removed/not-cleared callout.
6. **Download bundle** — contains `manifest.json`, the derivative, and
   `report.json` (plus the original, if the checkbox is ticked).
7. **Audit log** (top-right of the matter view) — event history for the
   matter.
8. **Sign out**.

Empty/loading/error states are exercised automatically: a fresh matter
shows friendly empty states, all list views show skeleton loading, and
failed uploads/inspects/sanitizes/matter-creates surface an inline error
instead of failing silently.

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
