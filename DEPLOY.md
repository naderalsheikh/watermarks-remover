# Deploying CounselClear to production

This guide deploys CounselClear as a **single web service** (FastAPI API +
built UI on one origin) using the [`render.yaml`](render.yaml) Blueprint and
[`deploy/Dockerfile.render`](deploy/Dockerfile.render). One origin keeps the
`SameSite=Strict` session cookie working without a separate reverse proxy.

> For the classic split deployment (nginx serving the static export and
> proxying `/v1/*` to a separate API container) keep using
> `service/Dockerfile.counselclear` + `deploy/nginx-counselclear.conf.example`.
> This guide is the PaaS-friendly single-container path.

Expected live URL pattern: `https://clearcounsel.onrender.com`
(Render derives the subdomain from the service `name` in `render.yaml`; the
exact host appears in the dashboard once the service is created).

---

## Render.com (recommended)

### 1. Prerequisites
- A Render account (https://render.com).
- This repository pushed to GitHub, with `render.yaml`, `deploy/Dockerfile.render`,
  and the `web/` + `service/` trees on the branch you deploy (default: `main`).
- Grant Render access to the repo when prompted (GitHub → Render app install).

### 2. Create the service from the Blueprint
1. Render dashboard → **New** → **Blueprint**.
2. Select this GitHub repository. Render reads `render.yaml` and proposes one
   web service named **clearcounsel** with a 1 GB persistent disk at `/data`.
3. Click **Apply**. The first build runs `deploy/Dockerfile.render` (Node builds
   the static UI, then it is baked into the Python API image).

### 3. Set environment variables (dashboard → the service → Environment)
The Blueprint declares these; you must supply the secret values (marked
`sync: false`). Set **one** authentication option:

**Option A — shared operator password (single-tenant pilot default)**

| Variable | Value |
| --- | --- |
| `COUNSELCLEAR_LOCAL_PASSWORD` | a long random string (this is the login password) |

**Option B — OIDC SSO (disables local login when all three are set)**

| Variable | Value |
| --- | --- |
| `COUNSELCLEAR_OIDC_ISSUER` | your IdP issuer URL |
| `COUNSELCLEAR_OIDC_CLIENT_ID` | OAuth client id |
| `COUNSELCLEAR_OIDC_CLIENT_SECRET` | OAuth client secret |
| `COUNSELCLEAR_OIDC_ALLOWED` | comma-separated email/sub allowlist (empty = nobody) |

These are pre-set by the Blueprint and normally need no change:
`COUNSELCLEAR_DATA_ROOT=/data`, `COUNSELCLEAR_COOKIE_SECURE=true`,
`COUNSELCLEAR_WORKER_MODE=subprocess`, `COUNSELCLEAR_STATIC_DIR=/app/web_out`,
`COUNSELCLEAR_ENABLE_DOCS=` (docs closed).

See [`.env.production.example`](.env.production.example) for the full annotated list.

### 4. Deploy & verify
- Render builds and starts the service. The health check hits `/health`.
- Once live, verify:
  - `https://<your-service>.onrender.com/health` → `{"ok":true,"status":"ok","product":"CounselClear","version":"..."}`
  - `https://<your-service>.onrender.com/version` → build identifier
  - `https://<your-service>.onrender.com/` → the CounselClear UI login
- Log in with the operator password (or via SSO) and run the walkthrough in
  [`docs/counselclear-eval-runbook.md`](docs/counselclear-eval-runbook.md).

### 5. Persistence & plan note
The Blueprint uses the **`starter`** plan because the app needs a persistent
disk for the SQLite database, the write-once document custody store, and the
audit chain. Render's **free** web services have an ephemeral disk and spin
down when idle, which would wipe the legal custody record on every restart —
do not use `free` for a real pilot. To scale beyond one replica, attach a
managed Postgres and set `COUNSELCLEAR_DATABASE_URL` (object custody stays on
the disk regardless).

---

## CI/CD flow after the first deploy
1. `autoDeploy: true` in `render.yaml` means every push to `main` triggers a
   new Render build + deploy automatically.
2. GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs
   on every push to `main` and every PR: Python tests + ruff lint/format, and
   the `web` job (npm lint, unit tests, and `next build` type-check/export).
3. Recommended flow: open a PR → CI must pass → merge to `main` → Render
   auto-deploys the merged commit. Roll back from the Render dashboard
   (**Deploys** → pick a previous successful deploy → **Redeploy**).

---

## Fly.io (alternative)
Fly also runs the single-container image well. Sketch:
1. `fly launch --dockerfile deploy/Dockerfile.render --no-deploy` (generates `fly.toml`).
2. In `fly.toml`, set the internal port to `8443` (or rely on `$PORT`), add a
   `[mounts]` block for a volume at `/data`, and a health check on `/health`.
3. `fly volumes create cc_data --size 1`.
4. `fly secrets set COUNSELCLEAR_LOCAL_PASSWORD=... COUNSELCLEAR_COOKIE_SECURE=true`.
5. `fly deploy`.
Render is the documented primary path because its Blueprint captures the disk +
env wiring declaratively in `render.yaml`.
