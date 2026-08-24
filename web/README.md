# CounselClear web (PR 19)

Next.js reviewer UI for the CounselClear control plane (`service/app/main.py`).
See `docs/COUNSELCLEAR_DESIGN.md` (PR 19) for the product spec.

## Architecture

Same-origin static export — no Next.js server in production. The
`cc_session` cookie is `SameSite=Strict`, so this app only ever talks to the
API at the same origin it's served from:

- **Production**: `next build` produces a static `out/` directory; nginx
  serves it at `/` and reverse-proxies `/v1/*` to `cc-api` (see
  `deploy/nginx-counselclear.conf.example` and `docs/COUNSELCLEAR_PRODUCTION.md`).
- **Development**: `next dev` has no proxy in front of it, so
  `next.config.ts` adds one — `rewrites()` forwards `/v1/*` to
  `COUNSELCLEAR_API_ORIGIN` (default `http://127.0.0.1:8443`). This only
  applies under `next dev`; static export doesn't support rewrites at all.

Runtime config (e.g. whether OIDC SSO is on) comes from `GET /v1/auth/config`,
not from an env var read at request time — a static export has no server to
read one from once deployed.

Auth is a client-side gate, not middleware: every page fetches its own data
on mount, and a 401 from any endpoint bounces to `/login` (see
`lib/useApi.ts`). Matter/job detail pages take their id as a `?id=` query
param rather than a `[id]` dynamic route segment — static export can't
pre-render pages for ids that don't exist at build time (see
`app/matters/view/page.tsx`, `app/matters/job/page.tsx`).

## Development

```bash
npm install
COUNSELCLEAR_API_ORIGIN=http://127.0.0.1:8443 npm run dev
```

Requires a running `cc-api` (see the repo root `README.md` / `compose.yaml`).

## Build

```bash
npm run build   # writes ./out
```
