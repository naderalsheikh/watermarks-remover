# CounselClear Server pilot: operator quick start

One organization, one API process, LOCAL/SQLite storage. This page is the
ordered path through the other docs — it duplicates nothing; each step
links to the doc that actually covers it.

## 0. What this is, and isn't

A bounded **Server pilot**: install on one supported Linux/Docker host,
run the browser document workflow, back it up, upgrade it, recover it on a
replacement host. Desktop and Cloud are separate roadmap items. Passing
every step below qualifies *this reference environment*, not your actual
production host, domain, or identity provider — see "What's still your
decision" at the end.

## 1. Build

```sh
docker build -f service/Dockerfile.counselclear \
  --build-arg CC_VERSION="$(git rev-parse --short HEAD)" \
  -t counselclear service
```

`--build-arg CC_VERSION` is not optional if you want to tell deployments
apart later: it's baked in as `COUNSELCLEAR_VERSION` and surfaced,
unauthenticated, at `GET /v1`. Omitting it leaves every build reporting
`"dev"`. Push it to your registry and pin the resulting digest — see
[`COUNSELCLEAR_PRODUCTION.md` §2](COUNSELCLEAR_PRODUCTION.md) ("Images: pin
everything"). The same digest is what `COUNSELCLEAR_WORKER_IMAGE` must
name, byte-for-byte (`repo@sha256:...`) — the app refuses to start jobs
against an unpinned reference.

Build the web static export separately (`npm ci && npm run build` in
`web/`) and serve `web/out` same-origin behind the proxy — see
[`COUNSELCLEAR_PRODUCTION.md` §1](COUNSELCLEAR_PRODUCTION.md) for the
topology diagram and the worked nginx config
(`deploy/nginx-counselclear.conf.example`).

## 2. Choose worker isolation and configure

Read [`COUNSELCLEAR_PRODUCTION.md` §3](COUNSELCLEAR_PRODUCTION.md)
("Worker sandboxing") before picking `subprocess` vs. `docker` mode — the
containerized compose `cc-api` cannot reach a Docker daemon by design (that
was a deliberate rejection, not an oversight); real per-job container
isolation needs `cc-api` running as a native host process
(`deploy/counselclear-api.service.example`). Do not let this default
silently to `subprocess` for anything beyond a development evaluation.

Copy `.env.example` to `.env` and work through it — local password vs. OIDC
SSO ([§6](COUNSELCLEAR_PRODUCTION.md)), storage backend, `COUNSELCLEAR_TSA_URL`
(anchoring is **on by default against a third party**; choose explicitly —
[§6b](COUNSELCLEAR_PRODUCTION.md)), and `COUNSELCLEAR_VERSION` from step 1.

## 3. Check before you start anything

```sh
python tools/counselclear_preflight.py \
  --data-root /srv/counselclear/data --web-root /srv/counselclear/web
```

Run this under the API's own service account and environment, **before**
starting the service. Exit 2 means a blocking configuration problem; it
creates nothing and starts nothing, so re-run it after every fix. See
[`COUNSELCLEAR_PREFLIGHT.md`](COUNSELCLEAR_PREFLIGHT.md) for exactly what
it does and does not check — worker isolation, signing/encryption key
presence, auth completeness, malware-scanner presence *and definition
freshness*, and web export completeness among them. A clean exit is a
configuration check passing, **not** production readiness.

## 4. Start, then rehearse

Bring up the stack (`docker compose up --build -d` for the pilot profile,
or the systemd unit for native `cc-api`), then rehearse — login, a
synthetic upload/inspect/release/refusal cycle, packet download, standalone
signature verification, browser packet verification, process restart.
`tests/test_deployment_http_smoke.py` is the reference rehearsal this
project's own CI runs against a real pinned worker image and a real nginx
TLS proxy; read it before improvising your own.

## 5. Back it up, then prove you can recover

```sh
python tools/counselclear_backup.py \
  --source /srv/counselclear/data --destination /backups/$(date +%F)
```

See [`COUNSELCLEAR_BACKUP.md`](COUNSELCLEAR_BACKUP.md) — in particular:
stop the API first (an unenforced precondition, not one this tool can
verify), and a "verified" backup report is *not* a recovery rehearsal by
itself. Periodically feed a real backup into
[`tools/counselclear_restore_drill.py`](COUNSELCLEAR_RESTORE_DRILL.md)
against a throwaway destination and confirm it boots and serves the same
evidence. Do this *before* you need it for real.

## 6. Upgrade and rollback

Back up first (step 5) — every time, not just for major upgrades.
`PRODUCTION_FOUNDATION.md` documents that migration `0012` (release
certificate snapshots) is not a byte-preserving schema downgrade once
snapshots exist; a pre-upgrade backup, not a schema downgrade, is the
reliable rollback path. Startup applies migrations automatically
(`upgrade_head`) — stop the old process, take the backup, start exactly
one upgraded process before admitting traffic; Alembic transactions are
not a cross-process migration lock.

## Troubleshooting

| Symptom | Likely cause | Where |
|---|---|---|
| Preflight exits 2 | A listed check is `block` — read its `detail`, it names the fix | `COUNSELCLEAR_PREFLIGHT.md` |
| Login works but every job fails "scanner error" | `COUNSELCLEAR_CLAMAV_DB_DIR` points at an empty/wrong directory | preflight's `malware_definitions` check; `service/app/malware.py` |
| Jobs refuse to start, citing the worker image | `COUNSELCLEAR_WORKER_IMAGE` isn't `repo@sha256:...`, or doesn't match what was built | `COUNSELCLEAR_PRODUCTION.md` §2 |
| Cookies missing `Secure` behind a proxy | `--proxy-headers` not passed to uvicorn, or `X-Forwarded-Proto` not forwarded | `COUNSELCLEAR_PRODUCTION.md` §6 |
| A release has no timestamp anchor | `COUNSELCLEAR_TSA_URL` unset (defaults to a public third party) or set to an endpoint that refused | `COUNSELCLEAR_PRODUCTION.md` §6b |
| Backup refuses "already exists" / "not drained" | Pick a new destination; a queued/running job, release, batch, or non-terminal mail submission is still live — this is by design, not a bug | `COUNSELCLEAR_BACKUP.md` |
| Restore refuses a mail submission | Only `refused`/permanently-`held`/`acknowledged` mail relocates; anything else means the coordinator could still act on it | `COUNSELCLEAR_RESTORE_DRILL.md` "Mail submissions" |
| `GET /v1` reports `"version": "dev"` | `--build-arg CC_VERSION` was omitted at build time | this doc, step 1 |

## What's still your decision (this pilot does not choose for you)

- The actual host, domain, TLS certificate, and reverse-proxy operator.
- Local password vs. OIDC SSO, and — if OIDC — the identity provider and
  allowlist.
- `COUNSELCLEAR_TSA_URL`: a named third party, your own timestamp
  authority, or `off` (zero egress, no independent timestamp claim).
- Malware-definition update cadence (the `cc-freshclam` sidecar, or your
  own schedule) and what "stale" means for your risk tolerance.
- Backup schedule, retention, and where backups (and the volume key,
  separately) are stored.
- Worker isolation mode and, if `docker`, whether gVisor is worth the
  operational cost on your host.

## What this pilot has *not* qualified

- Any real target host, domain, or identity provider — everything above
  was rehearsed against the reference environment (loopback, a synthetic
  cert, a real but disposable worker image and data root), not a live
  deployment.
- PostgreSQL or S3 backup/restore — this pilot's backup/restore tools are
  LOCAL/SQLite only; see `COUNSELCLEAR_BACKUP.md`/`COUNSELCLEAR_RESTORE_DRILL.md`
  for what a Postgres/S3 equivalent would still need.
- Desktop packaging, live mail transport (SMTP/Exchange), and multi-tenant
  Cloud — separate roadmap items, out of scope for this milestone.
- Malware-scanning coverage — this pilot checks that clamscan is present
  and its definitions are fresh under your configured directory; it does
  not (and cannot, offline) certify actual detection coverage.
