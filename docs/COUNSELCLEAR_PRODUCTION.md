# CounselClear — production deployment guide

This guide turns the compose `legal` profile into a deployment a law firm's
IT/security review can sign off. It separates three things explicitly:

- **enforced in code** — the product refuses to run unsafely;
- **deployment configuration** — decisions this guide walks through;
- **infrastructure obligations** — what your cloud/storage layer must
  provide, because no application setting can.

Everything here assumes `docs/COUNSELCLEAR_DESIGN.md` as background. The
threat model in one line: untrusted documents are parsed only inside
disposable, network-off workers; the API process and the custody store must
be protected accordingly.

---

## 1. Topology

A worked nginx TLS-terminating proxy config (upload-size cap matching the
engine's 256 MiB limit, login rate-limit zone, docs endpoints 404'd at the
edge, `X-Forwarded-Proto` for cookie `secure`) ships as
`deploy/nginx-counselclear.conf.example`.

```
            TLS terminate            ┌─────────────────────────────┐
browser ───────────────────────────▶│ reverse proxy (nginx/ALB)   │
                                    └──────────┬──────────────────┘
                                               │ plain HTTP, loopback/
                                               │ private network only
                                    ┌──────────▼──────────┐
                                    │ cc-api  (1..N)      │────▶ managed Postgres
                                    │ read_only container │      (COUNSELCLEAR_DATABASE_URL)
                                    └──────────┬──────────┘
                                               │ per-job: child process
                                               │ (subprocess mode, §3)
                                    ┌──────────▼──────────┐
                                    │ custody volume       │  WORM originals + bundles
                                    │ (matters/<id>/...)   │  → S3 + Object Lock (§5)
                                    └─────────────────────┘
```

- The API never parses documents; workers do (`app.runner`). The default
  topology above isolates that parsing to a separate OS process
  (subprocess mode) but not a separate container — see §3 for what it
  would take to get real per-job container/gVisor isolation, and why that
  is a different topology from "N containerized cc-api replicas."
- Multiple API replicas are supported **only** with Postgres
  (`COUNSELCLEAR_DATABASE_URL`); SQLite is single-writer by design.
- The login throttle and ClamAV-definition cache are per-process; behind
  replicas, enforce connection-level rate limits at the proxy too.

## 2. Images: pin everything

The product already enforces part of this:

| What | Status |
|---|---|
| Per-job worker image | **enforced**: `COUNSELCLEAR_WORKER_IMAGE` must be `repo@sha256:...`, jobs refuse to start otherwise |
| `cc-api` / `cc-postgres` / proxy images | deployment obligation — pin by digest in compose or your renderer of choice |

Build once, pin once:

```bash
docker build -f service/Dockerfile.counselclear -t registry.internal/counselclear service
docker push registry.internal/counselclear
DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' registry.internal/counselclear)
# use $DIGEST for COUNSELCLEAR_WORKER_IMAGE *and* the cc-api image reference
```

Worker and API should be **the same digest**: the worker is just the API
image invoked with an entrypoint that has no DB access. One digest means one
supply-chain review per release.

## 3. Worker sandboxing: subprocess mode (default) vs. docker mode (+ optional gVisor)

**Default: subprocess mode.** The shipped compose `cc-api` container is
read-only, non-root, and has no docker CLI or socket. `COUNSELCLEAR_WORKER_MODE`
defaults to `subprocess`: each job runs as a plain child OS process of
`cc-api` (`python -m app.worker`), isolated from the API's own DB session
(zero DB imports in `app/worker.py`, per-job scoped directories) but *not*
inside its own container — a parser exploit in a job can still reach
anything the `cc-api` container's own filesystem/user can reach, which is
why the container itself runs read-only and non-root. This is the deployment
default and works with no further setup.

**Docker mode gets you per-job container isolation, but needs a real Docker
daemon reachable from wherever the job launcher runs — which the
containerized `cc-api` above deliberately does not have.** Giving it one
means mounting the host Docker socket into `cc-api` (docker-outside-of-
docker) or running a `dind` sidecar reachable from it. Both were considered
and **rejected** for this deployment: `cc-api` is the one always-on,
network-facing, upload-handling process — handing it the docker socket
means a single `cc-api` compromise becomes host-root-equivalent (`docker run
-v /:/host ...`), which defeats not just per-job isolation but the write-once
custody guarantees this whole guide exists to make defensible. See
`docs/COUNSELCLEAR_DESIGN.md` ("Deliberately not done" under the 2026-08-22
hardening pass, and the PR 21 status note) for the fuller rationale.

**To get real per-job docker/gVisor isolation, run `cc-api` as a native host
process instead of the containerized compose service** — a host process
reaches the host's own Docker daemon the ordinary way (its user's normal
`docker` group membership / socket permissions), no socket-mounting into a
container required. A hardened systemd unit for exactly this shape ships as
`deploy/counselclear-api.service.example` (non-root user, `ProtectSystem=strict`
with the data root as the only writable path, `--proxy-headers` so cookies
keep their `secure` flag behind TLS, docker group commented in only when
`WORKER_MODE=docker`). This is a different topology from "N containerized
`cc-api` replicas behind a proxy" (§1): it trades that horizontal-scaling
shape for the isolation property. If you need both — many containerized
`cc-api` replicas *and* per-job container isolation — that requires a
privilege-separated launcher (a minimal separate daemon that owns the
Docker socket and exposes a narrow, schema-validated "launch exactly this
sandboxed job" RPC to `cc-api`, never the raw socket); that component does
not exist yet and is unscoped work, not a config flag.

Required settings for docker mode, once `cc-api` (or the launcher above)
actually has daemon access:

```yaml
COUNSELCLEAR_WORKER_MODE: docker
COUNSELCLEAR_WORKER_IMAGE: <digest-pinned>
COUNSELCLEAR_WORKER_TIMEOUT_S: "600"   # upper bound; Caps budgets tighten it per job kind
```

Workers launch with `--network none`, read-only rootfs, capped tmpfs, and
per-job fresh directories containing exactly one document copy. One
hardening upgrade available on top:

- **gVisor (runsc)** for the per-job workers: intercepts syscalls in
  userspace, so a parser 0-day faces a smaller kernel surface. Register
  the runtime with Docker on the host (`deploy/docker-daemon-gvisor.json.example`
  — merge the `runtimes` key into your existing `/etc/docker/daemon.json`):

  ```json
  // /etc/docker/daemon.json
  { "runtimes": { "runsc": { "path": "runsc" } } }
  ```

  then set `COUNSELCLEAR_WORKER_RUNTIME=runsc` — the runner passes
  `--runtime runsc` to every per-job container. Verify with
  `docker info | grep runtimes` on the host, and confirm a job's
  `docker inspect` shows `"Runtime": "runsc"` while it runs.

Separately, if your orchestrator supports per-container runtimes, running
`cc-api`'s own container under gVisor (or Kata) is still worth doing
regardless of worker mode — the API parses nothing itself, so plain `runc`
is acceptable, but gVisor is cheap insurance and shrinks the whole stack's
kernel exposure, not just the workers'.

## 4. Database

Use a managed Postgres where someone else owns patching and backups:

```
COUNSELCLEAR_DATABASE_URL=postgresql+psycopg://counselclear:<secret>@db.internal:5432/counselclear
```

- Migrations run automatically on every boot (`upgrade_head`) — replicas
  racing at boot is safe (Alembic runs inside a transaction).
- Enable encryption at rest (KMS-backed storage encryption) and automated
  snapshots with PITR. The audit hash chain detects tampering but does not
  replace backups.
- Network: private subnet only, no public address; security group allowing
  5432 from the API replicas exclusively.
- The bundled compose `cc-postgres` (pg profile) is for pilots, not for
  production — it lacks managed backups and failover.

## 5. Custody store: Object Lock, CMK, residency

Originals and derivative bundles are written once (`custody.write_once`
refuses overwrites of existing content) under `{data_root}/matters/...`.
For production, put that directory on storage with real immutability:

**S3 + Object Lock (recommended shape)**

- Create the bucket with **Object Lock enabled** (bucket property, only set
  at creation), versioning on.
- Use **compliance mode** retention for matter originals — nobody, including
  root, can shorten it. Choose the retention from your jurisdiction's
  retention schedule (e.g. 7–10 years); governance mode is only for testing.
- Default retention on the bucket (e.g. `COMPLIANCE`, N days) plus a
  lifecycle policy for non-original prefixes.
- Mount options: s3fs/Mountpoint-for-S3 works for the pilot profile; for
  throughput-sensitive deployments, sync to S3 asynchronously and keep the
  local volume as cache — the app only requires POSIX write-once semantics
  on the path it sees.

**CMK (customer-managed key)**

- Give the bucket its own KMS key (`aws:kms` default encryption), separate
  from other workloads' keys, with a key policy listing exactly the roles
  that may decrypt: API replica role + backup role. Rotation on, deletion
  protection via the key policy.
- Consequence worth stating out loud: deleting the key renders every
  archived original permanently unreadable. Treat key deletion like
  shredding the firm's filing cabinets — some jurisdictions require exactly
  that at end of retention; automate it, don't improvise it.

**Residency**

- Region-pin everything: bucket, KMS key, Postgres instance, and the
  compute running `cc-api`/workers in one region. Cross-region replication
  would silently defeat residency promises — don't enable it unless counsel
  says otherwise.
- The manifest records digests and tool versions, not personal data; the
  documents themselves are what residency rules target.
- Note egress exceptions honestly: the `cc-freshclam` sidecar needs
  outbound 443 to `database.clamav.net`, and OIDC login calls your IdP.
  Everything else (workers, DB, storage) stays inside the perimeter.

## 6. Authentication

Two supported postures:

1. **Local password (single operator)** — set `COUNSELCLEAR_LOCAL_PASSWORD`;
   argon2id hash lands in `{data_root}/auth/local.hash`. Rotate by deleting
   that file and restarting with the new value.
2. **OIDC SSO (recommended for firms >1 person)** —

   ```
   COUNSELCLEAR_OIDC_ISSUER=https://idp.example.com
   COUNSELCLEAR_OIDC_CLIENT_ID=counselclear
   COUNSELCLEAR_OIDC_CLIENT_SECRET=<from IdP>
   COUNSELCLEAR_OIDC_ALLOWED=alice@firm.com,bob@firm.com
   ```

   Register the callback `<public-base-url>/v1/auth/oidc/callback` in the
   IdP (RS256). The allowlist is fail-closed — an empty list locks everyone
   out, and the startup log warns about it. Sessions share the cookie TTL
   (12 h); `POST /v1/auth/revoke-sessions` rotates the cookie secret and
   kills all sessions instantly when a laptop goes missing.

Behind a TLS-terminating proxy, cookies get their `secure` flag automatically
(the flag follows the request scheme). Keep `/health` and `/health/ready`
off the public listener if your compliance checklist demands it; neither
leaks anything but neither is authenticated.

`GET /health` is a bare liveness check — no dependencies, always 200 once
the process is up. `GET /health/ready` additionally runs `SELECT 1` against
the database and returns 503 if it's unreachable. Wire an orchestrator's
**liveness** probe (the one that restarts the container) to `/health` and
its **readiness** probe (the one that stops routing traffic) to
`/health/ready` — a liveness probe on the DB-checking endpoint would
restart `cc-api` over a transient database outage that a restart can't fix
anyway, and would keep restarting it for as long as the outage lasts.
Compose's own `healthcheck:` (below) uses `/health/ready`, since compose
doesn't auto-restart on an unhealthy container by default — there the DB
check is purely informational, surfaced in `docker ps`.

## 7. Operations checklist

- [ ] Deploy artifacts match what's running: proxy config derived from
      `deploy/nginx-counselclear.conf.example` (rate-limit zones, 256m body
      cap, docs endpoints 404'd), service unit from
      `deploy/counselclear-api.service.example` (hardening intact, docker
      group only if `WORKER_MODE=docker`)
- [ ] `cc-api` healthcheck green (`GET /health/ready` exercises the DB);
      any orchestrator livenessProbe points at `/health` instead, not
      `/health/ready`
- [ ] Startup posture log reviewed: `worker_mode`, `auth_mode`, `db_backend`,
      no warnings about subprocess mode / missing clamscan / empty allowlist
- [ ] JSON request logs shipped somewhere durable; `X-Request-ID` echoed to
      clients matches log lines
- [ ] `cc-freshclam` running and the shared definitions volume younger than
      a week (else uploads fall back to depth checks only)
- [ ] Docs endpoints (`/docs`, `/openapi.json`) returning 404 — they are
      opt-in (`COUNSELCLEAR_ENABLE_DOCS=1`) for local development only
- [ ] Audit chains verified periodically: `GET /v1/matters/{id}/audit`
      reports `chain_ok: true` (hash chain recomputed server-side)
- [ ] Backup restore rehearsed: Postgres snapshot + custody volume restored
      into a scratch environment, bundle download succeeds
- [ ] pip-audit / image CVE scan in CI green for the deployed digest

## 8. What this product deliberately does not do

Stated so reviewers don't assume otherwise:

- No multi-tenant org model — ACLs scope matters within one firm's install.
- No built-in S3 client — custody targets a POSIX path; object-lock/KMS/
  residency are properties of the storage you mount there (§5).
- No per-user session revocation list — revocation = cookie-secret rotation
  (all sessions die together).
- The audit chain proves integrity after the fact; it cannot prevent a
  database administrator with raw SQL access from rewriting rows and
  recomputing hashes — restrict DB admin access accordingly.
