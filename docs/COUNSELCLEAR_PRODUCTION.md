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
                                               │ per-job: docker run --network none,
                                               │ digest-pinned worker image
                                    ┌──────────▼──────────┐
                                    │ custody volume       │  WORM originals + bundles
                                    │ (matters/<id>/...)   │  → S3 + Object Lock (§5)
                                    └─────────────────────┘
```

- The API never parses documents; workers do, isolated (`app.runner`).
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

## 3. Worker sandboxing: docker mode (+ optional gVisor)

Required settings (already the compose defaults):

```yaml
COUNSELCLEAR_WORKER_MODE: docker
COUNSELCLEAR_WORKER_IMAGE: <digest-pinned>
COUNSELCLEAR_WORKER_TIMEOUT_S: "600"   # upper bound; Caps budgets tighten it per job kind
```

Workers launch with `--network none`, read-only rootfs, capped tmpfs, and
per-job fresh directories containing exactly one document copy. Two hardening
upgrades available at deploy time:

1. **gVisor (runsc)** for the per-job workers: intercepts syscalls in
   userspace, so a parser 0-day faces a smaller kernel surface. Register
   the runtime with Docker on the host:

   ```json
   // /etc/docker/daemon.json
   { "runtimes": { "runsc": { "path": "runsc" } } }
   ```

   then set `COUNSELCLEAR_WORKER_RUNTIME=runsc` — the runner passes
   `--runtime runsc` to every per-job container. Verify with
   `docker info | grep runtimes` on the host, and confirm a job's
   `docker inspect` shows `"Runtime": "runsc"` while it runs.

2. **gVisor (or Kata) for `cc-api` itself** if your orchestrator supports
   per-container runtimes. The API parses nothing, so runc is acceptable;
   gVisor costs little and shrines the whole stack.

Honest limits: docker-mode workers need access to the host Docker daemon via
the mounted socket or dind sidecar — grant that socket to the API host
deliberately and audit who can reach it; anyone with it can run any
container image on that host.

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
(the flag follows the request scheme). Keep `/health` off the public
listener if your compliance checklist demands it; it leaks nothing but is
not authenticated.

## 7. Operations checklist

- [ ] `cc-api` healthcheck green (`GET /health` exercises the DB)
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
