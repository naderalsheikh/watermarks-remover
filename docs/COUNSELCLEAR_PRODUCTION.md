# CounselClear — production deployment guide

This guide describes the deployment components and the evidence still needed
for a controlled pilot. Passing CI does not qualify a firm's deployment or any
of the Desktop, Server, or Cloud editions. The current integration implements
durable jobs, request retries, version-pinned S3 originals, and an internal mail
attachment bridge. Live mail transport and central tenant administration remain
separate work.

For an installed single-operator LOCAL/SQLite pilot, run the
[read-only configuration preflight](COUNSELCLEAR_PREFLIGHT.md) under the API's
service account and environment before the synthetic deployment rehearsal.
It reports configuration blockers and unchecked runtime requirements without
starting services, connecting to databases, or creating keys.

Use one API process with a durable data root. For untrusted document processing,
use the Docker worker mode described below. The compose subprocess profile is a
development/evaluation configuration. The API also performs upload screening and
bounded archive inspection; it is incorrect to describe it as parsing no
untrusted input. Worker isolation reduces the document engine's exposure but
does not remove the API's own input-processing surface.

---

## 1. Topology

A worked nginx TLS-terminating proxy config (upload-size cap matching the
engine's 256 MiB limit, login rate-limit zone, docs endpoints 404'd at the
edge, `X-Forwarded-Proto` for cookie `secure`) ships as
`deploy/nginx-counselclear.conf.example`.

```text
browser -- HTTPS --> nginx (static web/out and same-origin API proxy)
                         |
                         v
                  native cc-api (one process) --> SQLite or PostgreSQL
                         |                              |
                         +--> durable local data root <-+
                         |    attempts, bundles, auth keys
                         +--> original store: local or S3 version references
                         |
                         +--> Docker daemon --> per-job engine container
                                                network off for metadata jobs
```

- The API's Docker access remains host-root-equivalent in this topology.
  Running it natively avoids a socket mount but does not remove that privilege.
  Restrict the host to this deployment and treat API compromise as a host-level
  custody risk. A separate constrained launcher is not implemented.
- The durable job queue uses database claims, shared capacity, renewable
  leases and attempt fencing. Single requests and batch children use the same
  queue. A request disconnect does not cancel admitted work; expired owners
  are recovered, and job/release/batch terminal records commit with their
  audit events. See [job recovery operations](COUNSELCLEAR_JOB_RECOVERY.md).
- Queue concurrency and transaction behavior have dedicated SQLite and real
  PostgreSQL tests, including independent processes. This does not qualify an
  entire multi-replica deployment: every executor still needs the same durable
  data-root paths for attempt files and bundles. Apply migrations once before
  starting workers. Keep the shipped one-API topology until shared-volume,
  ingress/identity and restore behavior are qualified for the target environment.
- The login throttle and ClamAV-definition cache remain per-process. A
  multi-replica deployment also needs proxy-level connection throttling.

## 2. Images: pin everything

The product already enforces part of this:

| What | Status |
|---|---|
| Per-job worker image | **enforced**: `COUNSELCLEAR_WORKER_IMAGE` must be `repo@sha256:...`, jobs refuse to start otherwise |
| `cc-api` / `cc-postgres` / proxy images | deployment obligation — pin by digest in compose or your renderer of choice |

Build once, pin once:

```bash
docker build -f service/Dockerfile.counselclear \
  --build-arg CC_VERSION="$(git rev-parse --short HEAD)" \
  -t registry.internal/counselclear service
docker push registry.internal/counselclear
DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' registry.internal/counselclear)
# use $DIGEST for COUNSELCLEAR_WORKER_IMAGE *and* the cc-api image reference
```

`--build-arg CC_VERSION` is baked into the image as `COUNSELCLEAR_VERSION` and
surfaced unauthenticated at `GET /v1` (`{"version": "..."}`) — the same
digest pin above proves *which bytes* are running; this proves which
release/commit an operator or support engineer is looking at without
needing to already know the digest. Omitting it leaves every deployment
reporting `"dev"`, indistinguishable from every other unversioned build.

Build the native API checkout and worker image from the same reviewed revision.
When using the evaluation API container, use that same image digest for both.
The worker entrypoint does not use the database; Docker mode withholds its
credentials and the main data root. Subprocess mode inherits API privileges.
Keep previously admitted worker images available until their queued jobs drain.

## 3. Worker sandboxing: subprocess mode (default) vs. docker mode (+ optional gVisor)

**Development default: subprocess mode.** The shipped compose `cc-api` container is
read-only, non-root, and has no docker CLI or socket. `COUNSELCLEAR_WORKER_MODE`
defaults to `subprocess`: each job runs as a plain child OS process of
`cc-api` (`python -m app.worker`), isolated from the API's own DB session
(zero DB imports in `app/worker.py`, per-job scoped directories) but *not*
inside its own container — a parser exploit in a job can still reach
anything the `cc-api` container's own filesystem/user can reach, which is
why read-only and non-root settings alone do not qualify this mode for a
production document-processing boundary.

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
regardless of worker mode — the API still handles uploads, archive screening, and authentication.
Runtime availability and compatibility must be tested on the target host;
the current real-image CI exercises Docker's default runtime, not gVisor.

## 4. Database

Use a managed Postgres where someone else owns patching and backups:

```
COUNSELCLEAR_DATABASE_URL=postgresql+psycopg://counselclear:<secret>@db.internal:5432/counselclear
```

- Startup invokes `upgrade_head`. Stop the existing service, preserve a cold
  backup, and start one upgraded API process to apply migrations before admitting
  requests. Alembic transactions are not a cross-process migration lock; do not
  race application starts while schema changes are being applied.
- Enable encryption at rest (KMS-backed storage encryption) and automated
  snapshots with PITR. The audit hash chain detects tampering but does not
  replace backups.
- Network: private subnet only, no public address; security group allowing
  5432 from the API replicas exclusively.
- The bundled compose `cc-postgres` (pg profile) is for pilots, not for
  production — it lacks managed backups and failover.

## 5. Custody store: Object Lock, CMK, residency

The original store is selected by `COUNSELCLEAR_STORAGE=local|s3`. Derivative
bundles, attempt staging, and auth keys remain under the durable local data root;
configuring S3 originals does not move or encrypt those files.

**Local originals** use exclusive creation and read-only file permissions.
Those permissions are not WORM storage against an administrator. Protect the
volume and its backups according to the deployment's retention and access policy.

**S3 originals** use the application's native S3 client, not a filesystem mount.
Configure `COUNSELCLEAR_S3_BUCKET`, `COUNSELCLEAR_S3_REGION`, the optional prefix,
and an explicit retention period. Startup requires enabled versioning and, when
retention is nonzero, Object Lock. Writes retain the exact uploaded `VersionId`;
reads and heads use that version. Missing or changed versions fail instead of
selecting the latest object. Legacy key-only references require separate handling.
See [object-version operations](COUNSELCLEAR_STORAGE_OBJECT_VERSIONS.md).

The application requests COMPLIANCE retention when configured. Choose the period
with the records owner before provisioning; do not treat an example retention
value as a policy decision. S3 permissions, live provider behavior, key recovery,
and restoration into the intended account still need deployment qualification.
Do not substitute an S3 filesystem mount for the local queue/attempt volume.

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
- Manifests, reports, filenames, actor identifiers, audit records, and document
  bytes may all contain sensitive information. Include them in the same residency
  and access review.
- Note egress exceptions honestly: the `cc-freshclam` sidecar needs
  outbound 443 to `database.clamav.net`, and OIDC login calls your IdP.
  The TSA, S3/KMS, identity provider, and any enabled rewrite provider add their
  own configured destinations. Review the actual endpoint inventory.

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
(the flag follows the request scheme when uvicorn runs with `--proxy-headers`,
as the shipped systemd unit does). If your proxy cannot forward the proto
(e.g. TCP passthrough), set `COUNSELCLEAR_COOKIE_SECURE=true` explicitly;
use `false` only for loopback-only development. Keep `/health` and
`/health/ready` off the public listener if your compliance checklist demands
it; neither leaks anything but neither is authenticated.

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

## 6b. Outbound network on the release path: RFC 3161 timestamping

**Anchoring is ON by default, and the default endpoint is a third party.**
An unset `COUNSELCLEAR_TSA_URL` resolves to `http://timestamp.digicert.com`,
and eligible packet generation can make an outbound request to it. Set the
intended TSA explicitly before deployment. Disabling it removes timestamp
egress; it does not disable OIDC, object storage/KMS, malware-definition updates,
or an explicitly enabled rewrite provider.

The default is deliberate. An RFC 3161 token is the only claim CounselClear
makes that does not rest on the operator's own key: everything else — the
manifest, the certificate, the audit chain, the Ed25519 packet signature —
is the producing system vouching for its own output. A timestamp is an
independent party asserting that a digest existed at a stated time.

| `COUNSELCLEAR_TSA_URL` | Behaviour | Startup line |
|---|---|---|
| unset | anchors against DigiCert | `tsa_anchor: enabled against the DEFAULT endpoint …` **(warning)** |
| a valid `http(s)` URL | anchors against your TSA | `tsa_anchor: enabled against <url>` |
| `off`, `none`, `disabled`, or empty | **zero egress**; no anchoring attempted | `tsa_anchor: disabled — zero egress on the release path` |
| anything else | never anchors, silently | `tsa_anchor: MISCONFIGURED` **(warning)** |

Check the startup log on every deploy. The two warning lines exist because
both states are otherwise invisible: an unchosen third-party dependency, and
a configured endpoint whose scheme the client refuses to open — the second
means every release falls through to unanchored while still succeeding, so
an operator can believe for months that they hold timestamps they do not.

**Failure is soft, by design.** A TSA that is slow, down, or unreachable
does not fail the release: one retry, a 5-second timeout, then the packet is
issued unanchored with that fact recorded in its own `anchor` field and
disclosed by the offline verifier. A release is never blocked on a third
party's availability.

**What you give up with `off`.** Packets remain internally consistent and
Ed25519-signed, and the verifier still reports that faithfully — but it will
print `NOT EXTERNALLY ANCHORED`, and no independent party will have confirmed
when the content existed. That is a real evidentiary difference; choose it
because zero egress is worth more to you, not by accident.

## 6c. Custody signing key: back it up, and send the fingerprint

The release-packet signing key is generated on first use and lives in this
deployment's data root. **Nothing else holds it.** Treat it the way you
already treat matter files that outlive the people who created them: back it
up under your records-retention policy, and make its succession somebody's
named responsibility.

Since 2026-09-05 each packet publishes the *public* half inside
`release_packet.json`, so a recipient can always check the signature
arithmetic even if every key file is lost. That fixes availability and
nothing else: a key a packet supplies about itself proves nothing about
whose key it is, because anyone able to alter the packet could also have
replaced that field. The verifier reports such a check as
`SELF-PUBLISHED KEY -- signature checks out, provenance unconfirmed` and
never as plain `VERIFIED`. The caution leads; the affirmative word never
opens the line, because a truncated quote or a screenshot carries only the
opening.

**So send recipients the fingerprint, not just the key.** It is printed in
every packet's `README.txt` and by the verifier on every run:

```bash
counselclear_verify_release_packet.py --key-fingerprint <sha256> packet.zip
```

A recipient who confirms that fingerprint once — in an engagement letter, on
a call, from a packet they already trust — can verify every future packet
from this deployment with no key file at all. The pin is their act, in their
records, which is exactly why it carries weight the packet's own claims
cannot.

Losing the *private* key means you can no longer sign new packets; already
issued packets remain checkable. Losing control of it is the serious case
and is not addressed by any of the above — rotate immediately, and see
`docs/counselclear-key-durability-proposal.md` §4 for what revocation would
require, which this product does not yet implement.

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
- [ ] `GET /v1` reports the actual release/commit in `version`, not `"dev"`
      — the image was built with `--build-arg CC_VERSION=...` (§2)
- [ ] JSON request logs shipped somewhere durable; `X-Request-ID` echoed to
      clients matches log lines
- [ ] ClamAV is available and its definitions are current under the deployment
      policy. A missing binary permits archive-depth-only screening; an installed
      scanner returning an error rejects the upload. Readiness does not check
      definitions or certify malware coverage.
- [ ] Docs endpoints (`/docs`, `/openapi.json`) returning 404 — they are
      opt-in (`COUNSELCLEAR_ENABLE_DOCS=1`) for local development only
- [ ] Audit chains verified periodically: `GET /v1/matters/{id}/audit`
      reports `chain_ok: true` (hash chain recomputed server-side)
- [ ] Restore rehearsed for the selected database, original store, durable
      volume, and keys. Verify the restored originals, audit chains, and downloaded
      packets while the old deployment is unavailable. SQLite/local qualification
      cannot stand in for a PostgreSQL/S3 restore.
- [ ] For the LOCAL/SQLite pilot: a scheduled cold backup
      (`tools/counselclear_backup.py`, see `COUNSELCLEAR_BACKUP.md`) exists,
      and at least one of those backups has actually been restored with
      `tools/counselclear_restore_drill.py` and reported `verified` — a
      "backup succeeded" report alone does not establish that.
- [ ] Back up before every upgrade. Schema downgrade is not a byte-preserving
      rollback once release certificate snapshots exist (migration `0012`,
      see `PRODUCTION_FOUNDATION.md`) — a pre-upgrade backup is the reliable
      rollback path, not a schema downgrade of the live database.
- [ ] pip-audit / image CVE scan in CI green for the deployed digest

## 8. What this product deliberately does not do

Stated so reviewers don't assume otherwise:

- No multi-tenant org model — ACLs scope matters within one firm's install.
- S3 support covers originals; local artifacts and database backups still need
  their own durability, encryption, retention, and restore arrangements.
- No per-user session revocation list — revocation = cookie-secret rotation
  (all sessions die together).
- The audit chain proves integrity after the fact; it cannot prevent a
  database administrator with raw SQL access from rewriting rows and
  recomputing hashes — restrict DB admin access accordingly.

## 9. Layer B (statistical watermark) rewrite — operations notes

PR 20 shipped the capability **off by default**; this section is for the
operator who has completed the license/ToS review and intends to enable it.

- **The gate is two-part:** `COUNSELCLEAR_WATERMARK_TOOLS=1` (org flag) AND
  a signed per-document attestation (`POST /v1/attestations`, server-HMAC-
  signed, doc-bound to the upload's sha256, 10-minute TTL, single-use).
  Without either, the attestation route 403s and `layer_b` sanitize jobs
  are refused — including at dispatch time (`run_job` re-checks the flag,
  so disabling it mid-flight fails queued Layer B jobs rather than running
  them).
- **Only two strengths are reachable from the product:** `preserve` and
  `paraphrase` (design doc KD 10). The aggressive `code`/`backtranslate`
  modes exist only in the CLI.
- **Failure semantics are hard by design:** a meaning-lock miss, a rewrite
  that produces no change, an unreachable provider, or a refused non-
  loopback endpoint all fail the job with a labeled error. There is no
  silent fallback to the original text in the product path — the manifest
  either records a verified rewrite (with `layer_b` block) or the job
  fails and no derivative is produced.
- **Rewrite endpoint:** subprocess workers inherit `WATERMARKS_REWRITE_*`
  from the API process env. Docker workers receive only that env namespace
  and join `COUNSELCLEAR_REWRITE_NETWORK` (default `counselclear-rewrite`)
  — a dedicated proxy-only network whose only peer should be the rewrite
  proxy. Non-Layer-B jobs keep `--network none`. If the proxy is addressed
  by hostname rather than loopback, set `WATERMARKS_REWRITE_ALLOW_REMOTE=1`
  (same opt-in the CLI requires).
- **Audit trail:** every attestation issues an `attest.issued` event and,
  on use, an `attest.used` event carrying the jti and job id; the job row
  stores `layer_b {strength, label, subject, jti}` and the manifest embeds
  the rewrite record. A post-hoc reviewer can prove exactly which
  authorization produced which rewritten derivative.
- **Replay protection:** `attestation_uses` enforces the receipt identity in
  the database. Admission, attestation consumption, job creation, and the audit
  event commit together. Request retry receipts allow the original authorized
  submission to be retrieved without consuming the attestation again.
