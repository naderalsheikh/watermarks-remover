# Installed pilot configuration check

Before rehearsing the browser document workflow on an installed single-operator
LOCAL/SQLite deployment, run the preflight using the API service account and
the same environment as the API:

```sh
python tools/counselclear_preflight.py \
  --data-root /srv/counselclear/data \
  --web-root /srv/counselclear/web
```

The command prints JSON to standard output. Exit 2 means a blocking configuration
issue was found. Exit 0 means the listed configuration checks passed. Neither
result establishes production readiness; the report always includes the checks
that require a deployment rehearsal. Warnings require an operator decision.

This is an installed-system check, not an installer. Missing directories, database,
password record or signing identity are reported without creating replacements.
It does not start the app, execute Docker, connect to a database, contact a TSA,
invoke a scanner, or create a key. It reads only the signing key needed to derive
its public fingerprint; other secret-file checks inspect presence/size. It does
not print paths, database credentials, endpoints, image names or key bytes.

The report identifies incomplete OIDC settings that would leave local login
enabled, silently defaulted numeric settings, an absent malware scanner,
development-only worker mode, an unpinned worker image, incomplete static web
files, missing key material, and an implicit public timestamp endpoint. Select
timestamp egress explicitly: `COUNSELCLEAR_TSA_URL=off` disables it; an explicitly
chosen HTTP(S) endpoint enables timestamp requests without proving availability
or trust. Original-store encryption does not cover every local derivative or
backup; an unencrypted configuration is reported for an explicit operator decision.

Compare the public signing-key fingerprint with the identity retained separately
for this installation. A successful load proves the current key can be parsed,
not that it is the intended key. The command never fixes a missing or changed
identity automatically.

After resolving blockers, rehearse HTTPS/proxy routing, login/logout, a synthetic
inspect/release/refusal workflow, verification of the downloaded packet against
the separately obtained fingerprint, and a cold restore with separately retained
keys. Use `tests/test_deployment_http_smoke.py` as the synthetic deployment
rehearsal reference and `tools/counselclear_restore_drill.py` for the supported
cold-restore check. Database migration state, available disk space, actual Docker
image execution/isolation, scanner definitions, and backup acquisition still need
verification on the intended host. `/health/ready` remains a database reachability
probe; this command does not change its API or orchestrator semantics.

SSO/multiuser, PostgreSQL, S3/KMS, Desktop distribution, and live mail delivery need
their own qualification. This command intentionally covers the installed local
browser pilot; those editions remain on the roadmap.
