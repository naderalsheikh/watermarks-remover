# Production foundation: integration and release notes

The product roadmap includes CounselClear Desktop, Server, and Cloud. This
increment repairs shared processing and evidence behavior; it does not ship the
native desktop client, central policy administration, managed cloud operations,
or Outlook/mobile mail integration.

## Integration baseline

Implementation starts from `6db22621fd08c1c0b3b1fa9a53415dec344b7e66` on the
product fork, `naderalsheikh/watermarks-remover`. The integration branch for this
increment is `build/production-foundation`, targeting the existing product branch
`feat/custody-record-truthfulness`.

Open PRs #3–#6 each contain one unique commit after that baseline. Their shared
earlier UI change is already present. This increment selectively integrates the
DOCX direct-highlight transformation from #6, preserving the existing detectors
and final verification. Style-only highlighting remains subject to the existing
limitation/refusal behavior. It does not merge the PR's broader detection/copy
changes.

Do not merge the other PRs wholesale to obtain this work:

- #3's deployment documentation needs correction for actual configuration and
  network egress, including timestamp anchoring and malware-definition updates.
- #4's upload allowlist omits existing supported Office input families. Rebuild
  that guard against the actual server capabilities.
- #5 needs explicit handling of the existing API `/` route, trusted proxy
  configuration, version metadata, and the chosen deployment branch.

## Runtime and worker upgrades

Upgrade the API and its pinned worker image together. New workers omit the
duplicate original from their output bundle because the original is already
retained in the custody backend. Older worker images emit that extra copy and
will fail the new parent's artifact checks. Legacy absolute bundle path strings
are understood only when all other output requirements are satisfied; they do
not guarantee compatibility with an older worker implementation.

The parent maps worker results to the expected job output directory and checks
file types, artifact names, result/manifest agreement, original identity, policy,
and actual derivative digest/size before recording a usable bundle. A timeout or
unsuccessful process exit cannot become success through a result file.

Existing terminal outcomes and already-issued artifacts are not rewritten by this change.
New batch completion timestamps and their `batch.completed` audit events commit
together. A failed completion append leaves the batch eligible for retry;
historical rows with missing events are not reconstructed by this change.
SQLite audit appends acquire the database transaction before the in-process
matter lock, preventing an inverse lock order between concurrent requests.
Caller-staged writes still commit or roll back with their audit append.
Original downloads continue through the existing explicit `download_original`
permission and custody backend. This increment does not remove plaintext copies
from historical bundles. Protection and retention for new and historical local
derivatives, reports, staging, and backups remain separate work; original-store
encryption does not cover them. Any remediation of existing records requires an
inventory and a procedure that preserves their evidence and access semantics.

Use one API process for the shipped deployment. Durable database leases now
distinguish live owners and recover expired jobs; SQLite and PostgreSQL concurrency
are tested. Shared-volume paths, ingress, identity, and restore still need
qualification before deploying multiple replicas. See COUNSELCLEAR_JOB_RECOVERY.md.

Local logical storage keys and extracted packet member names now use `/` on
every OS. Encrypted reads preserve previously readable Windows native-key
envelopes using the same stored reference; they do not reseal or rewrite existing
objects. ZIP membership uses the original archive names even when the host ZIP
library normalizes them; alternate spellings cannot alias a declared member,
and duplicate file entries are rejected. Signed packet bytes are unchanged. Test
fixtures retain exact committed bytes across checkout platforms. Windows suite
results cover functional behavior, not ACL protection or native sandboxing;
those are explicit requirements for the Desktop packaging workstream.

Subprocess mode remains a development execution mode with the host user's
privileges. Passing scoped paths does not create a filesystem or network sandbox.
Docker execution has a separate real-image CI gate; native desktop isolation is
a later per-OS implementation and qualification task.

## Preserved release certificates

Terminal releases now preserve one certificate snapshot in the database. The
release-result hash, standalone certificate, and certificate inside each new
packet use those same bytes, even when the clock, authorized downloader, or
display descriptions change. Packet signatures, timestamp requests, and download
audit events still describe each individual download. The certificate names the
release requester and states its actual snapshot generation time; it does not
attribute earlier processing to the later downloader.

Before serving the snapshot, the API checks its checksum and compares the current
terminal source facts and job-scoped audit evidence with the recorded snapshot.
Missing, changed, or invalid evidence produces a conflict response rather than a
replacement certificate. Failed cancellation/recovery releases without a job
execution event explicitly report unavailable evidence. This remains a check of
the job's own audit rows, not authentication of the whole matter audit chain.
Legacy jobs without a Release wrapper retain their existing certificate behavior.

Migration `0012` adds a nullable internal JSON column. Existing releases acquire
their first snapshot on a subsequent eligible request; previously downloaded
files are untouched, and the migration cannot retroactively make their differing
certificate hashes agree. Application startup applies the migration. Preserve the
database, including snapshot bytes, in the upgrade backup and restore procedure:
downgrading to `0011` drops those bytes, and the old application regenerates
certificates. Schema downgrade is therefore not a byte-preserving rollback after
snapshots have been used. PostgreSQL migration SQL is checked, but PostgreSQL
runtime concurrency is covered by dedicated live PostgreSQL CI, separately
from these snapshot tests.

## Browser verification

The browser validates the published JSON contract and compares only the file
bytes the operator supplies. It does not authenticate signatures, timestamp
authority trust, custody chains, or complete archive membership. Missing evidence
is shown as not checked or unavailable. Passing partial checks produce
`VERIFICATION INCOMPLETE`; they cannot establish an authenticated packet.

Use the offline verifier with the complete packet and a trusted installation key
fingerprint for its broader supported checks. Supply the exported `--audit-csv`
for audit-chain cross-checks. A self-published key alone does not establish the
producer's identity. Historical signed artifacts remain unchanged.

## Reproducible checks

CI installs the complete shipped Python runtime through `requirements-dev.txt`
and uses Python 3.14, matching the product image. It runs the Python suite on
Linux, Windows, and macOS, lint/format checks, dependency audits, web tests/lint/
static export, and the actual worker image workflow. The web job uses Node 24 and
the lockfile. The complete timestamp-mutation corpus runs in a separate required
job on each OS so it cannot consume the main suite's timeout budget; no cases or
OS coverage are removed. Windows main tests run in three deterministic, disjoint
groups; their combined collected nodes cover the full main suite.
Parametrized cases stay with their test function, so generated parameter labels
cannot move cases between independently collected groups. An aggregate
check retains the existing `test (windows-latest)` name and requires the main
matrix to succeed. Main jobs stop on their first failure so its traceback is
available before a slow runner can exhaust the job budget.
Host test jobs install ExifTool and qpdf so required
PDF/JPEG paths exercise their real tools instead of an unsupported fallback.
PDF cleanup requires qpdf's `--remove-info` capability (introduced in 11.10).
The Ubuntu job uses a checksum-pinned upstream 12.4.1 binary because its distro
package is too old; host CI and the worker image build probe the required option.
The frontend dependency patches address the advisories reported by the September 11 clean
install; the deployed static export does not run a Next.js server, but
development/build dependencies must still be maintained.

```sh
python -m pip install -r requirements-dev.txt
python -m pytest
python -m ruff check service tests
python -m ruff format --check service tests
```

Run `npm ci`, `npm test`, `npm run lint`, and `npm run build` from `web/`.
The optional Docker test is `tests/test_worker_docker_smoke.py`; CI sets
`COUNSELCLEAR_TEST_WORKER_IMAGE` to the digest of an image built from the current
checkout in a loopback registry. Without that setting, only the Docker test skips;
the encrypted-custody subprocess workflow still runs.

The image publisher calls this CI workflow against the release commit before
publishing. Publishing requires a stable `vMAJOR.MINOR.PATCH` tag; dispatching a
branch cannot update `latest`. This remains the backend/worker image publisher;
complete UI/service packaging still needs the separate deployment workstream.

## Remaining shared release blockers

- Deployment-specific storage/key recovery. Durable jobs and request receipts
  are implemented and tested; S3 originals now retain exact object versions.
- Production configuration propagation, readiness, and one qualified complete
  deployment, including UI, API, workers, storage, TLS, and backup/restore.
- Actual IdP qualification. New jobs now retain the admitted operator and
  validate that identity against the worker manifest.
- Release-page decision hierarchy, unavailable-evidence states, accessible forms,
  and the shared brand/system refinements.
- Edition packaging, tenant isolation, administration, and live mail integration
  qualification as defined in the three-edition roadmap.

Successful tests for this increment do not establish production readiness for
the whole product or any unimplemented edition.
