# Durable job execution and recovery

Single inspect, sanitize and release requests and batch children are admitted
as database jobs. The dispatcher runs them independently of the HTTP request.
Existing single-job routes still wait for their terminal response for API
compatibility; a client timeout does not mean its job stopped. Request-level
idempotency and an explicit asynchronous submission contract are separate work.

## Ownership and publication

A singleton `job_queue` row serializes capacity reservations across processes.
`COUNSELCLEAR_BATCH_MAX_CONCURRENT` now covers single jobs and batch children
(default 4). All dispatchers using a database must configure the same capacity;
a mismatch refuses startup. The limit bounds active database owners, not orphan
OS processes after a host/database/network failure.

Each claim increments an attempt number and assigns a random lease token with
an expiry calculated from the database clock. The default lease is 30 seconds
(`COUNSELCLEAR_JOB_LEASE_S`, minimum 3); a separate session renews it while the
worker runs. An expired owner cannot renew or publish a terminal result.

Each worker writes beneath `jobs/<job>/attempts/<attempt>-<token>/` within its
matter data root. The container mount is scoped to that attempt. Workers do not
have database credentials. A trusted parent records the process exit and output
location; this receipt is committed before publication. Result validation, the
job's terminal state, its release's terminal state, the final batch state and
the associated audit events publish in one database transaction. Cancellation
uses the same transaction boundary. Failed publication leaves no partial result.

Recovery requeues expired owners. If an exit receipt exists it retries result
validation/publication using that private output, without rerunning the engine.
Otherwise it retries execution up to `COUNSELCLEAR_JOB_MAX_ATTEMPTS` (default 3),
then records a terminal failure. A crash before the receipt commit may execute
the engine again. A late worker's private files cannot replace the newer attempt's
published references. This is fenced, retryable processing; it is not a claim
that the engine executes exactly once.

## Deployment and upgrades

Back up the database, data root and key material together before upgrading.
Stop API/dispatcher processes, apply migration 0013 once, then start the new
build. Do not mix old and new dispatchers: old workers do not honor leases.
Historical terminal rows are preserved. Legacy unowned pending jobs retain the
old startup interruption behavior; newly admitted jobs carry a durable actor
and are preserved across startup.

The first dispatcher records the shared capacity. To change it, stop all
workers, ensure no running leases remain, update `job_queue.capacity` for id
`default` in an administrative transaction, set the matching environment value
on every instance, then restart. Do not edit lease tokens or receipts to force a
job through. Inspect the queued/running status and application recovery logs.

Every executor must have the same durable filesystem paths for worker receipts,
private attempt output and released bundles. S3 original storage alone does not
provide that shared filesystem. Keep the shipped one-API deployment until the
target shared-volume, identity, ingress and backup/restore topology is tested.
A live stale OS worker may consume resources until its timeout even after it
loses ownership; process/container supervision remains necessary. Subprocess
mode is a development execution boundary, not a security sandbox.

Do not downgrade while jobs are queued or running. Drain work and take a new
backup before reverting; migration downgrade removes ownership/receipt fields,
and older binaries cannot resume these attempts safely. Private interrupted
attempt files are retained for investigation; automatic cleanup is separate work.

## Verification

`tests/test_job_transactions.py` injects failures in job, release and batch
audit insertion and checks atomic visibility, rollback and retry. The release
HTTP tests inject partial batch-admission and cancellation failures.
`tests/test_job_ownership.py` covers competing processes, shared capacity, live
startup preservation, process death, renewal, expired-worker fencing, persisted
exit recovery and retry exhaustion.

The default run uses temporary SQLite databases. Set
`COUNSELCLEAR_TEST_POSTGRES_URL` to an **isolated test server** to run each case
against PostgreSQL too. The test account needs database creation privileges;
the fixture creates and forcibly drops only randomly named `cc_queue_test_*`
databases that it owns. CI provisions its own PostgreSQL service for this job.
