# Durable mail admission and outbox

`app.mail.submissions.MailSubmissionRegistry` is an internal coordinator for
whole messages. Migration 0017 adds the retained admission and delivery state.
It does not listen for SMTP, send mail, expose an HTTP ingress, configure a
Microsoft 365 tenant, or establish tenant provenance. A future transport must
supply authenticated, tenant-bound context from its own verified connection.

## Admission and processing

A configured `TenantJobBinding` fixes the tenant, matter, service principal,
and policy. Every operation checks read/upload/sanitize matter permissions.
The authenticated transport supplies a stable request identity, authenticated
peer, and the full SMTP envelope, including Bcc. The tenant/request identity
is unique across matters. Reuse must match the original bytes, full ordered
envelope, service binding, policy version, transport identity, and adapter
limits. Message-ID is only message content; two transport request identities
can admit the same message. This is not SMTP retry deduplication.

Admission writes the raw message through the configured storage backend and
commits the row with its audit event. Database rollback can leave an immutable,
unreferenced object; it cannot leave a committed receipt without its audit.
Input and output reads validate retained plaintext hash and size. Storage
references are opaque, including version-pinned object references. No path
rebasing or local-only storage shortcut is used by the coordinator.

Processing uses the shared `MailAdapter` and `DurableAttachmentProcessor`.
Attachment jobs retain their existing engine, audit, policy, ownership and
verification requirements. Unsupported attachments always hold. Processing
leases use database time and a heartbeat. Publication rechecks the lease after
writing output, so an expired owner cannot publish. Pending jobs produce a
retryable hold; a new coordinator can resume those same jobs. Permanent holds
and refusals cannot be claimed again. `recover(id)` explicitly expires stale
processing leases; this module does not start a global recovery daemon.

## Delivery states

| State | Permitted next action |
|---|---|
| admitted | claim for processing |
| processing | fenced decision, or expiry to retryable held |
| held, retryable | claim again against the same admission |
| held, permanent / refused | no release or automatic retry |
| released | obtain one delivery ticket |
| submitted | trusted acknowledgment or ambiguous outcome |
| acknowledged / ambiguous | terminal; no automatic resend |

`prepare_delivery` verifies retained output and commits `submitted` and its
ownership token **before** returning message bytes and the complete envelope.
A second call cannot obtain another send ticket. A future sender must record
a trusted transport acknowledgment or mark the outcome ambiguous. Expired
submitted attempts become ambiguous through recovery or a late acknowledgment.
Even failure before DATA is treated conservatively once the ticket was issued.
There is no exactly-once delivery claim: an SMTP peer can accept DATA while its
reply is lost, and this registry cannot determine that outcome by itself.

The acknowledgment API records a trusted caller's assertion; it does not prove
an Exchange acceptance happened. The return-through-Exchange transport,
tenant-bound provenance, loop prevention, and real Outlook/OWA/mobile delivery
matrix remain separate integration work.

## Operational boundaries

Envelope addresses and authenticated request facts are retained in the database;
original-object encryption does not encrypt those database fields. Deployment
must protect database access and backups. Audit events use identifiers, hashes,
counts and state; they exclude addresses and raw message content.

Raw bytes must already fit the admission limit. MIME depth/part bounds apply to
the parsed tree, and the coordinator does not add an isolated MIME parser or a
streaming storage reader. Immutable objects left by rolled-back writes need a
future retention/garbage-collection policy that respects live references.

The current offline LOCAL/SQLite restore tool refuses **any nonempty mail spool**,
including terminal rows, because its relocation procedure has not qualified
mail input/output references and delivery recovery. An empty new table is safe
to preserve. This restriction must be resolved before enabling production mail
admission; the coordinator is not exposed to live traffic in this change.

## Verification

`tests/test_mail_submissions.py` exercises binding conflicts, Bcc preservation,
concurrency, audit rollback, stale-owner fencing, retry and real shared-engine
completion, storage failures, and delivery ambiguity. The database fixture runs
on SQLite and, when `COUNSELCLEAR_TEST_POSTGRES_URL` is supplied, isolated
PostgreSQL databases. CI explicitly includes these tests in the PostgreSQL job.
The worker image smoke test also exercises whole-message admission, processing,
and delivery-ticket creation through the pinned Docker image without sending.
