# CounselClear mail attachment adapter: M1 integration note

Status: local prototype, September 2026. Branch `feat/mail-adapter-m1`, started
from `build/production-foundation` at `51a823646ca99d250aa532e3d86673d9148081ac`.
Nothing here has been exercised against a Microsoft 365 tenant. M1 establishes
that a message can be parsed, its document attachments replaced with
engine-verified derivatives, and the result re-verified, all inside one
process with synthetic fixtures. It establishes nothing about Exchange Online
routing, message authentication, native isolation, or production readiness.

## What M1 delivers

| Piece | Location |
|---|---|
| Contract (envelope, caller context, policy reference, limits, outcomes) | `service/app/mail/contract.py` |
| Bounded MIME walk, stable part ids, filename sanitising, marker/Bcc stripping | `service/app/mail/mime.py` |
| Processor interface and the adapter's independent checks on results | `service/app/mail/processor.py` |
| The adapter: select → process → replace → serialize → re-verify | `service/app/mail/adapter.py` |
| Real engine, in-process (`engine_api.clean_to_bundle`) | `service/app/mail/engine_processor.py` |
| Deterministic test double (labelled; refused in production mode) | `service/app/mail/synthetic.py` |
| Synthetic message/document builders | `service/app/mail/fixtures.py` |
| Runnable harness | `service/app/mail/demo.py` |
| Tests with the test double (49) / with the real engine (6) | `tests/test_mail_adapter.py`, `tests/test_mail_adapter_engine.py` |

Run from a fresh checkout:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest tests/test_mail_adapter.py tests/test_mail_adapter_engine.py
python -m ruff check service tests
python -m ruff format --check service tests
cd service
python -m app.mail.demo            # test double: prints verification=synthetic
python -m app.mail.demo --engine   # real engine in-process: verification=engine_verified
python -m app.mail.demo --engine --json --out /tmp/out.eml
```

The engine-backed tests and `--engine` need ExifTool and qpdf on the host, as
the existing suite does.

## Boundary between the adapter and the trusted transport

The adapter is a pure function from `(raw RFC 822 bytes, envelope, caller
context, policy)` to `(decision, outcomes, optional outbound message,
evidence)`. It owns no sockets, queues, credentials, or storage. Everything
it needs to trust comes in through `TrustedCallerContext` and `Envelope`,
which only the transport process can populate:

| Adapter trusts | Adapter never trusts |
|---|---|
| `Envelope.mail_from`, `Envelope.rcpt_to` (all recipients, Bcc included) | `From`, `To`, `Cc`, `Bcc` headers as a recipient list |
| `TrustedCallerContext.tenant_id`, `transport`, `provenance_verified`, `peer_identity` | any header claiming the message was already processed |
| `PolicyReference` chosen by the transport for that tenant | filenames, content types, `Message-ID`, `Content-ID` |
| The injected processor's *bytes*, after re-hashing them | the processor's *claims* without re-checking them |

`provenance_verified` must be set by the code that authenticated the peer,
for example an SMTP listener that verified Exchange Online's TLS client
certificate for the tenant's outbound connector. A message-supplied boolean or
a secret-looking header value is never a substitute; the adapter refuses the
submission (`untrusted_submission`) before parsing if the context is not
marked verified.

Decision semantics are mandatory-cleaning only. There is no advisory mode in
M1: a hold or refusal never carries an outbound message, and no message is
released with some attachments replaced and others pending.

| Decision | Meaning | `retryable` |
|---|---|---|
| `release` | every selected attachment replaced by a checked result; rewritten bytes re-parsed and verified; envelope unchanged | – |
| `hold` | operator or retry needed: processor unavailable/failed; unsupported, ambiguous or oversize part; signed/encrypted message; output over the size limit | `True` only for processor unavailable/failed |
| `refuse` | definitive: untrusted submission, malformed MIME, structural bound exceeded, policy refusal, processor evidence contradicting the request, undecodable part, re-verification failure | `False` |

`AdapterRequest.unsupported_parts="pass_through"` lets parts the engine does
not handle at all (archives, images, legacy binary Office, text attachments,
attached messages) travel untouched while supported ones are still replaced.
The default is `hold`. Ambiguous parts (extension or content type says one
supported format, bytes say another), password-protected Office packages,
oversize parts and undecodable parts never pass through. Whether a tenant
runs `hold` or `pass_through` is a policy decision that belongs in central
administration; M1 only makes it explicit.

Bounds (defaults in `AdapterLimits`): message 50 MiB, output 50 MiB, 200 MIME
parts, nesting depth 10, 25 attachments, 25 MiB per attachment. Exceeding
message/part/attachment-count bounds refuses; an oversize attachment or an
oversize rewritten message holds.

What the adapter changes in a released message, and nothing else:

- the payload and `Content-Transfer-Encoding` (now base64) of each replaced
  part; the part's `Content-Type`, `Content-Disposition` and filename are
  kept verbatim, so the recipient sees the sender's filename;
- removal of every top-level `X-CounselClear-*` header and any `Bcc` header;
- addition of the transport-supplied `outbound_marker` header, if given;
- line endings normalised to the sender's (CRLF or LF, detected from the
  first line).

If no attachment was replaced and nothing had to be stripped or stamped, the
inbound bytes are returned verbatim (`rewritten=False`).

## Processor contract and the engine

`AttachmentProcessor.process(ProcessRequest) -> ProcessResult`. The adapter
re-derives the output digest and size, checks the reported source digest,
policy id and version against the request, and accepts only
`verification="engine_verified"` (or `"synthetic"` when constructed with
`allow_synthetic=True`, which tests and the demo do and production must not).
Anything else is `inconsistent` and refuses the message. This mirrors
`app.runner._validated_bundle`: original identity, policy, verification pass,
derivative digest and size.

`LocalEngineProcessor` maps the real engine onto that contract: malware scan
(`app.malware.get_scanner`, the same pre-check the worker runs), then
`clean_to_bundle(..., retain_original=False)` in a private temporary
directory, then the manifest checks above. Its `evidence_ref` is the SHA-256
of the canonical manifest JSON. A `plan refused` `CustodyError` becomes
`status="refused"`; any other exception becomes `status="failed"`.

It is deliberately *not* the production path. The API executes jobs in a
one-shot subprocess or a hardened container so a hostile document cannot
reach the API process, and a mail gateway needs that isolation at least as
much: attachments arrive from arbitrary senders. `LocalEngineProcessor` parses
attachments inside the calling process. It exists for fixtures and
engine-backed tests.

### The interface the shared core still lacks

To move the mail path onto the isolated worker/runner, the shared core needs
an attachment-job interface the current code does not expose. Today a
sanitize job is bound to a `Document` row uploaded into a matter by an
authenticated operator session, and `runner.run_job` reads the `Job` and
`Document` from the database. A mail gateway needs, without a matter upload:

1. `submit_attachment_job(tenant_id, request_id, part_id, content, policy,
   caller) -> job_id`: stage bytes for the runner, run the upload-time malware
   scan, execute under the runner's isolation (subprocess or digest-pinned
   container), retain or discard the original per tenant policy.
2. `await_job(job_id) -> validated bundle`: the derivative bytes plus the
   manifest, after `_validated_bundle`-equivalent checks, with `refused` and
   `failed` as first-class outcomes.
3. Durable ownership, lease and idempotency for those jobs: the
   "durable jobs" work package already listed as the next shared-core
   increment in the build status. Mail cannot run on the process-local
   capacity and startup sweep that PR #7 documents as a single-process
   limitation.
4. Operator attribution: worker manifests currently record the literal
   operator `operator`; mail jobs need the service principal and tenant
   recorded, which depends on the IdP/attribution work.

Until those exist, an M2 gateway can wire `MailAdapter` to a processor that
submits through a private queue to a worker process running
`LocalEngineProcessor`-equivalent code; that is an interim isolation
boundary, not the runner's, and should be labelled as such.

## Untrusted marker headers, rule ordering, loop prevention

Microsoft's reference topology routes internal senders' mail to the add-on
service with a mail flow rule whose only exception is "a message header
includes the service's marker". Applied literally, that exception is the
bypass: a sender who sets the header, or copies it from an earlier delivered
message, skips cleaning.

What the adapter guarantees on its side:

- Every top-level `X-CounselClear-*` header on an inbound message is removed
  before anything is decided and is recorded in evidence. An inbound marker
  never suppresses processing (`test_inbound_marker_never_suppresses_processing`).
- The outbound marker is whatever the transport passes in; the adapter
  validates its shape and stamps it only on a released message. It does not
  invent secrets, because a value in a delivered header is readable by every
  recipient and therefore not a secret.

What the live proof has to establish, because the adapter cannot: that
Exchange Online distinguishes a return from the authenticated service from a
client submission carrying the same header. Candidates to test, in this
order:

1. **Scope the routing rule by recipient location, not only by sender.**
   `external_sharing` is the policy; route "sender inside the organisation
   AND recipient outside" to the service. A returned copy destined for
   external recipients would still match, so this alone needs (2) or (3).
2. **Return-path provenance headers.** Microsoft documents that paired
   connectors with `CloudServicesMailEnabled` preserve Exchange's internal
   `X-MS-Exchange-Organization-*` headers so a return is treated as trusted
   internal mail. If a transport-rule condition on headers Exchange itself
   stamps for the certificate-authenticated connector return can reliably
   distinguish that return from a client submission, a higher-priority rule
   can first *remove* `X-CounselClear-*` from every message that did not
   arrive that way, and the reference exception becomes safe. Whether such
   headers exist for this path, cannot be supplied by a client, and are
   matchable by a rule is a tenant-observable fact to verify, not an
   assumption to build on.
3. **Make the service the delivery path for external recipients.** The
   service delivers cleaned external mail itself (or via a distinct outbound
   route) and only returns internal-recipient copies to Exchange, which the
   recipient-scoped rule from (1) no longer matches. No header exception is
   needed for loop prevention. Cost: the service becomes an outbound MTA for
   the tenant's domains (SPF include, DKIM signing keys, reputation), which is
   how hosted email-security gateways operate but is a larger onboarding
   footprint.

Required negative tests, all in the tenant: internal sender pre-sets
`X-CounselClear-Processed`; internal sender pastes the full header block of
an earlier delivered message; a message that legitimately returned once is
re-sent by the recipient (reply/forward) and must be processed again as a new
message. Required positive test: a legitimate return completes delivery
without a second trip. Record rule order, the `Received` and
`X-MS-Exchange-Organization-*` headers observed at the service and at the
final mailbox, and the delivered attachment digests. Exchange Online's own
hop-count loop detection is a safety net that produces NDRs; it is not the
design.

## Durable queue and SMTP acknowledgment ambiguity

The adapter is stateless. The gateway around it needs a durable outbox with
an explicit state machine:

```
accepted (bytes + envelope + caller context persisted, idempotency key =
          tenant + Message-ID + sha256(raw))
  -> processing (attachment jobs submitted; lease + heartbeat)
  -> released | held | refused (adapter decision + evidence persisted)
  -> submitted (DATA sent to the return smart host)
  -> acknowledged (250 received) | ambiguous (timeout/disconnect after DATA)
```

`ambiguous` is the state this note is asked to address. After the message
body has been sent, a dropped connection or timeout does not say whether
Exchange accepted it. Re-sending risks duplicate delivery; dropping risks
loss. The gateway must neither retry blindly nor discard: park the item in
`ambiguous`, reconcile against tenant message trace (the same `Message-ID`
and recipient set) with a bounded window, and surface unresolved items to an
operator. Exactly-once delivery is not a property the transport can promise;
"no silent loss, no blind duplicate, every ambiguous case visible" is.

Holds and refusals need an operator queue with the adapter evidence, the
per-attachment outcomes, and the actions the policy permits (retry, release
with an authorised exception, reject with notice). Retries re-run the
adapter on the persisted bytes, which is why M1 tests that repeated runs are
consistent; that consistency says nothing about transport-level
exactly-once or recovery, which the durable-jobs work has to provide.

## Live routing proof: prerequisites, matrix, setup, rollback

**Tenant prerequisites** (arrange in parallel with M2 work; none is done):

- A disposable Microsoft 365 test tenant with an administrator who can run
  Exchange Online PowerShell.
- Confirmation that an `OnPremises` inbound connector can be enabled. If the
  tenant returns "created in a disabled state, contact Support", open the
  Support case with the business justification immediately and record its
  owner and status; nothing below can be demonstrated until it is resolved.
- A unique certificate domain for the service, 48 characters or fewer, added
  as an accepted domain with its DNS TXT proof, and a CA-issued TLS
  certificate for that name on the service endpoint.
- A TLS-reachable prototype SMTP endpoint (port 25 from Exchange Online's
  published address ranges) that authenticates Exchange Online's connection
  and calls the adapter.
- Controlled sender and recipient mailboxes, including one external-domain
  recipient mailbox the tester can read, and a shared mailbox with Send As
  and Send on Behalf delegates.
- Clients: New Outlook on Windows, classic Outlook for Windows (current
  channel build recorded), Outlook on the web, Outlook for iOS, Outlook for
  Android. Record build numbers with every result.

**Setup outline** (PowerShell forms are the reference; admin-centre screens
may differ from Microsoft's screenshots):

1. `New-OutboundConnector -ConnectorType OnPremises -IsTransportRuleScoped
   $true -UseMxRecord $false -SmartHosts <service> -TlsSettings
   DomainValidation -TlsDomain <service> -CloudServicesMailEnabled $true`.
2. Add the certificate domain as an accepted domain; verify DNS.
3. `New-InboundConnector -ConnectorType OnPremises -RequireTls $true
   -RestrictDomainsToCertificate $true -TlsSenderCertificateName <certificate
   domain> -CloudServicesMailEnabled $true`, `SenderIPAddresses` empty.
4. The routing rule, initially scoped to a pilot distribution group and to
   external recipients, with the marker-safeguard rules from the section
   above in the agreed priority order. `Get-TransportRule | Format-List
   Priority,Name` is part of the evidence.
5. Verify every object with the corresponding `Get-*` cmdlet and keep the
   output with the run record.

**Rollback**: disable the routing rule first (mail flows normally again),
then the connectors; leave the accepted domain. While the rule is enabled and
the service is unreachable, Exchange is expected to queue and retry the
routed messages and eventually return NDRs, so a service outage becomes
delayed mail, not silent release of originals; confirm the actual retry
window and NDR behaviour in the tenant. Decide and document the tenant's tolerance for that before
widening the pilot group.

**Client routing matrix** (each cell: send, fetch the delivered message from
the recipient mailbox, compare attachment bytes with the adapter's recorded
`output_sha256`, record client/build, mailbox type, policy version, adapter
decision, transport acknowledgment, and confirmed receipt separately):

| Scenario | New Outlook | Classic Outlook | OWA | iOS | Android |
|---|---|---|---|---|---|
| one DOCX | | | | | |
| two attachments, same filename | | | | | |
| DOCX + PDF + inline image in HTML body | | | | | |
| reply / forward with attachment | | | | | |
| Bcc external recipient (received by Bcc only; not in headers) | | | | | |
| shared mailbox: Send As, Send on Behalf | | | | | |
| scheduled send; saved draft then send | | | | | |
| oversize attachment; derivative growth near tenant/client limits | | | | | |
| cloud link instead of attachment (expected: untouched, documented) | | | | | |
| nested archive (expected: hold or pass-through per policy) | | | | | |
| S/MIME signed; encrypted; password-protected Office (expected: hold) | | | | | |
| marker spoof: header pre-set; header block copied | | | | | |
| Simple MAPI send with Outlook running / closed | n/a | | n/a | n/a | n/a |
| Rich-text message producing `winmail.dat` (TNEF) | | | n/a | | |

The TNEF row matters: classic Outlook can wrap attachments in
`application/ms-tnef` for rich-text messages, which the adapter classifies
as unsupported and holds. The tenant's remote-domain TNEF setting is part of
onboarding.

**Tests that need real Microsoft 365 access** and therefore remain open
after M1: everything in the matrix; whether Exchange presents Bcc recipients
to the connector only in the envelope; DKIM signing and SPF alignment of the
returned message at Exchange egress, and of direct delivery if candidate (3)
is chosen; behaviour at the effective tenant, connector, mailbox and client
size limits; the marker-safeguard candidates; latency and throughput at the
declared sizes; certificate rotation on the connector; Purview/OME encrypted
mail; delegate and shared-mailbox sends; connector rollback.

## Known limitations of the adapter itself

- Supported formats are DOCX, XLSX, PPTX and PDF, decided by sniffing the
  bytes with the engine's own detector; the sender's extension and content
  type are used only to detect disagreement. The engine can clean more
  (images, ODT, EPUB, HTML); M1 keeps mail to ordinary document attachments.
- Attached messages, archives, TNEF, calendar parts with filenames and text
  attachments are unsupported, not descended.
- Signed and encrypted messages are held whole. Rewriting a
  `multipart/signed` body would invalidate the signature; the correct
  disposition is a policy question.
- Header preservation relies on the parser's `refold_source="none"`: source
  headers are emitted with their original folding. Headers containing raw
  8-bit bytes are re-encoded by the serializer; the re-verification compares
  decoded values, so semantic drift is caught, byte drift in that corner is
  not prevented.
- Any DKIM signature present on the inbound message is invalidated by
  rewriting. In the add-on topology Exchange signs at egress after the
  return, which the live proof has to confirm.
- The evidence dictionary is a draft of a custody record, not one: nothing
  is persisted, signed, or linked to the audit chain.
- No concurrency, retry, or persistence; the adapter is a function.
