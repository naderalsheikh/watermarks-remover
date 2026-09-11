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
| Tests with the test double (99) / with the real engine (9) | `tests/test_mail_adapter.py`, `tests/test_mail_adapter_engine.py` |

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

`provenance_verified` must be set by the code that authenticated the peer
*and* bound the submission to a tenant. Exchange Online's TLS client
certificate is shared across its tenants, so verifying it says "this is
Exchange Online", not "this is tenant A"; the transport needs a per-tenant
binding as well (the tenant-specific certificate domain and connector
identity, see "Untrusted marker headers") before it may fill in
`tenant_id`. A message-supplied boolean or a secret-looking header value is
never a substitute; the adapter refuses the submission
(`untrusted_submission`) before parsing if the context is not marked
verified. The adapter cannot tell a correct binding from a wrong one; that
is the transport's responsibility and a live-proof test.

Decision semantics are mandatory-cleaning only. There is no advisory mode in
M1: a hold or refusal never carries an outbound message, and no message is
released with some attachments replaced and others pending.

| Decision | Meaning | `retryable` |
|---|---|---|
| `release` | every selected attachment replaced by a checked result; rewritten bytes re-parsed and verified; envelope unchanged | – |
| `hold` | operator or retry needed: processor unavailable/failed; unsupported, ambiguous, password-protected or oversize part; signed/encrypted message; output over the size limit | `True` only for processor unavailable/failed |
| `refuse` | definitive: untrusted submission, malformed MIME, structural bound exceeded, policy refusal, processor evidence contradicting the request, undecodable part, re-verification failure | `False` |

### Which parts are selected

Selection is decided by bytes, not by what the sender declared. Every leaf
is decoded and sniffed with the engine's own detectors
(`container_meta.detect_container_format` with no extension, and
`image_meta.detect_format`). Exactly two kinds of part are left untouched:

- **body text**, qualified positively rather than by elimination:
  `text/plain`, `text/html` or `text/calendar` with no filename, whose bytes
  carry no document or archive signature, decode *strictly* in the declared
  charset (UTF-8 when none is declared), and contain no control characters
  other than tab, newline, carriage return and form feed. Decoding happens
  before the control check, so UTF-16 and other multibyte text whose
  encoded bytes contain zeros still qualifies. "The document detector
  returned `unknown`" is not evidence of text; a ZIP or 64 NUL bytes
  labelled `text/plain` is a candidate, not a body.
- **inline raster image**: `image/*` not sent with `Content-Disposition:
  attachment`, whose bytes sniff as PNG/JPEG/WebP/AVIF/HEIC/BMP/GIF/TIFF, and
  whose filename, if any, does not claim a document extension. A
  `Content-ID` is recorded but neither required nor sufficient.

Everything else is an attachment candidate: any part with an `attachment`
disposition, any part with a filename, any non-text/non-image part, an
`image/*` part whose bytes are not a raster image, a `text/*` part that
fails the body qualification (including other text subtypes such as
`text/x-vcard` or `text/csv` without a filename, which are deliberately
candidates), and attached messages. A `Content-ID`, an `inline`
disposition, a missing filename, or a `text/*` label never exempts a part:
those are sender-controlled and cost nothing to fabricate. A `text/*` part
that fails qualification is `ambiguous` (the declaration contradicts the
bytes), so it holds under every policy mode.

For each candidate the sender's assertions are checked *independently*
against the sniffed bytes: the filename extension, the media type (or its
`text`/`image` category), each on its own. Any assertion that contradicts
the bytes makes the part `ambiguous` — a DOCX named `Agreement.docx` but
declared `application/pdf` holds, and so does a PDF declared as DOCX, or a
document declared as `image/png`. A generic `application/octet-stream` or a
missing filename makes no assertion, so byte detection alone decides. Legacy
binary Office declarations (`.doc`, `application/msword`, …) are compatible
with the detector's `cfbf` answer and are `unsupported`, not `ambiguous`.

`AdapterRequest.unsupported_parts="pass_through"` lets parts the engine does
not handle at all (archives, images sent as attachments, legacy binary
Office, text attachments, attached messages, unknown inline binaries) travel
untouched while supported ones are still replaced. The default is `hold`,
and it stays the default after central administration exists: an
administrative screen is not a reason to relax mandatory cleaning. Any
pass-through is an explicitly authorised, versioned tenant policy exception,
attributable in the evidence, and its outcome (`unsupported`) never implies
the part was cleaned. The exception applies to the `unsupported` disposition
only. Password-protected Office packages carry their own disposition,
`password_protected`, precisely so the exception cannot reach them: a
document whose contents cannot be inspected is not "a file the engine does
not handle". Ambiguous parts, password-protected packages, signed/encrypted
messages, oversize parts and undecodable parts never pass through in either
mode.

Bounds (defaults in `AdapterLimits`): message 50 MiB, output 50 MiB, 200 MIME
parts, nesting depth 10, 25 attachments, 25 MiB per attachment. Exceeding
message/part/attachment-count bounds refuses; an oversize attachment or an
oversize outbound message holds — the output limit applies to every release,
including one that goes out byte-for-byte. What the bounds are, honestly:
the message-size check runs before parsing; the part-count and depth bounds
are enforced while walking a tree the standard-library parser has already
built in memory from the whole message. They stop the adapter from
enumerating or processing an unbounded structure; they are not a
pre-allocation limit on the parser and not a sandbox. Parser resource
isolation is production work that belongs with the runner boundary.

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

`AttachmentProcessor.process(ProcessRequest) -> ProcessResult`. What the
adapter itself checks on a `released` result, and all it checks: the
reported source digest equals the digest of the bytes it submitted; the
output digest and size equal the bytes returned; the reported policy id and
version equal the request's; and the verification label is one it is
allowed to accept (`engine_verified`, or `synthetic` only when constructed
with `allow_synthetic=True`, which tests and the demo do and production must
not). Anything else is `inconsistent` and refuses the message.

The evidence boundary is narrower than that list may suggest. The adapter
does not, and cannot, re-derive an injected processor's `engine_verified`
assertion: it has no manifest, no bundle, and no engine. It trusts the
processor implementation for that label the way the API trusts
`runner._validated_bundle`. Verification therefore lives in the processor:

- `LocalEngineProcessor` performs it. It runs the malware pre-check
  (`app.malware.get_scanner`, as the worker does), then
  `clean_to_bundle(..., retain_original=False)` in a private temporary
  directory, then checks the manifest the way `_validated_bundle` does:
  original filename/digest/size match the submitted bytes, policy id and
  version match, `verification.pass` is true, the derivative's digest and
  size match the bytes read back. Only then does it label the result
  `engine_verified`. Its `evidence_ref` (`manifest:sha256:…`) is the digest
  of a manifest that lived in a temporary directory and is deleted when the
  call returns: it is a correlation value for the run log, not retrievable
  custody evidence.
- A future runner-backed processor must obtain the *retained* job and bundle
  evidence from the job store, validate it the same way, and only then
  produce a `released` result whose `evidence_ref` points at something an
  auditor can fetch.

A `plan refused` `CustodyError` becomes `status="refused"`; any other
exception becomes `status="failed"`.

`LocalEngineProcessor` is deliberately *not* the production path, and the
reason needs stating precisely. It parses attachments inside the calling
process, so a parser bug or a hostile document has whatever the calling
process has. The API's subprocess mode is only process separation: the
worker runs under the same account with the same filesystem privileges, and
`docs/PRODUCTION_FOUNDATION.md` says so ("Passing scoped paths does not
create a filesystem or network sandbox"). Configured container mode
(`--network none`, read-only rootfs, a per-job mount) is the isolation the
product currently offers, and native/desktop isolation remains a separate
hardening and qualification task. A mail gateway receives documents from
arbitrary senders and needs at least the container-mode boundary, qualified
for that exposure, before any production claim.

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

Production attachment processing for mail uses the shared durable-job
runner once it exists; there will be no parallel production queue or second
engine execution path (Codex, acceptance review, 2026-09-11). Until then, M2
advances the transport/runner contract, the controlled fixture harness, and
tenant-routing feasibility. If exercising the harness needs a queue or a
separate process, it is disposable test infrastructure running synthetic
data, and it carries no claim of isolation, custody, recovery, or delivery
readiness. The contract is coordinated with Codex before any transport
worker is written against it.

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
3. **Not in scope: making the service the delivery path.** Delivering
   cleaned external mail directly from the service would remove the need for
   a header exception, at the cost of the service becoming an outbound MTA
   for the tenant's domains (SPF, DKIM keys, reputation). The owner's
   direction is to prefer return through Exchange with recipient scoping and
   a *demonstrated* authenticated provenance distinction. If the live proof
   cannot demonstrate one, the result is a reported blocker with
   alternatives brought back for a decision, not a quiet expansion of the
   assignment into direct delivery.

Recipient scoping alone does not prevent re-routing: a return whose
recipients are external still matches a "recipient outside the
organisation" rule. Candidate (2) is a hypothesis until tenant tests show
that clients cannot forge or replay whatever Exchange stamps, and that a
legitimate return completes exactly one service trip.

The service side of provenance is not a boolean either. The submission
Exchange makes to the service must be authenticated and bound to the tenant:
a TLS client certificate presented by Exchange Online is shared across
tenants and cannot by itself say *which* tenant's connector sent the
message. The transport therefore needs a per-tenant binding (the tenant's
own certificate domain on the inbound side, the connector/tenant identity
Exchange presents on the outbound side, or both) before it sets
`TrustedCallerContext.tenant_id` and `provenance_verified`. The adapter only
consumes that context; establishing it is transport work in M2 and a
tenant-observable fact in the live proof.

Required negative tests, all in the tenant: internal sender pre-sets
`X-CounselClear-Processed`; internal sender pastes the full header block of
an earlier delivered message; a message that legitimately returned once is
re-sent by the recipient (reply/forward) and must be processed again as a new
message; a submission arriving through the wrong connector or from another
tenant must be refused; mixed internal/external/Bcc recipient sets must
route and return exactly once. Required positive test: a legitimate return
completes delivery without a second trip. Record rule order, the `Received`
and `X-MS-Exchange-Organization-*` headers observed at the service and at
the final mailbox, and the delivered attachment digests. Exchange Online's
own hop-count loop detection is a safety net that produces NDRs; it is not
the design.

## Durable queue and SMTP acknowledgment ambiguity

The adapter is stateless. The gateway around it needs a durable outbox with
an explicit state machine:

```
accepted (bytes + envelope + caller context persisted under a trusted
          request identity; see admission below)
  -> processing (attachment jobs submitted; lease + heartbeat)
  -> released | held | refused (adapter decision + evidence persisted)
  -> submitted (DATA sent to the return smart host)
  -> acknowledged (250 received) | ambiguous (timeout/disconnect after DATA)
```

**Admission and idempotency.** The request identity the transport assigns
(`TrustedCallerContext.request_id`) is the admission key, and it is bound to
a digest over everything that defines the delivery: the raw bytes, the
complete SMTP envelope (sender and every recipient, Bcc included), the
tenant, and the resolved policy id and version. Two submissions with the
same request id and the same binding digest are one request; the same
request id with a different binding digest is a conflict that must fail
loudly, never a silent overwrite or a second delivery. A key built from
`Message-ID` and a body hash is not enough: `Message-ID` is sender-supplied
correlation data, and two deliveries of identical bytes to different
recipient sets (a different Bcc, for example) are different deliveries that
such a key would collapse. `Message-ID` is recorded for correlation and
message trace, not used for identity.

SMTP itself gives the transport no reliable idempotency token across
retries: when Exchange retries a submission after an ambiguous outcome on
its side, the gateway sees a new connection carrying the same bytes and
envelope and must decide whether that is a duplicate. The binding digest
lets it recognise byte-identical resubmissions to the same envelope and
tenant; it cannot promise that every retry is recognised (a retried
message may differ in `Received` headers), and the local request id does
not create exactly-once recovery on its own.

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
- The inline-image exemption is by raster magic bytes. An inline SVG, an
  icon, or an image in a format the engine's detector does not name is not
  exempt: it becomes an `unsupported` candidate and holds under the default
  policy. That is the conservative side of the trade; a tenant that sees it
  often decides through policy, not by widening the exemption.
- The body-text qualification is conservative in the same way: a body whose
  charset Python's codec registry does not know, that does not decode
  strictly in its declared charset, that contains C0 controls other than
  tab/LF/CR/FF, or that uses a text subtype outside plain/html/calendar is
  held as `ambiguous`. Sloppy but harmless clients may trip this; the fix is
  a deliberate widening with a control test, not a fallback to "unknown
  means text".
- Signed and encrypted messages are held whole. Rewriting a
  `multipart/signed` body would invalidate the signature; the correct
  disposition is a policy question.
- The adapter's checks on a processor result establish identity (the bytes
  it sent, the bytes it got back), policy fields, and an accepted
  verification label. They do not establish that the label is true; that is
  the processor's responsibility, as described under "Processor contract".
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
