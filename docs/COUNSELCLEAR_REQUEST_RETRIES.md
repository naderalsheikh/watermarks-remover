# Durable request admission and browser retries

The five job/release submission routes accept `Idempotency-Key`: document inspect jobs, document sanitize jobs, document releases, matter batches, and matter batch releases. Clients generate a random key for one intended submission and reuse it only when retrying that same request.

Keys are scoped to the authenticated principal, matter, and operation. Authorization runs before receipt lookup. The receipt binds the normalized request, resolved policy ID, and each selected document's recorded ID, SHA-256, and length. It does not pin a future worker image or policy implementation version. Only key and request hashes are stored. A key must contain 1–200 visible ASCII characters.

Identical retries return the existing resource, including after an API restart. Reusing the key for different content returns HTTP 409. A receipt, resource creation, required attestation consumption, and admission audit entries commit together. A retry does not consume its authorization twice. Omitting the key retains the existing non-idempotent API contract. Receipts currently have no expiry; operators must preserve them with the database.

Single-job and single-release clients can send `Prefer: respond-async`. Pending work then returns HTTP 202, `Preference-Applied: respond-async`, `Location`, and `Retry-After: 1`. The response includes the admitted job; a pending release has `release_result: null`. Poll the returned job until a terminal state. Finished work can return HTTP 200. Clients that omit the preference retain the bounded synchronous wait; a timeout does not cancel durable work. Batch routes retain their existing asynchronous response contract.

The browser uses both headers. It coalesces concurrent identical submissions and saves only a request fingerprint and random retry key in session storage. A failed request retains its key; successful admission clears it. The same details can be retried after a connection failure or page reload in the same session. Editing the request creates a distinct submission. This is not cross-device deduplication. Web Crypto requires HTTPS or a trusted local origin. Job polling is bounded to ten requests at a time, does not overlap rounds, and stops for terminal jobs and unmounted views.

## Original-file release packets

An explicitly requested original requires the existing matter permission. The server reads the recorded storage reference with the original SHA-256 and length before issuing a packet. A missing or mismatched original returns HTTP 409; the server does not quietly omit it. S3 references preserve the upload's exact version. Migration 0015 widens the reference column to text; downgrade refuses references longer than the old 1,024-character column rather than truncate custody identifiers.

## Validation

Regression coverage includes concurrent requests across SQLite and PostgreSQL, conflicting bodies, principal scoping, admission rollback, attestation replay, restart lookup, asynchronous responses, browser retry persistence, polling cancellation, original-file mismatch/missing errors, and long-reference migration round trips. Live synthetic browser inspection and release produced HTTP 202 admissions, terminal UI updates, and a signed release packet that passed the offline verifier with the preview deployment's separately read public-key fingerprint. External timestamping was disabled for that local check.
