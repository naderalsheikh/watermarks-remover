# Offline restore drill: cold LOCAL/SQLite data root into a new root

Status: implemented as `tools/counselclear_restore_drill.py` with tests in
`tests/test_restore_drill.py`. Original local/SQLite/mail-less relocation:
branch `feat/restore-drill`, from `build/production-foundation` at
`2a0cae7e40818513bdab2c5d0d1e94dbe169a35f`. Terminal mail-submission
relocation (this revision): branch `feat/mail-spool-restore`, from
`build/production-foundation` at `46290d1c09dfd335d3136ee69cab329fc3e64677`
(after PR #11, `app.mail.submissions.MailSubmissionRegistry` and migration
0017, merged). See "Mail submissions" below.

## What this qualifies, and what it does not

The drill qualifies one thing: a **cold, drained snapshot** of a
`COUNSELCLEAR_STORAGE=local` data root with its SQLite database can be
restored into a **new** root on the same or another host, its database
filesystem references re-rooted, and the restored state verified.

Two layers of evidence, kept distinct:

- **What the tool itself verifies** on every run: database integrity,
  per-matter audit chains, every original's plaintext hash and size
  (through the envelope with supplied key material), the bundle evidence of
  every done sanitize job, the findings result of every done inspect job,
  the certificate snapshot of every done release, that the custody signing
  key exists and loads whenever release custody depends on it, and -- for
  every demonstrably terminal mail submission -- its retained input/output
  bytes plus a live exercise of the real mail registry proving the record
  can never again be claimed or delivered (see "Mail submissions").
- **What the end-to-end test demonstrates** in addition
  (`test_restore_into_new_root_serves_original_and_release_without_old_root`):
  the application boots on the restored root, authenticates with the
  restored password hash, serves the release packet, the offline verifier
  accepts that packet, and the storage backend reads the restored original.
  The tool does not boot the application or sign anything; a `verified`
  report is the tool's claim, the application-level behaviour is the
  test's.

It does not qualify, and refuses rather than pretends:

| Out of scope | Behaviour |
|---|---|
| Live backup acquisition (quiescing the app, snapshotting a running root) | The snapshot is an input; the drill checks it is drained and copies it |
| S3 object storage (`s3v1:` or key-only references) | Refused: "object-storage (S3) references present" |
| PostgreSQL (`COUNSELCLEAR_DATABASE_URL` not SQLite) | Refused |
| Mail submissions the registry could still act on (admitted, processing, retryable held, released, submitted), or an unrecognised status | Refused -- see "Mail submissions" |
| `ambiguous` mail submissions -- terminal (no automatic resend), but conservatively excluded from relocation | Refused -- see "Mail submissions" |
| KMS-wrapped envelopes (`kms:` key id in the envelope header) | Refused: only the local volume key can be opened offline |
| External identity (OIDC) | Not exercised; the drill verifies the local password hash file only by presence |
| Cloud restore, cross-region replication | Not exercised |
| Regenerating, inferring or printing key material | Never: a missing key file is a refusal, not a new key |

## Invocation

```sh
python tools/counselclear_restore_drill.py \
  --source /backups/2026-09-11T02-00/data \
  --destination /srv/counselclear/restored/data \
  --old-data-root /srv/counselclear/data \
  --volume-key-file /srv/counselclear/restored-keys/volume.key \
  --report /srv/counselclear/restore-2026-09-11.json
```

| Argument | Meaning |
|---|---|
| `--source` | the cold snapshot; used read-only |
| `--destination` | the new root; must not exist yet |
| `--old-data-root` | the absolute root the snapshot's rows were written under; never inferred |
| `--volume-key-file` | the restored 32-byte volume key; only when originals are encrypted |
| `--report` | a new file for the JSON report, outside the snapshot, the restored root and the key file's directory |
| `--keep-on-failure` | keep the destination after a refusal or failure, for inspection |

Exit 0: verified. Exit 2: refused on a precondition (nothing about the
snapshot's evidence was judged). Exit 3: restored but verification failed.
Exit 1: unexpected error. The destination is owned by the drill from the
moment it is created: on 2, 3 or 1 it is removed unless `--keep-on-failure`
is given (read-only members are made writable first), and the report says
`destination_removed: false` if removal did not succeed rather than
claiming it did. A pre-existing destination is never touched. `--report`
is validated before anything is copied and refuses an existing path or a
path inside the snapshot, the restored root, or the key file's directory.

`--old-data-root` is required and never inferred. The snapshot's rows
contain absolute paths written by the application on the source host; the
declared root is the only authority for which prefix is "the data root".
Its flavour (POSIX or Windows, by backslash/drive-letter) decides how the
references are parsed, so a Windows-written snapshot restores on a POSIX
host and vice versa (`test_windows_spelled_references_restore_on_this_host`).

## What the drill does, in order

1. **Preflight, source untouched.** Refuses a non-SQLite database URL or
   non-local storage mode in the environment, a missing `counselclear.sqlite3`,
   an existing destination, a destination nested in the source (or the
   reverse), and any symlink or non-regular file anywhere in the snapshot.
   The source is walked with `followlinks=False` and is never opened for
   writing; no SQLite connection is ever made to it.
2. **Key material.** If `--volume-key-file` is given it must exist, not be
   a symlink, and hold 32 bytes. `LocalKeyring` creates a key when the file
   is missing; the drill checks first so that can never happen.
3. **Copy, byte-for-byte.** Every file is copied with its metadata and its
   SHA-256 is compared with the source before anything opens it.
4. **Open the destination database only.** `PRAGMA integrity_check` must
   return `ok`. If the snapshot carried a WAL, it is checkpointed into the
   restored database (`wal_checkpoint(TRUNCATE)`), which is a copy-side
   operation; the snapshot's own WAL is unchanged. The Alembic version and
   journal mode are recorded.
5. **Drained check.** Any job or release in `queued`/`running`, or any
   batch without `finished_utc`, is a refusal. The drill restores state; it
   does not resume work, and a resumed job would write to the restored
   root under leases the snapshot cannot vouch for.
6. **Rebase exactly three references.** `documents.storage_path`,
   `jobs.bundle_dir` and `jobs.execution_receipt.output_dir` (inside the
   receipt JSON) are re-rooted from the declared old root to the new root.
   Each must be an absolute path under the old root with no empty, `.` or
   `..` segment, and its re-rooted form must resolve inside the new root;
   otherwise refusal. A digest over every discovered table, including
   `admissions` and tables unknown to the tool, is taken before and after
   the update and must be identical. Only the three rebased columns are
   excluded; other columns in `documents` and `jobs` are also checked.
   After the update no reference column may still
   mention the old root.
7. **Audit chains.** Every matter's events are re-verified with the
   application's own `verify_chain` (seq contiguity, `prev_hash` linkage,
   `row_hash` recomputation). Orphaned events (a matter that no longer
   exists) fail verification.
8. **Originals.** Each document's file must exist at the restored path.
   `CCENC` envelopes are opened through `EncryptedStorage(LocalStorage(new
   root), LocalKeyring(supplied key))`; the AAD is the root-relative
   logical key, which is why relocation works without touching the
   envelope. The plaintext must match the row's `sha256` and `bytes`.
9. **Released artifact evidence.** The job kind is read from the row.
   Every `done` **sanitize** job must record a `bundle_dir` inside the
   restored root whose `manifest.json` parses; the derivative it names
   must be a plain file name confined to `bundle/derivative/` (an absolute
   or relative path in a manifest is a failure, and the manifest is never
   rewritten to repair it), the derivative directory must contain exactly
   that file, its digest and size must match the manifest, `report.html`
   must exist, the manifest's original digest/size must match the document
   row, `jobs.result_json` must be a JSON object whose manifest equals the
   stored one with `verification_pass` true, and where the execution
   receipt names an output directory its `result.json` must carry the same
   manifest. Every `done` **inspect** job must have no bundle and a findings
   list. Malformed result types (a list, `null`, empty, non-JSON) fail.
   Every `done` release must point at a `done` sanitize job whose bundle
   verified and must carry a certificate snapshot that parses and contains
   the certificate HTML. The packet signature itself is not recomputed by
   the drill; the end-to-end test downloads a packet from the restored root
   and runs `tools/counselclear_verify_release_packet.py` on it.
10. **Auth material.** File presence and sizes are reported, never
    contents. The custody signing key must exist and load as an Ed25519
    private key whenever release custody depends on it (any done release
    or done sanitize job); otherwise verification fails, because the
    application would generate a replacement signing identity at first
    use and every future packet would be signed by a different key than
    the restored records. On a root with nothing signed yet, a missing key
    is reported as a warning. The public fingerprint (SHA-256 of the raw
    public key, the value recipients pin) is reported for comparison.

## What "cold and drained" means for the operator

- The application process is stopped, or at minimum every dispatcher is
  stopped and no request is in flight. A clean shutdown checkpoints the
  WAL; a snapshot that still carries `counselclear.sqlite3-wal` is
  accepted and the frames are checkpointed on the copy, but a snapshot
  taken *while* the process wrote is not cold and the drill cannot detect
  every such case — integrity and chain checks catch torn state after the
  fact, not a consistent-but-stale one.
- No queued or running jobs, releases, or open batches. Drain them or let
  them finish before snapshotting; the drill refuses otherwise.
- Take the snapshot with a tool that preserves bytes and does not
  dereference symlinks; the drill refuses symlinks because a link into the
  old root would silently keep the restored deployment reading from it.

## Key material

Encrypted originals are envelopes sealed with the volume key named by
`COUNSELCLEAR_VOLUME_KEY_FILE`, which lives *outside* the data root by
design. Restoring the data root restores nothing that can open those
envelopes: the key file must be restored from its own backup and passed as
`--volume-key-file`. The drill reports `key_material.used` so an operator
can see whether the supplied key opened anything.

The custody signing key (`auth/custody_signing_key.pem`) *is* inside the
root and is copied byte-for-byte. The application loads it on the restored
root and continues signing under the same identity, which is why the
fingerprint is reported: compare it with the fingerprint recipients have
pinned. If the PEM were missing, the application would generate a new
identity at first use; the drill does not create one and reports absence.

## Mail submissions

`app.mail.submissions.MailSubmissionRegistry` (PR #11) retains whole
messages the internal mail coordinator admitted, processed, and possibly
delivered. Its own state machine (`docs/COUNSELCLEAR_MAIL_STATE.md`) is the
authority on which states are terminal; the drill relocates a submission
only when the registry itself can never again claim, process, or deliver
it, and then proves that against the real registry rather than trusting
the status string alone.

**Eligible (relocated):**

- `refused` -- the coordinator blocked the message; no release, no retry.
- `held`, permanently (`retryable=False`) -- an unsupported attachment or a
  policy refusal the mandatory-cleaning default cannot retry.
- `acknowledged` -- delivered and a trusted acknowledgment recorded.

**Refused (the whole drill run refuses, before any copy proceeds further):**

- `admitted`, `processing`, `held` with `retryable=True`, `released`,
  `submitted` -- every one of these means the registry could still act on
  the row (claim it, finish processing it, or obtain/retry a delivery
  ticket). Relocating any of them risks resurrecting a possible send after
  restore, which this drill's entire design exists to prevent.
- `ambiguous` -- terminal per `docs/COUNSELCLEAR_MAIL_STATE.md` (no
  automatic resend; the registry cannot claim, process, or deliver it
  either), but conservatively excluded anyway: it means a delivery attempt's
  outcome is unknown, and this drill only ever relocates evidence, not
  resolves it -- an ambiguous row belongs to a human decision, not a cold
  restore.
- Any status string the registry does not define. An unrecognised status
  is inconsistent data, not an assumed-safe one.
- A row whose stored fields contradict its status: a `refused` or
  permanently-`held` row that unexpectedly carries `output_ref`,
  `delivery_token`, or `acknowledgment_sha256`; or an `acknowledged` row
  missing any of them, marked `retryable`, or carrying a malformed
  `delivery_token` / `acknowledgment_sha256` / `delivery_expires_epoch` (not
  the shape the registry itself ever writes there). `acknowledge()` never
  clears `delivery_token` or `delivery_expires_epoch` -- they are retained,
  not erased -- so an acknowledged row is expected to still carry them, and
  a check that required them to be null would itself be wrong.

**What is relocated and verified.** Only `input_ref` (always present) and
`output_ref` (present on `acknowledged` rows only) are rebased, the same
way as `documents.storage_path` -- absolute local paths only, S3 references
refused, rebased path must resolve inside the new root. Every other mail
column is left exactly as copied and covered by the same before/after
digest that protects `audit_events`, `releases`, and every table this tool
does not otherwise know about. After rebasing, each relocated submission's
retained input (and output, if present) is read through the same
`EncryptedStorage`/`LocalStorage` path as originals, decrypted with the
supplied key material, and compared byte-for-byte with its recorded
`input_sha256`/`input_bytes` (and `output_sha256`/`output_bytes`).

**Reconciled against its own retained audit trail, before the registry is
even touched.** `binding_sha256` never covers `status` (see
`MailSubmissionRegistry._bound_fields` / `_row`), so a row whose `status`
column was edited directly in the snapshot -- a permanently held submission
flipped to refused, say -- still revalidates against `get()`'s own
recomputed binding hash: nothing about that recompute would notice. Once
`_verify_audit` has proven the matter's audit chain is internally unbroken,
the drill finds the last `mail.*` event recorded for each relocated
submission and checks it against the row: the expected terminal action
(`mail.decision` for refused/held, `mail.delivery.acknowledged` for
acknowledged), the event's matter and actor, and the retained
`status`/`binding_sha256`/`input_sha256`/`output_sha256`/`request_key`/
`attempt`/recipient count where the event payload carries them. This is
internal consistency between two parts of the same database, not
independent authentication of the snapshot's origin -- an unbroken hash
chain proves the events are self-consistent with each other, not that they
were written by the real coordinator rather than fabricated, together with
a matching row, by whatever produced the snapshot. Proving where a snapshot
actually came from is outside this tool's scope.

**Proof against the real registry, not a reimplementation of its checks.**
For every relocated submission, the drill constructs the tenant/matter/
actor/policy binding recorded on the row, builds a real
`MailSubmissionRegistry` against the restored database, and calls its
public `get`, `claim`, and `prepare_delivery` methods -- the same methods a
live coordinator would call. `get` revalidates the retained admission
binding hash and the matter ACL exactly as it would in production;
`claim` must return no owner; `prepare_delivery` must raise
`SubmissionConflict` (none of the three eligible states is `released`). No
change to the registry's public API was needed for this.

This exercise is pinned to the restored destination and to explicitly
supplied key material only: `Config(destination)` still reads
`COUNSELCLEAR_*` environment variables meant for a live deployment, so an
ambient `COUNSELCLEAR_DATABASE_URL` is discarded before the engine is built
-- the exercise always opens the destination's own SQLite file, never
whatever an inherited environment happens to name. Storage for the
exercise is built the same explicit way originals are verified (local to
the destination, wrapped in `EncryptedStorage` only when `--volume-key-file`
supplied a keyring) rather than through `storage_from_config`, which would
otherwise read an ambient `COUNSELCLEAR_VOLUME_KEY_FILE` and have
`LocalKeyring` silently *generate* a fresh key at that path outside the
restored root the first time it is asked for one that does not exist.

**Report privacy.** `report.mail` carries only aggregate counts and a
per-status tally (`submissions`, `by_status`, `bytes_verified`,
`encrypted`, `audit_reconciled`, `registry_exercised`,
`claims_returned_none`, `delivery_refused`) -- never a submission id,
envelope address, message content, or capability token, matching the same
field selection `app.mail.submissions._event` already uses for audit
payloads. `report.database.mail_submissions_by_status` and
`report.references.mail_input_refs_rebased` /
`mail_output_refs_rebased` are the only other mail-specific fields.

## Recovery outcomes

| Situation | Drill result |
|---|---|
| Original bytes damaged or replaced in the snapshot | exit 3, `document …: plaintext differs` |
| Wrong volume key supplied | exit 3, `envelope did not open` |
| Bundle directory or manifest missing | exit 3, `bundle or manifest.json missing` |
| Derivative bytes altered | exit 3, `derivative differs from manifest` |
| Audit row altered | exit 3, `audit chain verification failed` |
| Reference outside the declared root, `..`, S3 form | exit 2, refusal names the column |
| Queued/running work | exit 2, `snapshot is not drained` |
| Signing key missing or unloadable with release custody present | exit 3, `custody signing key is missing` / `did not load` |
| Done sanitize job without bundle evidence, or malformed `result_json` | exit 3, names the job |
| Manifest naming a derivative outside its bundle | exit 3, `is a path, not a confined file name` |
| Copy interrupted (I/O error) | exit 1, exception propagates, destination removed |
| Mail submission in a non-terminal or unrecognised state | exit 2, `mail_submissions: submission …` names the status |
| Terminal mail row inconsistent with its own status (e.g. `refused` carrying `output_ref`) | exit 2, names the unexpected or missing column |
| Retained mail input/output corrupted or wrong key supplied | exit 3, `retained input/output differs` / `envelope did not open` |
| Mail row's status, hashes, actor, matter, or request facts disagree with its own retained audit trail | exit 3, `mail audit reconciliation failed` |

A `verified` outcome means the restored root is internally consistent and
its evidence matches the database. It does not mean the snapshot was the
latest state: recency is a property of the backup schedule, not of the
restore.

## Remaining qualification

- Only LOCAL storage and SQLite. S3 references would need the object
  versions (`s3v1:`) to remain readable in the target account and the
  storage backend's own checks; PostgreSQL would need a dump/restore
  procedure and the same reference rebasing applied there. Both are
  separate drills, for mail submissions as much as for documents.
- Live transport qualification (an authenticated Exchange gateway,
  return-path provenance, message-trace reconciliation) is separate work
  entirely; this drill only ever handles retained state the coordinator
  already produced, never SMTP or a tenant.
- `released`, `submitted`, and `ambiguous` mail rows are refused, not
  merely left unrelocated: the whole drill stops rather than partially
  restore some submissions and refuse others. An operator who needs a
  root containing such rows restored must first let the coordinator (or
  its recovery path) move them to a terminal state, or accept that this
  drill cannot help until then.
- Cross-platform restore of *encrypted* originals sealed on Windows before
  canonical logical keys existed: the storage layer preserves those
  envelopes on Windows through their native path spelling; on a POSIX host
  they will not open. The drill reports each as an envelope that did not
  open. Plaintext originals and all post-canonical envelopes restore on
  either platform.
- The drill verifies with the application's own primitives (`verify_chain`,
  `EncryptedStorage`); it is not an independent implementation of them.
- No performance qualification: the copy is single-threaded and hashes
  every file twice; large roots will take time proportional to size.
- The tool is not yet in the CI lint path (`tools/ci_pytest_shard.py` is
  the only `tools/` entry there); it is ruff-clean locally and covered by
  `tests/test_restore_drill.py` in the main suite.
