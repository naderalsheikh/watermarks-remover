# Offline restore drill: cold LOCAL/SQLite data root into a new root

Status: implemented as `tools/counselclear_restore_drill.py` with tests in
`tests/test_restore_drill.py`. Branch `feat/restore-drill`, started from
`build/production-foundation` at `2a0cae7e40818513bdab2c5d0d1e94dbe169a35f`.

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
  the certificate snapshot of every done release, and that the custody
  signing key exists and loads whenever release custody depends on it.
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

A `verified` outcome means the restored root is internally consistent and
its evidence matches the database. It does not mean the snapshot was the
latest state: recency is a property of the backup schedule, not of the
restore.

## Remaining qualification

- Only LOCAL storage and SQLite. S3 references would need the object
  versions (`s3v1:`) to remain readable in the target account and the
  storage backend's own checks; PostgreSQL would need a dump/restore
  procedure and the same reference rebasing applied there. Both are
  separate drills.
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
