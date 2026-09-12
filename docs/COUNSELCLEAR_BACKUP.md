# Cold backup: LOCAL/SQLite data root

`tools/counselclear_backup.py` produces a snapshot directory that
[`tools/counselclear_restore_drill.py`](COUNSELCLEAR_RESTORE_DRILL.md) can
restore. It shares that tool's own copy-integrity and drained checks
(literally: it calls the same internal functions), so a "verified" backup
and "the restore drill will not refuse this copy's drained state" share one
definition — not a full guarantee that recovery will succeed. The restore
drill's own audit-chain, original/mail-submission byte, release-certificate
and signing-key checks are separate, and still need a real restore
rehearsal (with `--volume-key-file`) to qualify recovery end to end.

```sh
python tools/counselclear_backup.py \
  --source /srv/counselclear/data \
  --destination /srv/counselclear/backups/2026-09-12T03-00 \
  --report /srv/counselclear/backups/2026-09-12T03-00.json
```

## This backs up `--source`. That is not everything recovery needs

`--source` is the data root: the SQLite database, `auth/` (custody signing
key, cookie secret, local password hash — all included automatically), and
originals/derivatives/bundles under it. **Not included, because they live
outside the data root by design:**

- `COUNSELCLEAR_VOLUME_KEY_FILE` — the 32-byte local volume key, if
  encryption at rest is configured. Without it, a restored root's encrypted
  originals cannot be opened at all. Back it up separately, and keep it
  separate from the data-root backup (that is the point of it living
  outside the data root — see `COUNSELCLEAR_PRODUCTION.md` §5).
- Deployment configuration that is not a file under the data root at all:
  the OIDC client secret, the chosen TSA endpoint, the digest-pinned
  worker image reference, proxy/TLS configuration. Losing these doesn't
  lose data, but a restored root is not equivalently *configured* until
  they are reapplied.

A restore rehearsal that only checks the data-root copy is not a full
recovery rehearsal unless it also proves the separately-held key and
configuration were actually available and correct.

## Stop the API first — this is not verified for you

This is an explicit, **unenforced** precondition, not something the tool
detects. A WAL-mode SQLite database gives readers and writers separate
locks by design, so there is no way to *ask* whether another process holds
the write lock without attempting a write yourself — and even an
immediately-rolled-back write causes SQLite's own connection-close
checkpoint/recovery to run against whatever file was opened, which is a
real mutation, not a harmless probe. So this tool never opens `--source`'s
database at all, for reading or writing, in any form. Every file under
`--source` is copied with plain filesystem operations only (stat, copy,
digest) — never through `sqlite3.connect`. Only the *destination* copy,
which the tool created and owns, is ever opened, checkpointed, or
integrity-checked.

Practical consequence: if the API is not actually stopped, this tool
cannot tell, and will copy whatever bytes happen to be on disk — possibly
an inconsistent snapshot despite a "verified" report, since a torn read of
a live database is not guaranteed to fail its own integrity check. Stop
the process, keep it stopped for the whole backup, and only then run this.

## What it checks, and in what order

1. **Before touching `--source` at all** (plain filesystem inspection —
   `stat`, `lstat`, `os.walk`, no file content read): `--source` is a real
   directory, not a symlink; contains no symlinked file or directory
   anywhere in the tree (a symlinked `counselclear.sqlite3` is refused by
   `os.path.islink`, never followed); contains `counselclear.sqlite3`;
   `--destination` does not already exist and is not nested inside
   `--source` or vice versa. A refusal here changes nothing — `--source`
   was never opened, so there is nothing to change back.
2. **Copy**: every file is copied byte-for-byte into the new
   `--destination`, and each copy is digest-compared against its source
   file before anything trusts it.
3. **On the copy only**: WAL checkpoint, `PRAGMA integrity_check`, and the
   same drained check the restore drill requires at restore time (no
   queued/running jobs or releases, no open batches, no mail submission in
   a state the registry could still act on). A refusal at this stage is
   about the *copy this tool made* — `--source` is unaffected either way.

On any refusal or failure after the destination directory was created, it
is removed again (`--keep-on-failure` retains it for inspection).

## Recommended cadence

- Stop the API (or coordinate a maintenance window).
- Run this tool against the stopped data root.
- Periodically — not on every backup — feed a real backup into
  `tools/counselclear_restore_drill.py` with the corresponding
  `--volume-key-file` and `--old-data-root`, into a throwaway destination,
  and confirm it reports `verified`. That is the actual recovery rehearsal;
  a green backup report alone is not one.
- Keep the produced report alongside the backup (`--report`) as evidence
  of what was checked and when.

## Upgrade and rollback

Before applying a new release (startup runs `upgrade_head` automatically):
back up first. `docs/PRODUCTION_FOUNDATION.md` documents that migration
`0012` (release certificate snapshots) is not a byte-preserving downgrade:
reverting to an older schema after snapshots have been used discards those
bytes and the application regenerates certificates on next access — not
a safe rollback for any release that has already served a snapshot-backed
packet. Practically: a backup taken *before* the upgrade is the only
reliable rollback path once new certificate snapshots exist. Restoring an
older backup after new work has been admitted loses that newer work —
rollback recovers the schema, not time.

## Not established by this tool

- S3 originals or PostgreSQL — LOCAL/SQLite only, matching the restore
  drill's own scope.
- That the API was actually stopped — an operator precondition, not a
  machine-verified one.
- That every original/mail submission still decrypts correctly — run the
  restore drill with `--volume-key-file` for that.
- Live backup acquisition from a genuinely running service (snapshotting
  without stopping anything) — out of scope for this pilot.
