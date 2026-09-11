# Custody storage: exact S3 object-version references

Status: implemented in `service/app/storage.py` with mocked-client tests in
`tests/test_storage.py`. Branch `feat/storage-s3-object-versions`, started
from `build/production-foundation` at
`c549736cb7d9cf46ed5762e293c8745782ca484b`. No live AWS or S3-compatible
backend has been exercised; see "Remaining qualification".

## The defect this closes

Object Lock protects a specific *version* of an object. A key-only
reference (`documents.storage_path` = object key) discards the `VersionId`
S3 returns on PutObject and later reads whatever the key currently holds.
Versioning permits newer versions and delete markers at the same key, so a
key-only reference could serve a replaced object or fail on a deleted one
even though the locked original still exists. (Production-readiness review,
"P1 for S3", `storage.py:246–258` at `6db2262`.)

## Reference formats

| Form | Example | Read behaviour |
|---|---|---|
| Pinned (new writes) | `s3v1:3/L4kqtJlcpXroDTDmJ+rmSpXd3QBpUMLUo:prod/firm/matters/m1/docs/d1/original/a.docx` | `GetObject` with `VersionId`; the served version id must equal the recorded one |
| Legacy (rows written before this change) | `prod/firm/matters/m1/docs/d1/original/a.docx` | `GetObject` of the current version; **cannot** detect replacement |
| Local backend | absolute filesystem path | unchanged |

`s3v1:` is followed by the version id, a colon, then the object key. The
version id comes first because object keys may contain any character,
including `:`; S3 version ids are opaque URL-safe tokens (letters, digits,
`+ / = . _ -`, at most 1024 bytes) and never contain `:`. A pinned
reference that does not parse is refused, never reinterpreted as a key.
`describe_reference(ref)` reports `version_pinned` for operators.

`key_from_ref` strips the scheme and version, so the **logical key is
unchanged** for both forms. The envelope-encryption AAD is the logical key,
which means envelopes sealed before pinning open through a pinned
reference and vice versa (`test_legacy_envelope_is_readable_through_a_pinned_reference`).
Object Lock retention parameters, the `sha256` metadata idempotency key, and
the `If-None-Match: *` conditional PUT are unchanged. Callers' original
hash/size validation is unchanged; a new `Backend.read_expected(ref,
sha256=, size=)` helper packages it for readers that currently call `read`.

## What the backend now guarantees

- **Writes** record the exact `VersionId` from the PutObject response. A
  response without a durable version id (versioning never enabled → header
  absent; versioning suspended → `"null"`) raises `StorageError` and no
  reference is recorded. The object may exist on the bucket in that case;
  the error message says so. Opting out requires constructing
  `S3Storage(require_object_versions=False)` explicitly; `storage_from_config`
  passes `cfg.s3_require_object_versions` if the config module ever grows
  that field, and defaults to pinning.
- **Idempotent writes** (metadata says the same content is already the
  current version) pin the current version's id, read that exact version
  back, and compare it byte-for-byte with the submitted content before
  returning; the `sha256` object metadata is writer-supplied and is only a
  hint. Matching metadata over different bytes is a `WriteOnceViolation`.
  No second PUT either way.
- **Reads of a pinned reference** address the version explicitly. `NoSuchVersion`
  raises `VersionUnavailable` ("no longer exists; refusing to read the key's
  current version"). A recorded version that is a delete marker (S3 answers
  405 `MethodNotAllowed`) raises `VersionUnavailable` as corruption: no
  write of ours ever records a delete marker. A successful response must
  name the version it served: a `VersionId` that differs from the request,
  or a response with no `VersionId` at all (what a backend that ignores the
  parameter would return), raises `StorageError`; so does a success response
  flagged `DeleteMarker`. There is no code path that drops the version id
  and retries; the tests assert this from the request log. Response bodies
  are closed on success and on every validation failure.
- **`exists` of a pinned reference** is `False` for a permanently removed
  version and raises for a delete-marker version.
- **Newer versions and delete markers at the key** do not affect pinned
  reads (`test_overwritten_key_still_reads_the_recorded_version`,
  `test_delete_marker_after_write_does_not_hide_the_recorded_version`).
- **Prerequisites** are verified at construction (`verify_prerequisites`):
  `GetBucketVersioning` must report `Enabled`, and with
  `COUNSELCLEAR_RETENTION_DAYS > 0` `GetObjectLockConfiguration` must report
  `ObjectLockEnabled: Enabled`. Missing permission to check is a refusal,
  not a pass. `describe()` shows the verified state
  (`object-versions=pinned prerequisites=object_lock=Enabled,versioning=Enabled`).
- **`EncryptedStorage`'s conflict path** (a raced write that lost the
  conditional PUT) now returns the pinned reference of the version it
  compared, via the new `Backend.current_ref(key)`.
- PUTs that carry retention parameters now also send
  `ChecksumAlgorithm=SHA256`: S3 requires a content checksum on any upload
  that sets a retention period.

## Legacy references: compatibility limitation

Rows written before this change hold bare object keys. They keep working:
`read`, `exists`, and `key_from_ref` accept them, and the encryption AAD is
identical. What they cannot do is prove they return the original. On a
versioning-enabled bucket, a legacy reference serves the key's *current*
version; if the key was overwritten out of band, that is not the recorded
original, and if a delete marker is current, the read fails even though the
original version still exists under lock.

Mitigations, in order:

1. Every reader of an original already holds the custody row's `sha256`
   and `bytes`. `runner.run_job` checks them; the packet-download path in
   `main.py` reads the original for `include_original` without a digest
   check. Adopting `read_expected` there closes the gap for legacy rows
   (Codex's file; noted here, not changed).
2. `S3Storage.pin_reference(ref, sha256=, size=)` upgrades one legacy
   reference: it reads the key's current version, verifies it
   byte-for-byte against the recorded digest and size, and only then
   returns the pinned spelling. A mismatch is a recovery problem, not a
   migration step, and raises. Nothing is written to the bucket or the
   database by this call; a migration tool that updates
   `documents.storage_path` row by row, records the change in the audit
   chain, and stops on the first mismatch is the intended consumer. This
   change performs no bulk migration and rewrites no historical custody
   rows.

## Operations

**Bucket prerequisites** (must exist before `COUNSELCLEAR_STORAGE=s3` boots):

- Versioning `Enabled` (`aws s3api get-bucket-versioning`). Suspending it
  later makes every subsequent write fail with the "durable object version
  id" error by design; re-enable versioning rather than opting out.
- Object Lock enabled at bucket creation when retention is configured
  (`get-object-lock-configuration`). Object Lock requires versioning; it
  cannot be enabled on a bucket that lacks it.
- Lifecycle rules must not expire noncurrent versions before the retention
  period; a pinned reference to an expired version raises
  `VersionUnavailable` and needs a restore from backup.
- IAM for the service principal, in addition to what it had:
  `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration`,
  `s3:GetObjectVersion` (reads with `versionId` need it; `s3:GetObject`
  alone is not sufficient per the GetObject reference). Writes with
  retention still need `s3:PutObjectRetention` alongside `s3:PutObject`.

**Recovery cases**

| Event | Pinned reference | Legacy reference |
|---|---|---|
| Key overwritten by a later PUT | unaffected | serves the new object; digest check fails |
| Key deleted (delete marker current) | unaffected | read fails (404) |
| Recorded version permanently deleted | `VersionUnavailable`; restore from backup | n/a |
| Versioning suspended after boot | new writes refused; existing pinned reads unaffected | unchanged |
| Bucket replication / restore to a new bucket | version ids are **not** preserved across buckets; restored objects need re-pinning with `pin_reference` against recorded digests | same |

The last row matters for disaster recovery: S3 assigns new version ids to
objects written into a different bucket, including by replication or a
backup restore. A restored deployment must re-pin references from the
recorded digests before it can claim exact-version custody again.

**Logging.** Nothing in this change logs object keys, version ids, or key
material. Error messages name the bucket and the failure class only.

## Remaining qualification

- All tests use a versioning-aware client double written from the S3 API
  reference (PutObject `x-amz-version-id`, GetObject `versionId`, 405 for
  delete-marker versions, `NoSuchVersion`, `If-None-Match`). They establish
  the client's behaviour against that contract, not a live bucket. A live
  qualification run against AWS S3 with versioning + Object Lock, and
  against any S3-compatible backend the product intends to support
  (MinIO, Ceph RGW, …), is still required; S3-compatible implementations
  differ in version-id format, delete-marker status codes, and
  `GetBucketVersioning` support.
- `ChecksumAlgorithm=SHA256` on retention PUTs assumes a botocore that
  computes flexible checksums; older SDKs need `Content-MD5` instead.
  Verify the pinned SDK version in `service/requirements-app.txt` behaves.
- The `documents.storage_path` column is `String(1024)`; a pinned reference
  adds `len("s3v1:") + len(version id) + 1` characters. AWS version ids
  observed in practice are ~32 characters; the format allows up to 1024,
  which would not fit. Qualify the observed length on the target backend
  or widen the column (schema change: Codex's migration).
- `main.py`'s `include_original` packet path should adopt `read_expected`;
  `runner.run_job` already validates digest and size.
- A migration/verification tool for legacy rows (`pin_reference` consumer)
  with audit events is not part of this change.
- KMS (`KmsKeyring`) behaviour is unchanged and untested live here.
- `docs/COUNSELCLEAR_DESIGN.md` still describes the S3 reference as "object
  key on S3" (PR 21 ledger line); the ledger update is Codex's.
