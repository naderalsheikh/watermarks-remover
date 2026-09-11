"""Custody storage backends (PR 21): S3 Object Lock, CMK, residency.

Design contract (``docs/COUNSELCLEAR_DESIGN.md``, PR 21 — production
tenancy): production originals live in S3-compatible object storage under
Object Lock retention, encrypted at rest under a customer-managed key, and
pinned to a residency region. Local installs keep the engine's O_EXCL+0444
write-once files (``custody.write_once``).

This module is the storage boundary for the **original custody store only**.
Job staging and worker output stay on local disk — that is the PR 17 worker
contract (``app/runner.py`` stages a copy of the original into the scoped
job directory; the worker never sees the storage backend).

Key layout (design doc, one scheme for local and S3):
    {org}/matters/{matter}/docs/{doc}/original/{filename}

The org segment is ``COUNSELCLEAR_ORG`` (default ``local``; the shipped
schema is single-tenant, the segment exists to keep the one key scheme the
design doc specifies). New uploads on an existing local data root land
under ``{root}/{org}/matters/...``; pre-PR-21 files keep working because
every row stores its own reference.

References: what the DB stores in ``documents.storage_path``. Local = the
absolute filesystem path; S3 = a *version-pinned* reference
``s3v1:{VersionId}:{object key}`` for every write made since object-version
pinning landed, or the bare object key for references recorded before it
(see ``docs/COUNSELCLEAR_STORAGE_OBJECT_VERSIONS.md``). Every read of an
original goes through the backend — never a bare ``Path``. A pinned
reference is read by its exact version and never falls back to whatever the
key currently holds; a legacy bare-key reference reads the current version
because that is all it can name, which is the documented compatibility
limitation callers must cover with their own digest checks.

Everything is opt-in via env; the empty default is the Phase 2 profile:

- ``COUNSELCLEAR_STORAGE`` = ``local`` (default) | ``s3``
- ``COUNSELCLEAR_S3_BUCKET`` (required in s3 mode), ``COUNSELCLEAR_S3_PREFIX``
- ``COUNSELCLEAR_S3_REGION`` (client region), ``COUNSELCLEAR_RESIDENCY_REGION``
  (pin — the bucket's actual location is checked at startup and a mismatch
  refuses to boot, so a misconfigured deployment fails loudly, not on the
  first upload)
- ``COUNSELCLEAR_RETENTION_DAYS`` (Object Lock retain-until, default 365;
  0 disables the lock — the startup posture line warns then)
- ``COUNSELCLEAR_ORG`` (org segment for S3 keys, default ``local``)
- ``COUNSELCLEAR_CMK_ARN`` (AWS KMS customer-managed key; enables at-rest
  envelope encryption) or ``COUNSELCLEAR_VOLUME_KEY_FILE`` (0600 key file,
  the local stand-in for a CMK). Setting both is refused. Unset = storage
  is unencrypted.
"""

from __future__ import annotations

import os
import secrets
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import custody as custody_mod  # write-once semantics; never parses documents
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- envelope format ---------------------------------------------------------
# b"CCENC" | version u8 | key_id_len u8 | key_id | nonce(12) |
# wrapped_dek_len u16 | wrapped_dek | AES-256-GCM ciphertext+tag
_ENV_MAGIC = b"CCENC"
_ENV_VERSION = 1
_WRAP_AAD = b"cc-wrap-v1"

_NOT_FOUND_CODES = ("404", "NotFound", "NoSuchKey")
# A request that names a version which no longer exists. S3 answers
# ``NoSuchVersion`` (404); HeadObject surfaces it as a bare 404.
_NO_SUCH_VERSION_CODES = ("NoSuchVersion", *_NOT_FOUND_CODES)
# GetObject/HeadObject with the versionId of a *delete marker* is refused
# with 405 Method Not Allowed (S3 API reference, GetObject).
_DELETE_MARKER_CODES = ("MethodNotAllowed", "405")

# --- version-pinned S3 references -------------------------------------------
# ``s3v1:{VersionId}:{object key}``. The version id comes first so the object
# key, which may contain any character including ':', is the unambiguous
# remainder. S3 version ids are opaque URL-safe tokens (base64-like with
# '/', '+', '.', '=', '-') of at most 1024 bytes and never contain ':'.
# ``null`` is the version id S3 gives objects while versioning is suspended;
# it is overwritten by the next write and is therefore never pinned.
S3_VERSIONED_REF_PREFIX = "s3v1:"
_VERSION_ID_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=._-"
)
_MAX_VERSION_ID_LEN = 1024


class StorageError(RuntimeError):
    """Refusal to read/write custody storage, or a storage misconfiguration."""


class WriteOnceViolation(StorageError):
    """The key already holds different content — the backend's O_EXCL
    equivalent fired. Distinguished from transport errors so callers
    (EncryptedStorage) can treat it as an idempotency question."""


class VersionUnavailable(StorageError):
    """A pinned reference names an object version that cannot be read: the
    version was permanently removed, or the recorded version is a delete
    marker. The backend never substitutes the key's current version."""


def is_durable_version_id(version_id: object) -> bool:
    """True for a version id S3 will keep addressing after later writes.
    Absent (versioning never enabled) and ``"null"`` (versioning suspended)
    are not durable: the next PutObject replaces them."""
    return (
        isinstance(version_id, str)
        and 0 < len(version_id) <= _MAX_VERSION_ID_LEN
        and version_id != "null"
        and all(ch in _VERSION_ID_CHARS for ch in version_id)
    )


def make_versioned_ref(object_key: str, version_id: str) -> str:
    if not is_durable_version_id(version_id):
        raise StorageError("refusing to build a reference from a non-durable version id")
    if not object_key:
        raise StorageError("refusing to build a reference without an object key")
    return f"{S3_VERSIONED_REF_PREFIX}{version_id}:{object_key}"


def parse_s3_ref(ref: str) -> tuple[str, str | None]:
    """``(object key, version id)``; the version is ``None`` for a legacy
    bare-key reference. Malformed pinned references are refused rather than
    reinterpreted as legacy keys."""
    if not isinstance(ref, str) or not ref:
        raise StorageError("empty storage reference")
    if not ref.startswith(S3_VERSIONED_REF_PREFIX):
        return ref, None
    rest = ref[len(S3_VERSIONED_REF_PREFIX) :]
    version_id, sep, object_key = rest.partition(":")
    if not sep or not object_key or not is_durable_version_id(version_id):
        raise StorageError("malformed version-pinned storage reference")
    return object_key, version_id


def describe_reference(ref: str) -> dict[str, object]:
    """Operator-facing shape of a stored reference. Contains no secrets and
    no object content; the object key is a custody path, so callers decide
    whether it may be logged."""
    if isinstance(ref, str) and ref.startswith(S3_VERSIONED_REF_PREFIX):
        object_key, version_id = parse_s3_ref(ref)
        return {
            "scheme": "s3v1",
            "version_pinned": True,
            "object_key": object_key,
            "version_id": version_id,
        }
    return {"scheme": "plain", "version_pinned": False}


def _err_code(exc: Exception) -> str | None:
    """Extract the AWS/backend error code from an exception, if it carries
    one. Works with real botocore ``ClientError`` and with the test double;
    anything without a ``response`` dict is a transport/unknown error and
    stays None so the caller re-raises it."""
    resp = getattr(exc, "response", None)
    if not isinstance(resp, dict):
        return None
    err = resp.get("Error")
    return err.get("Code") if isinstance(err, dict) else None


def original_key(org: str, matter_id: str, doc_id: str, filename: str) -> str:
    """``{org}/matters/{matter}/docs/{doc}/original/{basename}`` — the one
    key layout from the design doc, used by the S3 backend."""
    return f"{org}/matters/{matter_id}/docs/{doc_id}/original/{Path(filename).name}"


class Backend:
    """Write-once original store. ``write_once`` returns the reference to
    store in ``documents.storage_path``; ``key_from_ref`` maps a reference
    back to its logical key (the envelope AAD); ``ref_for`` maps a key to
    its reference without writing."""

    def write_once(self, key: str, data: bytes) -> str:  # pragma: no cover - protocol
        raise NotImplementedError

    def read(self, ref: str) -> bytes:  # pragma: no cover - protocol
        raise NotImplementedError

    def exists(self, ref: str) -> bool:  # pragma: no cover - protocol
        raise NotImplementedError

    def ref_for(self, key: str) -> str:  # pragma: no cover - protocol
        raise NotImplementedError

    def key_from_ref(self, ref: str) -> str:  # pragma: no cover - protocol
        raise NotImplementedError

    def describe(self) -> str:  # pragma: no cover - protocol
        raise NotImplementedError

    def current_ref(self, key: str) -> str | None:
        """The reference a caller should record for what ``key`` holds *now*,
        or ``None`` when nothing is stored. Backends that pin object versions
        return a pinned reference here; ``ref_for`` stays the version-less
        spelling."""
        ref = self.ref_for(key)
        return ref if self.exists(ref) else None

    def read_expected(self, ref: str, *, sha256: str, size: int) -> bytes:
        """Read and refuse anything but the recorded bytes. Callers that hold
        the custody row's digest and size (every reader of an original does)
        should prefer this over ``read``: for a legacy S3 reference it is the
        only thing standing between the caller and a replaced object."""
        data = self.read(ref)
        if len(data) != size or custody_mod.sha256_bytes(data) != sha256:
            raise StorageError("stored object differs from its recorded hash or size")
        return data


class LocalStorage(Backend):
    """Filesystem write-once via the engine's ``custody.write_once``
    (O_EXCL + 0444). Keys carry the org segment like S3 (one scheme)."""

    def __init__(self, root: Path | str, org: str = "local"):
        self._root = Path(root).absolute()
        self._org = org

    def write_once(self, key: str, data: bytes) -> str:
        dest = self._root / key
        try:
            stored, _created = custody_mod.write_once(dest, data)
        except custody_mod.CustodyError as e:
            raise WriteOnceViolation(str(e)) from e
        return str(stored)

    def read(self, ref: str) -> bytes:
        return Path(ref).read_bytes()

    def exists(self, ref: str) -> bool:
        return Path(ref).exists()

    def ref_for(self, key: str) -> str:
        return str(self._root / key)

    def _relative_path_from_ref(self, ref: str) -> Path:
        p = Path(ref).absolute()
        try:
            return p.relative_to(self._root)
        except ValueError:
            raise StorageError(f"reference outside storage root: {ref}") from None

    def key_from_ref(self, ref: str) -> str:
        # Logical keys (and the original envelope AAD) use forward slashes
        # on every platform, even when the stored reference is a Windows path.
        return self._relative_path_from_ref(ref).as_posix()

    def _native_key_from_ref(self, ref: str) -> str:
        # Read compatibility only: before canonical key rendering, native
        # Windows keys were the only spelling read() could authenticate.
        return str(self._relative_path_from_ref(ref))

    def describe(self) -> str:
        return f"local ({self._root}, O_EXCL+0444 write-once)"


class S3Storage(Backend):
    """S3-compatible backend with Object Lock retention and residency pin.

    Write-once semantics without a filesystem: the PUT carries
    ``If-None-Match: *`` so a raced concurrent write fails server-side
    (the S3-native equivalent of O_EXCL) instead of depending on a
    head-then-put window. The object's ``sha256`` metadata is the
    idempotency key: same content → same key returns quietly.

    Object Lock (``ObjectLockMode=COMPLIANCE`` + retain-until) makes the
    bucket itself refuse overwrite/delete until the date passes — the
    production WORM story the design doc calls for. It requires the bucket
    to have lock enabled; retention_days=0 skips the params (startup logs a
    warning).

    Object versions: every write records the exact ``VersionId`` S3 returned
    in the reference it hands back (``s3v1:{VersionId}:{key}``), and every
    read of such a reference addresses that version explicitly. A key can
    later gain newer versions or a delete marker; the recorded reference
    keeps resolving to the bytes that were written, and if that version is
    gone the read fails instead of quietly returning the current object.
    Object Lock protects a *version*, not a key, which is why a key-only
    reference was never enough. Bucket versioning must be ``Enabled``
    (Object Lock itself requires it); ``verify_prerequisites`` checks that
    and the lock configuration up front so a bucket that cannot pin
    versions refuses to boot rather than failing on the first upload.
    """

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        region: str = "",
        residency_region: str = "",
        retention_days: int = 365,
        org: str = "local",
        client=None,
        require_object_versions: bool = True,
        verify_prerequisites: bool = True,
    ):
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._org = org
        self._retention_days = max(0, int(retention_days))
        self._require_versions = bool(require_object_versions)
        self._prerequisites: dict[str, str] | None = None
        if client is None:
            import boto3  # lazy: local deployments never install it

            client = boto3.client("s3", region_name=region or None)
        self._client = client
        self._residency_region = residency_region
        if residency_region:
            self._assert_residency()
        if verify_prerequisites:
            self.verify_prerequisites()

    def _key(self, logical: str) -> str:
        return f"{self._prefix}/{logical}" if self._prefix else logical

    def verify_prerequisites(self) -> dict[str, str]:
        """Check the bucket can honour pinned references before any write.

        Versioning must be ``Enabled``: ``Suspended`` hands out the
        overwritable ``null`` version and a never-versioned bucket hands out
        none, so neither can pin. With retention configured the bucket must
        also have Object Lock enabled, or every PUT carrying lock parameters
        is rejected. Each answer is recorded for ``describe``. Fails loudly
        on missing permissions: an unverifiable bucket is not a verified one.
        """
        status: dict[str, str] = {}
        try:
            versioning = self._client.get_bucket_versioning(Bucket=self._bucket)
        except Exception as e:
            code = _err_code(e)
            raise StorageError(
                f"cannot verify bucket versioning: {code or type(e).__name__} "
                "(s3:GetBucketVersioning is required)"
            ) from e
        vstate = (versioning or {}).get("Status") or "Disabled"
        status["versioning"] = vstate
        if self._require_versions and vstate != "Enabled":
            raise StorageError(
                f"bucket {self._bucket} versioning is {vstate!r}; version-pinned custody "
                "references require it to be Enabled"
            )
        if self._retention_days > 0:
            try:
                lock = self._client.get_object_lock_configuration(Bucket=self._bucket)
            except Exception as e:
                code = _err_code(e)
                if code == "ObjectLockConfigurationNotFoundError":
                    raise StorageError(
                        f"bucket {self._bucket} has no Object Lock configuration; "
                        "COUNSELCLEAR_RETENTION_DAYS>0 requires Object Lock to be enabled"
                    ) from e
                raise StorageError(
                    f"cannot verify Object Lock configuration: {code or type(e).__name__} "
                    "(s3:GetBucketObjectLockConfiguration is required)"
                ) from e
            enabled = ((lock or {}).get("ObjectLockConfiguration") or {}).get("ObjectLockEnabled")
            status["object_lock"] = enabled or "Disabled"
            if enabled != "Enabled":
                raise StorageError(
                    f"bucket {self._bucket} Object Lock is {enabled or 'disabled'!r}; "
                    "COUNSELCLEAR_RETENTION_DAYS>0 requires it to be Enabled"
                )
        self._prerequisites = status
        return dict(status)

    def _pinned_ref(self, object_key: str, version_id: object) -> str:
        """The reference to record for ``object_key`` given the version id S3
        reported. Refuses to record an unpinned reference unless the backend
        was explicitly constructed with ``require_object_versions=False``."""
        if is_durable_version_id(version_id):
            return make_versioned_ref(object_key, str(version_id))
        if self._require_versions:
            raise StorageError(
                "s3 did not return a durable object version id (bucket versioning disabled "
                "or suspended); the object may be stored but cannot be pinned, so no "
                "reference is recorded"
            )
        return object_key

    def _assert_residency(self) -> None:
        try:
            loc = self._client.get_bucket_location(Bucket=self._bucket)
        except Exception as e:
            code = _err_code(e)
            raise StorageError(
                f"cannot verify bucket region for residency pin: {code or type(e).__name__}"
            ) from e
        # AWS returns None for us-east-1 (the historical quirk).
        actual = loc.get("LocationConstraint") or "us-east-1"
        if actual != self._residency_region:
            raise StorageError(
                f"residency violation: bucket {self._bucket} is in {actual!r}, "
                f"COUNSELCLEAR_RESIDENCY_REGION pins {self._residency_region!r}"
            )

    def write_once(self, key: str, data: bytes) -> str:
        object_key = self._key(key)
        digest = custody_mod.sha256_bytes(data)
        try:
            head = self._client.head_object(Bucket=self._bucket, Key=object_key)
        except Exception as e:
            code = _err_code(e)
            if code in _NOT_FOUND_CODES:
                head = None
            elif code is None:
                raise
            else:
                raise StorageError(f"s3 head_object failed: {code}") from e
        if head is not None:
            if head.get("Metadata", {}).get("sha256") == digest:
                # Idempotent: the same content is already the current
                # version. Pin *that* version; a later write to the key
                # cannot make this reference resolve to something else.
                return self._pinned_ref(object_key, head.get("VersionId"))
            raise WriteOnceViolation(
                f"write-once violation: {object_key} exists with different content"
            )
        params = {
            "Bucket": self._bucket,
            "Key": object_key,
            "Body": data,
            "IfNoneMatch": "*",  # server-side O_EXCL: fail if key appeared
            "Metadata": {"sha256": digest},
        }
        if self._retention_days > 0:
            params["ObjectLockMode"] = "COMPLIANCE"
            params["ObjectLockRetainUntilDate"] = datetime.now(UTC) + timedelta(
                days=self._retention_days
            )
            # S3 requires a content checksum on any PUT that sets a retention
            # period (PutObject reference, Object Lock section). Ask for one
            # explicitly rather than relying on the SDK's default policy.
            params["ChecksumAlgorithm"] = "SHA256"
        try:
            response = self._client.put_object(**params)
        except Exception as e:
            code = _err_code(e)
            if code in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise WriteOnceViolation(
                    f"write-once violation: {object_key} exists with different content"
                ) from e
            raise StorageError(f"s3 put_object failed: {code or type(e).__name__}") from e
        version_id = response.get("VersionId") if isinstance(response, dict) else None
        return self._pinned_ref(object_key, version_id)

    def _version_params(self, ref: str) -> tuple[dict[str, str], str | None]:
        object_key, version_id = parse_s3_ref(ref)
        params = {"Bucket": self._bucket, "Key": object_key}
        if version_id is not None:
            params["VersionId"] = version_id
        return params, version_id

    def read(self, ref: str) -> bytes:
        params, version_id = self._version_params(ref)
        try:
            response = self._client.get_object(**params)
        except Exception as e:
            code = _err_code(e)
            if version_id is not None and code in _DELETE_MARKER_CODES:
                raise VersionUnavailable(
                    "recorded object version is a delete marker; the reference is corrupt "
                    "and the key's current version is not a substitute"
                ) from e
            if version_id is not None and code in _NO_SUCH_VERSION_CODES:
                raise VersionUnavailable(
                    "recorded object version no longer exists; refusing to read the key's "
                    "current version in its place"
                ) from e
            raise StorageError(f"s3 get_object failed: {code or type(e).__name__}") from e
        if version_id is not None:
            served = response.get("VersionId") if isinstance(response, dict) else None
            if served is not None and served != version_id:
                raise StorageError("s3 served a different object version than the one requested")
        elif isinstance(response, dict) and response.get("DeleteMarker"):
            raise StorageError("s3 current version is a delete marker")
        return response["Body"].read()

    def exists(self, ref: str) -> bool:
        params, version_id = self._version_params(ref)
        try:
            self._client.head_object(**params)
            return True
        except Exception as e:
            code = _err_code(e)
            if version_id is not None and code in _DELETE_MARKER_CODES:
                # Not "absent": the reference names a delete marker, which no
                # write of ours ever produced. Surface it as corruption.
                raise VersionUnavailable(
                    "recorded object version is a delete marker; the reference is corrupt"
                ) from e
            if code in _NO_SUCH_VERSION_CODES:
                return False
            # Anything else (access denied, throttled, ...) is not an
            # answer — refusing to guess beats silently reporting absent.
            raise StorageError(f"s3 head_object failed: {code or type(e).__name__}") from e

    def current_ref(self, key: str) -> str | None:
        object_key = self._key(key)
        try:
            head = self._client.head_object(Bucket=self._bucket, Key=object_key)
        except Exception as e:
            code = _err_code(e)
            if code in _NOT_FOUND_CODES:
                return None
            raise StorageError(f"s3 head_object failed: {code or type(e).__name__}") from e
        return self._pinned_ref(object_key, head.get("VersionId"))

    def pin_reference(self, ref: str, *, sha256: str, size: int) -> str:
        """Upgrade a legacy bare-key reference to a pinned one, for an
        explicit migration step driven by the caller that holds the custody
        row's digest and size. Nothing is rewritten here: the current version
        is read, checked byte-for-byte against the recorded digest and size,
        and only then named. A reference that is already pinned is verified
        the same way and returned unchanged. A mismatch means the key no
        longer holds the recorded original and the caller has a recovery
        problem, not a migration step."""
        object_key, version_id = parse_s3_ref(ref)
        if version_id is None:
            try:
                head = self._client.head_object(Bucket=self._bucket, Key=object_key)
            except Exception as e:
                code = _err_code(e)
                raise StorageError(
                    f"cannot pin reference: s3 head_object failed: {code or type(e).__name__}"
                ) from e
            current = head.get("VersionId")
            if not is_durable_version_id(current):
                raise StorageError(
                    "cannot pin reference: the current object has no durable version id"
                )
            pinned = make_versioned_ref(object_key, str(current))
        else:
            pinned = ref
        self.read_expected(pinned, sha256=sha256, size=size)
        return pinned

    def ref_for(self, key: str) -> str:
        """Version-less spelling of ``key``'s reference (the legacy form).
        Use ``current_ref`` to obtain a pinned reference for stored content."""
        return self._key(key)

    def key_from_ref(self, ref: str) -> str:
        object_key, _version_id = parse_s3_ref(ref)
        if self._prefix:
            marker = f"{self._prefix}/"
            if not object_key.startswith(marker):
                raise StorageError(f"reference outside storage prefix: {ref}")
            return object_key[len(marker) :]
        return object_key

    def describe(self) -> str:
        lock = (
            f"object-lock COMPLIANCE {self._retention_days}d"
            if self._retention_days
            else "object-lock OFF"
        )
        pin = f" residency={self._residency_region}" if self._residency_region else ""
        versions = "pinned" if self._require_versions else "unpinned-allowed"
        if self._prerequisites is None:
            checked = "unverified"
        else:
            checked = ",".join(f"{k}={v}" for k, v in sorted(self._prerequisites.items()))
        return (
            f"s3 bucket={self._bucket} prefix={self._prefix or '-'} {lock}{pin} "
            f"object-versions={versions} prerequisites={checked}"
        )


class Keyring:
    """Customer-managed-key envelope: a fresh per-object data key, wrapped by
    the customer key. ``new_data_key`` returns (plaintext DEK, wrapped DEK)."""

    key_id: str = ""

    def new_data_key(self) -> tuple[bytes, bytes]:  # pragma: no cover - protocol
        raise NotImplementedError

    def unwrap(self, wrapped: bytes) -> bytes:  # pragma: no cover - protocol
        raise NotImplementedError


class LocalKeyring(Keyring):
    """0600 volume key file — the local stand-in for a KMS CMK (design doc:
    "local uses OS keychain or a 0600 volume key"). The file is created with
    O_EXCL+0600 on first use; an existing file wins (rotation is a deliberate
    act of replacing it, and replacing it orphans every stored envelope)."""

    key_id = "local"

    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._kek = self._load_or_create()

    def _load_or_create(self) -> bytes:
        if self._path.exists():
            data = self._path.read_bytes()
            if len(data) != 32:
                raise StorageError(
                    f"volume key file {self._path} must contain 32 bytes, got {len(data)}"
                )
            return data
        key = secrets.token_bytes(32)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # Lost the race to a concurrent boot: the winner's key is
            # authoritative, ours must not replace it.
            return self._load_or_create()
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        except BaseException:
            self._path.unlink(missing_ok=True)
            raise
        return key

    def new_data_key(self) -> tuple[bytes, bytes]:
        dek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        # AESGCM.encrypt returns ciphertext+tag only — the nonce must be
        # prepended here or unwrap() slices garbage off the front.
        wrapped = nonce + AESGCM(self._kek).encrypt(nonce, dek, _WRAP_AAD)
        return dek, wrapped

    def unwrap(self, wrapped: bytes) -> bytes:
        try:
            return AESGCM(self._kek).decrypt(wrapped[:12], wrapped[12:], _WRAP_AAD)
        except InvalidTag:
            raise StorageError(
                "volume-key unwrap failed: the stored envelope does not match "
                "this key file (key rotated or object tampered)"
            ) from None


class KmsKeyring(Keyring):
    """AWS KMS CMK: each object's data key is generated by KMS and only its
    ciphertext ever touches the disk (generate_data_key / decrypt)."""

    def __init__(self, key_arn: str, client=None):
        self._key_arn = key_arn
        self.key_id = f"kms:{key_arn.rsplit('/', 1)[-1]}"
        if client is None:
            import boto3  # lazy: local deployments never install it

            client = boto3.client("kms")
        self._client = client

    def new_data_key(self) -> tuple[bytes, bytes]:
        resp = self._client.generate_data_key(KeyId=self._key_arn, KeySpec="AES_256")
        return resp["Plaintext"], resp["CiphertextBlob"]

    def unwrap(self, wrapped: bytes) -> bytes:
        resp = self._client.decrypt(CiphertextBlob=wrapped, KeyId=self._key_arn)
        return resp["Plaintext"]


def _seal(keyring: Keyring, data: bytes, aad: bytes) -> bytes:
    dek, wrapped = keyring.new_data_key()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(nonce, data, aad)
    kid = keyring.key_id.encode("utf-8")
    if len(kid) > 255:
        raise StorageError(f"key id too long for envelope: {keyring.key_id}")
    return (
        _ENV_MAGIC
        + bytes([_ENV_VERSION, len(kid)])
        + kid
        + nonce
        + struct.pack(">H", len(wrapped))
        + wrapped
        + ciphertext
    )


def _open(keyring: Keyring, blob: bytes, aad: bytes) -> bytes:
    if not blob.startswith(_ENV_MAGIC):
        raise StorageError("stored object is not a CCENC envelope")
    if len(blob) < len(_ENV_MAGIC) + 2 + 12 + 2:
        raise StorageError("stored envelope is truncated")
    version, kid_len = blob[5], blob[6]
    if version != _ENV_VERSION:
        raise StorageError(f"unsupported envelope version: {version}")
    off = len(_ENV_MAGIC) + 2
    kid = blob[off : off + kid_len]
    off += kid_len
    if kid != keyring.key_id.encode("utf-8"):
        raise StorageError(f"envelope key id {kid!r} does not match keyring {keyring.key_id!r}")
    nonce = blob[off : off + 12]
    off += 12
    (wrapped_len,) = struct.unpack(">H", blob[off : off + 2])
    off += 2
    wrapped = blob[off : off + wrapped_len]
    off += wrapped_len
    dek = keyring.unwrap(wrapped)
    try:
        return AESGCM(dek).decrypt(nonce, blob[off:], aad)
    except InvalidTag:
        raise StorageError(
            "integrity check failed: stored object is tampered or the key does not match"
        ) from None


class EncryptedStorage(Backend):
    """Composes a backend with a keyring: every object is envelope-encrypted
    at rest, transparently to callers. Idempotency is judged on the
    *plaintext* (two writes of the same original are one object), which the
    inner backend cannot see — a conflict therefore reads back and decrypts
    before deciding."""

    def __init__(self, inner: Backend, keyring: Keyring):
        self._inner = inner
        self._keyring = keyring

    def write_once(self, key: str, data: bytes) -> str:
        sealed = _seal(self._keyring, data, key.encode("utf-8"))
        try:
            return self._inner.write_once(key, sealed)
        except WriteOnceViolation:
            # Inner refused (existing content). Idempotent iff the stored
            # plaintext is byte-identical. ``current_ref`` (not ``ref_for``)
            # so a version-pinning backend hands back the pinned reference
            # of the object that was actually compared.
            ref = self._inner.current_ref(key)
            if ref is not None:
                stored = self.read(ref)
                if stored == data:
                    return ref
            raise WriteOnceViolation(
                f"write-once violation: {key} exists with different content"
            ) from None

    def read(self, ref: str) -> bytes:
        key = self._inner.key_from_ref(ref)
        blob = self._inner.read(ref)
        try:
            return _open(self._keyring, blob, key.encode("utf-8"))
        except StorageError:
            if isinstance(self._inner, LocalStorage):
                native_key = self._inner._native_key_from_ref(ref)
                if native_key != key:
                    # Windows historically authenticated its native relative
                    # path spelling. Preserve those immutable envelopes too.
                    # On POSIX the spellings are identical: a literal '\\'
                    # must never be treated as a different directory path.
                    return _open(self._keyring, blob, native_key.encode("utf-8"))
            raise

    def exists(self, ref: str) -> bool:
        return self._inner.exists(ref)

    def ref_for(self, key: str) -> str:
        return self._inner.ref_for(key)

    def current_ref(self, key: str) -> str | None:
        return self._inner.current_ref(key)

    def key_from_ref(self, ref: str) -> str:
        return self._inner.key_from_ref(ref)

    def pin_reference(self, ref: str, *, sha256: str, size: int) -> str:
        """Pin a legacy reference through the encryption layer: the digest
        and size describe the *plaintext* original, so the check decrypts
        the exact version before it is named."""
        inner_pin = getattr(self._inner, "pin_reference", None)
        if inner_pin is None:
            self.read_expected(ref, sha256=sha256, size=size)
            return ref
        object_key, version_id = parse_s3_ref(ref)
        if version_id is None:
            pinned = self._inner.current_ref(self._inner.key_from_ref(object_key))
            if pinned is None:
                raise StorageError("cannot pin reference: object is absent")
        else:
            pinned = ref
        self.read_expected(pinned, sha256=sha256, size=size)
        return pinned

    def describe(self) -> str:
        return f"{self._inner.describe()} + envelope-encrypted ({self._keyring.key_id})"


def keyring_from_config(cfg) -> Keyring | None:
    """CMK via KMS, else the 0600 volume-key file, else unencrypted. Setting
    both is refused — silently preferring one would mask a misconfiguration
    the operator must resolve (which key is the data wrapped with?)."""
    cmk = getattr(cfg, "cmk_arn", "")
    vol = getattr(cfg, "volume_key_file", "")
    if cmk and vol:
        raise StorageError(
            "set at most one of COUNSELCLEAR_CMK_ARN and COUNSELCLEAR_VOLUME_KEY_FILE"
        )
    if cmk:
        return KmsKeyring(cmk)
    if vol:
        return LocalKeyring(vol)
    return None


def storage_from_config(cfg) -> Backend:
    mode = getattr(cfg, "storage_mode", "local")
    if mode == "s3":
        if not getattr(cfg, "s3_bucket", ""):
            raise StorageError("COUNSELCLEAR_STORAGE=s3 requires COUNSELCLEAR_S3_BUCKET")
        backend: Backend = S3Storage(
            bucket=cfg.s3_bucket,
            prefix=cfg.s3_prefix,
            region=cfg.s3_region,
            residency_region=cfg.residency_region,
            retention_days=cfg.retention_days,
            org=cfg.org,
            # Pinning is the default; a config surface for opting out is the
            # config module's decision, so read it defensively if it exists.
            require_object_versions=bool(getattr(cfg, "s3_require_object_versions", True)),
        )
    elif mode in ("", "local"):
        backend = LocalStorage(cfg.data_root, org=cfg.org)
    else:
        raise ValueError(f"unsupported COUNSELCLEAR_STORAGE: {mode}")
    keyring = keyring_from_config(cfg)
    if keyring is not None:
        backend = EncryptedStorage(backend, keyring)
    return backend
