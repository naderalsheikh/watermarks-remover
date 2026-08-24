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
absolute filesystem path; S3 = the object key. Every read of an original
goes through the backend — never a bare ``Path``.

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


class StorageError(RuntimeError):
    """Refusal to read/write custody storage, or a storage misconfiguration."""


class WriteOnceViolation(StorageError):
    """The key already holds different content — the backend's O_EXCL
    equivalent fired. Distinguished from transport errors so callers
    (EncryptedStorage) can treat it as an idempotency question."""


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

    def key_from_ref(self, ref: str) -> str:
        p = Path(ref).absolute()
        try:
            return str(p.relative_to(self._root))
        except ValueError:
            raise StorageError(f"reference outside storage root: {ref}") from None

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
    ):
        import boto3  # lazy: local deployments never install it

        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._org = org
        self._retention_days = max(0, int(retention_days))
        if client is None:
            import boto3  # lazy: local deployments never install it

            client = boto3.client("s3", region_name=region or None)
        self._client = client
        self._residency_region = residency_region
        if residency_region:
            self._assert_residency()

    def _key(self, logical: str) -> str:
        return f"{self._prefix}/{logical}" if self._prefix else logical

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
                return object_key  # idempotent: same content already stored
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
        try:
            self._client.put_object(**params)
        except Exception as e:
            code = _err_code(e)
            if code in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise WriteOnceViolation(
                    f"write-once violation: {object_key} exists with different content"
                ) from e
            raise StorageError(f"s3 put_object failed: {code or type(e).__name__}") from e
        return object_key

    def read(self, ref: str) -> bytes:
        try:
            body = self._client.get_object(Bucket=self._bucket, Key=ref)["Body"]
        except Exception as e:
            code = _err_code(e)
            raise StorageError(f"s3 get_object failed: {code or type(e).__name__}") from e
        return body.read()

    def exists(self, ref: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=ref)
            return True
        except Exception as e:
            code = _err_code(e)
            if code in _NOT_FOUND_CODES:
                return False
            # Anything else (access denied, throttled, ...) is not an
            # answer — refusing to guess beats silently reporting absent.
            raise StorageError(f"s3 head_object failed: {code or type(e).__name__}") from e

    def ref_for(self, key: str) -> str:
        return self._key(key)

    def key_from_ref(self, ref: str) -> str:
        if self._prefix:
            marker = f"{self._prefix}/"
            if not ref.startswith(marker):
                raise StorageError(f"reference outside storage prefix: {ref}")
            return ref[len(marker) :]
        return ref

    def describe(self) -> str:
        lock = (
            f"object-lock COMPLIANCE {self._retention_days}d"
            if self._retention_days
            else "object-lock OFF"
        )
        pin = f" residency={self._residency_region}" if self._residency_region else ""
        return f"s3 bucket={self._bucket} prefix={self._prefix or '-'} {lock}{pin}"


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
            # plaintext is byte-identical.
            ref = self._inner.ref_for(key)
            if self._inner.exists(ref):
                try:
                    stored = _open(self._keyring, self._inner.read(ref), key.encode("utf-8"))
                except StorageError:
                    raise
                if stored == data:
                    return ref
            raise WriteOnceViolation(
                f"write-once violation: {key} exists with different content"
            ) from None

    def read(self, ref: str) -> bytes:
        aad = self._inner.key_from_ref(ref).encode("utf-8")
        return _open(self._keyring, self._inner.read(ref), aad)

    def exists(self, ref: str) -> bool:
        return self._inner.exists(ref)

    def ref_for(self, key: str) -> str:
        return self._inner.ref_for(key)

    def key_from_ref(self, ref: str) -> str:
        return self._inner.key_from_ref(ref)

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
        )
    elif mode in ("", "local"):
        backend = LocalStorage(cfg.data_root, org=cfg.org)
    else:
        raise ValueError(f"unsupported COUNSELCLEAR_STORAGE: {mode}")
    keyring = keyring_from_config(cfg)
    if keyring is not None:
        backend = EncryptedStorage(backend, keyring)
    return backend
