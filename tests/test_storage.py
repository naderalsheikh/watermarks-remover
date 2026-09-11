"""PR 21 — custody storage backends: local write-once, S3 Object Lock,
CMK envelope encryption, residency pin."""

from __future__ import annotations

import io
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.config import Config
from app.storage import (
    EncryptedStorage,
    KmsKeyring,
    LocalKeyring,
    LocalStorage,
    S3Storage,
    StorageError,
    VersionUnavailable,
    WriteOnceViolation,
    describe_reference,
    is_durable_version_id,
    make_versioned_ref,
    original_key,
    parse_s3_ref,
    storage_from_config,
)


class _S3Error(Exception):
    """Botocore-ClientError-shaped test double (production code reads
    ``exc.response["Error"]["Code"]`` via app.storage._err_code)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Versioning-aware S3 double, modelled on the S3 API reference:

    - versioning ``"Enabled"``: every PUT creates a new version with a fresh
      ``VersionId``; ``"Suspended"``: the ``null`` version is (over)written;
      ``None``: versioning never enabled, no ``VersionId`` in responses.
    - GET/HEAD without ``VersionId`` serve the current version; a current
      delete marker answers 404 with ``DeleteMarker``.
    - GET/HEAD with a ``VersionId`` that does not exist answer
      ``NoSuchVersion``; one that names a delete marker answers
      ``MethodNotAllowed`` (405).
    - ``If-None-Match: *`` fails with ``PreconditionFailed`` when a current
      object exists; a current delete marker counts as absent.
    ``overwrite`` and ``delete_object`` simulate out-of-band changes to a
    key after the custody write; ``calls`` records every request.
    """

    def __init__(
        self,
        location: str | None = None,
        *,
        versioning: str | None = "Enabled",
        object_lock: bool = True,
    ):
        self.versions: dict[str, list[dict]] = {}
        self.puts: list[dict] = []
        self.calls: list[tuple[str, dict]] = []
        self.location = location
        self.versioning = versioning
        self.object_lock = object_lock
        self._counter = 0

    # -- simulation helpers ----------------------------------------------------

    def _new_version_id(self) -> str:
        self._counter += 1
        # Real ids carry '/', '+' and '.'; keep those in the double so the
        # reference format is exercised against them.
        return f"v{self._counter}/Ab+cd.{self._counter:03d}=="

    def _store(self, key: str, body: bytes, meta: dict) -> dict:
        entry = {"body": body, "meta": meta, "delete_marker": False}
        if self.versioning == "Enabled":
            entry["vid"] = self._new_version_id()
            self.versions.setdefault(key, []).append(entry)
        elif self.versioning == "Suspended":
            entry["vid"] = "null"
            chain = [v for v in self.versions.get(key, []) if v.get("vid") != "null"]
            self.versions[key] = [*chain, entry]
        else:
            entry["vid"] = None
            self.versions[key] = [entry]
        return entry

    def overwrite(self, key: str, body: bytes, meta: dict | None = None) -> str | None:
        """Out-of-band write that bypasses the conditional PUT."""
        return self._store(key, body, meta or {}).get("vid")

    def _current(self, key: str) -> dict | None:
        chain = self.versions.get(key)
        return chain[-1] if chain else None

    def _find(self, key: str, vid: str) -> dict | None:
        for entry in self.versions.get(key, []):
            if entry.get("vid") == vid:
                return entry
        return None

    def _lookup(self, kw: dict) -> dict:
        key = kw["Key"]
        vid = kw.get("VersionId")
        if vid is None:
            current = self._current(key)
            if current is None or current["delete_marker"]:
                raise _S3Error("404")
            return current
        entry = self._find(key, vid)
        if entry is None:
            raise _S3Error("NoSuchVersion")
        if entry["delete_marker"]:
            raise _S3Error("MethodNotAllowed")
        return entry

    # -- client surface ----------------------------------------------------------

    def get_bucket_location(self, **kw):
        self.calls.append(("get_bucket_location", kw))
        return {"LocationConstraint": self.location}

    def get_bucket_versioning(self, **kw):
        self.calls.append(("get_bucket_versioning", kw))
        return {"Status": self.versioning} if self.versioning else {}

    def get_object_lock_configuration(self, **kw):
        self.calls.append(("get_object_lock_configuration", kw))
        if not self.object_lock:
            raise _S3Error("ObjectLockConfigurationNotFoundError")
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def head_object(self, **kw):
        self.calls.append(("head_object", kw))
        entry = self._lookup(kw)
        response = {"Metadata": entry["meta"]}
        if entry.get("vid") is not None:
            response["VersionId"] = entry["vid"]
        return response

    def put_object(self, **kw):
        self.calls.append(("put_object", kw))
        self.puts.append(kw)
        key = kw["Key"]
        current = self._current(key)
        if kw.get("IfNoneMatch") == "*" and current is not None and not current["delete_marker"]:
            raise _S3Error("PreconditionFailed")
        if "ObjectLockMode" in kw and not self.object_lock:
            raise _S3Error("InvalidRequest")
        entry = self._store(key, kw["Body"], kw.get("Metadata", {}))
        return {"VersionId": entry["vid"]} if entry.get("vid") is not None else {}

    def get_object(self, **kw):
        self.calls.append(("get_object", kw))
        entry = self._lookup(kw)
        response = {"Body": io.BytesIO(entry["body"])}
        if entry.get("vid") is not None:
            response["VersionId"] = entry["vid"]
        return response

    def delete_object(self, **kw):
        """No VersionId: add a delete marker (versioned) or remove the object.
        With VersionId: permanently remove that version."""
        self.calls.append(("delete_object", kw))
        key = kw["Key"]
        vid = kw.get("VersionId")
        if vid is not None:
            self.versions[key] = [v for v in self.versions.get(key, []) if v.get("vid") != vid]
            return {}
        if self.versioning == "Enabled":
            marker = {"body": b"", "meta": {}, "delete_marker": True, "vid": self._new_version_id()}
            self.versions.setdefault(key, []).append(marker)
            return {"DeleteMarker": True, "VersionId": marker["vid"]}
        self.versions.pop(key, None)
        return {}


class FakeKMS:
    def __init__(self):
        self._wrapped: dict[bytes, bytes] = {}

    def generate_data_key(self, **kw):
        assert kw["KeySpec"] == "AES_256"
        dek = os.urandom(32)
        wrapped = b"w:" + dek
        self._wrapped[wrapped] = dek
        return {"Plaintext": dek, "CiphertextBlob": wrapped}

    def decrypt(self, **kw):
        return {"Plaintext": self._wrapped[kw["CiphertextBlob"]]}


def make_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **env) -> Config:
    for name in (
        "COUNSELCLEAR_STORAGE",
        "COUNSELCLEAR_S3_BUCKET",
        "COUNSELCLEAR_S3_PREFIX",
        "COUNSELCLEAR_S3_REGION",
        "COUNSELCLEAR_RESIDENCY_REGION",
        "COUNSELCLEAR_RETENTION_DAYS",
        "COUNSELCLEAR_ORG",
        "COUNSELCLEAR_CMK_ARN",
        "COUNSELCLEAR_VOLUME_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, str(value))
    return Config(tmp_path / "data")


# --- key layout ---------------------------------------------------------------


def test_original_key_layout():
    key = original_key("firm", "m1", "d1", "SPA_v3.docx")
    assert key == "firm/matters/m1/docs/d1/original/SPA_v3.docx"


def test_original_key_sanitizes_basename():
    assert original_key("firm", "m1", "d1", "../../evil.docx") == (
        "firm/matters/m1/docs/d1/original/evil.docx"
    )


# --- local backend ------------------------------------------------------------


def test_local_write_once_conflict_and_idempotent(tmp_path):
    s = LocalStorage(tmp_path / "root")
    ref = s.write_once("matters/m1/docs/d1/original/a.docx", b"content")
    assert Path(ref).is_absolute() and Path(ref).exists()

    # identical content -> same ref, no error
    assert s.write_once("matters/m1/docs/d1/original/a.docx", b"content") == ref
    # different content -> refusal
    with pytest.raises(StorageError):
        s.write_once("matters/m1/docs/d1/original/a.docx", b"other")
    # stored bytes untouched by the refused write
    assert Path(ref).read_bytes() == b"content"


def test_local_key_from_ref_roundtrip(tmp_path):
    s = LocalStorage(tmp_path / "root")
    ref = s.write_once("local/matters/m1/docs/d1/original/a.docx", b"x")
    assert s.key_from_ref(ref) == "local/matters/m1/docs/d1/original/a.docx"


def test_local_windows_reference_renders_a_portable_logical_key(tmp_path, monkeypatch):
    storage = LocalStorage(tmp_path / "root")
    relative = PureWindowsPath(r"local\matters\m1\docs\d1\original\a.docx")
    monkeypatch.setattr(storage, "_relative_path_from_ref", lambda ref: relative)
    ref = str(PureWindowsPath(r"D:\custody") / relative)
    assert storage.key_from_ref(ref) == relative.as_posix()


def test_local_key_from_ref_rejects_outside_path(tmp_path):
    s = LocalStorage(tmp_path / "root")
    with pytest.raises(StorageError):
        s.key_from_ref(str(tmp_path / "elsewhere" / "x"))


# --- factory / config ---------------------------------------------------------


def test_storage_from_config_defaults_to_local(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path, monkeypatch)
    assert isinstance(storage_from_config(cfg), LocalStorage)


def test_storage_from_config_s3_requires_bucket(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path, monkeypatch, COUNSELCLEAR_STORAGE="s3")
    with pytest.raises(StorageError):
        storage_from_config(cfg)


def test_storage_from_config_refuses_two_key_sources(tmp_path, monkeypatch):
    cfg = make_cfg(
        tmp_path,
        monkeypatch,
        COUNSELCLEAR_CMK_ARN="arn:aws:kms:us-east-1:1:key/abc",
        COUNSELCLEAR_VOLUME_KEY_FILE=str(tmp_path / "volume.key"),
    )
    with pytest.raises(StorageError):
        storage_from_config(cfg)


# --- CMK envelope encryption --------------------------------------------------


def test_encrypted_local_roundtrip_and_idempotent(tmp_path):
    keyfile = tmp_path / "volume.key"
    inner = LocalStorage(tmp_path / "root")
    s = EncryptedStorage(inner, LocalKeyring(keyfile))

    key = "local/matters/m1/docs/d1/original/a.docx"
    ref = s.write_once(key, b"secret bytes")
    assert s.read(ref) == b"secret bytes"
    # same plaintext again -> idempotent, same ref
    assert s.write_once(key, b"secret bytes") == ref
    # different plaintext -> refusal
    with pytest.raises(StorageError):
        s.write_once(key, b"different")


@pytest.mark.parametrize("legacy_spelling", ["portable", "windows_native"])
def test_existing_windows_envelope_keeps_reference_and_ciphertext(
    tmp_path, monkeypatch, legacy_spelling
):
    from app.storage import _seal

    key = "local/matters/m1/docs/d1/original/a.docx"
    inner = LocalStorage(tmp_path / "root")
    keyring = LocalKeyring(tmp_path / "volume.key")
    aad = key if legacy_spelling == "portable" else str(PureWindowsPath(key))
    # Construct the historical envelope directly, independent of current
    # EncryptedStorage.write_once, then exercise the real persistent store.
    sealed = _seal(keyring, b"historical original", aad.encode("utf-8"))
    ref = inner.write_once(key, sealed)
    monkeypatch.setattr(inner, "_relative_path_from_ref", lambda ref: PureWindowsPath(key))
    storage = EncryptedStorage(inner, keyring)
    assert storage.read(ref) == b"historical original"
    assert storage.write_once(key, b"historical original") == ref
    with pytest.raises(StorageError):
        storage.write_once(key, b"a different original")
    assert Path(ref).read_bytes() == sealed
    assert storage.key_from_ref(ref) == key


@pytest.mark.skipif(os.name == "nt", reason="literal backslashes distinguish POSIX filenames")
def test_envelope_cannot_move_between_literal_backslash_and_directory_key(tmp_path):
    inner = LocalStorage(tmp_path / "root")
    storage = EncryptedStorage(inner, LocalKeyring(tmp_path / "volume.key"))
    ref = storage.write_once(r"local\other.txt", b"bound to its exact key")
    assert storage.read(ref) == b"bound to its exact key"
    moved = inner.write_once("local/other.txt", Path(ref).read_bytes())
    with pytest.raises(StorageError, match="integrity check failed"):
        storage.read(moved)


def test_encrypted_local_tamper_detected(tmp_path):
    inner = LocalStorage(tmp_path / "root")
    keyring = LocalKeyring(tmp_path / "volume.key")
    s = EncryptedStorage(inner, keyring)
    ref = s.write_once("k/m1/d1/original/a.docx", b"content")
    path = Path(ref)
    path.chmod(0o600)  # custody files are 0444 write-once; this is the tamper sim
    path.write_bytes(path.read_bytes()[:-1] + bytes([path.read_bytes()[-1] ^ 0xFF]))
    with pytest.raises(StorageError):
        s.read(ref)


def test_encrypted_at_rest_is_not_plaintext(tmp_path):
    inner = LocalStorage(tmp_path / "root")
    s = EncryptedStorage(inner, LocalKeyring(tmp_path / "volume.key"))
    ref = s.write_once("k/m1/d1/original/a.docx", b"top secret")
    assert b"top secret" not in Path(ref).read_bytes()


def test_s3_client_injection_needs_no_boto3(tmp_path, monkeypatch):
    """boto3 is a lazy, optional dependency: constructing a backend with an
    injected client must not import it, so test doubles work on hosts that
    never install boto3. (Regression: the constructor used to import boto3
    unconditionally, shadowed by the real lazy import three lines later.)"""
    monkeypatch.setitem(sys.modules, "boto3", None)  # `import boto3` -> ImportError
    s3 = S3Storage(bucket="cc", client=FakeS3())
    ref = s3.write_once("k", b"x")
    assert parse_s3_ref(ref) == ("k", "v1/Ab+cd.001==")
    kms = KmsKeyring("arn:aws:kms:x:1:key/abc", client=FakeKMS())
    _dek, wrapped = kms.new_data_key()
    assert kms.unwrap(wrapped) is not None


def test_volume_key_file_created_0600_and_reused(tmp_path):
    keyfile = tmp_path / "volume.key"
    LocalKeyring(keyfile)
    assert keyfile.exists()
    if os.name != "nt":
        # Windows chmod bits do not express ACL privacy; the persistence
        # and encryption checks still run there, but this is a POSIX check.
        assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
    assert len(keyfile.read_bytes()) == 32
    # second instance reuses the same key (rotation orphans envelopes)
    assert LocalKeyring(keyfile).unwrap(LocalKeyring(keyfile).new_data_key()[1])


def test_kms_keyring_envelope_roundtrip(tmp_path):
    inner = LocalStorage(tmp_path / "root")
    s = EncryptedStorage(inner, KmsKeyring("arn:aws:kms:x:1:key/abc", client=FakeKMS()))
    ref = s.write_once("k/m1/d1/original/a.docx", b"kms sealed")
    assert s.read(ref) == b"kms sealed"


def test_volume_key_wrong_file_fails_unwrap(tmp_path):
    keyring = LocalKeyring(tmp_path / "volume.key")
    _dek, wrapped = keyring.new_data_key()
    other = LocalKeyring(tmp_path / "other.key")
    with pytest.raises(StorageError):
        other.unwrap(wrapped)


# --- S3 backend ---------------------------------------------------------------

KEY = "firm/matters/m1/docs/d1/original/a.docx"


def test_s3_write_once_sets_object_lock_and_conditional(tmp_path):
    fake = FakeS3()
    s = S3Storage(bucket="cc", retention_days=365, org="firm", client=fake)
    ref = s.write_once(KEY, b"content")
    assert ref == make_versioned_ref(KEY, "v1/Ab+cd.001==")
    assert s.key_from_ref(ref) == KEY

    put = fake.puts[0]
    assert put["IfNoneMatch"] == "*"
    assert put["ObjectLockMode"] == "COMPLIANCE"
    assert put["ChecksumAlgorithm"] == "SHA256"
    until = put["ObjectLockRetainUntilDate"]
    assert isinstance(until, datetime)
    assert until > datetime.now(UTC)
    assert (
        put["Metadata"]["sha256"]
        == "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73"
    )
    assert fake.versions[KEY][0]["body"] == b"content"


def test_s3_no_lock_when_retention_zero(tmp_path):
    s = S3Storage(bucket="cc", retention_days=0, client=FakeS3(object_lock=False))
    s.write_once("k", b"x")
    assert "ObjectLockMode" not in s._client.puts[0]
    assert "ChecksumAlgorithm" not in s._client.puts[0]


def test_s3_idempotent_and_conflict(tmp_path):
    fake = FakeS3()
    s = S3Storage(bucket="cc", client=fake)
    ref = s.write_once("k", b"content")
    # Same content again: the existing version is pinned, no second PUT.
    assert s.write_once("k", b"content") == ref
    assert len(fake.puts) == 1
    with pytest.raises(WriteOnceViolation):
        s.write_once("k", b"other")
    assert s.read(ref) == b"content"


def test_s3_read_exists(tmp_path):
    fake = FakeS3()
    s = S3Storage(bucket="cc", client=fake)
    ref = s.write_once("k", b"data")
    assert s.exists(ref)
    assert not s.exists("missing")
    assert s.read(ref) == b"data"
    with pytest.raises(StorageError):
        s.read("missing")


def test_s3_residency_pin(tmp_path):
    # mismatch -> refuse at construction (fails loudly, not on first upload)
    with pytest.raises(StorageError, match="residency"):
        S3Storage(bucket="cc", residency_region="eu-central-1", client=FakeS3(location="us-west-2"))
    # us-east-1 is AWS's None quirk
    s = S3Storage(bucket="cc", residency_region="us-east-1", client=FakeS3(location=None))
    assert parse_s3_ref(s.write_once("k", b"x"))[0] == "k"
    assert S3Storage(
        bucket="cc", residency_region="eu-central-1", client=FakeS3(location="eu-central-1")
    )


def test_s3_prefix_key_roundtrip(tmp_path):
    s = S3Storage(bucket="cc", prefix="prod", client=FakeS3())
    ref = s.write_once("firm/m1/d1/original/a.docx", b"x")
    object_key, version_id = parse_s3_ref(ref)
    assert object_key == "prod/firm/m1/d1/original/a.docx"
    assert is_durable_version_id(version_id)
    assert s.key_from_ref(ref) == "firm/m1/d1/original/a.docx"
    # Legacy bare-key references keep resolving to the same logical key.
    assert s.key_from_ref("prod/firm/m1/d1/original/a.docx") == "firm/m1/d1/original/a.docx"
    with pytest.raises(StorageError, match="outside storage prefix"):
        s.key_from_ref(make_versioned_ref("elsewhere/a.docx", "v9"))


def test_encrypted_s3_roundtrip(tmp_path):
    fake = FakeS3()
    inner = S3Storage(bucket="cc", client=fake)
    s = EncryptedStorage(inner, LocalKeyring(tmp_path / "volume.key"))
    ref = s.write_once("firm/m1/d1/original/a.docx", b"sealed in s3")
    assert describe_reference(ref)["version_pinned"] is True
    assert s.read(ref) == b"sealed in s3"
    assert b"sealed in s3" not in fake.versions["firm/m1/d1/original/a.docx"][0]["body"]
    # idempotent through the encrypted wrapper, still pinned
    assert s.write_once("firm/m1/d1/original/a.docx", b"sealed in s3") == ref


# --- S3 object versions -------------------------------------------------------


def _s3(**kw) -> tuple[S3Storage, FakeS3]:
    fake = FakeS3(**{k: v for k, v in kw.items() if k in ("versioning", "object_lock", "location")})
    store = S3Storage(
        bucket="cc",
        client=fake,
        **{k: v for k, v in kw.items() if k not in ("versioning", "object_lock", "location")},
    )
    return store, fake


def test_reference_format_roundtrip_and_validation():
    ref = make_versioned_ref("prod/a:b/c.docx", "3/L4kqtJlcpXroDTDmJ+rmSpXd3QBpUMLUo")
    assert ref == "s3v1:3/L4kqtJlcpXroDTDmJ+rmSpXd3QBpUMLUo:prod/a:b/c.docx"
    assert parse_s3_ref(ref) == ("prod/a:b/c.docx", "3/L4kqtJlcpXroDTDmJ+rmSpXd3QBpUMLUo")
    assert parse_s3_ref("prod/plain/key.docx") == ("prod/plain/key.docx", None)
    assert describe_reference("prod/plain/key.docx") == {"scheme": "plain", "version_pinned": False}
    assert describe_reference(ref)["version_id"] == "3/L4kqtJlcpXroDTDmJ+rmSpXd3QBpUMLUo"
    for bad in ("s3v1:", "s3v1:v1", "s3v1:v1:", "s3v1::key", "s3v1:null:key", "s3v1:v 1:key"):
        with pytest.raises(StorageError, match=r"malformed|empty"):
            parse_s3_ref(bad)
    with pytest.raises(StorageError):
        parse_s3_ref("")
    assert not is_durable_version_id(None)
    assert not is_durable_version_id("null")
    assert not is_durable_version_id("")
    assert not is_durable_version_id("x" * 1025)
    assert is_durable_version_id("v1")
    with pytest.raises(StorageError, match="non-durable"):
        make_versioned_ref("k", "null")


def test_overwritten_key_still_reads_the_recorded_version():
    s, fake = _s3()
    ref = s.write_once(KEY, b"original bytes")
    newer = fake.overwrite(KEY, b"replaced out of band")
    assert newer != parse_s3_ref(ref)[1]
    assert s.read(ref) == b"original bytes"
    assert s.exists(ref)
    reads = [kw for name, kw in fake.calls if name == "get_object"]
    assert all(kw.get("VersionId") == parse_s3_ref(ref)[1] for kw in reads)
    # The legacy (bare key) spelling names whatever the key holds now: that
    # is the documented limitation, and read_expected is the caller's guard.
    assert s.read(KEY) == b"replaced out of band"
    with pytest.raises(StorageError, match="differs from its recorded hash"):
        s.read_expected(KEY, sha256=_sha(b"original bytes"), size=len(b"original bytes"))
    assert s.read_expected(ref, sha256=_sha(b"original bytes"), size=14) == b"original bytes"


def test_delete_marker_after_write_does_not_hide_the_recorded_version():
    s, fake = _s3()
    ref = s.write_once(KEY, b"kept")
    fake.delete_object(Bucket="cc", Key=KEY)  # newest version is now a delete marker
    assert s.read(ref) == b"kept"
    assert s.exists(ref)
    # The legacy spelling sees a deleted key and says so; it never resurrects
    # an older version on its own.
    with pytest.raises(StorageError):
        s.read(KEY)
    assert not s.exists(KEY)
    # A later same-content write is a new version and a new pinned reference.
    again = s.write_once(KEY, b"kept")
    assert again != ref
    assert s.read(again) == b"kept"


def test_missing_recorded_version_fails_without_fallback():
    s, fake = _s3()
    ref = s.write_once(KEY, b"first")
    fake.overwrite(KEY, b"second")
    fake.delete_object(Bucket="cc", Key=KEY, VersionId=parse_s3_ref(ref)[1])  # permanently gone
    fake.calls.clear()
    with pytest.raises(VersionUnavailable, match="no longer exists"):
        s.read(ref)
    assert not s.exists(ref)
    # No request ever dropped the VersionId to try the current object.
    for name, kw in fake.calls:
        if name in ("get_object", "head_object"):
            assert kw.get("VersionId") == parse_s3_ref(ref)[1]


def test_reference_naming_a_delete_marker_is_corrupt_not_absent():
    s, fake = _s3()
    s.write_once(KEY, b"x")
    marker_vid = fake.delete_object(Bucket="cc", Key=KEY)["VersionId"]
    bogus = make_versioned_ref(KEY, marker_vid)
    with pytest.raises(VersionUnavailable, match="delete marker"):
        s.read(bogus)
    with pytest.raises(VersionUnavailable, match="delete marker"):
        s.exists(bogus)


def test_served_version_mismatch_is_refused():
    s, fake = _s3()
    ref = s.write_once(KEY, b"x")

    real_get = fake.get_object

    def lying_get(**kw):
        response = real_get(**kw)
        response["VersionId"] = "someone-else"
        return response

    fake.get_object = lying_get
    with pytest.raises(StorageError, match="different object version"):
        s.read(ref)


@pytest.mark.parametrize("versioning", [None, "Suspended"])
def test_write_without_durable_version_id_is_refused(versioning):
    fake = FakeS3(versioning=versioning, object_lock=False)
    # Construction with prerequisites verified refuses the bucket outright.
    with pytest.raises(StorageError, match="versioning"):
        S3Storage(bucket="cc", retention_days=0, client=fake)
    # Even with prerequisite verification skipped (a bucket whose state
    # changed after startup), the write itself refuses to record a reference.
    s = S3Storage(bucket="cc", retention_days=0, client=fake, verify_prerequisites=False)
    with pytest.raises(StorageError, match="durable object version id"):
        s.write_once(KEY, b"x")
    # And the idempotent branch refuses the same way for an existing object.
    with pytest.raises(StorageError, match="durable object version id"):
        s.write_once(KEY, b"x")


def test_unpinned_references_only_by_explicit_opt_out():
    fake = FakeS3(versioning=None, object_lock=False)
    s = S3Storage(
        bucket="cc",
        retention_days=0,
        client=fake,
        require_object_versions=False,
        verify_prerequisites=False,
    )
    ref = s.write_once(KEY, b"x")
    assert ref == KEY
    assert describe_reference(ref)["version_pinned"] is False
    assert s.read(ref) == b"x"
    assert "object-versions=unpinned-allowed" in s.describe()


def test_put_response_without_version_id_on_a_versioned_bucket_is_refused():
    """The bucket said Enabled at startup but a PUT came back without a
    version id (backend regression, mid-flight suspension): still no
    unpinned reference."""
    s, fake = _s3()
    real_put = fake.put_object
    fake.put_object = lambda **kw: {k: v for k, v in real_put(**kw).items() if k != "VersionId"}
    with pytest.raises(StorageError, match="durable object version id"):
        s.write_once(KEY, b"x")


def test_prerequisites_are_checked_before_any_write():
    with pytest.raises(StorageError, match="versioning is 'Suspended'"):
        S3Storage(bucket="cc", client=FakeS3(versioning="Suspended"))
    with pytest.raises(StorageError, match="versioning is 'Disabled'"):
        S3Storage(bucket="cc", client=FakeS3(versioning=None))
    with pytest.raises(StorageError, match="Object Lock"):
        S3Storage(bucket="cc", retention_days=365, client=FakeS3(object_lock=False))
    # Lock not required when retention is 0.
    s = S3Storage(bucket="cc", retention_days=0, client=FakeS3(object_lock=False))
    assert "prerequisites=versioning=Enabled" in s.describe()
    s = S3Storage(bucket="cc", retention_days=30, client=FakeS3())
    assert "object_lock=Enabled" in s.describe() and "versioning=Enabled" in s.describe()
    assert "object-versions=pinned" in s.describe()

    class NoPermission(FakeS3):
        def get_bucket_versioning(self, **kw):
            raise _S3Error("AccessDenied")

    with pytest.raises(StorageError, match="cannot verify bucket versioning"):
        S3Storage(bucket="cc", client=NoPermission())
    unverified = S3Storage(bucket="cc", client=NoPermission(), verify_prerequisites=False)
    assert "prerequisites=unverified" in unverified.describe()


def test_encrypted_read_uses_the_exact_recorded_version(tmp_path):
    inner, fake = _s3()
    s = EncryptedStorage(inner, LocalKeyring(tmp_path / "volume.key"))
    ref = s.write_once(KEY, b"plaintext original")
    # Out-of-band replacement with garbage and with a different envelope.
    fake.overwrite(KEY, b"not an envelope")
    assert s.read(ref) == b"plaintext original"
    other = EncryptedStorage(
        S3Storage(bucket="cc", client=fake), LocalKeyring(tmp_path / "other.key")
    )
    fake.overwrite(KEY, fake.versions[KEY][0]["body"][::-1])
    assert s.read(ref) == b"plaintext original"
    with pytest.raises(StorageError):
        other.read(ref)
    # The legacy spelling now decrypts the current (foreign) version or fails;
    # either way it is not the original, and read_expected says so.
    with pytest.raises(StorageError):
        s.read_expected(KEY, sha256=_sha(b"plaintext original"), size=18)


def test_legacy_envelope_is_readable_through_a_pinned_reference(tmp_path):
    """An envelope sealed under the logical-key AAD before pinning existed
    must open through the pinned spelling: the AAD is the logical key, and
    the version id is not part of it."""
    fake = FakeS3()
    keyring = LocalKeyring(tmp_path / "volume.key")
    pinned_store = EncryptedStorage(S3Storage(bucket="cc", prefix="prod", client=fake), keyring)
    written = pinned_store.write_once("firm/m1/d1/original/a.docx", b"sealed before pinning")
    # A pre-pinning row stored the bare object key for this same envelope.
    legacy_ref = pinned_store.ref_for("firm/m1/d1/original/a.docx")
    assert legacy_ref == "prod/firm/m1/d1/original/a.docx"
    assert not describe_reference(legacy_ref)["version_pinned"]

    assert pinned_store.read(legacy_ref) == b"sealed before pinning"
    pinned = pinned_store.pin_reference(
        legacy_ref, sha256=_sha(b"sealed before pinning"), size=len(b"sealed before pinning")
    )
    assert pinned == written
    assert describe_reference(pinned)["version_pinned"] is True
    assert pinned_store.key_from_ref(pinned) == pinned_store.key_from_ref(legacy_ref)
    assert pinned_store.read(pinned) == b"sealed before pinning"
    # Pinning is idempotent and a pinned reference verifies in place.
    assert (
        pinned_store.pin_reference(pinned, sha256=_sha(b"sealed before pinning"), size=21) == pinned
    )
    # After an out-of-band replacement the pinned spelling still opens; the
    # legacy one can no longer be pinned because the digest no longer matches.
    fake.overwrite("prod/firm/m1/d1/original/a.docx", b"garbage")
    assert pinned_store.read(pinned) == b"sealed before pinning"
    with pytest.raises(StorageError):
        pinned_store.pin_reference(legacy_ref, sha256=_sha(b"sealed before pinning"), size=21)


def test_pin_reference_refuses_mismatched_or_missing_objects():
    s, fake = _s3()
    fake.overwrite(KEY, b"whatever is there now")
    with pytest.raises(StorageError, match="differs from its recorded hash"):
        s.pin_reference(KEY, sha256=_sha(b"recorded original"), size=17)
    pinned = s.pin_reference(KEY, sha256=_sha(b"whatever is there now"), size=21)
    assert parse_s3_ref(pinned)[1] == fake.versions[KEY][-1]["vid"]
    with pytest.raises(StorageError, match="head_object failed"):
        s.pin_reference("absent/key", sha256=_sha(b""), size=0)


def test_encrypted_conflict_path_returns_a_pinned_reference(tmp_path):
    """A raced write that loses the conditional PUT compares plaintext and,
    when identical, returns the reference of the version it compared."""
    inner, fake = _s3()
    s = EncryptedStorage(inner, LocalKeyring(tmp_path / "volume.key"))
    first = s.write_once(KEY, b"same original")

    real_head = fake.head_object

    def head_as_if_absent(**kw):
        # First look-up says absent (race window), so the PUT happens and
        # loses the conditional; later look-ups tell the truth.
        fake.head_object = real_head
        raise _S3Error("404")

    fake.head_object = head_as_if_absent
    second = s.write_once(KEY, b"same original")
    assert second == first
    assert describe_reference(second)["version_pinned"] is True
    with pytest.raises(WriteOnceViolation):
        s.write_once(KEY, b"different original")


def test_current_ref_reports_the_pinned_current_version():
    s, fake = _s3()
    assert s.current_ref(KEY) is None
    ref = s.write_once(KEY, b"x")
    assert s.current_ref(KEY) == ref
    fake.overwrite(KEY, b"y")
    assert s.current_ref(KEY) != ref
    assert s.ref_for(KEY) == KEY  # the version-less spelling is unchanged


def test_storage_from_config_s3_pins_by_default(tmp_path, monkeypatch):
    cfg = make_cfg(
        tmp_path,
        monkeypatch,
        COUNSELCLEAR_STORAGE="s3",
        COUNSELCLEAR_S3_BUCKET="cc",
        COUNSELCLEAR_RETENTION_DAYS="0",
    )
    fake = FakeS3(object_lock=False)
    monkeypatch.setattr(
        "app.storage.S3Storage.__init__",
        _init_with_fake(fake),
    )
    backend = storage_from_config(cfg)
    assert isinstance(backend, S3Storage)
    assert "object-versions=pinned" in backend.describe()


def _init_with_fake(fake):
    original_init = S3Storage.__init__

    def init(self, **kw):
        kw["client"] = fake
        original_init(self, **kw)

    return init


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


# --- app integration ----------------------------------------------------------

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


def test_upload_writes_encrypted_envelope_through_the_app(tmp_path, monkeypatch):
    """End-to-end: with a volume key file configured, the upload route stores
    an envelope on disk (never the plaintext) and the document reference
    round-trips through the backend."""
    from app.main import create_app
    from fastapi.testclient import TestClient

    keyfile = tmp_path / "volume.key"
    data_root = tmp_path / "data"
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw12345")
    monkeypatch.setenv("COUNSELCLEAR_VOLUME_KEY_FILE", str(keyfile))
    monkeypatch.delenv("COUNSELCLEAR_STORAGE", raising=False)

    sample = FIXTURES / "spa.docx"
    if not sample.exists():  # corpus generator may not have run; skip gracefully
        pytest.skip("legal corpus fixture not present")

    c = TestClient(create_app(data_root))
    c.post("/v1/auth/login", json={"password": "pw12345"})
    r = c.post(
        "/v1/matters",
        json={"name": "m"},
    )
    matter_id = r.json()["id"]
    with open(sample, "rb") as fh:
        r = c.post(
            f"/v1/matters/{matter_id}/documents",
            files={"file": ("spa.docx", fh.read(), "application/octet-stream")},
        )
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["id"]

    # The API never exposes storage_path; find the custody object on disk
    # under the one-scheme layout {root}/{org}/matters/... .
    originals = list(
        (data_root / "local" / "matters" / matter_id / "docs" / doc["id"] / "original").glob("*")
    )
    assert len(originals) == 1
    on_disk = originals[0]
    assert not on_disk.read_bytes().startswith(b"PK")  # not the plaintext docx
    assert on_disk.read_bytes().startswith(b"CCENC")
    assert keyfile.exists()
    if os.name != "nt":
        # POSIX permission bits do not qualify Windows ACL privacy; the
        # encrypted-envelope and key-existence checks run on both systems.
        assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
