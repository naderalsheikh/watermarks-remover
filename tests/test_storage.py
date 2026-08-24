"""PR 21 — custody storage backends: local write-once, S3 Object Lock,
CMK envelope encryption, residency pin."""

from __future__ import annotations

import io
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

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
    original_key,
    storage_from_config,
)


class _S3Error(Exception):
    """Botocore-ClientError-shaped test double (production code reads
    ``exc.response["Error"]["Code"]`` via app.storage._err_code)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self, location: str | None = None):
        self.objects: dict[str, dict] = {}
        self.puts: list[dict] = []
        self.location = location

    def get_bucket_location(self, **kw):
        return {"LocationConstraint": self.location}

    def head_object(self, **kw):
        key = kw["Key"]
        if key not in self.objects:
            raise _S3Error("404")
        return {"Metadata": self.objects[key]["meta"]}

    def put_object(self, **kw):
        self.puts.append(kw)
        key = kw["Key"]
        if key in self.objects:
            raise _S3Error("PreconditionFailed")
        self.objects[key] = {"body": kw["Body"], "meta": kw.get("Metadata", {})}

    def get_object(self, **kw):
        key = kw["Key"]
        if key not in self.objects:
            raise _S3Error("404")
        return {"Body": io.BytesIO(self.objects[key]["body"])}


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
    assert s3.write_once("k", b"x") == "k"
    kms = KmsKeyring("arn:aws:kms:x:1:key/abc", client=FakeKMS())
    _dek, wrapped = kms.new_data_key()
    assert kms.unwrap(wrapped) is not None


def test_volume_key_file_created_0600_and_reused(tmp_path):
    keyfile = tmp_path / "volume.key"
    LocalKeyring(keyfile)
    assert keyfile.exists()
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


def test_s3_write_once_sets_object_lock_and_conditional(tmp_path):
    fake = FakeS3()
    s = S3Storage(bucket="cc", retention_days=365, org="firm", client=fake)
    key = "firm/matters/m1/docs/d1/original/a.docx"
    ref = s.write_once(key, b"content")
    assert ref == key

    put = fake.puts[0]
    assert put["IfNoneMatch"] == "*"
    assert put["ObjectLockMode"] == "COMPLIANCE"
    until = put["ObjectLockRetainUntilDate"]
    assert isinstance(until, datetime)
    assert until > datetime.now(UTC)
    assert (
        put["Metadata"]["sha256"]
        == "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73"
    )
    assert fake.objects[key]["body"] == b"content"


def test_s3_no_lock_when_retention_zero(tmp_path):
    s = S3Storage(bucket="cc", retention_days=0, client=FakeS3())
    s.write_once("k", b"x")
    assert "ObjectLockMode" not in s._client.puts[0]


def test_s3_idempotent_and_conflict(tmp_path):
    fake = FakeS3()
    s = S3Storage(bucket="cc", client=fake)
    ref = s.write_once("k", b"content")
    assert s.write_once("k", b"content") == ref
    with pytest.raises(StorageError):
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
    assert s.write_once("k", b"x") == "k"
    assert S3Storage(
        bucket="cc", residency_region="eu-central-1", client=FakeS3(location="eu-central-1")
    )


def test_s3_prefix_key_roundtrip(tmp_path):
    s = S3Storage(bucket="cc", prefix="prod", client=FakeS3())
    ref = s.write_once("firm/m1/d1/original/a.docx", b"x")
    assert ref == "prod/firm/m1/d1/original/a.docx"
    assert s.key_from_ref(ref) == "firm/m1/d1/original/a.docx"


def test_encrypted_s3_roundtrip(tmp_path):
    fake = FakeS3()
    inner = S3Storage(bucket="cc", client=fake)
    s = EncryptedStorage(inner, LocalKeyring(tmp_path / "volume.key"))
    ref = s.write_once("firm/m1/d1/original/a.docx", b"sealed in s3")
    assert s.read(ref) == b"sealed in s3"
    assert b"sealed in s3" not in fake.objects[ref]["body"]
    # idempotent through the encrypted wrapper
    assert s.write_once("firm/m1/d1/original/a.docx", b"sealed in s3") == ref


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
    assert keyfile.exists() and stat.S_IMODE(keyfile.stat().st_mode) == 0o600
