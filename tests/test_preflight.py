"""The pilot preflight must expose configuration problems without side effects."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SPEC = importlib.util.spec_from_file_location(
    "counselclear_preflight",
    Path(__file__).resolve().parents[1] / "tools/counselclear_preflight.py",
)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


@pytest.fixture
def installation(tmp_path):
    data, web = tmp_path / "data", tmp_path / "web"
    (data / "auth").mkdir(parents=True)
    (web / "_next/static").mkdir(parents=True)
    (data / "counselclear.sqlite3").write_bytes(b"synthetic-presence-only")
    (data / "auth/local.hash").write_text("synthetic-presence-only")
    for name in ("index.html", "login.html"):
        (web / name).write_text("<html>synthetic</html>")
    key = Ed25519PrivateKey.generate()
    (data / "auth/custody_signing_key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    env = {
        "COUNSELCLEAR_WORKER_MODE": "docker",
        "COUNSELCLEAR_WORKER_IMAGE": "private-registry.invalid/private-image@sha256:" + "a" * 64,
        "COUNSELCLEAR_COOKIE_SECURE": "true",
        "COUNSELCLEAR_TSA_URL": "off",
    }
    return data, web, key, env


def run(installation, **updates):
    data, web, _, env = installation
    return preflight.inspect_installation(
        data, web, environ={**env, **updates}, which=lambda name: "/synthetic/bin/" + name
    )


def check(report, name):
    return next(c for c in report["checks"] if c["name"] == name)


def files(root):
    return {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_configuration_pass_is_explicitly_not_production_readiness(installation):
    data, web, key, _ = installation
    before = files(data.parent)
    report = run(installation)
    assert report["configuration_checks_passed"]
    assert report["production_readiness"] == "not_established"
    assert check(report, "backup_restore")["status"] == "not_checked"
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert report["signing_key_fingerprint_sha256"] == hashlib.sha256(public).hexdigest()
    assert files(data.parent) == before
    assert str(data) not in json.dumps(report) and str(web) not in json.dumps(report)


def test_missing_root_or_keys_are_never_provisioned(tmp_path):
    data, web = tmp_path / "absent-data", tmp_path / "absent-web"
    report = preflight.inspect_installation(data, web, environ={}, which=lambda _: None)
    assert not report["configuration_checks_passed"]
    assert not data.exists() and not web.exists()
    assert check(report, "signing_identity")["status"] == "block"


def test_missing_volume_key_is_not_generated(installation, tmp_path):
    path = tmp_path / "absent-volume.key"
    report = run(installation, COUNSELCLEAR_VOLUME_KEY_FILE=str(path))
    assert check(report, "encryption")["status"] == "block"
    assert not path.exists()


def test_partial_oidc_is_reported_without_echoing_credentials(installation):
    secret = "private-oidc-secret-sentinel"  # noqa: S105 - deliberate redaction sentinel
    report = run(installation, COUNSELCLEAR_OIDC_CLIENT_SECRET=secret)
    assert check(report, "authentication")["status"] == "block"
    assert secret not in json.dumps(report)


def test_external_database_and_kms_are_never_opened(installation, monkeypatch):
    import socket
    import sqlite3

    def forbidden(*args, **kwargs):
        pytest.fail("preflight attempted a connection")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    report = run(
        installation,
        COUNSELCLEAR_DATABASE_URL="postgresql://private-user:private-password@private-host/db",
        COUNSELCLEAR_CMK_ARN="arn:private-key-sentinel",
    )
    assert check(report, "storage_scope")["status"] == "block"
    assert check(report, "encryption")["status"] == "block"
    serialized = json.dumps(report)
    for value in ("private-user", "private-password", "private-host", "private-key-sentinel"):
        assert value not in serialized


@pytest.mark.parametrize("value", ["nonsense-secret", "0", "-1", "2"])
def test_silently_defaulted_or_clamped_lease_is_blocked(installation, value):
    report = run(installation, COUNSELCLEAR_JOB_LEASE_S=value)
    assert check(report, "job_lease_s")["status"] == "block"
    assert "nonsense-secret" not in json.dumps(report)


def test_unset_tsa_does_not_silently_select_public_egress(installation):
    data, web, _, env = installation
    del env["COUNSELCLEAR_TSA_URL"]
    report = preflight.inspect_installation(data, web, environ=env, which=lambda _: "installed")
    assert check(report, "timestamp_policy")["status"] == "block"


@pytest.mark.parametrize("value", ["off", "", "none", "disabled"])
def test_explicit_no_timestamp_egress_is_preserved(installation, value):
    assert (
        check(run(installation, COUNSELCLEAR_TSA_URL=value), "timestamp_policy")["status"] == "pass"
    )


def test_endpoints_and_image_names_are_redacted(installation):
    report = run(installation, COUNSELCLEAR_TSA_URL="https://user:secret@private-tsa.invalid/path")
    assert check(report, "timestamp_policy")["status"] == "pass"
    serialized = json.dumps(report)
    for text in ("private-tsa", "secret", "private-registry", "private-image"):
        assert text not in serialized


def test_invalid_signing_key_does_not_become_a_new_identity(installation):
    data, _, _, _ = installation
    path = data / "auth/custody_signing_key.pem"
    path.write_bytes(b"private-invalid-key-sentinel")
    report = run(installation)
    assert check(report, "signing_identity")["status"] == "block"
    assert path.read_bytes() == b"private-invalid-key-sentinel"
    assert "private-invalid-key-sentinel" not in json.dumps(report)


def test_malware_definitions_not_checked_when_clamscan_absent(installation):
    data, web, _, env = installation
    report = preflight.inspect_installation(data, web, environ=env, which=lambda name: None)
    assert check(report, "malware_definitions")["status"] == "not_checked"


def test_malware_definitions_warns_when_db_dir_unset(installation):
    report = run(installation)
    assert check(report, "malware_definitions")["status"] == "warning"


def test_malware_definitions_blocked_when_configured_dir_missing(installation, tmp_path):
    missing = tmp_path / "no-such-clamav-dir"
    report = run(installation, COUNSELCLEAR_CLAMAV_DB_DIR=str(missing))
    assert check(report, "malware_definitions")["status"] == "block"


def test_malware_definitions_blocked_when_no_daily_database_present(installation, tmp_path):
    db_dir = tmp_path / "clamav-defs"
    db_dir.mkdir()
    report = run(installation, COUNSELCLEAR_CLAMAV_DB_DIR=str(db_dir))
    assert check(report, "malware_definitions")["status"] == "block"


def test_malware_definitions_pass_when_fresh(installation, tmp_path):
    db_dir = tmp_path / "clamav-defs"
    db_dir.mkdir()
    (db_dir / "daily.cvd").write_bytes(b"synthetic-fresh-database")
    report = run(installation, COUNSELCLEAR_CLAMAV_DB_DIR=str(db_dir))
    assert check(report, "malware_definitions")["status"] == "pass"


def test_malware_definitions_warns_when_stale(installation, tmp_path):
    import os
    import time

    db_dir = tmp_path / "clamav-defs"
    db_dir.mkdir()
    daily = db_dir / "daily.cld"
    daily.write_bytes(b"synthetic-stale-database")
    stale_time = time.time() - (preflight._STALE_DEFINITIONS_DAYS + 1) * 86400
    os.utime(daily, (stale_time, stale_time))
    report = run(installation, COUNSELCLEAR_CLAMAV_DB_DIR=str(db_dir))
    result = check(report, "malware_definitions")
    assert result["status"] == "warning"
    assert "older than" in result["detail"]


def test_cli_exit_code_tracks_blockers_and_output_is_json(installation, monkeypatch, capsys):
    data, web, _, env = installation
    for name in tuple(preflight.os.environ):
        if name.startswith("COUNSELCLEAR_"):
            monkeypatch.delenv(name)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/synthetic/bin/tool")
    assert preflight.main(["--data-root", str(data), "--web-root", str(web)]) == 0
    assert json.loads(capsys.readouterr().out)["configuration_checks_passed"]
    monkeypatch.setenv("COUNSELCLEAR_WORKER_MODE", "subprocess")
    assert preflight.main(["--data-root", str(data), "--web-root", str(web)]) == 2
    assert not json.loads(capsys.readouterr().out)["configuration_checks_passed"]
