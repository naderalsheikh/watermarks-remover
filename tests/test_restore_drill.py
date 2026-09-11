"""Offline restore drill: a cold local data root restored into a new root.

The decisive case builds a real synthetic release through the API (upload,
release job, certificate), snapshots the stopped data root, renames the
original root away, restores into a different root, and then reads and
verifies the restored original and release packet through the application
and the offline verifier — with the old root gone, so nothing can resolve
against it by accident.
"""

from __future__ import annotations

import gc
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "tools", ROOT / "service", ROOT / "service" / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import counselclear_restore_drill as drill
from counselclear_verify_release_packet import verify_release_packet

FIXTURES = ROOT / "tests" / "fixtures" / "legal"
PASSWORD = "restore-drill-pw"  # noqa: S105 - test-only local password
DB = drill.DB_NAME


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stop_app(app) -> None:
    """A stopped application holds no database handle. The TestClient
    context already ran shutdown (dispatcher stopped); the pooled SQLite
    connection is what keeps the directory undeletable and un-renameable
    on Windows, so dispose the engine explicitly."""
    dispatcher = getattr(app.state, "batch_dispatcher", None)
    factory = getattr(dispatcher, "_session_factory", None)
    engine = getattr(factory, "kw", {}).get("bind") if factory is not None else None
    if engine is not None:
        engine.dispose()
    gc.collect()


def _checkpoint(root: Path) -> None:
    con = sqlite3.connect(root / DB)
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()


def _build_release_root(tmp_path: Path, monkeypatch, *, encrypted: bool = True) -> dict:
    """Run a real release and stop the app. Returns the live root, the key
    file (if any), ids, and the original bytes."""
    from app.main import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PASSWORD)
    keyfile = tmp_path / "keys" / "volume.key"
    if encrypted:
        monkeypatch.setenv("COUNSELCLEAR_VOLUME_KEY_FILE", str(keyfile))
    else:
        monkeypatch.delenv("COUNSELCLEAR_VOLUME_KEY_FILE", raising=False)
    root = tmp_path / "live" / "data"
    original = (FIXTURES / "spa.docx").read_bytes()

    app = create_app(root)
    with TestClient(app) as c:
        assert c.post("/v1/auth/login", json={"password": PASSWORD}).status_code == 200
        matter = c.post("/v1/matters", json={"name": "Restore drill"}).json()["id"]
        r = c.post(
            f"/v1/matters/{matter}/documents",
            files={"file": ("spa.docx", original, "application/octet-stream")},
        )
        assert r.status_code == 200, r.text
        doc = r.json()
        release = c.post(
            f"/v1/matters/{matter}/documents/{doc['id']}/releases",
            json={"profile_id": "counterparty_deal_room"},
        ).json()
        assert release["job"]["status"] == "done", release["job"].get("error")
        packet = c.get(f"/v1/matters/{matter}/jobs/{release['job']['id']}/bundle")
        assert packet.status_code == 200
    _stop_app(app)
    _checkpoint(root)
    return {
        "root": root,
        "keyfile": keyfile if encrypted else None,
        "matter": matter,
        "document": doc["id"],
        "job": release["job"]["id"],
        "release": release["release"]["id"] if isinstance(release.get("release"), dict) else None,
        "original": original,
        "packet_before": packet.content,
    }


def _cold_snapshot(live_root: Path, where: Path) -> Path:
    shutil.copytree(live_root, where, symlinks=True)
    return where


@pytest.fixture()
def release_snapshot(tmp_path, monkeypatch):
    built = _build_release_root(tmp_path, monkeypatch, encrypted=True)
    snapshot = _cold_snapshot(built["root"], tmp_path / "backup" / "data")
    # The original root becomes inaccessible: any code path that still
    # resolved against it would fail loudly instead of silently succeeding.
    gone = built["root"].with_name("data.gone")
    os.rename(built["root"], gone)
    built["old_root"] = str(built["root"])
    built["snapshot"] = snapshot
    built["gone"] = gone
    return built


def _run(snapshot: Path, destination: Path, old_root: str, **kw) -> drill.DrillReport:
    return drill.run_drill(snapshot, destination, old_root, **kw)


# --- the decisive case ------------------------------------------------------


def test_restore_into_new_root_serves_original_and_release_without_old_root(
    release_snapshot, tmp_path, monkeypatch
):
    from app.config import Config
    from app.main import create_app
    from app.storage import storage_from_config
    from fastapi.testclient import TestClient

    built = release_snapshot
    restored_root = tmp_path / "restored" / "data"
    restored_root.parent.mkdir()
    # Key material is restored separately and supplied explicitly.
    restored_key = tmp_path / "restored" / "volume.key"
    shutil.copyfile(built["keyfile"], restored_key)

    report = _run(built["snapshot"], restored_root, built["old_root"], volume_key_file=restored_key)
    assert report.outcome == "verified", (report.refusal, report.failures)
    assert report.exit_code == 0
    assert report.references["documents_rebased"] == 1
    assert report.references["bundle_dirs_rebased"] == 1
    assert report.references["receipt_output_dirs_rebased"] == 1
    assert report.references["old_root_mentions_remaining_in_reference_columns"] == 0
    assert report.references["preserved_tables_digest_unchanged"] is True
    assert report.originals == {"documents": 1, "verified": 1, "encrypted": 1, "plaintext": 0}
    assert report.releases["bundles_verified"] == 1
    assert report.releases["releases_done"] == 1
    assert report.releases["certificate_snapshots_present"] == 1
    assert report.audit["events"] >= 5 and all(
        "intact" in v for v in report.audit["chains"].values()
    )
    assert report.key_material["used"] is True
    assert report.auth["custody_signing_key_fingerprint"]
    assert not built["gone"].with_name("data").exists()  # the old root really is gone

    # No reference column carries the old root; every reference lives in
    # the restored root.
    con = sqlite3.connect(restored_root / DB)
    storage_path = con.execute("SELECT storage_path FROM documents").fetchone()[0]
    bundle_dir, receipt = con.execute("SELECT bundle_dir, execution_receipt FROM jobs").fetchone()
    con.close()
    assert storage_path.startswith(str(restored_root)) and Path(storage_path).is_file()
    assert bundle_dir.startswith(str(restored_root)) and Path(bundle_dir).is_dir()
    assert json.loads(receipt)["output_dir"].startswith(str(restored_root))
    assert built["old_root"] not in storage_path + bundle_dir + receipt

    # The restored root boots, authenticates with the restored hash, serves
    # the release packet, and the packet verifies offline.
    monkeypatch.setenv("COUNSELCLEAR_VOLUME_KEY_FILE", str(restored_key))
    with TestClient(create_app(restored_root)) as c:
        assert c.post("/v1/auth/login", json={"password": PASSWORD}).status_code == 200
        packet = c.get(f"/v1/matters/{built['matter']}/jobs/{built['job']}/bundle")
        assert packet.status_code == 200, packet.text
        manifest = c.get(f"/v1/matters/{built['matter']}/jobs/{built['job']}/manifest").json()
        assert manifest["original"]["sha256"] == _sha(built["original"])
    zip_path = tmp_path / "restored-packet.zip"
    zip_path.write_bytes(packet.content)
    verdict = verify_release_packet(zip_path)
    assert verdict.valid, verdict.to_text()
    with zipfile.ZipFile(io.BytesIO(packet.content)) as zf:
        names = set(zf.namelist())
        assert "manifest.json" in names and "certificate.html" in names
        restored_manifest = json.loads(zf.read("manifest.json"))
    with zipfile.ZipFile(io.BytesIO(built["packet_before"])) as zf:
        assert json.loads(zf.read("manifest.json")) == restored_manifest

    # The restored original decrypts and matches the fixture byte-for-byte
    # through the same storage backend the application uses.
    storage = storage_from_config(Config(restored_root))
    assert storage.read(storage_path) == built["original"]
    assert (
        storage.read_expected(
            storage_path, sha256=_sha(built["original"]), size=len(built["original"])
        )
        == built["original"]
    )

    # The snapshot itself was not touched by the drill.
    src_db = built["snapshot"] / DB
    assert src_db.exists()
    src_con = sqlite3.connect(f"file:{src_db}?mode=ro", uri=True)
    src_ref = src_con.execute("SELECT storage_path FROM documents").fetchone()[0]
    src_con.close()
    assert src_ref.startswith(built["old_root"])


def test_cli_writes_report_and_exit_code(release_snapshot, tmp_path):
    built = release_snapshot
    destination = tmp_path / "cli-restored"
    report_path = tmp_path / "drill.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "counselclear_restore_drill.py"),
            "--source",
            str(built["snapshot"]),
            "--destination",
            str(destination),
            "--old-data-root",
            built["old_root"],
            "--volume-key-file",
            str(built["keyfile"]),
            "--report",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(report_path.read_text())
    assert report["outcome"] == "verified"
    assert report["scope"]["does_not_qualify"]
    # Secrets never reach stdout or the report.
    key_hex = built["keyfile"].read_bytes().hex()
    local_hash = (destination / "auth" / "local.hash").read_text()
    for blob in (completed.stdout, report_path.read_text()):
        assert key_hex not in blob and local_hash not in blob
        assert "cookie.secret" not in blob or "bytes" in blob  # only sizes, never contents


# --- refusals: preconditions ---------------------------------------------------


def test_missing_key_material_is_refused_and_destination_removed(release_snapshot, tmp_path):
    built = release_snapshot
    destination = tmp_path / "no-key"
    report = _run(built["snapshot"], destination, built["old_root"])
    assert report.outcome == "refused" and report.exit_code == 2
    assert "no --volume-key-file" in report.refusal
    assert not destination.exists() and report.destination_removed is True

    absent = tmp_path / "keys" / "never-created.key"
    report = _run(built["snapshot"], destination, built["old_root"], volume_key_file=absent)
    assert report.outcome == "refused" and "does not exist" in report.refusal
    assert not absent.exists()  # the drill never manufactures a key
    assert not destination.exists()


def test_wrong_key_fails_verification(release_snapshot, tmp_path):
    built = release_snapshot
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(os.urandom(32))
    destination = tmp_path / "wrong-key"
    report = _run(built["snapshot"], destination, built["old_root"], volume_key_file=wrong)
    assert report.outcome == "failed" and report.exit_code == 3
    assert "envelope did not open" in report.failures[0]
    assert not destination.exists()


def test_queued_or_running_work_is_refused(release_snapshot, tmp_path):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    con.execute("UPDATE jobs SET status = 'running'")
    con.commit()
    con.close()
    destination = tmp_path / "not-drained"
    report = _run(
        built["snapshot"], destination, built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "refused"
    assert "not drained" in report.refusal and "1 queued/running jobs" in report.refusal
    assert not destination.exists()


@pytest.mark.parametrize(
    ("column", "value", "fragment"),
    [
        ("storage_path", "{old}/../escape/spa.docx", "unsafe path segment"),
        ("storage_path", "{anchor}somewhere/else/spa.docx", "outside the declared old data root"),
        ("storage_path", "relative/spa.docx", "not an absolute local path"),
        ("storage_path", "s3v1:abc:prod/firm/x.docx", "object-storage (S3) references"),
        ("bundle_dir", "{old}/matters/../../x", "unsafe path segment"),
    ],
)
def test_unsafe_or_foreign_references_are_refused(
    release_snapshot, tmp_path, column, value, fragment
):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    table = "documents" if column == "storage_path" else "jobs"
    rendered = value.format(old=built["old_root"], anchor=Path(built["old_root"]).anchor)
    con.execute(f"UPDATE {table} SET {column} = ?", (rendered,))  # noqa: S608
    con.commit()
    con.close()
    destination = tmp_path / "unsafe"
    report = _run(
        built["snapshot"], destination, built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "refused", report.failures
    assert fragment in report.refusal
    assert not destination.exists()


def test_symlink_in_snapshot_is_refused(release_snapshot, tmp_path):
    built = release_snapshot
    link = built["snapshot"] / "auth" / "linked.pem"
    try:
        link.symlink_to(tmp_path / "outside.pem")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    destination = tmp_path / "symlinked"
    report = _run(
        built["snapshot"], destination, built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "refused" and "symlink" in report.refusal
    assert not destination.exists()


def test_destination_must_be_new_and_not_nested(release_snapshot, tmp_path):
    built = release_snapshot
    existing = tmp_path / "exists"
    existing.mkdir()
    report = _run(built["snapshot"], existing, built["old_root"], volume_key_file=built["keyfile"])
    assert report.outcome == "refused" and "already exists" in report.refusal
    assert existing.exists()  # we did not create it, so we do not remove it
    nested = built["snapshot"] / "inner"
    report = _run(built["snapshot"], nested, built["old_root"], volume_key_file=built["keyfile"])
    assert report.outcome == "refused" and "nested" in report.refusal
    report = _run(
        built["snapshot"], tmp_path / "x", "relative/root", volume_key_file=built["keyfile"]
    )
    assert report.outcome == "refused" and "absolute" in report.refusal
    report = _run(built["snapshot"], tmp_path / "x", "", volume_key_file=built["keyfile"])
    assert report.outcome == "refused" and "not inferred" in report.refusal


def test_non_local_deployment_modes_are_refused(release_snapshot, tmp_path, monkeypatch):
    built = release_snapshot
    monkeypatch.setenv("COUNSELCLEAR_DATABASE_URL", "postgresql://cc@db/cc")
    report = _run(
        built["snapshot"], tmp_path / "pg", built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "refused" and "SQLite" in report.refusal
    monkeypatch.delenv("COUNSELCLEAR_DATABASE_URL")
    monkeypatch.setenv("COUNSELCLEAR_STORAGE", "s3")
    report = _run(
        built["snapshot"], tmp_path / "s3", built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "refused" and "LOCAL storage only" in report.refusal


# --- failures: verification -----------------------------------------------------


def test_corrupt_original_fails_verification(release_snapshot, tmp_path):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    stored = con.execute("SELECT storage_path FROM documents").fetchone()[0]
    con.close()
    relative = Path(stored).relative_to(built["old_root"])
    target = built["snapshot"] / relative
    data = bytearray(target.read_bytes())
    data[-1] ^= 0xFF
    os.chmod(target, 0o600)
    target.write_bytes(bytes(data))
    destination = tmp_path / "corrupt"
    report = _run(
        built["snapshot"], destination, built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "failed" and report.exit_code == 3
    assert "document" in report.failures[0]
    assert not destination.exists()


def test_missing_bundle_fails_verification(release_snapshot, tmp_path):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    bundle = con.execute("SELECT bundle_dir FROM jobs").fetchone()[0]
    con.close()
    # Write-once derivatives are read-only; use the drill's own remover so the
    # case runs on Windows too.
    assert drill._remove_tree(built["snapshot"] / Path(bundle).relative_to(built["old_root"]))
    destination = tmp_path / "no-bundle"
    report = _run(
        built["snapshot"], destination, built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "failed"
    assert "bundle or manifest.json missing" in report.failures[0]
    assert not destination.exists()


def test_tampered_derivative_and_broken_audit_chain_fail(release_snapshot, tmp_path):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    bundle = Path(con.execute("SELECT bundle_dir FROM jobs").fetchone()[0])
    con.close()
    deriv_dir = built["snapshot"] / bundle.relative_to(built["old_root"]) / "derivative"
    deriv = next(deriv_dir.iterdir())
    os.chmod(deriv, 0o600)
    deriv.write_bytes(deriv.read_bytes() + b"x")
    report = _run(
        built["snapshot"],
        tmp_path / "tampered",
        built["old_root"],
        volume_key_file=built["keyfile"],
    )
    assert report.outcome == "failed" and "derivative differs" in report.failures[0]

    con = sqlite3.connect(built["snapshot"] / DB)
    con.execute("UPDATE audit_events SET actor_id = 'someone-else' WHERE seq = 1")
    con.commit()
    con.close()
    report = _run(
        built["snapshot"], tmp_path / "chain", built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "failed" and "audit chain" in report.failures[0]


def test_keep_on_failure_retains_destination_for_inspection(release_snapshot, tmp_path):
    built = release_snapshot
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(os.urandom(32))
    destination = tmp_path / "kept"
    report = _run(
        built["snapshot"],
        destination,
        built["old_root"],
        volume_key_file=wrong,
        keep_on_failure=True,
    )
    assert report.outcome == "failed"
    assert destination.is_dir() and report.destination_removed is False


# --- acceptance-review regressions (Codex, PR #10) ------------------------------


def _bundle_paths(built: dict) -> tuple[Path, Path]:
    """(bundle dir, worker output dir) inside the snapshot."""
    con = sqlite3.connect(built["snapshot"] / DB)
    bundle, receipt = con.execute("SELECT bundle_dir, execution_receipt FROM jobs").fetchone()
    con.close()
    old = built["old_root"]
    output = json.loads(receipt)["output_dir"]
    return (
        built["snapshot"] / Path(bundle).relative_to(old),
        built["snapshot"] / Path(output).relative_to(old),
    )


def _rewrite_manifest_everywhere(built: dict, mutate) -> None:
    """Apply ``mutate`` to the manifest and mirror it into result_json and the
    worker result.json, the way a consistent forgery would."""
    bundle, output = _bundle_paths(built)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    mutate(manifest)
    os.chmod(manifest_path, 0o600)
    manifest_path.write_text(json.dumps(manifest))
    con = sqlite3.connect(built["snapshot"] / DB)
    result = json.loads(con.execute("SELECT result_json FROM jobs").fetchone()[0])
    result["manifest"] = manifest
    con.execute("UPDATE jobs SET result_json = ?", (json.dumps(result),))
    con.commit()
    con.close()
    payload_path = output / "result.json"
    payload = json.loads(payload_path.read_bytes())
    payload["result"]["manifest"] = manifest
    os.chmod(payload_path, 0o600)
    payload_path.write_text(json.dumps(payload))


def test_missing_or_invalid_signing_key_is_not_verified(release_snapshot, tmp_path):
    built = release_snapshot
    pem = built["snapshot"] / "auth" / "custody_signing_key.pem"
    pem.unlink()
    report = _run(
        built["snapshot"], tmp_path / "no-pem", built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "failed" and report.exit_code == 3
    assert "custody signing key is missing" in report.failures[0]
    assert "replacement signing identity" in report.failures[0]
    assert report.auth["custody_signing_key_present"] is False
    assert report.auth["custody_depends_on_signing_key"] is True
    assert not (tmp_path / "no-pem").exists()

    pem.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
    report = _run(
        built["snapshot"], tmp_path / "bad-pem", built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "failed"
    assert "did not load" in report.failures[0]
    assert report.auth["custody_signing_key_fingerprint"] is None


def test_signing_key_absence_is_only_a_warning_without_release_custody(tmp_path, monkeypatch):
    """A root with no done sanitize job or release has nothing signed yet;
    the drill reports the gap instead of failing on it."""
    from app.main import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", PASSWORD)
    monkeypatch.delenv("COUNSELCLEAR_VOLUME_KEY_FILE", raising=False)
    root = tmp_path / "live" / "data"
    app = create_app(root)
    with TestClient(app) as c:
        assert c.post("/v1/auth/login", json={"password": PASSWORD}).status_code == 200
        c.post("/v1/matters", json={"name": "empty"})
    _stop_app(app)
    _checkpoint(root)
    snapshot = _cold_snapshot(root, tmp_path / "backup" / "data")
    old_root = str(root)
    os.rename(root, root.with_name("data.gone"))
    (snapshot / "auth" / "custody_signing_key.pem").unlink(missing_ok=True)
    report = _run(snapshot, tmp_path / "restored", old_root)
    assert report.outcome == "verified", (report.refusal, report.failures)
    assert report.auth["custody_depends_on_signing_key"] is False
    assert report.auth["warning"] == "custody signing key is missing"


def test_done_sanitize_job_without_bundle_evidence_is_not_verified(release_snapshot, tmp_path):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    con.execute("UPDATE jobs SET bundle_dir = '', result_json = '{}'")
    con.commit()
    con.close()
    report = _run(
        built["snapshot"],
        tmp_path / "no-bundle-dir",
        built["old_root"],
        volume_key_file=built["keyfile"],
    )
    assert report.outcome == "failed"
    assert "records no bundle_dir" in report.failures[0]
    assert report.releases["releases_done"] == 1 and report.releases["bundles_verified"] == 0
    assert "its job's bundle evidence did not verify" in report.failures[0]


@pytest.mark.parametrize(
    ("result_json", "fragment"),
    [
        ("[]", "not a JSON object"),
        ("null", "not a JSON object"),
        ("not json", "not valid JSON"),
        ("", "is missing"),
        ('{"manifest": {}, "verification_pass": true}', "differs from the stored manifest"),
    ],
    ids=["list", "null", "garbage", "empty", "wrong-manifest"],
)
def test_malformed_result_json_is_not_verified(release_snapshot, tmp_path, result_json, fragment):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    con.execute("UPDATE jobs SET result_json = ?", (result_json,))
    con.commit()
    con.close()
    report = _run(
        built["snapshot"],
        tmp_path / "bad-result",
        built["old_root"],
        volume_key_file=built["keyfile"],
    )
    assert report.outcome == "failed"
    assert fragment in report.failures[0]


def test_release_pointing_at_an_inspect_job_is_not_verified(release_snapshot, tmp_path):
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    con.execute(
        "UPDATE jobs SET kind = 'inspect', bundle_dir = '', result_json = '{\"findings\": []}'"
    )
    con.commit()
    con.close()
    report = _run(
        built["snapshot"],
        tmp_path / "inspect-release",
        built["old_root"],
        volume_key_file=built["keyfile"],
    )
    assert report.outcome == "failed"
    assert "done without a done sanitize job" in report.failures[0]


@pytest.mark.parametrize(
    ("make_name", "fragment"),
    [
        (str, "is a path, not a confined file name"),
        (lambda outside: "../" + outside.name, "is a path, not a confined file name"),
        (lambda outside: "..", "is not a file name"),
        (lambda outside: "", "is not a file name"),
    ],
    ids=["absolute", "dotdot-relative", "dotdot", "empty"],
)
def test_manifest_derivative_name_is_confined_to_the_bundle(
    release_snapshot, tmp_path, make_name, fragment
):
    """A consistent forgery (manifest, result_json and worker result.json all
    agree) that names a derivative outside the bundle must still fail; the
    manifest is never rewritten to repair it."""
    built = release_snapshot
    bundle, _ = _bundle_paths(built)
    original_manifest = json.loads((bundle / "manifest.json").read_bytes())
    outside = tmp_path / "outside.docx"
    shutil.copyfile(bundle / "derivative" / original_manifest["derivative"]["filename"], outside)

    def mutate(manifest):
        manifest["derivative"]["filename"] = make_name(outside)

    _rewrite_manifest_everywhere(built, mutate)
    destination = tmp_path / "escaped"
    report = _run(
        built["snapshot"],
        destination,
        built["old_root"],
        volume_key_file=built["keyfile"],
        keep_on_failure=True,
    )
    assert report.outcome == "failed"
    assert fragment in report.failures[0]
    # The (forged) manifest was carried as-is, not corrected.
    restored_bundle = destination / bundle.relative_to(built["snapshot"])
    assert json.loads((restored_bundle / "manifest.json").read_bytes())["derivative"][
        "filename"
    ] == make_name(outside)


def test_extra_file_in_derivative_dir_is_not_verified(release_snapshot, tmp_path):
    built = release_snapshot
    bundle, _ = _bundle_paths(built)
    (bundle / "derivative" / "extra.docx").write_bytes(b"stray")
    report = _run(
        built["snapshot"], tmp_path / "extra", built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "failed"
    assert "exactly the declared derivative" in report.failures[0]


def test_copy_failure_removes_partial_destination_and_propagates(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / DB).write_bytes(b"synthetic")
    (source / "auth").mkdir()
    (source / "auth" / "local.hash").write_bytes(b"x")
    destination = tmp_path / "restored"
    calls = {"n": 0}
    real = drill.shutil.copyfile

    def fail_second(src, dst, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("synthetic copy failure")
        return real(src, dst, **kw)

    monkeypatch.setattr(drill.shutil, "copyfile", fail_second)
    with pytest.raises(OSError, match="synthetic copy failure"):
        drill.run_drill(source, destination, str(source))
    assert not destination.exists()


def test_failed_cleanup_is_reported_not_claimed(release_snapshot, tmp_path, monkeypatch):
    built = release_snapshot
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(os.urandom(32))
    destination = tmp_path / "stuck"
    monkeypatch.setattr(drill, "_remove_tree", lambda path: False)
    report = _run(built["snapshot"], destination, built["old_root"], volume_key_file=wrong)
    assert report.outcome == "failed"
    assert report.destination_removed is False
    assert any("could not be removed" in f for f in report.failures)
    assert destination.exists()


def test_cleanup_handles_read_only_members(release_snapshot, tmp_path):
    """Write-once originals are stored read-only; the cleanup must still
    remove the destination it created."""
    built = release_snapshot
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(os.urandom(32))
    destination = tmp_path / "ro"
    report = _run(built["snapshot"], destination, built["old_root"], volume_key_file=wrong)
    assert report.outcome == "failed" and report.destination_removed is True
    assert not destination.exists()


def test_report_path_must_be_new_and_outside_snapshot_and_root(release_snapshot, tmp_path):
    built = release_snapshot
    destination = tmp_path / "report-target"
    existing = tmp_path / "existing.json"
    existing.write_text("{}")
    cases = [
        (existing, "already exists"),
        (built["snapshot"] / "drill.json", "inside the source snapshot"),
        (destination / "drill.json", "inside the destination root"),
        (built["keyfile"].parent / "drill.json", "volume key file's directory"),
        (tmp_path / "missing-dir" / "drill.json", "parent directory does not exist"),
    ]
    for path, fragment in cases:
        with pytest.raises(drill.Refused, match=fragment):
            drill.validate_report_path(path, built["snapshot"], destination, built["keyfile"])
        assert not destination.exists()
    fine = tmp_path / "fine.json"
    assert (
        drill.validate_report_path(fine, built["snapshot"], destination, built["keyfile"]) == fine
    )
    assert drill.validate_report_path(None, built["snapshot"], destination, None) is None


def _tree_digest(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): _sha(path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_report_path_aliases_into_protected_trees_are_refused(release_snapshot, tmp_path):
    """A symlinked parent that resolves into the snapshot, the restored root
    or the key directory is refused exactly like the real path, and the
    snapshot is provably untouched afterwards."""
    built = release_snapshot
    destination = tmp_path / "alias-target"
    before = _tree_digest(built["snapshot"])
    try:
        (tmp_path / "alias-source").symlink_to(built["snapshot"], target_is_directory=True)
        (tmp_path / "alias-keys").symlink_to(built["keyfile"].parent, target_is_directory=True)
        destination.parent.joinpath("alias-dest").symlink_to(destination, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    for path, fragment in (
        (tmp_path / "alias-source" / "report.json", "inside the source snapshot"),
        (tmp_path / "alias-keys" / "report.json", "volume key file's directory"),
        (tmp_path / "alias-dest" / "report.json", "inside the destination root"),
    ):
        with pytest.raises(drill.Refused, match=fragment):
            drill.validate_report_path(path, built["snapshot"], destination, built["keyfile"])
        assert not path.exists()
    assert not (built["snapshot"] / "report.json").exists()
    assert _tree_digest(built["snapshot"]) == before

    # A legitimate alias elsewhere is accepted and the report lands on the
    # resolved path, created exclusively.
    real_dir = tmp_path / "reports"
    real_dir.mkdir()
    (tmp_path / "alias-reports").symlink_to(real_dir, target_is_directory=True)
    accepted = drill.validate_report_path(
        tmp_path / "alias-reports" / "drill.json", built["snapshot"], destination, built["keyfile"]
    )
    assert accepted == real_dir.resolve() / "drill.json"
    drill._write_report(accepted, "{}")
    assert (real_dir / "drill.json").read_text() == "{}\n"
    with pytest.raises(FileExistsError):
        drill._write_report(accepted, "{}")


def test_cli_alias_into_snapshot_leaves_snapshot_unchanged(release_snapshot, tmp_path):
    built = release_snapshot
    try:
        (tmp_path / "alias").symlink_to(built["snapshot"], target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    before = _tree_digest(built["snapshot"])
    destination = tmp_path / "cli-alias"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "counselclear_restore_drill.py"),
            "--source",
            str(built["snapshot"]),
            "--destination",
            str(destination),
            "--old-data-root",
            built["old_root"],
            "--volume-key-file",
            str(built["keyfile"]),
            "--report",
            str(tmp_path / "alias" / "report.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert "inside the source snapshot" in completed.stdout
    assert not destination.exists()
    assert _tree_digest(built["snapshot"]) == before


def test_every_non_reference_table_is_preserved_including_unknown_ones(release_snapshot, tmp_path):
    """Tables this tool does not know about must survive restore
    byte-for-byte and be covered by the preservation digest. The fixture
    adds a deliberately unknown table; the real ``admissions`` table
    (migration 0014 on the integration branch) is asserted whenever the
    schema under test has it."""
    built = release_snapshot
    con = sqlite3.connect(built["snapshot"] / DB)
    snapshot_tables = {
        row[0]
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert "future_restore_receipts" not in snapshot_tables
    con.execute(
        "CREATE TABLE future_restore_receipts (id TEXT PRIMARY KEY, request_digest TEXT, payload TEXT)"
    )
    rows = [("frr-1", "ab" * 32, '{"kind": "sanitize"}'), ("frr-2", "cd" * 32, "null")]
    con.executemany("INSERT INTO future_restore_receipts VALUES (?, ?, ?)", rows)
    con.commit()
    con.close()
    destination = tmp_path / "with-unknown-table"
    report = _run(
        built["snapshot"], destination, built["old_root"], volume_key_file=built["keyfile"]
    )
    assert report.outcome == "verified", (report.refusal, report.failures)
    preserved = set(report.references["preserved_tables"])
    assert preserved == snapshot_tables | {"future_restore_receipts"}
    if "admissions" in snapshot_tables:
        assert "admissions" in preserved
    assert report.references["rebased_columns"] == {
        "documents": ["storage_path"],
        "jobs": ["bundle_dir", "execution_receipt"],
    }
    con = sqlite3.connect(destination / DB)
    restored_rows = con.execute(
        "SELECT id, request_digest, payload FROM future_restore_receipts ORDER BY id"
    ).fetchall()
    restored_tables = {
        row[0]
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    con.close()
    assert restored_rows == rows
    assert restored_tables == snapshot_tables | {"future_restore_receipts"}


def test_preservation_digest_detects_changes_outside_rebased_columns(tmp_path):
    con = sqlite3.connect(tmp_path / "scratch.sqlite3")
    con.execute("CREATE TABLE documents (id TEXT, storage_path TEXT, sha256 TEXT)")
    con.execute("CREATE TABLE jobs (id TEXT, bundle_dir TEXT, execution_receipt TEXT, status TEXT)")
    con.execute("CREATE TABLE admissions (id TEXT, payload TEXT)")
    con.execute("INSERT INTO documents VALUES ('d', '/old/x', 'h')")
    con.execute("INSERT INTO jobs VALUES ('j', '/old/b', '{}', 'done')")
    con.execute("INSERT INTO admissions VALUES ('a', 'p')")
    con.commit()
    base = drill._digest_tables(con)
    assert set(base) == {"documents", "jobs", "admissions"}
    # Rebasing the reference columns leaves the digest unchanged...
    con.execute("UPDATE documents SET storage_path = '/new/x'")
    con.execute(
        "UPDATE jobs SET bundle_dir = '/new/b', execution_receipt = '{\"output_dir\": \"/new\"}'"
    )
    con.commit()
    assert drill._digest_tables(con) == base
    # ...and any other change is detected, in known and unknown tables alike.
    con.execute("UPDATE jobs SET status = 'failed'")
    con.commit()
    assert drill._digest_tables(con)["jobs"] != base["jobs"]
    con.execute("UPDATE jobs SET status = 'done'")
    con.execute("UPDATE admissions SET payload = 'changed'")
    con.commit()
    changed = drill._digest_tables(con)
    assert changed["jobs"] == base["jobs"] and changed["admissions"] != base["admissions"]
    con.close()


def test_cli_refuses_bad_report_path_before_copying(release_snapshot, tmp_path):
    built = release_snapshot
    destination = tmp_path / "cli-bad-report"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "counselclear_restore_drill.py"),
            "--source",
            str(built["snapshot"]),
            "--destination",
            str(destination),
            "--old-data-root",
            built["old_root"],
            "--volume-key-file",
            str(built["keyfile"]),
            "--report",
            str(built["snapshot"] / "drill.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert "inside the source snapshot" in completed.stdout
    assert not destination.exists()
    assert not (built["snapshot"] / "drill.json").exists()


# --- variants -------------------------------------------------------------------


def test_plaintext_snapshot_restores_without_key(tmp_path, monkeypatch):
    built = _build_release_root(tmp_path, monkeypatch, encrypted=False)
    snapshot = _cold_snapshot(built["root"], tmp_path / "backup" / "data")
    old_root = str(built["root"])
    os.rename(built["root"], built["root"].with_name("data.gone"))
    destination = tmp_path / "plain-restored"
    report = _run(snapshot, destination, old_root)
    assert report.outcome == "verified", (report.refusal, report.failures)
    assert report.originals["plaintext"] == 1 and report.originals["encrypted"] == 0
    assert report.key_material == {"volume_key_file": None, "supplied": False}
    # A key supplied for a plaintext snapshot is accepted and reported unused.
    key = tmp_path / "unused.key"
    key.write_bytes(os.urandom(32))
    report = _run(snapshot, tmp_path / "plain-restored-2", old_root, volume_key_file=key)
    assert report.outcome == "verified" and report.key_material["used"] is False


def test_windows_spelled_references_restore_on_this_host(tmp_path, monkeypatch):
    """A snapshot whose references were written on Windows (backslashes,
    drive letter) restores on any host: the declared old root's flavour
    drives the parsing, the remainder is re-rooted with host separators."""
    built = _build_release_root(tmp_path, monkeypatch, encrypted=False)
    snapshot = _cold_snapshot(built["root"], tmp_path / "backup" / "data")
    old_root = str(built["root"])
    os.rename(built["root"], built["root"].with_name("data.gone"))
    win_root = "C:\\CounselClear\\data"

    def to_windows(ref: str) -> str:
        return win_root + "\\" + Path(ref).relative_to(old_root).as_posix().replace("/", "\\")

    con = sqlite3.connect(snapshot / DB)
    storage_path = con.execute("SELECT storage_path FROM documents").fetchone()[0]
    bundle_dir, receipt = con.execute("SELECT bundle_dir, execution_receipt FROM jobs").fetchone()
    receipt_obj = json.loads(receipt)
    receipt_obj["output_dir"] = to_windows(receipt_obj["output_dir"])
    con.execute("UPDATE documents SET storage_path = ?", (to_windows(storage_path),))
    con.execute(
        "UPDATE jobs SET bundle_dir = ?, execution_receipt = ?",
        (to_windows(bundle_dir), json.dumps(receipt_obj)),
    )
    con.commit()
    con.close()

    destination = tmp_path / "from-windows"
    report = _run(snapshot, destination, win_root)
    assert report.outcome == "verified", (report.refusal, report.failures)
    con = sqlite3.connect(destination / DB)
    restored = con.execute("SELECT storage_path FROM documents").fetchone()[0]
    con.close()
    assert Path(restored).is_file() and restored.startswith(str(destination))


def test_root_mapper_rejects_escapes_and_foreign_flavours(tmp_path):
    mapper = drill.RootMapper("/srv/cc/data", tmp_path / "new")
    assert mapper.rebase("/srv/cc/data/a/b.docx", column="c") == tmp_path / "new" / "a" / "b.docx"
    for bad in ("/srv/cc/data", "/srv/cc/data/../x", "/srv/cc/other/x", "relative/x", ""):
        with pytest.raises(drill.Refused):
            mapper.rebase(bad, column="c")
    with pytest.raises(drill.Refused, match="backslash"):
        mapper.rebase("/srv/cc/data/a\\b.docx", column="c")
    win = drill.RootMapper("D:\\cc\\data", tmp_path / "new")
    assert win.rebase("D:\\cc\\data\\m\\x.docx", column="c") == tmp_path / "new" / "m" / "x.docx"
    with pytest.raises(drill.Refused):
        win.rebase("D:\\cc\\data\\..\\x.docx", column="c")
    with pytest.raises(drill.Refused, match="absolute"):
        drill.RootMapper("cc/data", tmp_path / "new")
