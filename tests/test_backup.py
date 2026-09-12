"""tools/counselclear_backup.py: cold backup of a LOCAL/SQLite data root.

Reuses tests/test_restore_drill.py's own root-building helpers so a backup
is proven against a real, application-produced root (matter, document,
completed release job) rather than a hand-built schema -- and the decisive
test proves the actual promise: a backup this tool calls "verified" is a
snapshot the restore drill can actually restore.

The source-preservation tests below prove the sharper claim the module
docstring makes: --source's database is never opened at all, so a refusal
(an existing destination, a symlinked db file) can never leave source bytes
-- including an uncheckpointed WAL a live writer left behind -- changed.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "tools", ROOT / "service", ROOT / "service" / "scripts", ROOT / "tests"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import counselclear_backup as backup
import counselclear_restore_drill as drill
import test_restore_drill as trd


def _tree_digests(path: Path) -> dict[str, str]:
    return {
        str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in path.rglob("*")
        if p.is_file() and not p.is_symlink()
    }


def _uncheckpointed_wal_root(tmp_path: Path, name: str) -> Path:
    """A cold copy of a WAL-mode database with committed data still sitting
    in its -wal file (wal_autocheckpoint=0 keeps it there) -- exactly what
    a crash or an ordinary cold copy of a live root can look like. Any code
    that opens this db file, even briefly, risks SQLite checkpointing (and
    thus changing) it on close."""
    live = tmp_path / f"{name}-live"
    live.mkdir()
    db = live / drill.DB_NAME
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE synthetic (value TEXT)")
    con.execute("INSERT INTO synthetic VALUES ('committed data in WAL')")
    con.commit()
    # Copy while the connection is still open: closing it triggers SQLite's
    # own last-connection checkpoint regardless of wal_autocheckpoint,
    # which would checkpoint away exactly the uncheckpointed WAL state this
    # fixture exists to construct.
    source = tmp_path / name
    shutil.copytree(live, source)
    con.close()
    assert (source / f"{drill.DB_NAME}-wal").stat().st_size > 0
    return source


def test_refused_existing_destination_does_not_change_source(tmp_path):
    """An already-existing --destination is a _preflight refusal that must
    happen before source is ever touched -- not after opening it to check
    for a live writer, which would itself checkpoint (mutate) the WAL."""
    source = _uncheckpointed_wal_root(tmp_path, "cold-source")
    destination = tmp_path / "existing-destination"
    destination.mkdir()
    before = _tree_digests(source)

    report = backup.run_backup(source, destination)

    assert report.outcome == "refused"
    assert _tree_digests(source) == before, "refused backup changed source database/WAL files"


def test_refused_symlinked_db_does_not_touch_the_file_outside_source(tmp_path):
    """A source whose counselclear.sqlite3 is a symlink must be refused by
    plain filesystem inspection (os.lstat/os.path.islink), never by opening
    the path and following the link into whatever it points at."""
    outside = _uncheckpointed_wal_root(tmp_path, "outside")
    source = tmp_path / "source-with-link"
    source.mkdir()
    (source / drill.DB_NAME).symlink_to(outside / drill.DB_NAME)
    before = _tree_digests(outside)

    report = backup.run_backup(source, tmp_path / "destination")

    assert report.outcome == "refused"
    assert _tree_digests(outside) == before, "symlink target was opened before validation"
    assert not (tmp_path / "destination").exists()


def test_successful_backup_of_a_real_root_preserves_source_with_committed_wal(
    tmp_path, monkeypatch
):
    """Guards against a fix that merely reorders the refusal checks: even a
    backup that goes on to succeed must never have touched --source's
    database, so a real drained root with committed-but-uncheckpointed WAL
    data (a legitimate cold-copy state, not just a synthetic edge case)
    must come out of a *verified* backup byte-identical to how it went in."""
    built = trd._build_release_root(tmp_path, monkeypatch, encrypted=False)
    con = sqlite3.connect(built["root"] / drill.DB_NAME)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("CREATE TABLE synthetic_backup_probe (value TEXT)")
        con.execute("INSERT INTO synthetic_backup_probe VALUES ('committed WAL survives')")
        con.commit()
        source = tmp_path / "cold-release-source"
        shutil.copytree(built["root"], source)
    finally:
        con.close()

    before = _tree_digests(source)
    report = backup.run_backup(source, tmp_path / "accepted-backup")
    assert report.outcome == "verified", report.to_dict()
    assert _tree_digests(source) == before, "successful backup changed source DB/WAL files"


def test_backup_of_a_real_drained_root_round_trips_through_restore(tmp_path, monkeypatch):
    """The full chain a real recovery needs: a real app produces a release,
    backup copies it, restore relocates it into a new root, and the
    restored root actually boots and serves the same packet -- not merely
    a "verified" report at each hop."""
    built = trd._build_release_root(tmp_path, monkeypatch, encrypted=True)
    dest = tmp_path / "backup-1"

    report = backup.run_backup(built["root"], dest)
    assert report.outcome == "verified", (report.refusal, report.failures)
    assert report.copied_files > 0
    assert report.copied_bytes > 0
    assert report.database["active_jobs"] == 0
    assert report.database["active_releases"] == 0
    assert report.database["open_batches"] == 0
    # The original root is untouched -- still there, still whatever it was.
    assert built["root"].exists()

    # Key material is restored separately and supplied explicitly -- it is
    # not part of the backup's --source tree (COUNSELCLEAR_VOLUME_KEY_FILE
    # lives outside the data root by design; see COUNSELCLEAR_BACKUP.md).
    restored_key = tmp_path / "restored-volume.key"
    shutil.copyfile(built["keyfile"], restored_key)
    restored = tmp_path / "restored"
    restore_report = drill.run_drill(
        dest, restored, str(built["root"]), volume_key_file=restored_key
    )
    assert restore_report.outcome == "verified", (
        restore_report.refusal,
        restore_report.failures,
    )

    # The restored root actually boots and serves the packet the original
    # release produced -- not merely a drill report claiming it would.
    from app.main import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setenv("COUNSELCLEAR_VOLUME_KEY_FILE", str(restored_key))
    with TestClient(create_app(restored)) as c:
        assert c.post("/v1/auth/login", json={"password": trd.PASSWORD}).status_code == 200
        packet = c.get(f"/v1/matters/{built['matter']}/jobs/{built['job']}/bundle")
        assert packet.status_code == 200, packet.text
        manifest = c.get(f"/v1/matters/{built['matter']}/jobs/{built['job']}/manifest").json()
        assert manifest["original"]["sha256"] == trd._sha(built["original"])


def test_backup_refuses_an_undrained_source(tmp_path, monkeypatch):
    built = trd._build_release_root(tmp_path, monkeypatch, encrypted=False)
    con = sqlite3.connect(built["root"] / drill.DB_NAME)
    con.execute("UPDATE jobs SET status = 'queued' WHERE id = ?", (built["job"],))
    con.commit()
    con.close()

    dest = tmp_path / "backup-undrained"
    report = backup.run_backup(built["root"], dest)
    assert report.outcome == "refused"
    assert "not drained" in report.refusal
    assert not dest.exists()


def test_backup_keep_on_failure_retains_the_partial_copy(tmp_path, monkeypatch):
    built = trd._build_release_root(tmp_path, monkeypatch, encrypted=False)
    con = sqlite3.connect(built["root"] / drill.DB_NAME)
    con.execute("UPDATE jobs SET status = 'queued' WHERE id = ?", (built["job"],))
    con.commit()
    con.close()

    dest = tmp_path / "backup-kept"
    report = backup.run_backup(built["root"], dest, keep_on_failure=True)
    assert report.outcome == "refused"
    assert dest.exists()


def test_backup_refuses_an_existing_destination(tmp_path, monkeypatch):
    built = trd._build_release_root(tmp_path, monkeypatch, encrypted=False)
    dest = tmp_path / "already-here"
    dest.mkdir()
    report = backup.run_backup(built["root"], dest)
    assert report.outcome == "refused"
    assert "already exists" in report.refusal


def test_cli_writes_report_and_exit_code(tmp_path, monkeypatch, capsys):
    built = trd._build_release_root(tmp_path, monkeypatch, encrypted=False)
    dest = tmp_path / "cli-backup"
    report_path = tmp_path / "report.json"
    code = backup.main(
        ["--source", str(built["root"]), "--destination", str(dest), "--report", str(report_path)]
    )
    assert code == 0
    assert report_path.is_file()
    printed = capsys.readouterr().out
    assert '"outcome": "verified"' in printed
