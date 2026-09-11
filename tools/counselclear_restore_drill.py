#!/usr/bin/env python3
"""Offline restore drill for a cold LOCAL/SQLite CounselClear data root.

    python tools/counselclear_restore_drill.py \\
        --source /backups/2026-09-11/data \\
        --destination /srv/counselclear/restored \\
        --old-data-root /srv/counselclear/data \\
        --volume-key-file /restored-keys/volume.key \\
        --report /srv/counselclear/restore-2026-09-11.json

``--volume-key-file`` is needed only when originals are encrypted;
``--report`` names a new file outside the snapshot and the restored root.

What it qualifies: that a *cold, drained* snapshot of a local data root can
be copied into a NEW root, its database filesystem references rebased from
the declared old root, and the result verified end to end -- database
integrity, per-matter audit chains, original plaintext hashes and sizes
(decrypting envelopes with explicitly supplied key material), and the
released artifact evidence each terminal job left behind.

What it does not qualify: live backup acquisition (the snapshot is an
input), S3 object storage, PostgreSQL, KMS-wrapped keys, external identity,
or cloud restore. It refuses those rather than claiming them.

Rules the tool holds itself to:

- The source is never opened for writing and never modified. Every file is
  copied byte-for-byte into the destination and the copy is digest-checked
  before anything opens it. The database is opened only in the destination.
- Only the three known filesystem references are rebased:
  ``documents.storage_path``, ``jobs.bundle_dir`` and
  ``jobs.execution_receipt.output_dir``. Every other row -- audit events,
  release rows, certificate snapshots, attestation uses -- is left exactly
  as copied, and a digest over those tables is proven unchanged. Signed
  JSON on disk is never rewritten.
- A reference that is not an absolute path under the declared old root,
  that contains ``..`` segments, or that would resolve outside the new root
  is a refusal, not a best effort. So is any symlink in the snapshot.
- Queued or running work in the snapshot is a refusal: the drill restores
  drained state, it does not resume execution.
- Key material is supplied, never generated. An encrypted original with no
  key, a key file that does not exist, or an envelope sealed under a KMS
  key id is a refusal. No key bytes, password hashes, or cookie secrets are
  printed or written to the report.
- On any refusal or failure after the destination was created, the
  destination is removed again (``--keep-on-failure`` retains it for
  inspection).

Exit status: 0 verified, 2 refused (precondition), 3 verification failed,
1 unexpected error.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "service", ROOT / "service" / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2
EXIT_FAILED = 3

DB_NAME = "counselclear.sqlite3"
DB_SIDECARS = (f"{DB_NAME}-wal", f"{DB_NAME}-shm", f"{DB_NAME}-journal")
ENVELOPE_MAGIC = b"CCENC"
ACTIVE_JOB_STATES = ("queued", "running")
# Tables whose rows the drill must leave exactly as copied.
PRESERVED_TABLES = (
    "matters",
    "matter_acl",
    "audit_events",
    "attestation_uses",
    "batches",
    "releases",
    "job_queue",
    "alembic_version",
)


class Refused(Exception):
    """A precondition failed; nothing about the snapshot was judged."""


class VerificationFailed(Exception):
    """The restore completed but the restored state did not verify."""


@dataclass
class DrillReport:
    source: str
    destination: str
    old_data_root: str
    outcome: str = "incomplete"
    exit_code: int = EXIT_ERROR
    refusal: str | None = None
    failures: list[str] = field(default_factory=list)
    copied_files: int = 0
    copied_bytes: int = 0
    database: dict[str, Any] = field(default_factory=dict)
    references: dict[str, Any] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=dict)
    originals: dict[str, Any] = field(default_factory=dict)
    releases: dict[str, Any] = field(default_factory=dict)
    auth: dict[str, Any] = field(default_factory=dict)
    key_material: dict[str, Any] = field(default_factory=dict)
    destination_removed: bool = False
    scope: dict[str, Any] = field(
        default_factory=lambda: {
            "qualifies": "cold local data-root restore into a new root (LOCAL storage, SQLite)",
            "does_not_qualify": [
                "live backup acquisition",
                "S3 object storage",
                "PostgreSQL",
                "KMS-wrapped key material",
                "external identity providers",
                "cloud restore",
            ],
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "old_data_root": self.old_data_root,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "refusal": self.refusal,
            "failures": list(self.failures),
            "copied_files": self.copied_files,
            "copied_bytes": self.copied_bytes,
            "database": self.database,
            "references": self.references,
            "audit": self.audit,
            "originals": self.originals,
            "releases": self.releases,
            "auth": self.auth,
            "key_material": self.key_material,
            "destination_removed": self.destination_removed,
            "scope": self.scope,
        }


# --- helpers ---------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RootMapper:
    """Rebase absolute references from the declared old root to the new one.

    The old root's path flavour (Windows or POSIX) decides how references
    are parsed, so a snapshot taken on one platform can be restored on
    another. Every component of the relative remainder is checked: no
    empty, ``.`` or ``..`` segments, and the rebased path must resolve
    inside the new root.
    """

    def __init__(self, old_root: str, new_root: Path) -> None:
        text = old_root.strip()
        if not text:
            raise Refused("--old-data-root must be declared explicitly; it is not inferred")
        self.windows = "\\" in text or (len(text) >= 2 and text[1] == ":")
        pure = PureWindowsPath(text) if self.windows else PurePosixPath(text)
        if not pure.is_absolute():
            raise Refused("--old-data-root must be an absolute path")
        self.old = pure
        self.new_root = new_root
        self._new_resolved = new_root.resolve()

    def _pure(self, ref: str):
        return PureWindowsPath(ref) if self.windows else PurePosixPath(ref)

    def is_absolute_reference(self, ref: str) -> bool:
        return isinstance(ref, str) and bool(ref) and self._pure(ref).is_absolute()

    def rebase(self, ref: str, *, column: str) -> Path:
        if not isinstance(ref, str) or not ref:
            raise Refused(f"{column}: empty reference")
        pure = self._pure(ref)
        if not pure.is_absolute():
            raise Refused(f"{column}: reference is not an absolute path")
        try:
            relative = pure.relative_to(self.old)
        except ValueError:
            raise Refused(f"{column}: reference is outside the declared old data root") from None
        parts = relative.parts
        if not parts:
            raise Refused(f"{column}: reference is the data root itself")
        for part in parts:
            if part in ("", ".", "..") or "\x00" in part:
                raise Refused(f"{column}: reference contains an unsafe path segment")
            if not self.windows and "\\" in part:
                # A POSIX name containing a backslash would become a
                # directory separator on a Windows host; refuse rather than
                # restore into a different tree.
                raise Refused(f"{column}: reference contains a backslash in a POSIX segment")
        new = self.new_root.joinpath(*parts)
        try:
            new.resolve(strict=False).relative_to(self._new_resolved)
        except ValueError:
            raise Refused(f"{column}: rebased reference escapes the new data root") from None
        return new


def _digest_tables(con: sqlite3.Connection, tables: tuple[str, ...]) -> dict[str, str]:
    """A digest of every row in every preserved table, in rowid order, so
    the drill can prove its own updates touched nothing else."""
    out: dict[str, str] = {}
    for table in tables:
        exists = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if not exists:
            continue
        digest = hashlib.sha256()
        for row in con.execute(f'SELECT * FROM "{table}" ORDER BY rowid'):  # noqa: S608 - name from constant
            digest.update(repr(tuple(row)).encode("utf-8"))
            digest.update(b"\n")
        out[table] = digest.hexdigest()
    return out


def _envelope_key_id(data: bytes) -> str | None:
    """Key id named by a CCENC envelope header, or None for plaintext."""
    if not data.startswith(ENVELOPE_MAGIC):
        return None
    if len(data) < len(ENVELOPE_MAGIC) + 2:
        return "<truncated>"
    kid_len = data[len(ENVELOPE_MAGIC) + 1]
    start = len(ENVELOPE_MAGIC) + 2
    return data[start : start + kid_len].decode("utf-8", errors="replace")


# --- phases ----------------------------------------------------------------


def _preflight(source: Path, destination: Path, report: DrillReport) -> list[Path]:
    if os.environ.get("COUNSELCLEAR_DATABASE_URL", "").strip():
        url = os.environ["COUNSELCLEAR_DATABASE_URL"].strip()
        if not url.startswith("sqlite"):
            raise Refused(
                "COUNSELCLEAR_DATABASE_URL points at a non-SQLite database; this drill "
                "restores the SQLite file inside the data root only"
            )
    if os.environ.get("COUNSELCLEAR_STORAGE", "").strip().lower() not in ("", "local"):
        raise Refused("COUNSELCLEAR_STORAGE is not local; this drill restores LOCAL storage only")
    if not source.is_dir():
        raise Refused(f"source is not a directory: {source}")
    if source.is_symlink():
        raise Refused("source path is a symlink")
    if destination.exists():
        raise Refused(f"destination already exists: {destination}")
    if not destination.parent.is_dir():
        raise Refused(f"destination parent does not exist: {destination.parent}")
    src_res = source.resolve()
    dst_res = destination.parent.resolve() / destination.name
    if dst_res == src_res or dst_res.is_relative_to(src_res) or src_res.is_relative_to(dst_res):
        raise Refused("source and destination must not be nested in each other")
    if not (source / DB_NAME).is_file():
        raise Refused(f"snapshot has no {DB_NAME}; not a local data root")

    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        here = Path(dirpath)
        for name in dirnames:
            if (here / name).is_symlink():
                raise Refused(
                    f"snapshot contains a symlinked directory: {(here / name).relative_to(source)}"
                )
        for name in filenames:
            path = here / name
            st = os.lstat(path)
            if os.path.islink(path):
                raise Refused(f"snapshot contains a symlink: {path.relative_to(source)}")
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"snapshot contains a non-regular file: {path.relative_to(source)}")
            files.append(path)
    return files


def _copy_tree(source: Path, destination: Path, files: list[Path], report: DrillReport) -> None:
    """Copy into an already-created, empty destination the caller owns."""
    total = 0
    for src in files:
        rel = src.relative_to(source)
        dst = destination / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst, follow_symlinks=False)
        if _sha256_file(src) != _sha256_file(dst):
            raise VerificationFailed(f"copy of {rel} does not match the source bytes")
        shutil.copystat(src, dst, follow_symlinks=False)
        total += dst.stat().st_size
    report.copied_files = len(files)
    report.copied_bytes = total


def _open_database(destination: Path, report: DrillReport) -> sqlite3.Connection:
    db = destination / DB_NAME
    wal = destination / f"{DB_NAME}-wal"
    info: dict[str, Any] = {
        "path": str(db),
        "wal_present_in_snapshot": wal.exists(),
        "wal_bytes_in_snapshot": wal.stat().st_size if wal.exists() else 0,
    }
    # The sidecar files may be read-only copies of a stopped process's
    # state; SQLite needs to write them to recover and checkpoint.
    for name in (DB_NAME, *DB_SIDECARS):
        path = destination / name
        if path.exists():
            os.chmod(path, 0o600)
    con = sqlite3.connect(db, isolation_level=None)
    con.row_factory = sqlite3.Row
    integrity = [row[0] for row in con.execute("PRAGMA integrity_check")]
    info["integrity_check"] = integrity[:5]
    if integrity != ["ok"]:
        raise VerificationFailed(f"database integrity check failed: {integrity[:3]}")
    info["journal_mode_in_snapshot"] = con.execute("PRAGMA journal_mode").fetchone()[0]
    if info["wal_present_in_snapshot"]:
        checkpoint = con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        info["wal_checkpoint"] = list(checkpoint)
    version = con.execute("SELECT version_num FROM alembic_version").fetchone()
    info["alembic_version"] = version[0] if version else None
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for required in ("documents", "jobs", "audit_events", "matters", "releases"):
        if required not in tables:
            raise Refused(f"database lacks the {required} table; not a CounselClear data root")
    report.database = info
    return con


def _check_drained(con: sqlite3.Connection, report: DrillReport) -> None:
    active_jobs = [
        (row["id"], row["status"])
        for row in con.execute(
            "SELECT id, status FROM jobs WHERE status IN (?, ?)", ACTIVE_JOB_STATES
        )
    ]
    active_releases = [
        (row["id"], row["status"])
        for row in con.execute(
            "SELECT id, status FROM releases WHERE status IN (?, ?)", ACTIVE_JOB_STATES
        )
    ]
    open_batches = [
        row["id"] for row in con.execute("SELECT id FROM batches WHERE finished_utc IS NULL")
    ]
    report.database["active_jobs"] = len(active_jobs)
    report.database["active_releases"] = len(active_releases)
    report.database["open_batches"] = len(open_batches)
    if active_jobs or active_releases or open_batches:
        raise Refused(
            "snapshot is not drained: "
            f"{len(active_jobs)} queued/running jobs, {len(active_releases)} queued/running "
            f"releases, {len(open_batches)} unfinished batches"
        )


def _rebase_references(
    con: sqlite3.Connection, mapper: RootMapper, destination: Path, report: DrillReport
) -> dict[str, Any]:
    before = _digest_tables(con, PRESERVED_TABLES)
    documents: dict[str, dict[str, Any]] = {}
    jobs: dict[str, dict[str, Any]] = {}
    updates: list[tuple[str, str, str]] = []

    for row in con.execute("SELECT id, filename, storage_path, sha256, bytes FROM documents"):
        ref = row["storage_path"]
        if not isinstance(ref, str) or not ref:
            raise Refused(f"documents.storage_path: document {row['id']} has no reference")
        if ref.startswith("s3v1:") or not mapper.is_absolute_reference(ref):
            raise Refused(
                "documents.storage_path: object-storage (S3) references present; this drill "
                "restores LOCAL storage only"
            )
        new = mapper.rebase(ref, column="documents.storage_path")
        documents[row["id"]] = {
            "path": new,
            "filename": row["filename"],
            "sha256": row["sha256"],
            "bytes": row["bytes"],
        }
        updates.append(("documents", row["id"], str(new)))

    receipt_updates: list[tuple[str, str]] = []
    for row in con.execute(
        "SELECT id, document_id, kind, status, bundle_dir, execution_receipt, result_json FROM jobs"
    ):
        entry: dict[str, Any] = {
            "document_id": row["document_id"],
            "kind": row["kind"],
            "status": row["status"],
            "bundle": None,
            "output_dir": None,
            "result_json": row["result_json"],
        }
        if row["bundle_dir"]:
            entry["bundle"] = mapper.rebase(row["bundle_dir"], column="jobs.bundle_dir")
            updates.append(("jobs", row["id"], str(entry["bundle"])))
        receipt_text = row["execution_receipt"]
        if receipt_text:
            try:
                receipt = json.loads(receipt_text)
            except ValueError:
                raise Refused(
                    f"jobs.execution_receipt: job {row['id']} is not valid JSON"
                ) from None
            if isinstance(receipt, dict) and receipt.get("output_dir"):
                entry["output_dir"] = mapper.rebase(
                    receipt["output_dir"], column="jobs.execution_receipt.output_dir"
                )
                receipt["output_dir"] = str(entry["output_dir"])
                receipt_updates.append((row["id"], json.dumps(receipt)))
        jobs[row["id"]] = entry

    con.execute("BEGIN")
    try:
        for table, row_id, value in updates:
            column = "storage_path" if table == "documents" else "bundle_dir"
            con.execute(f'UPDATE "{table}" SET {column} = ? WHERE id = ?', (value, row_id))  # noqa: S608 - constants
        for row_id, text in receipt_updates:
            con.execute("UPDATE jobs SET execution_receipt = ? WHERE id = ?", (text, row_id))
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    after = _digest_tables(con, PRESERVED_TABLES)
    if before != after:
        raise VerificationFailed("rebase changed rows outside the known reference columns")

    stale = 0
    old_text = str(mapper.old)
    for table, column in (
        ("documents", "storage_path"),
        ("jobs", "bundle_dir"),
        ("jobs", "execution_receipt"),
    ):
        stale += con.execute(
            f'SELECT COUNT(*) FROM "{table}" WHERE {column} LIKE ?',  # noqa: S608 - constants
            (f"{old_text}%",),
        ).fetchone()[0]
    report.references = {
        "documents_rebased": len(documents),
        "bundle_dirs_rebased": sum(1 for j in jobs.values() if j["bundle"] is not None),
        "receipt_output_dirs_rebased": len(receipt_updates),
        "old_root_mentions_remaining_in_reference_columns": stale,
        "preserved_tables_digest_unchanged": True,
        "preserved_tables": sorted(after),
    }
    if stale:
        raise VerificationFailed("old data root still present in a reference column after rebase")
    return {"documents": documents, "jobs": jobs}


def _verify_audit(con: sqlite3.Connection, report: DrillReport) -> None:
    from app.audit import verify_chain

    per_matter: dict[str, list[SimpleNamespace]] = {}
    for row in con.execute(
        "SELECT matter_id, seq, prev_hash, actor_id, action, payload, row_hash FROM audit_events"
    ):
        payload = row["payload"]
        try:
            payload_obj = json.loads(payload) if isinstance(payload, str) else (payload or {})
        except ValueError:
            raise VerificationFailed(
                f"audit event payload is not valid JSON (matter {row['matter_id']}, seq {row['seq']})"
            ) from None
        per_matter.setdefault(row["matter_id"], []).append(
            SimpleNamespace(
                seq=row["seq"],
                prev_hash=row["prev_hash"],
                actor_id=row["actor_id"],
                action=row["action"],
                payload=payload_obj,
                row_hash=row["row_hash"],
            )
        )
    matters = [row["id"] for row in con.execute("SELECT id FROM matters")]
    results: dict[str, str] = {}
    broken: list[str] = []
    for matter_id in matters:
        ok, detail = verify_chain(per_matter.get(matter_id, []))
        results[matter_id] = detail
        if not ok:
            broken.append(f"{matter_id}: {detail}")
    orphaned = sorted(set(per_matter) - set(matters))
    report.audit = {
        "matters": len(matters),
        "events": sum(len(v) for v in per_matter.values()),
        "chains": results,
        "orphaned_event_matters": orphaned,
    }
    if broken:
        raise VerificationFailed("audit chain verification failed: " + "; ".join(broken))
    if orphaned:
        raise VerificationFailed("audit events reference matters that do not exist")


def _load_keyring(volume_key_file: Path | None, report: DrillReport):
    if volume_key_file is None:
        report.key_material = {"volume_key_file": None, "supplied": False}
        return None
    if volume_key_file.is_symlink():
        raise Refused("--volume-key-file must not be a symlink")
    if not volume_key_file.is_file():
        # LocalKeyring would create a fresh key here; a restore must never
        # manufacture key material it did not receive.
        raise Refused(f"--volume-key-file does not exist: {volume_key_file}")
    size = volume_key_file.stat().st_size
    if size != 32:
        raise Refused(f"--volume-key-file must contain 32 bytes, got {size}")
    from app.storage import LocalKeyring

    report.key_material = {"volume_key_file": str(volume_key_file), "supplied": True, "used": False}
    return LocalKeyring(volume_key_file)


def _verify_originals(
    destination: Path, documents: dict[str, dict[str, Any]], keyring, report: DrillReport
) -> None:
    from app.storage import EncryptedStorage, LocalStorage, StorageError

    local = LocalStorage(destination)
    encrypted_backend = EncryptedStorage(local, keyring) if keyring is not None else None
    checked = 0
    encrypted = 0
    failures: list[str] = []
    for doc_id, doc in documents.items():
        path: Path = doc["path"]
        if not path.is_file():
            failures.append(f"document {doc_id}: original missing at restored path")
            continue
        head = path.read_bytes()
        kid = _envelope_key_id(head)
        if kid is None:
            plain = head
        else:
            encrypted += 1
            if kid != "local":
                raise Refused(
                    f"document {doc_id}: original is sealed under key id {kid!r}; this drill "
                    "can only open envelopes sealed with the local volume key"
                )
            if encrypted_backend is None:
                raise Refused(
                    "encrypted originals present but no --volume-key-file was supplied; "
                    "the drill does not infer or generate key material"
                )
            report.key_material["used"] = True
            try:
                plain = encrypted_backend.read(str(path))
            except StorageError as exc:
                failures.append(f"document {doc_id}: envelope did not open ({exc})")
                continue
        if len(plain) != doc["bytes"] or _sha256_bytes(plain) != doc["sha256"]:
            failures.append(f"document {doc_id}: plaintext differs from recorded hash or size")
            continue
        checked += 1
    report.originals = {
        "documents": len(documents),
        "verified": checked,
        "encrypted": encrypted,
        "plaintext": len(documents) - encrypted,
    }
    if failures:
        raise VerificationFailed("original verification failed: " + "; ".join(failures))


def _confined_child(base: Path, name: object, *, what: str, job_id: str) -> Path:
    """``base/name`` where ``name`` must be a plain file name that stays
    inside ``base`` after resolution. Manifests are signed evidence and are
    never rewritten, so a manifest that names a path is a failure, not a
    correction."""
    if not isinstance(name, str) or not name or name in (".", ".."):
        raise VerificationFailed(f"job {job_id}: {what} is not a file name")
    if "/" in name or "\\" in name or "\x00" in name or Path(name).is_absolute():
        raise VerificationFailed(f"job {job_id}: {what} is a path, not a confined file name")
    candidate = base / name
    try:
        candidate.resolve(strict=False).relative_to(base.resolve())
    except ValueError:
        raise VerificationFailed(f"job {job_id}: {what} escapes its bundle directory") from None
    return candidate


def _json_object(text: object, *, what: str, job_id: str) -> dict[str, Any]:
    if isinstance(text, dict):
        return text
    if not isinstance(text, str) or not text:
        raise VerificationFailed(f"job {job_id}: {what} is missing")
    try:
        value = json.loads(text)
    except ValueError:
        raise VerificationFailed(f"job {job_id}: {what} is not valid JSON") from None
    if not isinstance(value, dict):
        raise VerificationFailed(f"job {job_id}: {what} is not a JSON object")
    return value


def _verify_sanitize_bundle(
    job_id: str, job: dict[str, Any], documents: dict[str, dict[str, Any]], destination: Path
) -> None:
    bundle: Path | None = job["bundle"]
    if bundle is None:
        raise VerificationFailed(f"job {job_id}: done sanitize job records no bundle_dir")
    try:
        bundle.resolve(strict=False).relative_to(destination.resolve())
    except ValueError:
        raise VerificationFailed(f"job {job_id}: bundle_dir escapes the restored root") from None
    if not bundle.is_dir():
        raise VerificationFailed(f"job {job_id}: bundle or manifest.json missing after restore")
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise VerificationFailed(f"job {job_id}: bundle or manifest.json missing after restore")
    manifest = _json_object(
        manifest_path.read_bytes().decode("utf-8", "replace"), what="manifest.json", job_id=job_id
    )
    derivative = manifest.get("derivative")
    original = manifest.get("original")
    if not isinstance(derivative, dict) or not isinstance(original, dict):
        raise VerificationFailed(f"job {job_id}: manifest lacks original/derivative records")

    derivative_dir = bundle / "derivative"
    if not derivative_dir.is_dir():
        raise VerificationFailed(f"job {job_id}: derivative named in manifest is missing")
    deriv_path = _confined_child(
        derivative_dir,
        derivative.get("filename"),
        what="manifest derivative filename",
        job_id=job_id,
    )
    if not deriv_path.is_file() or deriv_path.is_symlink():
        raise VerificationFailed(f"job {job_id}: derivative named in manifest is missing")
    present = sorted(p.name for p in derivative_dir.iterdir())
    if present != [deriv_path.name]:
        raise VerificationFailed(
            f"job {job_id}: derivative directory must contain exactly the declared derivative"
        )
    deriv_bytes = deriv_path.read_bytes()
    if len(deriv_bytes) != derivative.get("bytes") or _sha256_bytes(deriv_bytes) != derivative.get(
        "sha256"
    ):
        raise VerificationFailed(f"job {job_id}: derivative differs from manifest digest or size")
    if not (bundle / "report.html").is_file():
        raise VerificationFailed(f"job {job_id}: report.html missing from bundle")

    doc = documents.get(job["document_id"])
    if doc is None:
        raise VerificationFailed(f"job {job_id}: document row is missing")
    if original.get("sha256") != doc["sha256"] or original.get("bytes") != doc["bytes"]:
        raise VerificationFailed(f"job {job_id}: manifest original does not match the document row")

    result = _json_object(job["result_json"], what="result_json", job_id=job_id)
    if result.get("manifest") != manifest:
        raise VerificationFailed(
            f"job {job_id}: result_json manifest differs from the stored manifest"
        )
    if (
        result.get("verification_pass") is not True
        or (manifest.get("verification") or {}).get("pass") is not True
    ):
        raise VerificationFailed(
            f"job {job_id}: sanitize result does not carry a passing verification"
        )

    output_dir: Path | None = job["output_dir"]
    if output_dir is not None:
        try:
            output_dir.resolve(strict=False).relative_to(destination.resolve())
        except ValueError:
            raise VerificationFailed(
                f"job {job_id}: execution receipt output_dir escapes the restored root"
            ) from None
        result_file = output_dir / "result.json"
        if not result_file.is_file():
            raise VerificationFailed(
                f"job {job_id}: execution receipt output_dir lacks result.json"
            )
        payload = _json_object(
            result_file.read_bytes().decode("utf-8", "replace"),
            what="worker result.json",
            job_id=job_id,
        )
        worker_result = payload.get("result")
        if not isinstance(worker_result, dict) or worker_result.get("manifest") != manifest:
            raise VerificationFailed(
                f"job {job_id}: worker result.json manifest differs from bundle"
            )


def _verify_releases(
    con: sqlite3.Connection,
    documents: dict[str, dict[str, Any]],
    jobs: dict[str, dict[str, Any]],
    destination: Path,
    report: DrillReport,
) -> None:
    """Every done sanitize job must carry its complete bundle evidence, every
    done inspect job a findings result, and every done release a done
    sanitize job whose bundle verified. Malformed result types fail; the
    job kind is read from the row, never guessed from the result."""
    failures: list[str] = []
    verified_sanitize: set[str] = set()
    done_jobs = 0
    for job_id, job in jobs.items():
        if job["status"] != "done":
            continue
        done_jobs += 1
        try:
            if job["kind"] == "sanitize":
                _verify_sanitize_bundle(job_id, job, documents, destination)
                verified_sanitize.add(job_id)
            elif job["kind"] == "inspect":
                if job["bundle"] is not None:
                    raise VerificationFailed(f"job {job_id}: inspect job records a bundle_dir")
                result = _json_object(job["result_json"], what="result_json", job_id=job_id)
                if not isinstance(result.get("findings"), list):
                    raise VerificationFailed(f"job {job_id}: inspect result lacks a findings list")
            else:
                raise VerificationFailed(f"job {job_id}: unknown job kind {job['kind']!r}")
        except VerificationFailed as exc:
            failures.append(str(exc))

    releases = list(con.execute("SELECT id, job_id, status, certificate_snapshot FROM releases"))
    done_releases = 0
    snapshots = 0
    for row in releases:
        if row["status"] != "done":
            continue
        done_releases += 1
        job = jobs.get(row["job_id"])
        if job is None or job["status"] != "done" or job["kind"] != "sanitize":
            failures.append(f"release {row['id']}: done without a done sanitize job")
            continue
        if row["job_id"] not in verified_sanitize:
            failures.append(f"release {row['id']}: its job's bundle evidence did not verify")
            continue
        snapshot = row["certificate_snapshot"]
        if not snapshot:
            failures.append(f"release {row['id']}: done release has no certificate snapshot")
            continue
        try:
            parsed = json.loads(snapshot)
        except ValueError:
            failures.append(f"release {row['id']}: certificate snapshot is not valid JSON")
            continue
        if not isinstance(parsed, dict) or not parsed.get("html"):
            failures.append(f"release {row['id']}: certificate snapshot lacks html")
            continue
        snapshots += 1
    report.releases = {
        "jobs_done": done_jobs,
        "bundles_verified": len(verified_sanitize),
        "releases": len(releases),
        "releases_done": done_releases,
        "certificate_snapshots_present": snapshots,
        "note": "certificate snapshots and release rows are carried byte-for-byte; the "
        "packet signature itself is re-verified by the offline verifier on a downloaded packet",
    }
    if failures:
        raise VerificationFailed("release evidence verification failed: " + "; ".join(failures))


def _verify_auth(destination: Path, report: DrillReport, *, custody_depends_on_key: bool) -> None:
    """Report the auth directory by presence and size only, and require the
    custody signing key to exist and load when any release custody depends
    on it. The application generates a replacement identity at first use
    when the PEM is missing; a restore that silently allows that would
    change the signer of every future packet."""
    auth = destination / "auth"
    info: dict[str, Any] = {"present": auth.is_dir(), "files": {}}
    if auth.is_dir():
        for path in sorted(auth.iterdir()):
            if path.is_file():
                info["files"][path.name] = {"bytes": path.stat().st_size}
    pem = auth / "custody_signing_key.pem"
    info["custody_signing_key_present"] = pem.is_file()
    info["custody_signing_key_fingerprint"] = None
    problem: str | None = None
    if pem.is_file():
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            key = serialization.load_pem_private_key(pem.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                problem = "custody signing key is not an Ed25519 private key"
            else:
                public = key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                info["custody_signing_key_fingerprint"] = _sha256_bytes(public)
        except Exception as exc:  # the key is opaque to the drill; report the class only
            problem = f"custody signing key did not load ({type(exc).__name__})"
    else:
        problem = "custody signing key is missing"
    info["local_password_hash_present"] = (auth / "local.hash").is_file()
    info["custody_depends_on_signing_key"] = custody_depends_on_key
    report.auth = info
    if problem and custody_depends_on_key:
        raise VerificationFailed(
            f"{problem}; the application would generate a replacement signing identity on "
            "boot, which release custody cannot survive"
        )
    if problem:
        info["warning"] = problem


# --- driver ------------------------------------------------------------------


def _remove_tree(path: Path) -> bool:
    """Remove a destination the drill created. Read-only members (write-once
    originals, Windows attributes) are made writable first. Returns whether
    the path is gone afterwards; never raises."""

    def _on_error(func, target, _exc):
        with contextlib.suppress(OSError):
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            os.chmod(Path(target).parent, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            func(target)

    with contextlib.suppress(OSError):
        for dirpath, dirnames, filenames in os.walk(path):
            for name in (*dirnames, *filenames):
                with contextlib.suppress(OSError):
                    os.chmod(Path(dirpath) / name, 0o700)
        shutil.rmtree(path, onexc=_on_error)
    return not path.exists()


def run_drill(
    source: Path,
    destination: Path,
    old_data_root: str,
    *,
    volume_key_file: Path | None = None,
    keep_on_failure: bool = False,
) -> DrillReport:
    source = Path(source)
    destination = Path(destination)
    report = DrillReport(str(source), str(destination), old_data_root)
    created = False
    con: sqlite3.Connection | None = None
    try:
        files = _preflight(source, destination, report)
        mapper = RootMapper(old_data_root, destination)
        keyring = _load_keyring(volume_key_file, report)
        destination.mkdir(parents=False, exist_ok=False)
        created = True  # from here on, every failure path removes the destination
        _copy_tree(source, destination, files, report)
        con = _open_database(destination, report)
        _check_drained(con, report)
        refs = _rebase_references(con, mapper, destination, report)
        _verify_audit(con, report)
        _verify_originals(destination, refs["documents"], keyring, report)
        _verify_releases(con, refs["documents"], refs["jobs"], destination, report)
        custody_depends_on_key = bool(
            con.execute("SELECT 1 FROM releases WHERE status = 'done' LIMIT 1").fetchone()
        ) or any(j["status"] == "done" and j["kind"] == "sanitize" for j in refs["jobs"].values())
        _verify_auth(destination, report, custody_depends_on_key=custody_depends_on_key)
        con.close()
        con = None
        report.outcome = "verified"
        report.exit_code = EXIT_OK
    except Refused as exc:
        report.outcome = "refused"
        report.refusal = str(exc)
        report.exit_code = EXIT_REFUSED
    except VerificationFailed as exc:
        report.outcome = "failed"
        report.failures.append(str(exc))
        report.exit_code = EXIT_FAILED
    except BaseException:
        # Unexpected errors propagate to the caller, but never leave a
        # half-written destination behind.
        report.outcome = "error"
        report.exit_code = EXIT_ERROR
        raise
    finally:
        if con is not None:
            con.close()
        if created and report.exit_code != EXIT_OK and not keep_on_failure:
            report.destination_removed = _remove_tree(destination)
            if not report.destination_removed:
                report.failures.append(
                    "destination could not be removed after failure; inspect and delete it manually"
                )
    return report


def validate_report_path(
    report_path: Path | None, source: Path, destination: Path, volume_key_file: Path | None
) -> Path | None:
    """The report is written to a new file only, never over an existing one,
    never inside the snapshot, the restored root, or beside the key file."""
    if report_path is None:
        return None
    target = Path(report_path)
    if target.exists() or target.is_symlink():
        raise Refused(f"--report must be a new path; {target} already exists")
    resolved = Path(os.path.abspath(target))
    for label, forbidden in (
        ("the source snapshot", Path(os.path.abspath(source))),
        ("the destination root", Path(os.path.abspath(destination))),
        (
            "the volume key file's directory",
            volume_key_file.parent.resolve() if volume_key_file is not None else None,
        ),
    ):
        if forbidden is not None and (resolved == forbidden or resolved.is_relative_to(forbidden)):
            raise Refused(f"--report must not be written inside {label}")
    if not target.parent.is_dir():
        raise Refused(f"--report parent directory does not exist: {target.parent}")
    return target


def _write_report(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--source", required=True, type=Path, help="cold snapshot of a data root")
    parser.add_argument("--destination", required=True, type=Path, help="new root; must not exist")
    parser.add_argument(
        "--old-data-root",
        required=True,
        help="absolute data root the snapshot's database references were written under",
    )
    parser.add_argument(
        "--volume-key-file",
        type=Path,
        default=None,
        help="restored 32-byte volume key for encrypted originals (never generated)",
    )
    parser.add_argument("--report", type=Path, default=None, help="write the JSON report here")
    parser.add_argument(
        "--keep-on-failure",
        action="store_true",
        help="leave the destination in place after a refusal or failure",
    )
    args = parser.parse_args(argv)

    try:
        report_path = validate_report_path(
            args.report, args.source, args.destination, args.volume_key_file
        )
    except Refused as exc:
        refusal = DrillReport(str(args.source), str(args.destination), args.old_data_root)
        refusal.outcome, refusal.refusal, refusal.exit_code = "refused", str(exc), EXIT_REFUSED
        print(json.dumps(refusal.to_dict(), indent=2, sort_keys=True))
        return EXIT_REFUSED

    try:
        report = run_drill(
            args.source,
            args.destination,
            args.old_data_root,
            volume_key_file=args.volume_key_file,
            keep_on_failure=args.keep_on_failure,
        )
    except Exception as exc:  # unexpected: report the class, never a secret
        print(f"restore drill error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    text = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if report_path is not None:
        _write_report(report_path, text)
    print(text)
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
