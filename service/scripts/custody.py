"""Write-once storage primitives and manifest emission (PR 12).

Custody doctrine (design doc):
- The original is immutable. Files are created with O_EXCL and locked to
  mode 0444; writing *different* content to an existing key is refused.
  Re-writing identical content is idempotent (same hash -> same file).
- The derivative always lives at a separate path; there is no in-place mode.

``emit_manifest`` produces the audit record: hashes of original and
derivative, actions taken, processor/tool versions, verification stub and
timestamps. ``write_manifest`` stores it under the same write-once rules.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MANIFEST_VERSION = 1
PRODUCT = "counselclear"

_POLICY_SUFFIX = {
    "external_sharing": "external",
    "privacy_only": "privacy",
    "production": "production",
}


class CustodyError(RuntimeError):
    """Refusal to mutate or weaken existing custody records."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lock_readonly(path: Path) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def write_once(dest: Path, data: bytes) -> tuple[Path, bool]:
    """Create ``dest`` write-once with O_EXCL + 0444.

    Returns ``(path, created)``. Idempotent for identical content;
    raises :class:`CustodyError` on conflicting content or a directory
    collision. A failed write removes only the partial file *this call*
    created — never a file that lost the O_EXCL race to a concurrent writer,
    which belongs to whoever created it and must stay immutable.
    """
    dest = Path(dest).absolute()
    if dest.is_dir():
        raise CustodyError(f"refusing to write a file over a directory: {dest}")
    if dest.exists():
        if sha256_file(dest) == sha256_bytes(data):
            _lock_readonly(dest)
            return dest, False
        raise CustodyError(
            f"write-once violation: {dest} exists with different content"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    except FileExistsError:
        # Lost the O_EXCL race to a concurrent writer: dest is not ours to
        # remove. Defer to the same idempotent/conflict check used above for
        # a pre-existing file.
        if sha256_file(dest) == sha256_bytes(data):
            _lock_readonly(dest)
            return dest, False
        raise CustodyError(
            f"write-once violation: {dest} exists with different content"
        ) from None
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    _lock_readonly(dest)
    return dest, True


def derivative_name(original_name: str, policy_id: str = "external_sharing") -> str:
    """``SPA.docx`` -> ``SPA.external.docx`` (unknown policies -> ``cleaned``)."""
    p = Path(original_name)
    suffix = _POLICY_SUFFIX.get(policy_id, "cleaned")
    return f"{p.stem}.{suffix}{p.suffix}"


def tool_presence(names: tuple[str, ...] = ("qpdf", "exiftool", "c2patool")) -> dict[str, bool]:
    return {name: shutil.which(name) is not None for name in names}


def emit_manifest(
    *,
    original_name: str,
    original_sha256: str,
    original_bytes: int,
    derivative_name_: str,
    derivative_sha256: str,
    derivative_bytes: int,
    policy_id: str,
    actions: list[str],
    processor: dict[str, Any],
    findings_before: list[str] | None = None,
    verification: dict[str, Any] | None = None,
    operator_id: str | None = None,
    matter_id: str | None = None,
    attestation_kind: str = "checkbox",
) -> dict[str, Any]:
    """Build the manifest dict. Downloaded manifests must omit matter names,
    so only ids ever appear here."""
    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "product": PRODUCT,
        "original": {
            "filename": Path(original_name).name,
            "sha256": original_sha256,
            "bytes": original_bytes,
        },
        "derivative": {
            "filename": Path(derivative_name_).name,
            "sha256": derivative_sha256,
            "bytes": derivative_bytes,
        },
        "policy": {"id": policy_id, "version": 1},
        "processor": processor,
        "actions": list(actions),
        "findings_before": list(findings_before or []),
        "verification": dict(verification or {}),
        "timestamps": {
            "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        },
        "attestation_kind": attestation_kind,
    }
    if operator_id is not None:
        manifest["operator"] = {"id": str(operator_id)}
    if matter_id is not None:
        manifest["matter"] = {"id": str(matter_id)}
    return manifest


def write_manifest(out_dir: Path, manifest: dict[str, Any]) -> tuple[Path, bool]:
    """Store ``manifest.json`` inside ``out_dir`` under write-once rules."""
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    return write_once(Path(out_dir) / "manifest.json", payload.encode("utf-8"))
