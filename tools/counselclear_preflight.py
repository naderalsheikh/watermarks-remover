#!/usr/bin/env python3
"""Read-only configuration checks for an installed LOCAL/SQLite pilot.

Run with the API's environment and service account. No application startup,
database connection, Docker execution, network request, or key provisioning.
Exit 0 means these configuration checks passed, not production readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from urllib.parse import urlsplit

_STALE_DEFINITIONS_DAYS = 7


def _add_malware_definitions_check(
    add: Callable[[str, str, str], None], setting: Callable[[str, str], str], clam: bool
) -> None:
    """Definition *freshness*, not merely clamscan's presence (that is the
    separate "malware_scanner" check above). Filesystem-only, matching this
    command's own "does not invoke a scanner" promise: it inspects the
    mtime of the well-known daily.cvd/daily.cld files under the configured
    COUNSELCLEAR_CLAMAV_DB_DIR (the directory app.malware.clam_db_dir()
    resolves and the compose cc-freshclam sidecar keeps current) rather
    than running `clamscan --version` to ask it directly."""
    if not clam:
        add("malware_definitions", "not_checked", "clamscan is absent; freshness does not apply.")
        return
    db_dir = setting("CLAMAV_DB_DIR")
    if not db_dir:
        add(
            "malware_definitions",
            "warning",
            "COUNSELCLEAR_CLAMAV_DB_DIR is not set; clamscan uses its own default database "
            "location, whose freshness this command cannot inspect from here. Point it at "
            "the freshclam-updated volume (see compose.yaml's cc-freshclam sidecar) to make "
            "definition freshness checkable.",
        )
        return
    path = Path(db_dir)
    try:
        is_dir = path.is_dir()
    except OSError:
        is_dir = False
    if not is_dir:
        add(
            "malware_definitions",
            "block",
            f"COUNSELCLEAR_CLAMAV_DB_DIR={db_dir!r} does not exist or is not a directory; "
            "app.malware.clam_db_dir() silently falls back to clamscan's own default "
            "location when this is misconfigured, which this command flags rather than "
            "let pass unnoticed.",
        )
        return
    candidates = [path / name for name in ("daily.cvd", "daily.cld")]
    existing = []
    for candidate in candidates:
        try:
            if candidate.is_file():
                existing.append(candidate)
        except OSError:
            continue
    if not existing:
        add(
            "malware_definitions",
            "block",
            f"No daily.cvd/daily.cld found under {db_dir!r}; clamscan would run against "
            "an empty or incomplete database.",
        )
        return
    try:
        newest = max(p.stat().st_mtime for p in existing)
    except OSError:
        add(
            "malware_definitions",
            "block",
            f"daily.cvd/daily.cld under {db_dir!r} exist but could not be read.",
        )
        return
    age_days = (time.time() - newest) / 86400
    stale = age_days > _STALE_DEFINITIONS_DAYS
    add(
        "malware_definitions",
        "warning" if stale else "pass",
        f"Definitions under {db_dir!r} are {age_days:.1f} days old"
        + (
            f" -- older than {_STALE_DEFINITIONS_DAYS} days; confirm the freshclam "
            "sidecar/schedule is actually running."
            if stale
            else "; presence and age checked, not their actual detection coverage."
        ),
    )


def inspect_installation(
    data_root: Path, web_root: Path, *, environ: Mapping[str, str] | None = None, which=None
) -> dict:
    env = os.environ if environ is None else environ
    which = shutil.which if which is None else which
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    def setting(name: str, default: str = "") -> str:
        return env.get("COUNSELCLEAR_" + name, default).strip()

    def readable_file(path: Path, max_size: int | None = None) -> bool:
        try:
            return (
                path.is_file()
                and os.access(path, os.R_OK)
                and (max_size is None or 0 < path.stat().st_size <= max_size)
            )
        except OSError:
            return False

    try:
        usable_root = data_root.is_dir() and os.access(data_root, os.R_OK | os.W_OK | os.X_OK)
    except OSError:
        usable_root = False
    add(
        "data_root",
        "pass" if usable_root else "block",
        "Installed data directory is accessible to this account."
        if usable_root
        else "Use an existing data directory accessible to the API service account.",
    )
    database_override = setting("DATABASE_URL")
    storage_mode = setting("STORAGE", "local").lower()
    local_scope = not database_override and storage_mode in ("", "local")
    add(
        "storage_scope",
        "pass" if local_scope else "block",
        "Embedded SQLite and LOCAL storage selected."
        if local_scope
        else "This preflight covers embedded SQLite and LOCAL storage; remove database "
        "overrides or use a separately qualified deployment procedure.",
    )
    database_present = readable_file(data_root / "counselclear.sqlite3")
    add(
        "database_file",
        "pass" if database_present else "block",
        "Installed SQLite file is readable; contents are not checked."
        if database_present
        else "The installed SQLite file is missing or unreadable; complete installation first.",
    )

    fingerprint = None
    key_path = data_root / "auth" / "custody_signing_key.pem"
    if readable_file(key_path, 65536):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if isinstance(key, Ed25519PrivateKey):
                public = key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                fingerprint = hashlib.sha256(public).hexdigest()
        except (
            Exception
        ):  # Invalid/unsupported key formats must not leak key data or create identity.
            fingerprint = None
    add(
        "signing_identity",
        "pass" if fingerprint else "block",
        "Existing Ed25519 signing identity loads; compare its public fingerprint independently."
        if fingerprint
        else "Existing signing identity is missing, unreadable, or invalid. Restore/provision "
        "it deliberately before using this installation; this command creates no keys.",
    )

    cmk, volume_key = setting("CMK_ARN"), setting("VOLUME_KEY_FILE")
    if cmk:
        add("encryption", "block", "KMS key access/recovery requires separate qualification.")
    elif volume_key:
        path = Path(volume_key)
        valid = readable_file(path, 32)
        if valid:
            try:
                valid = path.stat().st_size == 32
            except OSError:
                valid = False
        add(
            "encryption",
            "pass" if valid else "block",
            "Configured local volume-key file has the required length; decryption is untested."
            if valid
            else "Configured local volume-key file is missing, unreadable, or not 32 bytes. "
            "Recover the existing key; this command creates no replacement.",
        )
    else:
        add(
            "encryption",
            "warning",
            "Application original-store encryption is off. Host protection and backup "
            "protection need a recorded operator decision before matter documents are used.",
        )

    oidc = [setting(name) for name in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET")]
    if any(oidc) and not all(oidc):
        add(
            "authentication",
            "block",
            "OIDC settings are incomplete; the API would use local login.",
        )
    elif all(oidc):
        add(
            "authentication",
            "block",
            "OIDC is configured. This single-operator pilot preflight does not qualify an IdP "
            "or multiuser identity; use the separate SSO acceptance procedure.",
        )
    else:
        local_hash = readable_file(data_root / "auth" / "local.hash", 16384)
        add(
            "authentication",
            "pass" if local_hash else "block",
            "Local password record is present; an actual login still needs rehearsal."
            if local_hash
            else "Installed local password record is missing or unreadable.",
        )
    cookie = setting("COOKIE_SECURE", "auto").lower()
    add(
        "secure_cookie",
        "pass" if cookie == "true" else "warning" if cookie == "auto" else "block",
        "Secure session cookies are required explicitly."
        if cookie == "true"
        else "Automatic Secure cookies depend on correctly trusted HTTPS proxy headers."
        if cookie == "auto"
        else "Set COUNSELCLEAR_COOKIE_SECURE=true for the HTTPS pilot.",
    )

    worker_mode = setting("WORKER_MODE", "subprocess").lower()
    pinned = re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", setting("WORKER_IMAGE")) is not None
    worker_configured = worker_mode == "docker" and pinned and bool(which("docker"))
    add(
        "worker_configuration",
        "pass" if worker_configured else "block",
        "Docker executable and digest-pinned worker reference are present; daemon/image "
        "availability and isolation are not tested."
        if worker_configured
        else "Pilot processing requires Docker mode, an installed Docker executable, and "
        "COUNSELCLEAR_WORKER_IMAGE pinned with @sha256. Subprocess mode is development only.",
    )
    clam = bool(which("clamscan"))
    add(
        "malware_scanner",
        "pass" if clam else "block",
        "clamscan is installed; definition freshness and a scan still need rehearsal."
        if clam
        else "clamscan is absent; the API would fall back to archive-depth checks only.",
    )
    _add_malware_definitions_check(add, setting, clam)
    for name, default, minimum, maximum in (
        ("WORKER_TIMEOUT_S", "600", 1, None),
        ("BATCH_MAX_CONCURRENT", "4", 1, None),
        ("JOB_LEASE_S", "30", 3, None),
        ("JOB_MAX_ATTEMPTS", "3", 1, None),
    ):
        raw = setting(name, default)
        try:
            value = int(raw)
            valid = value >= minimum and (maximum is None or value <= maximum)
        except ValueError:
            valid = False
        add(
            name.lower(),
            "pass" if valid else "block",
            "Explicit/default numeric setting is valid."
            if valid
            else f"COUNSELCLEAR_{name} is invalid; the API would silently clamp or default it.",
        )

    tsa = env.get("COUNSELCLEAR_TSA_URL")
    if tsa is None:
        add(
            "timestamp_policy",
            "block",
            "Choose COUNSELCLEAR_TSA_URL explicitly; unset uses a public TSA.",
        )
    elif tsa.strip().lower() in ("", "none", "off", "disabled"):
        add("timestamp_policy", "pass", "External timestamp requests are explicitly disabled.")
    else:
        try:
            parsed = urlsplit(tsa.strip())
            valid_tsa = parsed.scheme in ("http", "https") and bool(parsed.hostname)
        except ValueError:
            valid_tsa = False
        add(
            "timestamp_policy",
            "pass" if valid_tsa else "block",
            "A timestamp endpoint is explicitly selected; availability/trust are untested."
            if valid_tsa
            else "Configured timestamp endpoint is not an HTTP(S) URL.",
        )

    web_present = (
        readable_file(web_root / "index.html")
        and any(
            readable_file(p) for p in (web_root / "login.html", web_root / "login" / "index.html")
        )
        and (web_root / "_next" / "static").is_dir()
    )
    add(
        "web_export",
        "pass" if web_present else "block",
        "Static home/login pages and asset directory are present; HTTP serving is untested."
        if web_present
        else "Static export is incomplete; build the web app and select its installed export directory.",
    )
    for name, detail in (
        (
            "https_proxy",
            "Rehearse HTTPS, proxy routing, cookies and logout against the actual deployment.",
        ),
        (
            "document_workflow",
            "Rehearse a synthetic upload, inspect, release, refusal and packet verification.",
        ),
        (
            "backup_restore",
            "Rehearse a cold backup (tools/counselclear_backup.py) then restore "
            "(tools/counselclear_restore_drill.py) with independently preserved keys, "
            "and verify old packets.",
        ),
        (
            "runtime_dependencies",
            "Verify Docker/image execution, scanner definitions, writable capacity and DB migrations.",
        ),
    ):
        add(name, "not_checked", detail)
    blocked = any(c["status"] == "block" for c in checks)
    return {
        "schema_version": 1,
        "scope": "installed single-operator LOCAL/SQLite pilot configuration",
        "configuration_checks_passed": not blocked,
        "production_readiness": "not_established",
        "signing_key_fingerprint_sha256": fingerprint,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--web-root", required=True, type=Path)
    args = parser.parse_args(argv)
    report = inspect_installation(args.data_root, args.web_root)
    print(json.dumps(report, indent=2))
    return 0 if report["configuration_checks_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
