"""App configuration: everything derives from a writable data root."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


class Config:
    def __init__(self, data_root: str | Path | None = None):
        root = data_root or os.environ.get("COUNSELCLEAR_DATA_ROOT") or "./data"
        self.data_root = Path(root).absolute()
        self.db_path = self.data_root / "counselclear.sqlite3"
        self.auth_dir = self.data_root / "auth"
        self.hash_file = self.auth_dir / "local.hash"
        self.secret_file = self.auth_dir / "cookie.secret"
        # download_original permission (audited); off by default
        self.allow_original_download = os.environ.get(
            "COUNSELCLEAR_ALLOW_ORIGINAL_DOWNLOAD", ""
        ).lower() in ("1", "true", "yes")

    def ensure_dirs(self) -> None:
        self.auth_dir.mkdir(parents=True, exist_ok=True)

    def ensure_cookie_secret(self) -> bytes:
        self.ensure_dirs()
        if not self.secret_file.exists():
            self.secret_file.write_bytes(secrets.token_bytes(32))
            self.secret_file.chmod(0o600)
        return self.secret_file.read_bytes()
