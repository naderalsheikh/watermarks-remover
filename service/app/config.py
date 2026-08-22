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

        # --- PR 17: out-of-process workers ------------------------------------
        # subprocess: run app.worker in a child process (dev/test default).
        # docker: hardened per-job container (--network none etc.), image
        # must be digest-pinned.
        mode = os.environ.get("COUNSELCLEAR_WORKER_MODE", "subprocess").strip().lower()
        if mode not in ("subprocess", "docker"):
            raise ValueError(f"unsupported COUNSELCLEAR_WORKER_MODE: {mode}")
        self.worker_mode = mode
        self.worker_image = os.environ.get("COUNSELCLEAR_WORKER_IMAGE", "").strip()
        raw_timeout = os.environ.get("COUNSELCLEAR_WORKER_TIMEOUT_S", "600")
        try:
            self.worker_timeout_s = max(1, int(raw_timeout))
        except ValueError:
            self.worker_timeout_s = 600

        # Note: original downloads are gated solely by the per-matter
        # download_original permission (PR 16) — no deployment flag.

    def ensure_dirs(self) -> None:
        self.auth_dir.mkdir(parents=True, exist_ok=True)

    def ensure_cookie_secret(self) -> bytes:
        self.ensure_dirs()
        if not self.secret_file.exists():
            self.secret_file.write_bytes(secrets.token_bytes(32))
            self.secret_file.chmod(0o600)
        return self.secret_file.read_bytes()
