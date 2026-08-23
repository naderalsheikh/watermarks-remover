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

        # --- Phase 3: optional Postgres backend -------------------------------
        # Empty (default) keeps the embedded SQLite file — the single-tenant
        # profile everything else assumes. A SQLAlchemy URL here (e.g.
        # "postgresql+psycopg://user:pass@host:5432/counselclear") switches
        # every engine and migration run to that database: the supported way
        # to run several API replicas against one shared state. Object
        # custody stays on the filesystem regardless — only relational
        # state moves.
        self.database_url = os.environ.get("COUNSELCLEAR_DATABASE_URL", "").strip()

        # --- PR 17: out-of-process workers ------------------------------------
        # subprocess: run app.worker in a child process (dev/test default).
        # docker: hardened per-job container (--network none etc.), image
        # must be digest-pinned.
        mode = os.environ.get("COUNSELCLEAR_WORKER_MODE", "subprocess").strip().lower()
        if mode not in ("subprocess", "docker"):
            raise ValueError(f"unsupported COUNSELCLEAR_WORKER_MODE: {mode}")
        self.worker_mode = mode
        self.worker_image = os.environ.get("COUNSELCLEAR_WORKER_IMAGE", "").strip()
        # Optional OCI runtime for per-job worker containers (docker mode):
        # e.g. "runsc" (gVisor) adds a userspace kernel between the hostile
        # parser and the host kernel. Empty = Docker's default runtime.
        self.worker_runtime = os.environ.get("COUNSELCLEAR_WORKER_RUNTIME", "").strip()
        raw_timeout = os.environ.get("COUNSELCLEAR_WORKER_TIMEOUT_S", "600")
        try:
            self.worker_timeout_s = max(1, int(raw_timeout))
        except ValueError:
            self.worker_timeout_s = 600

        # Note: original downloads are gated solely by the per-matter
        # download_original permission (PR 16) — no deployment flag.

        # --- login brute-force throttle ---------------------------------------
        # Sliding-window failure counter per client peer address, held in
        # process memory (a restart resets it; a second API process keeps its
        # own counts — acceptable for the single-tenant profile, and the
        # argon2id verify cost bounds offline guessing regardless).
        self.login_max_failures = self._int_env("COUNSELCLEAR_LOGIN_MAX_FAILURES", 5, 1)
        self.login_window_s = self._int_env("COUNSELCLEAR_LOGIN_WINDOW_S", 300, 1)
        self.login_lockout_s = self._int_env("COUNSELCLEAR_LOGIN_LOCKOUT_S", 300, 1)

        # --- Phase 3: optional OIDC SSO ---------------------------------------
        # All three of ISSUER/CLIENT_ID/CLIENT_SECRET must be set to switch
        # authentication from the local shared password to an OpenID Connect
        # provider (authorization-code flow). With OIDC on, /v1/auth/login is
        # disabled, no password hash file is created, and every session is
        # issued to a per-identity subject (oidc:<hash-of-sub>) — matter ACLs
        # then decide what each principal may touch. The allowlist below is
        # fail-closed: empty means NO ONE can complete a login.
        self.oidc_issuer = os.environ.get("COUNSELCLEAR_OIDC_ISSUER", "").strip().rstrip("/")
        self.oidc_client_id = os.environ.get("COUNSELCLEAR_OIDC_CLIENT_ID", "").strip()
        self.oidc_client_secret = os.environ.get("COUNSELCLEAR_OIDC_CLIENT_SECRET", "").strip()
        self.oidc_scopes = os.environ.get("COUNSELCLEAR_OIDC_SCOPES", "openid profile email")
        # Comma-separated emails (case-insensitive) or raw `sub` values that
        # may sign in. Empty list = deny all.
        raw_allowed = os.environ.get("COUNSELCLEAR_OIDC_ALLOWED", "")
        self.oidc_allowed = {
            item.strip().lower() for item in raw_allowed.split(",") if item.strip()
        }
        # Override only when the app sits behind a proxy/Path-based route so
        # the redirect_uri seen by the IdP differs from the request's own
        # scheme://host/v1/auth/oidc/callback.
        self.oidc_redirect_uri = os.environ.get("COUNSELCLEAR_OIDC_REDIRECT_URI", "").strip()

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @staticmethod
    def _int_env(name: str, default: int, minimum: int) -> int:
        raw = os.environ.get(name, "")
        try:
            return max(minimum, int(raw))
        except ValueError:
            return default

    def db_url(self) -> str:
        """Engine/migration URL: the configured backend, else SQLite."""
        return self.database_url or f"sqlite:///{self.db_path}"

    def ensure_dirs(self) -> None:
        self.auth_dir.mkdir(parents=True, exist_ok=True)

    def ensure_cookie_secret(self) -> bytes:
        self.ensure_dirs()
        if not self.secret_file.exists():
            self.secret_file.write_bytes(secrets.token_bytes(32))
            self.secret_file.chmod(0o600)
        return self.secret_file.read_bytes()
