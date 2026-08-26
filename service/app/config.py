"""App configuration: everything derives from a writable data root."""

from __future__ import annotations

import os
import secrets
import tempfile
from contextlib import suppress
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

        # --- PR 20: Layer B watermark rewrite gate ----------------------------
        # Off by default. When off, every Layer B path refuses (403 at the
        # attestation route, job refusal in the runner). This is the product
        # control the license/ToS review signs off on: the capability exists
        # in the engine (service/scripts/rewrite_text.py) but is unreachable
        # through the product unless the operator explicitly flips it on and
        # the per-document signed attestation is presented.
        self.watermark_tools_enabled = os.environ.get(
            "COUNSELCLEAR_WATERMARK_TOOLS", ""
        ).strip().lower() in ("1", "true", "yes", "on")
        self.attest_secret_file = self.auth_dir / "attest.secret"
        raw_timeout = os.environ.get("COUNSELCLEAR_WORKER_TIMEOUT_S", "600")
        try:
            self.worker_timeout_s = max(1, int(raw_timeout))
        except ValueError:
            self.worker_timeout_s = 600

        # Note: original downloads are gated solely by the per-matter
        # download_original permission (PR 16) — no deployment flag.

        # --- PR 21: custody storage (S3 Object Lock / CMK / residency) ---------
        # Empty/default keeps the engine's local O_EXCL+0444 write-once files
        # (Phase 2 profile). "s3" switches the original store to S3-compatible
        # object storage with Object Lock retention; CMK/VOLUME_KEY_FILE enable
        # at-rest envelope encryption; RESIDENCY_REGION pins the bucket region
        # (checked at startup, mismatch refuses to boot).
        self.storage_mode = os.environ.get("COUNSELCLEAR_STORAGE", "local").strip().lower()
        self.s3_bucket = os.environ.get("COUNSELCLEAR_S3_BUCKET", "").strip()
        self.s3_prefix = os.environ.get("COUNSELCLEAR_S3_PREFIX", "").strip().strip("/")
        self.s3_region = os.environ.get("COUNSELCLEAR_S3_REGION", "").strip()
        self.residency_region = os.environ.get("COUNSELCLEAR_RESIDENCY_REGION", "").strip()
        self.retention_days = self._int_env("COUNSELCLEAR_RETENTION_DAYS", 365, 0)
        self.org = os.environ.get("COUNSELCLEAR_ORG", "local").strip() or "local"
        self.cmk_arn = os.environ.get("COUNSELCLEAR_CMK_ARN", "").strip()
        self.volume_key_file = os.environ.get("COUNSELCLEAR_VOLUME_KEY_FILE", "").strip()

        # PR 31: bound on concurrently-executing batch child jobs. Enforced
        # in-process only (ThreadPoolExecutor max_workers) — see
        # service/app/dispatcher.py's module docstring for the multi-replica
        # caveat this implies.
        self.batch_max_concurrent = self._int_env("COUNSELCLEAR_BATCH_MAX_CONCURRENT", 4, 1)

        # --- login brute-force throttle ---------------------------------------
        # Sliding-window failure counter per client peer address, held in
        # process memory (a restart resets it; a second API process keeps its
        # own counts — acceptable for the single-tenant profile, and the
        # argon2id verify cost bounds offline guessing regardless).
        self.login_max_failures = self._int_env("COUNSELCLEAR_LOGIN_MAX_FAILURES", 5, 1)
        self.login_window_s = self._int_env("COUNSELCLEAR_LOGIN_WINDOW_S", 300, 1)
        self.login_lockout_s = self._int_env("COUNSELCLEAR_LOGIN_LOCKOUT_S", 300, 1)
        # Session-cookie Secure flag: "auto" (default) follows the request
        # scheme (correct with uvicorn --proxy-headers behind a TLS-terminating
        # proxy); "true" always sets Secure; "false" never does (loopback dev).
        self.cookie_secure = os.environ.get("COUNSELCLEAR_COOKIE_SECURE", "auto").strip().lower()

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
        # may sign in. Empty list = deny all. `sub` is an opaque IdP
        # identifier and the OIDC spec treats it as case-sensitive, so it
        # keeps its original case here; oidc_allowed_lower exists only for
        # matching the email claim, which is conventionally
        # case-insensitive.
        raw_allowed = os.environ.get("COUNSELCLEAR_OIDC_ALLOWED", "")
        self.oidc_allowed = {item.strip() for item in raw_allowed.split(",") if item.strip()}
        self.oidc_allowed_lower = {item.lower() for item in self.oidc_allowed}
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

    def ensure_attest_secret(self) -> bytes:
        """Key material for Layer B attestation tokens (0600, provisioned
        idempotently like the cookie secret). Distinct from the cookie
        secret so a session-rotation can never invalidate outstanding
        attestations mid-flight, and vice versa."""
        self.ensure_dirs()
        if not self.attest_secret_file.exists():
            self.attest_secret_file.write_bytes(secrets.token_bytes(32))
            self.attest_secret_file.chmod(0o600)
        return self.attest_secret_file.read_bytes()

    def rotate_cookie_secret(self) -> bytes:
        """Replace the cookie secret with a fresh one, atomically.

        The old revoke path did unlink() then ensure_cookie_secret(),
        leaving a window with no secret file at all. Anything racing that
        window (another thread issuing a session, or a second concurrent
        revoke) would call ensure_cookie_secret() itself, see the file
        missing, and create its own — so whichever caller wrote last could
        silently overwrite a secret another caller had just handed out to a
        client, invalidating a session before its cookie ever reached the
        browser. Writing to a temp file and os.replace()-ing it into place
        means the secret file always exists and always holds one complete,
        valid value — every concurrent reader sees either the pre- or
        post-rotation secret, never a missing file or a torn write.
        """
        self.ensure_dirs()
        fd, tmp_name = tempfile.mkstemp(dir=self.auth_dir, prefix=".cookie.secret.")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.secret_file)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise
        return self.secret_file.read_bytes()
