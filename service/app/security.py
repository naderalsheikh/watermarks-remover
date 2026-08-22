"""Local auth: argon2id hash file (0600) + HMAC-signed session cookie."""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .config import Config

_pwhasher = PasswordHasher()
SESSION_TTL_S = 12 * 3600


def ensure_local_password(cfg: Config) -> None:
    """Hash COUNSELCLEAR_LOCAL_PASSWORD into {data_root}/auth/local.hash
    (0600). Idempotent: an existing file wins so operator rotation is a
    deliberate act of deleting it."""
    cfg.ensure_dirs()
    password = os.environ.get("COUNSELCLEAR_LOCAL_PASSWORD")
    if not password:
        raise RuntimeError("COUNSELCLEAR_LOCAL_PASSWORD must be set on first boot")
    if cfg.hash_file.exists():
        return
    cfg.hash_file.write_text(_pwhasher.hash(password), encoding="utf-8")
    cfg.hash_file.chmod(0o600)


def verify_password(cfg: Config, password: str) -> bool:
    if not cfg.hash_file.exists():
        return False
    stored = cfg.hash_file.read_text(encoding="utf-8").strip()
    try:
        return _pwhasher.verify(stored, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def _sign(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def issue_session(cfg: Config) -> str:
    secret = cfg.ensure_cookie_secret()
    issued = int(time.time())
    payload = f"operator.{issued}".encode()
    return f"{payload.decode()}.{_sign(secret, payload)}"


def valid_session(cfg: Config, token: str | None) -> bool:
    if not token or token.count(".") != 2:
        return False
    subject, issued_s, sig = token.split(".")
    if subject != "operator":
        return False
    try:
        issued = int(issued_s)
    except ValueError:
        return False
    if time.time() - issued > SESSION_TTL_S:
        return False
    secret = cfg.ensure_cookie_secret()
    expected = _sign(secret, f"{subject}.{issued_s}".encode())
    return hmac.compare_digest(sig, expected)
