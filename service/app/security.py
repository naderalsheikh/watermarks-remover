"""Auth: argon2id hash file (0600) + HMAC-signed session cookie.

Two authentication sources feed the same session-cookie scheme:
- the local shared password (single-operator profile; subject "operator");
- OIDC SSO (Phase 3; per-identity subjects "oidc:<hash>", see app.oidc).
Tokens are f"{subject}.{issued}.{hmac}" — the subject is validated against
a strict charset so it can safely key matter ACLs and audit actor_ids.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
import time
from collections import deque
from contextlib import suppress

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .config import Config

_pwhasher = PasswordHasher()
SESSION_TTL_S = 12 * 3600

LOCAL_SUBJECT = "operator"
# What a session subject may look like anywhere in this codebase: ACL
# user_id columns (String(64)) and audit actor_ids are populated from it,
# so no whitespace, no separators beyond . _ : @ -, bounded length.
_SUBJECT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,62}\Z")


def valid_subject(subject: str) -> bool:
    return bool(_SUBJECT_RE.fullmatch(subject))


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


def issue_session(cfg: Config, subject: str = LOCAL_SUBJECT) -> str:
    if not valid_subject(subject):
        raise ValueError(f"invalid session subject: {subject!r}")
    secret = cfg.ensure_cookie_secret()
    issued = int(time.time())
    payload = f"{subject}.{issued}".encode()
    return f"{payload.decode()}.{_sign(secret, payload)}"


def session_subject(cfg: Config, token: str | None) -> str | None:
    """Return the authenticated subject for a valid, unexpired token —
    None otherwise. Replaces the old boolean valid_session()."""
    if not token or token.count(".") != 2:
        return None
    subject, issued_s, sig = token.split(".")
    if not valid_subject(subject):
        return None
    try:
        issued = int(issued_s)
    except ValueError:
        return None
    if time.time() - issued > SESSION_TTL_S:
        return None
    secret = cfg.ensure_cookie_secret()
    expected = _sign(secret, f"{subject}.{issued_s}".encode())
    if not hmac.compare_digest(sig, expected):
        return None
    return subject


def revoke_all_sessions(cfg: Config) -> None:
    """Rotate the cookie secret: every outstanding session token everywhere
    fails signature verification from this instant. This is the only honest
    revocation story for stateless HMAC tokens — per-token blacklists would
    reintroduce shared mutable session state this profile deliberately does
    not have. Use when an operator suspects a leaked cookie."""
    with suppress(FileNotFoundError):
        cfg.secret_file.unlink()
    cfg.ensure_cookie_secret()


class LoginThrottle:
    """Sliding-window brute-force guard for the login route.

    Keyed by client peer address (the socket peer — NOT a spoofable
    X-Forwarded-For header; a deployment behind a proxy that terminates
    connections should enforce its own limit at the proxy). Once
    ``max_failures`` failures accrue inside ``window_s``, the key is locked
    out for ``lockout_s`` regardless of which password arrives — including
    the correct one — so guessing is not just slowed but rate-capped.
    """

    def __init__(self, *, max_failures: int = 5, window_s: int = 300, lockout_s: int = 300):
        self.max_failures = max(1, max_failures)
        self.window_s = max(1, window_s)
        self.lockout_s = max(1, lockout_s)
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_sweep = 0.0

    def _prune(self, key: str, now: float) -> None:
        wins = self._failures.get(key)
        if wins:
            cutoff = now - self.window_s
            while wins and wins[0] < cutoff:
                wins.popleft()
            if not wins:
                self._failures.pop(key, None)

    def _maybe_sweep(self, now: float) -> None:
        """Opportunistic full sweep, at most once per ``window_s``.

        ``_failures`` / ``_locked_until`` are otherwise only pruned when the
        same key is touched again, so a low-and-slow scan from many distinct
        addresses — each failing once or twice and never returning — would
        otherwise leave one permanent entry per address. This walk drops every
        key with no live state (no failure inside ``window_s``, no active
        lockout) under the same lock as the rest of the class; an address that
        is still within its window or lockout is never evicted.
        """
        if now - self._last_sweep < self.window_s:
            return
        self._last_sweep = now
        cutoff = now - self.window_s
        # Expired lockouts: same cleanup allow() performs on touch.
        for key, until in list(self._locked_until.items()):
            if until <= now:
                del self._locked_until[key]
                self._failures.pop(key, None)
        # Cold keys: prune every deque like _prune() would for the touched key.
        for key, wins in list(self._failures.items()):
            while wins and wins[0] < cutoff:
                wins.popleft()
            if not wins:
                del self._failures[key]

    def allow(self, key: str) -> bool:
        with self._lock:
            now = time.time()
            self._maybe_sweep(now)
            until = self._locked_until.get(key)
            if until is not None:
                if now < until:
                    return False
                del self._locked_until[key]
                self._failures.pop(key, None)
            self._prune(key, now)
            wins = self._failures.get(key)
            if wins and len(wins) >= self.max_failures:
                self._locked_until[key] = now + self.lockout_s
                return False
            return True

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.time()
            self._maybe_sweep(now)
            self._prune(key, now)
            self._failures.setdefault(key, deque()).append(now)
            if len(self._failures[key]) >= self.max_failures:
                self._locked_until[key] = now + self.lockout_s

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def retry_after_s(self, key: str) -> int:
        with self._lock:
            until = self._locked_until.get(key)
            if until is None:
                return 0
            return max(1, int(until - time.time()) + 1)
