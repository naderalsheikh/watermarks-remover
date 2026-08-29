"""Auth: argon2id hash file (0600) + HMAC-signed session cookie.

Two authentication sources feed the same session-cookie scheme:
- the local shared password (single-operator profile; subject "operator");
- OIDC SSO (Phase 3; per-identity subjects "oidc:<hash>", see app.oidc).
Tokens are f"{subject}.{issued}.{hmac}" — the subject is validated against
a strict charset so it can safely key matter ACLs and audit actor_ids.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
import uuid
from collections import deque
from datetime import UTC, datetime

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


def sign_hmac_sha256(secret: bytes, payload: bytes) -> str:
    """The one HMAC-SHA256-hexdigest construction for every signed token in
    this app (session cookies here, OIDC CSRF state in app.oidc) — a single
    implementation so a future digest/encoding change can't silently drift
    between the two call sites."""
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


_sign = sign_hmac_sha256


# --- MUST-2: release-packet signatures (2026-08-29) ---------------------------
#
# Ed25519, not the HMAC above: the HMAC secrets are fine for server-side
# tokens (only this server ever needed to verify them), but a release
# packet's signature is checked OFFLINE by a recipient — opposing
# counsel's expert — who must be able to verify without being able to
# forge. Symmetric HMAC hands every verifier the signing key itself;
# asymmetric Ed25519 ships only the public half. See
# docs/counselclear-release-packet-signing.md for the full decision.

PACKET_SIGNATURE_SIGNED_FIELDS = "release_packet.v1.canonical"


def packet_canonical_bytes(packet: dict) -> bytes:
    """The exact bytes the signature covers: the packet dict minus its
    own ``signature`` block, re-serialized with a fixed canonical form.
    The packet FILE is written indent=2/sort_keys for humans; the
    signature deliberately does not cover that formatting — only the
    parsed content — so the verifier can reproduce these bytes from any
    parse of the file regardless of how it was pretty-printed.

    Stability: the packet schema carries strings, ints, nulls, booleans
    and nested dicts/lists only (no floats), so json.dumps with
    sort_keys + compact separators + ensure_ascii is byte-stable across
    Python versions for everything that can appear here.
    test_packet_canonical_bytes_roundtrip_stability pins that claim
    against a payload exercising every field type.
    """
    content = {k: v for k, v in packet.items() if k != "signature"}
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def custody_key_id(cfg: Config) -> str:
    """Stable identifier for the current signing key: sha256 of the
    public half, truncated. Lived in every signature block so a rotated
    key never invalidates old packets — the verifier selects the right
    public key from a bundle by this id."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = cfg.ensure_custody_signing_key()
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("custody signing key is not an Ed25519 private key")
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def sign_release_packet(cfg: Config, packet: dict) -> dict:
    """Sign *packet* (which must not yet carry a ``signature`` block)
    and return that block: algorithm/key_id/signed_fields/digest/value.

    The digest is the sha256 of the canonical bytes (belt-and-suspenders
    alongside the raw Ed25519 value — a verifier can confirm the signed
    digest matches its own recomputation before the signature check, so
    a canonicalization drift surfaces as a digest mismatch rather than
    an opaque Ed25519 failure).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    canonical = packet_canonical_bytes(packet)
    digest = hashlib.sha256(canonical).hexdigest()
    key = cfg.ensure_custody_signing_key()
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("custody signing key is not an Ed25519 private key")
    value = key.sign(canonical).hex()
    return {
        "algorithm": "ed25519",
        "key_id": custody_key_id(cfg),
        "signed_fields": PACKET_SIGNATURE_SIGNED_FIELDS,
        "digest": f"sha256:{digest}",
        "value": value,
    }


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
    cfg.rotate_cookie_secret()


# --- PR 20: Layer B attestation tokens -------------------------------------
# A signed, short-lived, doc-bound authorization to run a content-altering
# (Layer B / statistical watermark) rewrite on one specific document. The
# server signs it because the value being bound is "this authenticated
# principal authorized this content-altering act on this exact document" —
# a client self-attestation proves nothing for the audit chain.

ATTEST_TTL_S = 600  # 10 minutes: bearer token, keep the replay window small
ATTEST_LABEL = "content_altering"
# Product-pinned strengths (design doc KD 10: the product refuses the
# aggressive CLI-only strengths). code/backtranslate stay CLI-only.
ATTEST_STRENGTHS = ("preserve", "paraphrase")

# Single-use jti tracking. In-memory: like LoginThrottle, this process owns
# the fast path only — the durable, race-free record is the attestation_uses
# table (app.models.AttestationUse; jti is its primary key), written in the
# same transaction as the job it authorizes (app.main.sanitize_job). A
# process restart clears this set; the DB row is what actually survives a
# restart or a second worker process and makes a duplicate INSERT fail
# instead of racing a read-then-write check.
_consumed_jtis: set[str] = set()


def _fmt_utc(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


def issue_attestation(
    cfg: Config,
    *,
    subject: str,
    matter_id: str,
    doc_sha256: str,
    strength: str,
    label: str = ATTEST_LABEL,
) -> tuple[str, str, str]:
    """Sign a Layer B attestation token. Returns (token, jti, expires_utc)."""
    if not valid_subject(subject):
        raise ValueError(f"invalid attestation subject: {subject!r}")
    if strength not in ATTEST_STRENGTHS:
        raise ValueError(f"strength not product-allowed: {strength!r}")
    if label != ATTEST_LABEL:
        raise ValueError(f"label not product-allowed: {label!r}")
    secret = cfg.ensure_attest_secret()
    now = int(time.time())
    jti = uuid.uuid4().hex
    payload = {
        "v": 1,
        "sub": subject,
        "matter_id": matter_id,
        "doc_sha256": doc_sha256,
        "strength": strength,
        "label": label,
        "iat": now,
        "exp": now + ATTEST_TTL_S,
        "jti": jti,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    token = f"{base64.urlsafe_b64encode(body).decode().rstrip('=')}.{_sign(secret, body)}"
    return token, jti, _fmt_utc(now + ATTEST_TTL_S)


def verify_attestation(
    cfg: Config,
    token: str | None,
    *,
    matter_id: str,
    doc_sha256: str,
) -> dict | None:
    """Validate an attestation token against a document. Returns the claims
    dict on success, None on any miss (bad shape, bad signature, expired,
    wrong matter/doc, already consumed)."""
    if not token or token.count(".") != 1:
        return None
    body_b64, sig = token.split(".")
    try:
        body = base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4))
        claims = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return None
    secret = cfg.ensure_attest_secret()
    if not hmac.compare_digest(sig, _sign(secret, body)):
        return None
    now = int(time.time())
    if claims.get("v") != 1 or claims.get("label") != ATTEST_LABEL:
        return None
    if claims.get("matter_id") != matter_id or claims.get("doc_sha256") != doc_sha256:
        return None
    if not isinstance(claims.get("exp"), int) or now >= claims["exp"]:
        return None
    jti = claims.get("jti")
    if not isinstance(jti, str) or jti in _consumed_jtis:
        return None
    return claims


def consume_attestation(token_claims: dict) -> None:
    """Mark an attestation token single-used (called when the job commits)."""
    jti = token_claims.get("jti")
    if isinstance(jti, str):
        _consumed_jtis.add(jti)


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
