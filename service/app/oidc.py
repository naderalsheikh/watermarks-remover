"""Optional OpenID Connect SSO (authorization-code flow).

Enabled when COUNSELCLEAR_OIDC_ISSUER + CLIENT_ID + CLIENT_SECRET are all
set (Config.oidc_enabled). Design constraints inherited from this product's
single-tenant profile:

- Stateless server: the anti-CSRF `state` is HMAC-signed with the cookie
  secret and carries its own nonce + expiry — nothing is stored between
  the redirect and the callback.
- Fail-closed identity gate: only principals on Config.oidc_allowed
  (emails or raw `sub`, case-insensitive) may sign in; an empty allowlist
  denies everyone.
- Bounded, opaque local subject: the IdP's immutable `sub` is mapped to
  "oidc:" + sha256(sub)[:24] so ACL user_id / audit actor_id columns get a
  stable value with a charset and length we control (the raw sub can be
  arbitrarily long and is not always printable).

Network calls live in three functions (discover, exchange_code,
validated_claims) kept narrow so tests can stub exactly the IdP boundary;
everything else is pure.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
import urllib.request

import jwt as pyjwt

from .config import Config
from .security import sign_hmac_sha256

STATE_TTL_S = 600
_DISCOVERY_TTL_S = 3600
_HTTP_TIMEOUT_S = 10
_LEEWAY_S = 30

_discovery_cache: dict[str, tuple[float, dict]] = {}


class OidcError(Exception):
    """Any failure during SSO; routes turn this into a 401."""


def _http_get_json(url: str) -> dict:
    _require_http_s(url)
    # scheme is validated by _require_http_s above (https, or http on loopback)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        raise OidcError(f"oidc discovery failed: {e}") from e


def _require_http_s(url: str) -> None:
    """SSO endpoints are fetched from the configured issuer only; refuse
    anything but https (http is allowed solely for loopback dev IdPs)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return
    raise OidcError(f"refusing non-https OIDC endpoint: {url}")


def discover(cfg: Config) -> dict:
    """Fetch (and cache) the issuer's discovery document."""
    now = time.time()
    hit = _discovery_cache.get(cfg.oidc_issuer)
    if hit and now - hit[0] < _DISCOVERY_TTL_S:
        return hit[1]
    doc = _http_get_json(f"{cfg.oidc_issuer}/.well-known/openid-configuration")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(key):
            raise OidcError(f"oidc discovery document lacks {key}")
    _discovery_cache[cfg.oidc_issuer] = (now, doc)
    return doc


def make_state(cfg: Config) -> str:
    """Signed, self-describing CSRF state: nonce.timestamp.hmac."""
    secret = cfg.ensure_cookie_secret()
    nonce = hashlib.sha256(
        hashlib.sha256(secret).digest() + str(time.time_ns()).encode()
    ).hexdigest()[:32]
    issued = int(time.time())
    payload = f"{nonce}.{issued}".encode()
    return f"{payload.decode()}.{sign_hmac_sha256(secret, b'state|' + payload)}"


def parse_state(cfg: Config, state: str) -> str:
    """Verify signature + freshness; return the nonce."""
    secret = cfg.ensure_cookie_secret()
    parts = state.split(".")
    if len(parts) != 3:
        raise OidcError("malformed state")
    nonce, issued_s, sig = parts
    payload = f"{nonce}.{issued_s}".encode()
    expected = sign_hmac_sha256(secret, b"state|" + payload)
    if not hmac.compare_digest(sig, expected):
        raise OidcError("state signature mismatch")
    try:
        issued = int(issued_s)
    except ValueError:
        raise OidcError("malformed state timestamp") from None
    if time.time() - issued > STATE_TTL_S:
        raise OidcError("state expired")
    return nonce


def redirect_uri_for(cfg: Config, request) -> str:
    if cfg.oidc_redirect_uri:
        return cfg.oidc_redirect_uri
    base = str(request.base_url).rstrip("/")
    return f"{base}/v1/auth/oidc/callback"


def authorization_redirect(cfg: Config, request) -> str:
    doc = discover(cfg)
    state = make_state(cfg)
    q = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": cfg.oidc_client_id,
            "redirect_uri": redirect_uri_for(cfg, request),
            "scope": cfg.oidc_scopes,
            "state": state,
            # nonce rides inside the signed state; validated_claims checks it
            "nonce": parse_state(cfg, state),
        }
    )
    return f"{doc['authorization_endpoint']}?{q}"


def _http_post_form(url: str, fields: dict) -> dict:
    _require_http_s(url)
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(  # noqa: S310
        url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        raise OidcError(f"token exchange failed: {e}") from e


def exchange_code(cfg: Config, redirect_uri: str, code: str) -> str:
    """Swap the authorization code for tokens; return the id_token."""
    doc = discover(cfg)
    tok = _http_post_form(
        doc["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": cfg.oidc_client_id,
            "client_secret": cfg.oidc_client_secret,
        },
    )
    id_token = tok.get("id_token")
    if not id_token:
        raise OidcError("token response contains no id_token")
    return id_token


_jwk_clients: dict[str, pyjwt.PyJWKClient] = {}


def _jwk_client(cfg: Config) -> pyjwt.PyJWKClient:
    doc = discover(cfg)
    uri = doc["jwks_uri"]
    client = _jwk_clients.get(uri)
    if client is None:
        client = pyjwt.PyJWKClient(uri, cache_keys=True, lifespan=_DISCOVERY_TTL_S)
        _jwk_clients[uri] = client
    return client


def validated_claims(cfg: Config, id_token: str, expected_nonce: str) -> dict:
    """Signature (JWKS), issuer, audience, expiry and nonce checks."""
    signing_key = _jwk_client(cfg).get_signing_key_from_jwt(id_token)
    try:
        claims = pyjwt.decode(
            id_token,
            key=signing_key.key,
            algorithms=["RS256"],
            audience=cfg.oidc_client_id,
            issuer=cfg.oidc_issuer,
            leeway=_LEEWAY_S,
        )
    except pyjwt.PyJWTError as e:
        raise OidcError(f"id_token validation failed: {e}") from e
    if claims.get("nonce") != expected_nonce:
        raise OidcError("nonce mismatch")
    return claims


def allowed_principal(cfg: Config, claims: dict) -> bool:
    """`sub` is the OIDC spec's case-sensitive opaque identifier — matched
    exactly against the allowlist as configured, not lowercased. Only
    `email` (conventionally case-insensitive) is folded to lowercase."""
    sub = str(claims.get("sub", ""))
    email = str(claims.get("email", "")).lower()
    return bool(sub and sub in cfg.oidc_allowed) or bool(email and email in cfg.oidc_allowed_lower)


def principal_for(sub: str) -> str:
    """Stable bounded local subject for an IdP sub (see module docstring)."""
    return "oidc:" + hashlib.sha256(sub.encode()).hexdigest()[:24]
