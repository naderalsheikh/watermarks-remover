"""Phase 3: optional OIDC SSO.

No live IdP: the three network-boundary functions in app.oidc (discover,
exchange_code, validated_claims) are monkeypatched with canned responses,
and the real JWT-verification path is exercised separately by minting an
RS256 keypair in-process. Everything else (state signing, allowlist gating,
principal isolation via matter ACLs) runs for real.
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
for p in (str(SCRIPTS), str(APP_DIR.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app import oidc
from app.oidc import OidcError, make_state, parse_state, principal_for
from app.security import issue_session, session_subject

OIDC_ENV = {
    "COUNSELCLEAR_OIDC_ISSUER": "https://idp.example.com",
    "COUNSELCLEAR_OIDC_CLIENT_ID": "counselclear",
    "COUNSELCLEAR_OIDC_CLIENT_SECRET": "shhh",
    "COUNSELCLEAR_OIDC_ALLOWED": "alice@example.com",
}

DISCOVERY = {
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "jwks_uri": "https://idp.example.com/jwks.json",
}


@pytest.fixture(autouse=True)
def _clean_caches():
    oidc._discovery_cache.clear()
    oidc._jwk_clients.clear()
    yield
    oidc._discovery_cache.clear()
    oidc._jwk_clients.clear()


def _make_app(tmp_path, monkeypatch, extra_env=None):
    env = dict(OIDC_ENV)
    env.update(extra_env or {})
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from app.main import create_app

    return TestClient(create_app(tmp_path / "data"))


# --- config -------------------------------------------------------------------


def test_oidc_disabled_without_full_config(tmp_path, monkeypatch):
    from app.config import Config

    monkeypatch.delenv("COUNSELCLEAR_OIDC_ISSUER", raising=False)
    assert not Config(tmp_path).oidc_enabled
    monkeypatch.setenv("COUNSELCLEAR_OIDC_ISSUER", "https://idp")
    # client id/secret still missing -> disabled (fail closed)
    assert not Config(tmp_path).oidc_enabled


def test_allowed_list_parsing(tmp_path, monkeypatch):
    from app.config import Config

    for k, v in OIDC_ENV.items():
        monkeypatch.setenv(k, v)
    cfg = Config(tmp_path)
    assert cfg.oidc_allowed == {"alice@example.com"}
    monkeypatch.setenv("COUNSELCLEAR_OIDC_ALLOWED", " Alice@Example.com , sub-123 ,")
    assert Config(tmp_path).oidc_allowed == {"alice@example.com", "sub-123"}
    monkeypatch.setenv("COUNSELCLEAR_OIDC_ALLOWED", "")
    assert Config(tmp_path).oidc_allowed == set()


# --- state (CSRF) ---------------------------------------------------------------


def test_state_roundtrip_and_tamper(tmp_path):
    from app.config import Config

    cfg = Config(tmp_path)
    state = make_state(cfg)
    nonce = parse_state(cfg, state)
    assert len(nonce) == 32
    assert parse_state(cfg, state) == nonce  # stable within TTL

    head, _sig = state.rsplit(".", 1)
    with pytest.raises(OidcError):
        parse_state(cfg, f"{head}.{'0' * 64}")  # forged signature
    other = Config(tmp_path / "other")  # different cookie secret
    with pytest.raises(OidcError):
        parse_state(other, state)


def test_state_expiry(tmp_path, monkeypatch):
    from app.config import Config

    cfg = Config(tmp_path)
    state = make_state(cfg)
    real_time = time.time
    monkeypatch.setattr(oidc.time, "time", lambda: real_time() + oidc.STATE_TTL_S + 5)
    with pytest.raises(OidcError, match="expired"):
        parse_state(cfg, state)


# --- subjects -------------------------------------------------------------------


def test_principal_for_is_stable_and_bounded():
    a = principal_for("user-sub-123")
    b = principal_for("user-sub-123")
    c = principal_for("different")
    assert a == b and a != c
    assert a.startswith("oidc:")
    assert len(a) <= 64


def test_session_tokens_carry_arbitrary_subjects(tmp_path):
    from app.config import Config

    cfg = Config(tmp_path)
    tok = issue_session(cfg, principal_for("sub-x"))
    assert session_subject(cfg, tok) == principal_for("sub-x")
    # local subject still round-trips
    tok_op = issue_session(cfg)
    assert session_subject(cfg, tok_op) == "operator"
    # garbage subjects are refused at issuance and validation
    with pytest.raises(ValueError):
        issue_session(cfg, "../etc/passwd")
    with pytest.raises(ValueError):
        issue_session(cfg, "x" * 100)


def test_local_login_disabled_when_oidc_on(tmp_path, monkeypatch):
    c = _make_app(tmp_path, monkeypatch)
    r = c.post("/v1/auth/login", json={"password": "whatever"})
    assert r.status_code == 403


def test_no_password_hash_file_created_when_oidc_on(tmp_path, monkeypatch):
    _make_app(tmp_path, monkeypatch)
    assert not (tmp_path / "data" / "auth" / "local.hash").exists()


# --- full flow (IdP stubbed at the module boundary) ------------------------------


def _stub_idp(monkeypatch, claims_by_code: dict, *, fail_claims=False):
    monkeypatch.setattr(oidc, "discover", lambda cfg: DISCOVERY)

    def fake_exchange(cfg, redirect_uri, code):
        if code not in claims_by_code:
            raise OidcError("bad code")
        return f"header.{code}.sig"

    monkeypatch.setattr(oidc, "exchange_code", fake_exchange)

    def fake_claims(cfg, id_token, expected_nonce):
        if fail_claims:
            raise OidcError("id_token validation failed: bad signature")
        code = id_token.split(".")[1]
        claims = dict(claims_by_code[code])
        # The route passes the nonce it recovered from the signed state;
        # echo it back like a compliant IdP would.
        claims["nonce"] = expected_nonce
        return claims

    monkeypatch.setattr(oidc, "validated_claims", fake_claims)


def test_login_redirect_targets_discovered_authorize_endpoint(tmp_path, monkeypatch):
    _stub_idp(monkeypatch, {})
    c = _make_app(tmp_path, monkeypatch)
    r = c.get("/v1/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith(DISCOVERY["authorization_endpoint"])
    assert "state=" in loc and "nonce=" in loc
    assert "client_id=counselclear" in loc


def test_callback_issues_session_for_allowed_email(tmp_path, monkeypatch):
    _stub_idp(monkeypatch, {"good-code": {"sub": "sub-alice", "email": "Alice@Example.com"}})
    c = _make_app(tmp_path, monkeypatch)
    r = c.get("/v1/auth/oidc/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1].split("&")[0]
    r2 = c.get(
        "/v1/auth/oidc/callback",
        params={"code": "good-code", "state": state},
        follow_redirects=False,
    )
    assert r2.status_code == 200
    assert "cc_session" in r2.cookies

    # The session works, and the principal is the OIDC identity, not operator.
    from app.config import Config as C
    from app.security import session_subject

    cfg = C(tmp_path / "data")
    got = session_subject(cfg, c.cookies["cc_session"])
    assert got == principal_for("sub-alice")

    # Creating a matter grants OWNER perms to this principal.
    m = c.post("/v1/matters", json={"name": "m"}).json()
    audit = c.get(f"/v1/matters/{m['id']}/audit").json()
    assert audit["chain_ok"]


def test_oidc_principal_cannot_revoke_all_sessions(tmp_path, monkeypatch):
    """revoke-sessions is a deployment-wide action gated on the local
    operator subject, not on being merely authenticated. An OIDC principal
    is a real, matter-scoped identity — full login, valid cookie, even
    OWNER perms on a matter it created — but must still be refused here;
    Depends(principal) alone is authentication, not this authorization."""
    _stub_idp(monkeypatch, {"good-code": {"sub": "sub-alice", "email": "alice@example.com"}})
    c = _make_app(tmp_path, monkeypatch)
    r = c.get("/v1/auth/oidc/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1].split("&")[0]
    c.get("/v1/auth/oidc/callback", params={"code": "good-code", "state": state})

    assert c.post("/v1/matters", json={"name": "m"}).status_code == 200

    r2 = c.post("/v1/auth/revoke-sessions")
    assert r2.status_code == 403
    # And the session is still intact — nothing was revoked.
    assert c.post("/v1/matters", json={"name": "m2"}).status_code == 200


def test_callback_denies_non_allowlisted_principal(tmp_path, monkeypatch):
    _stub_idp(monkeypatch, {"eve-code": {"sub": "sub-eve", "email": "eve@example.com"}})
    c = _make_app(tmp_path, monkeypatch)
    r = c.get("/v1/auth/oidc/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1].split("&")[0]
    r2 = c.get("/v1/auth/oidc/callback", params={"code": "eve-code", "state": state})
    assert r2.status_code == 403


def test_callback_rejects_bad_or_missing_state(tmp_path, monkeypatch):
    _stub_idp(monkeypatch, {"good-code": {"sub": "sub-alice", "email": "alice@example.com"}})
    c = _make_app(tmp_path, monkeypatch)

    assert c.get("/v1/auth/oidc/callback", params={"code": "x"}).status_code == 400
    assert (
        c.get(
            "/v1/auth/oidc/callback",
            params={"code": "good-code", "state": "forged.123.abc"},
        ).status_code
        == 401
    )


def test_callback_maps_idp_errors_to_401(tmp_path, monkeypatch):
    _stub_idp(monkeypatch, {}, fail_claims=True)
    c = _make_app(tmp_path, monkeypatch)
    r = c.get("/v1/auth/oidc/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1].split("&")[0]
    r2 = c.get("/v1/auth/oidc/callback", params={"code": "missing", "state": state})
    assert r2.status_code == 401


# --- ACL isolation between OIDC principals ---------------------------------------


def test_principals_are_isolated_by_matter_acl(tmp_path, monkeypatch):
    """Two allowed principals: alice's matters are invisible to bob until an
    explicit admin grant exists."""
    env = dict(OIDC_ENV)
    env["COUNSELCLEAR_OIDC_ALLOWED"] = "alice@example.com,bob@example.com"
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from app.main import create_app

    alice = TestClient(create_app(tmp_path / "data"))
    bob = TestClient(create_app(tmp_path / "data"))

    def sign_in(client, code, email):
        _stub_idp(monkeypatch, {code: {"sub": f"sub-{email}", "email": email}})
        r = client.get("/v1/auth/oidc/login", follow_redirects=False)
        state = r.headers["location"].split("state=")[1].split("&")[0]
        client.get("/v1/auth/oidc/callback", params={"code": code, "state": state})

    sign_in(alice, "code-a", "alice@example.com")
    sign_in(bob, "code-b", "bob@example.com")

    m = alice.post("/v1/matters", json={"name": "alice-matter"}).json()
    # Bob cannot even see it.
    assert bob.get(f"/v1/matters/{m['id']}").status_code == 403
    # Alice can upload; bob cannot.
    files = {"file": ("a.txt", b"hello", "text/plain")}
    assert alice.post(f"/v1/matters/{m['id']}/documents", files=files).status_code == 200
    assert (
        bob.post(
            f"/v1/matters/{m['id']}/documents", files={"file": ("b.txt", b"x", "text/plain")}
        ).status_code
        == 403
    )

    # Explicit cross-principal grant by alice (admin on her own matter).
    bob_subject = principal_for("sub-bob@example.com")
    r = alice.put(
        f"/v1/matters/{m['id']}/acl",
        json={"user_id": bob_subject, "perm": "read"},
    )
    assert r.status_code == 200
    assert bob.get(f"/v1/matters/{m['id']}").status_code == 200
    # ...but read-only: upload is still denied for the lack of that perm.
    r_up = bob.post(
        f"/v1/matters/{m['id']}/documents", files={"file": ("b.txt", b"x", "text/plain")}
    )
    assert r_up.status_code == 403


# --- RS256 ID-token verification (real crypto, no network) ------------------------


def test_validated_claims_verifies_signature_nonce_issuer_audience(tmp_path, monkeypatch):
    import json as _json

    import jwt as pyjwt
    from app.config import Config
    from cryptography.hazmat.primitives.asymmetric import rsa

    for k, v in OIDC_ENV.items():
        monkeypatch.setenv(k, v)
    cfg = Config(tmp_path)

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = uuid.uuid4().hex[:8]

    def b64u(n: int) -> str:
        from base64 import urlsafe_b64encode

        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return urlsafe_b64encode(raw).decode().rstrip("=")

    pub = priv.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64u(pub.n),
        "e": b64u(pub.e),
    }

    class FakeJWKClient:
        """Stands in for PyJWKClient's HTTP fetch of the jwks_uri."""

        def __init__(self, uri, **_kwargs):
            assert uri == DISCOVERY["jwks_uri"]

        def get_signing_key_from_jwt(self, token):
            class K:
                key = pyjwt.algorithms.RSAAlgorithm.from_jwk(_json.dumps(jwk))

            return K()

    monkeypatch.setattr(oidc, "discover", lambda cfg_: DISCOVERY)
    # Pre-seed the module's client cache: validated_claims then uses our
    # fake without any network fetch (and without patching pyjwt itself).
    monkeypatch.setitem(
        oidc._jwk_clients, DISCOVERY["jwks_uri"], FakeJWKClient(DISCOVERY["jwks_uri"])
    )

    now = int(time.time())
    nonce = "n" * 32
    good = pyjwt.encode(
        {
            "iss": cfg.oidc_issuer,
            "aud": cfg.oidc_client_id,
            "sub": "sub-alice",
            "email": "alice@example.com",
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        },
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )
    claims = oidc.validated_claims(cfg, good, nonce)
    assert claims["sub"] == "sub-alice"

    # Wrong nonce is refused even with a valid signature.
    with pytest.raises(OidcError, match="nonce"):
        oidc.validated_claims(cfg, good, "other-nonce")

    # A token signed by a different key fails verification.
    evil = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = pyjwt.encode(
        {
            "iss": cfg.oidc_issuer,
            "aud": cfg.oidc_client_id,
            "sub": "sub-alice",
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        },
        evil,
        algorithm="RS256",
        headers={"kid": kid},
    )
    with pytest.raises(OidcError):
        oidc.validated_claims(cfg, forged, nonce)

    # Wrong audience is refused.
    wrong_aud = pyjwt.encode(
        {
            "iss": cfg.oidc_issuer,
            "aud": "someone-else",
            "sub": "s",
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        },
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )
    with pytest.raises(OidcError):
        oidc.validated_claims(cfg, wrong_aud, nonce)

    # Expired tokens are refused (beyond leeway).
    expired = pyjwt.encode(
        {
            "iss": cfg.oidc_issuer,
            "aud": cfg.oidc_client_id,
            "sub": "s",
            "nonce": nonce,
            "iat": now - 3600,
            "exp": now - 1800,
        },
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )
    with pytest.raises(OidcError):
        oidc.validated_claims(cfg, expired, nonce)
