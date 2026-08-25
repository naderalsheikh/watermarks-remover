"""FastAPI application factory and /v1 routes (single-tenant profile)."""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import time
import uuid
import zipfile
from pathlib import Path

import custody as custody_mod  # WORM storage only — never parses documents
from common import MAX_INPUT_BYTES  # a size constant, not a parser
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# Imported as a module (not by name): tests stub IdP calls on the module
# object, and attribute access must resolve at call time for that to work.
from . import oidc as oidc_mod

# PR 17 doctrine: this module must NOT import engine_api / custody or call
# inspect_bytes/clean_to_bundle — untrusted bytes are parsed only inside
# isolated worker processes (see app.runner). A test enforces the ban.
from .acl import OPERATOR, bootstrap_operator, grant, has_perm, revoke
from .audit import append_event, verify_chain
from .config import Config
from .db import make_engine, make_session_factory
from .malware import get_scanner
from .migrate import upgrade_head
from .models import AttestationUse, AuditEvent, Document, Job, Matter, MatterAcl, _now, _uuid
from .oidc import OidcError
from .runner import run_job, sync_job
from .security import (
    ATTEST_STRENGTHS,
    LOCAL_SUBJECT,
    LoginThrottle,
    consume_attestation,
    ensure_local_password,
    issue_attestation,
    issue_session,
    revoke_all_sessions,
    session_subject,
    verify_attestation,
    verify_password,
)
from .storage import StorageError as StorageError_
from .storage import original_key, storage_from_config

# Four frozen v1 default policies (docs/COUNSELCLEAR_DESIGN.md, "Key
# Decisions" #5, and the full subtype table under Policy Engine). Literal
# ids/labels here, not an import of scripts.policies: main.py stays out of
# the engine's import graph (PR 17 isolation) for what is, by design, a
# frozen list that only ever changes alongside this file.
POLICIES = [
    {
        "id": "external_sharing",
        "label": "External sharing",
        "description": (
            "For sending outside the firm: strips comments, external links, "
            "embedded objects, and custom XML; accepts all tracked changes; "
            "flags headers/footers and hidden content for review."
        ),
    },
    {
        "id": "privacy_only",
        "label": "Privacy only",
        "description": (
            "Minimal, no-visible-change: strips only PII authoring fields "
            "and GPS location. Keeps comments, tracked changes, and C2PA "
            "provenance untouched."
        ),
    },
    {
        "id": "production",
        "label": "Production",
        "description": (
            "Litigation production: most findings require an explicit "
            "per-finding approve/keep decision instead of an automatic strip."
        ),
    },
    {
        "id": "evidence_preservation",
        "label": "Evidence preservation",
        "description": (
            "Inspect-only — never produces a derivative. Preserves the "
            "original for evidentiary integrity."
        ),
    },
]


class LoginBody(BaseModel):
    password: str


class MatterBody(BaseModel):
    name: str


class SanitizeBody(BaseModel):
    policy_id: str = "external_sharing"
    reason: str = ""
    signature_break_attestation: bool = False
    # {subtype: "approve"|"keep"}, for policies with approve-default cells
    # (production's comments_and_notes and friends). Validated inside the
    # worker by plan_actions itself (an unknown subtype or action becomes a
    # failed job with a clear PolicyError message) — the same place
    # policy_id's own validity is checked, not pre-validated here.
    finding_decisions: dict[str, str] = {}
    # PR 20: Layer B (statistical watermark) rewrite, gated by the signed
    # attestation token issued by POST /v1/attestations. Absent = Layer A
    # only. The token is verified server-side before the job is created.
    layer_b: LayerBBody | None = None


class LayerBBody(BaseModel):
    strength: str
    token: str


class AttestationBody(BaseModel):
    matter_id: str
    document_id: str
    strength: str
    reason: str = ""


class AclBody(BaseModel):
    # Phase 3 (OIDC): user_id here is an arbitrary ACL principal — the local
    # "operator", or another principal's "oidc:<hash>" subject.
    user_id: str = OPERATOR
    perm: str


log = logging.getLogger("counselclear")


def _jlog(level: int, event: str, **fields) -> None:
    """Structured single-line JSON log record.

    The design doc's observability section requires machine-parsable logs
    (one JSON object per line, no basename/author/GPS/text payloads) — this
    is the one funnel for every app-level log line. Field order is stable
    via dict insertion; values are operator-safe by construction.
    """
    payload = {"event": event, **fields}
    log.log(level, json.dumps(payload, separators=(",", ":"), default=str))


def _sweep_orphaned_jobs(s: Session) -> int:
    """Fail jobs left queued/running by a previous process death.

    With in-request job execution a "running" row can only exist while the
    request that spawned it is alive — so at boot, before the app serves
    anything, any queued/running row is by definition orphaned: its worker
    subprocess/container died with the old API process and sync_job will
    never run for it. Left alone it would sit "running" forever.

    A single bulk UPDATE, not a load-then-mutate-per-row loop: boot already
    blocks on this (the app must not start serving before orphans are
    reconciled), and a restart after a long queue backlog could otherwise
    mean thousands of individual ORM-tracked UPDATE statements before the
    first request is served.
    """
    result = s.execute(
        update(Job)
        .where(Job.status.in_(("queued", "running")))
        .values(
            status="failed",
            error="interrupted by an application restart",
            finished_utc=_now(),
        )
    )
    s.commit()
    return result.rowcount or 0


def _log_startup_posture(cfg: Config, swept: int, storage) -> None:
    """One-time, non-secret operational summary at boot — this app shipped
    with zero logging until now, which meant an operator running it
    unisolated or with a no-op malware scanner had no way to notice short
    of reading the source. Never logs the password, hash, or cookie secret."""
    _jlog(
        logging.INFO,
        "startup",
        data_root=str(cfg.data_root),
        worker_mode=cfg.worker_mode,
        auth_mode="oidc" if cfg.oidc_enabled else "local_password",
        db_backend="postgres" if cfg.database_url else "sqlite",
        storage=storage.describe(),
        orphaned_jobs_failed=swept,
    )
    if cfg.storage_mode == "s3" and cfg.retention_days <= 0:
        log.warning(
            "COUNSELCLEAR_STORAGE=s3 with COUNSELCLEAR_RETENTION_DAYS=0: "
            "Object Lock is off — overwrite/delete protection relies on "
            "If-None-Match only (and any Object-Lock-enabled bucket still "
            "enforces it)."
        )
    if cfg.oidc_enabled and not cfg.oidc_allowed:
        log.warning(
            "OIDC is enabled but COUNSELCLEAR_OIDC_ALLOWED is empty: the "
            "fail-closed allowlist denies every principal — nobody can sign "
            "in until it names at least one email or subject."
        )
    if cfg.worker_mode != "docker":
        log.warning(
            'worker_mode=%s: sanitize/inspect jobs run as a plain child '
            "process of this API, sharing its filesystem access — not "
            "isolated from a hostile file. Set COUNSELCLEAR_WORKER_MODE="
            "docker (see compose.yaml's legal profile) for real isolation.",
            cfg.worker_mode,
        )
    if shutil.which("clamscan") is None:
        log.warning(
            "clamscan not found on PATH: uploads are only checked for "
            "nested-archive depth, not scanned for malware. "
            "Dockerfile.counselclear installs clamav; a bare non-container "
            "run of this app does not."
        )


_unknown_client_state = {"warned": False}


def _client_host(request: Request) -> str:
    # Socket peer only — X-Forwarded-For is client-controlled and would let
    # an attacker rotate fake IPs past the throttle. Proxy deployments that
    # need real-IP accounting should rate-limit at the proxy.
    #
    # request.client is None only when the ASGI server exposes no peer
    # address at all (e.g. bound to a Unix domain socket) — every such
    # request collapses onto this one literal key, sharing one throttle
    # bucket and one access-log "client" value across every caller. That's
    # a real loss of the per-peer isolation this exists for, not a
    # theoretical one: it silently affects 100% of traffic on that
    # deployment shape. It isn't attacker-triggerable over a normal TCP
    # path (the ASGI server decides this, not the client), so it can't be
    # abused to dodge the throttle — but an operator deploying that way
    # needs to know the throttle is now effectively deployment-wide and
    # must rate-limit at the proxy, so warn once instead of failing silent.
    if request.client:
        return request.client.host
    if not _unknown_client_state["warned"]:
        _unknown_client_state["warned"] = True
        log.warning(
            "request.client is unavailable (no ASGI peer address, e.g. a "
            "Unix-socket bind): the login throttle and access log now "
            "share one bucket across every caller on this deployment — "
            "rate-limit at the proxy instead."
        )
    return "unknown"


async def _read_capped(file: UploadFile, cap: int | None = None) -> bytes:
    """Read an upload in bounded chunks, never buffering past ``cap`` bytes.

    ``await file.read()`` has no size limit of its own — a client that
    omits Content-Length (or lies about it) could otherwise make this
    process buffer an arbitrarily large body before the engine's own
    MAX_INPUT_BYTES check ever runs (which only happens later, inside the
    isolated worker). This is the same cap, enforced at the door instead.
    ``cap`` defaults to the module-level constant, looked up at call time
    (not bound as a default value) so tests can override it.
    """
    if cap is None:
        cap = MAX_INPUT_BYTES
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise HTTPException(413, f"upload exceeds {cap} byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(data_root: str | Path | None = None) -> FastAPI:
    cfg = Config(data_root)
    cfg.data_root.mkdir(parents=True, exist_ok=True)
    # With OIDC SSO enabled the shared-password credential is retired
    # entirely: no hash file is created or required, and /v1/auth/login is
    # disabled (below).
    if not cfg.oidc_enabled:
        ensure_local_password(cfg)
    engine = make_engine(cfg)
    upgrade_head(cfg.db_url())
    session_factory = make_session_factory(engine)
    throttle = LoginThrottle(
        max_failures=cfg.login_max_failures,
        window_s=cfg.login_window_s,
        lockout_s=cfg.login_lockout_s,
    )
    with session_factory() as s:
        swept = _sweep_orphaned_jobs(s)
    storage = storage_from_config(cfg)
    _log_startup_posture(cfg, swept, storage)

    # Docs are fail-closed: /docs, /redoc and /openapi.json carry no auth
    # check, so they only exist when explicitly opted in with
    # COUNSELCLEAR_ENABLE_DOCS=1 (the legacy COUNSELCLEAR_DISABLE_DOCS=1
    # still force-disables, winning over the enable flag).
    docs_enabled = (
        os.environ.get("COUNSELCLEAR_ENABLE_DOCS", "").strip() == "1"
        and os.environ.get("COUNSELCLEAR_DISABLE_DOCS", "").strip() != "1"
    )
    app = FastAPI(
        title="CounselClear",
        version="product-mvp",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    access_log_enabled = os.environ.get("COUNSELCLEAR_ACCESS_LOG", "1").strip() != "0"

    @app.middleware("http")
    async def _request_logging(request: Request, call_next):
        """One JSON line per request: method, path (no query string —
        include_original etc. carry nothing sensitive but the path is what
        belongs in a request log), status, duration, correlation id. The
        X-Request-ID header lets an operator match a client-side failure to
        exactly one server-side log line."""
        rid = uuid.uuid4().hex[:12]
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.perf_counter() - start) * 1000)
            _jlog(
                logging.ERROR,
                "http_request",
                request_id=rid,
                method=request.method,
                path=request.url.path,
                status=500,
                duration_ms=duration_ms,
                client=_client_host(request),
            )
            raise
        response.headers["X-Request-ID"] = rid
        if access_log_enabled:
            _jlog(
                logging.INFO,
                "http_request",
                request_id=rid,
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=int((time.perf_counter() - start) * 1000),
                client=_client_host(request),
            )
        return response

    def db_session():
        s = session_factory()
        try:
            yield s
        finally:
            s.close()

    @app.get("/health")
    def health():
        """Liveness only: the process is up and serving HTTP. No DB, no
        dependencies — a probe wired to this should never restart the
        container over a transient database outage; use /health/ready for
        that instead (see docs/COUNSELCLEAR_PRODUCTION.md)."""
        return {"ok": True}

    @app.get("/health/ready")
    def health_ready(s: Session = Depends(db_session)):
        """Readiness: can this instance actually serve a request right
        now. 503 when the database is unreachable — an orchestrator should
        stop routing traffic here, not restart the process (restarting
        doesn't fix a downed database and just adds churn)."""
        try:
            s.execute(text("SELECT 1"))
        except Exception:
            raise HTTPException(503, "database unavailable") from None
        return {"ok": True}

    def principal(request: Request) -> str:
        """Auth dependency: validates the session cookie and returns the
        authenticated subject ("operator" for local-password logins, an
        "oidc:<hash>" identity for SSO). Every permission check and audit
        actor_id below is keyed on this, so OIDC principals are isolated
        from each other by the same matter ACL that scopes the operator."""
        subject = session_subject(cfg, request.cookies.get("cc_session"))
        if not subject:
            raise HTTPException(401, "authentication required")
        return subject

    def _require(matter_id: str, perm: str, s: Session, user: str) -> None:
        if not has_perm(s, matter_id, user, perm):
            raise HTTPException(403, f"missing permission: {perm}")

    def _cookie_secure(request: Request) -> bool:
        """Session-cookie Secure flag per COUNSELCLEAR_COOKIE_SECURE.

        auto (default): follow the request scheme — correct when uvicorn runs
        with --proxy-headers behind a TLS-terminating proxy (the documented
        topology; it then reflects X-Forwarded-Proto from the trusted proxy).
        true/false: explicit override for deployments where the proxy cannot
        forward the proto (e.g. TCP passthrough) or for loopback dev.
        """
        mode = cfg.cookie_secure
        if mode == "true":
            return True
        if mode == "false":
            return False
        return request.url.scheme == "https"

    # --- auth ---------------------------------------------------------------

    @app.get("/v1/auth/config")
    def auth_config():
        """Public, unauthenticated: tells the login page which flow to
        render. The static-export web UI has no server at request time to
        read an env var from, so this is the one thing it fetches before
        a session exists. No secrets — just the OIDC on/off bit."""
        return {"oidc_enabled": cfg.oidc_enabled}

    @app.post("/v1/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        if cfg.oidc_enabled:
            # The shared password is retired when SSO is on — keeping a
            # second, phishable credential path alive would defeat the
            # point of federating identity.
            raise HTTPException(403, "local login disabled; use OIDC SSO")
        peer = _client_host(request)
        if not throttle.allow(peer):
            # Headers must ride on the exception itself — FastAPI's handler
            # builds a fresh response for HTTPException and drops anything
            # set on `response` beforehand.
            raise HTTPException(
                429,
                "too many failed logins; try again later",
                headers={"Retry-After": str(throttle.retry_after_s(peer))},
            )
        if not verify_password(cfg, body.password):
            throttle.record_failure(peer)
            raise HTTPException(403, "invalid credentials")
        throttle.record_success(peer)
        # Secure flag policy lives in _cookie_secure: "auto" follows the
        # request scheme (this app has no TLS termination of its own today —
        # loopback-bound plain HTTP is the documented v1 deployment — and a
        # hardcoded secure flag would just make the cookie never get sent at
        # all rather than add any real protection), with explicit
        # COUNSELCLEAR_COOKIE_SECURE=true/false overrides for proxy
        # deployments that cannot forward the proto.
        response.set_cookie(
            "cc_session", issue_session(cfg),
            httponly=True, samesite="strict", secure=_cookie_secure(request),
        )
        return {"ok": True}

    if cfg.oidc_enabled:

        @app.get("/v1/auth/oidc/login")
        def oidc_login(request: Request):
            try:
                return RedirectResponse(
                    oidc_mod.authorization_redirect(cfg, request), status_code=303
                )
            except OidcError as e:
                log.warning("oidc discovery failed for peer %s: %s", _client_host(request), e)
                raise HTTPException(502, "identity provider unavailable") from e

        @app.get("/v1/auth/oidc/callback")
        def oidc_callback(request: Request, code: str = "", state: str = ""):
            # Same per-peer sliding-window guard as local-password login:
            # this is the credential-establishing step (state/code/id_token
            # validation), so it deserves the same brute-force/DoS backstop
            # as /v1/auth/login rather than being reachable at unlimited
            # rate just because the password check happens to live at the
            # IdP instead of here.
            peer = _client_host(request)
            if not throttle.allow(peer):
                raise HTTPException(
                    429,
                    "too many failed sign-in attempts; try again later",
                    headers={"Retry-After": str(throttle.retry_after_s(peer))},
                )
            if not code or not state:
                throttle.record_failure(peer)
                raise HTTPException(400, "missing code/state")
            try:
                nonce = oidc_mod.parse_state(cfg, state)  # CSRF: signed + fresh
                id_token = oidc_mod.exchange_code(
                    cfg, oidc_mod.redirect_uri_for(cfg, request), code
                )
                claims = oidc_mod.validated_claims(cfg, id_token, nonce)
            except OidcError as e:
                throttle.record_failure(peer)
                # Never echo IdP/validation internals to the client — the
                # exception text can carry token endpoints, audience values,
                # and PyJWT internals. Log it server-side for the operator.
                log.warning("oidc sign-in refused for peer %s: %s", peer, e)
                raise HTTPException(401, "SSO sign-in failed") from e
            if not oidc_mod.allowed_principal(cfg, claims):
                # Fail closed: not on the allowlist. Same message shape for
                # all denials; no enumeration help.
                throttle.record_failure(peer)
                raise HTTPException(403, "principal not permitted")
            throttle.record_success(peer)
            sub = str(claims["sub"])
            redirect = RedirectResponse("/", status_code=303)
            redirect.set_cookie(
                "cc_session",
                issue_session(cfg, oidc_mod.principal_for(sub)),
                httponly=True,
                samesite="strict",
                secure=_cookie_secure(request),
            )
            # This is a top-level browser navigation (the IdP redirected the
            # user here), not a fetch() call from the web app — returning
            # JSON would leave the user staring at a JSON blob instead of
            # landing back in the UI. "/" is the web app's root in the
            # deployed topology (nginx serves it; see next.config.ts); this
            # route has no opinion on what's there in a bare API-only test.
            return redirect

    @app.post("/v1/auth/logout", dependencies=[Depends(principal)])
    def logout(response: Response):
        """Clear the session cookie client-side. The HMAC token itself stays
        valid until its TTL — use /v1/auth/revoke-sessions when a cookie may
        have leaked and must die server-side."""
        response.delete_cookie("cc_session", httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/v1/auth/revoke-sessions")
    def revoke_sessions(response: Response, user: str = Depends(principal)):
        """Rotate the cookie secret: every issued session token fails
        signature verification from now on (including this caller's).

        Restricted to the local operator identity. This product has no
        global-admin concept — permissions are per-matter ACL rows — so
        `Depends(principal)` alone (any authenticated session, including an
        OIDC principal scoped to a single matter) is not authorization for a
        deployment-wide action. Under OIDC, local login is disabled and no
        session can ever carry the operator subject, so this route is
        unreachable there by design; the equivalent action is deleting
        `{data_root}/auth/cookie.secret` on the host, which any operator with
        host access already has."""
        if user != LOCAL_SUBJECT:
            raise HTTPException(403, "session revocation is restricted to the local operator")
        revoke_all_sessions(cfg)
        response.delete_cookie("cc_session", httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/v1/attestations")
    def create_attestation(
        body: AttestationBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        """PR 20: sign a Layer B (content-altering) attestation token for one
        document. The product gate: 403 unless watermark tools are enabled,
        the caller holds the sanitize permission, and the strength is one the
        product allows (KD 10 — code/backtranslate stay CLI-only). The token
        is HMAC-signed, doc-bound (sha256), 10-minute TTL, single-use; the
        resulting job records the jti so the audit chain can tie the rewrite
        back to this exact authorization."""
        if not cfg.watermark_tools_enabled:
            raise HTTPException(403, "watermark tools are disabled")
        if body.strength not in ATTEST_STRENGTHS:
            raise HTTPException(400, f"strength not product-allowed: {body.strength!r}")
        _require(body.matter_id, "sanitize", s, user)
        doc = _document(body.matter_id, body.document_id, s)
        token, jti, expires_utc = issue_attestation(
            cfg,
            subject=user,
            matter_id=body.matter_id,
            doc_sha256=doc.sha256,
            strength=body.strength,
        )
        append_event(
            s,
            matter_id=body.matter_id,
            actor_id=user,
            action="attest.issued",
            payload={
                "jti": jti,
                "document_id": doc.id,
                "sha256": doc.sha256,
                "strength": body.strength,
                "reason": body.reason[:500],
            },
        )
        s.commit()
        return {"token": token, "jti": jti, "expires_utc": expires_utc}

    @app.get("/v1/policies", dependencies=[Depends(principal)])
    def list_policies():
        return {"policies": POLICIES}

    # --- matters ------------------------------------------------------------

    @app.get("/v1/matters")
    def list_matters(
        user: str = Depends(principal),
        s: Session = Depends(db_session),
        limit: int = 100,
    ):
        limit = min(max(1, limit), 500)  # server-capped, never unbounded
        matter_ids = [
            r[0]
            for r in s.query(MatterAcl.matter_id).filter_by(user_id=user, perm="read").distinct()
        ]
        matters = (
            s.query(Matter)
            .filter(Matter.id.in_(matter_ids))
            .order_by(Matter.created_utc.desc())
            .limit(limit)
        )
        return {"matters": [_matter_dict(m) for m in matters]}

    @app.post("/v1/matters")
    def create_matter(body: MatterBody, user: str = Depends(principal), s: Session = Depends(db_session)):
        matter = Matter(name=body.name)
        s.add(matter)
        s.flush()
        # The creating principal gets OWNER_PERMS (minus download_original,
        # which is always a deliberate grant). In local-password mode this
        # is exactly the historical bootstrap_operator(OPERATOR) behaviour.
        bootstrap_operator(s, matter.id, user_id=user)
        append_event(
            s,
            matter_id=matter.id,
            actor_id=user,
            action="matter.create",
            payload={"name": body.name},
        )
        s.commit()
        return _matter_dict(matter)

    @app.get("/v1/matters/{matter_id}")
    def get_matter(
        matter_id: str, user: str = Depends(principal), s: Session = Depends(db_session)
    ):
        # Permission check first (uniform 403 for both nonexistent and
        # unauthorized), matching every other matter-scoped route — the
        # old existence-first order leaked an ID-existence oracle.
        _require(matter_id, "read", s, user)
        return _matter_dict(_matter(matter_id, s))

    # --- documents ----------------------------------------------------------

    @app.post("/v1/matters/{matter_id}/documents")
    async def upload_document(
        matter_id: str,
        file: UploadFile = File(...),
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "upload", s, user)
        _matter(matter_id, s)
        data = await _read_capped(file)
        name = Path(file.filename or "upload").name
        verdict = get_scanner().scan(data, name)
        if not verdict.clean:
            raise HTTPException(422, f"malware scanner flagged upload ({verdict.scanner})")
        doc = Document(
            id=_uuid(),
            matter_id=matter_id,
            filename=name,
            sha256=custody_mod.sha256_bytes(data),
            bytes=len(data),
            storage_path="",
        )
        key = original_key(cfg.org, matter_id, doc.id, name)
        try:
            doc.storage_path = storage.write_once(key, data)
        except StorageError_ as e:
            raise HTTPException(409, str(e)) from e
        s.add(doc)
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="document.upload",
            payload={"filename_ext": Path(name).suffix, "sha256": doc.sha256, "bytes": doc.bytes},
        )
        s.commit()
        return _doc_dict(doc)

    @app.get("/v1/matters/{matter_id}/documents")
    def list_documents(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
        limit: int = 100,
    ):
        limit = min(max(1, limit), 500)  # server-capped, never unbounded
        _require(matter_id, "read", s, user)
        _matter(matter_id, s)
        docs = (
            s.query(Document)
            .filter_by(matter_id=matter_id)
            .order_by(Document.created_utc.desc())
            .limit(limit)
        )
        return {"documents": [_doc_dict(d) for d in docs]}

    @app.get("/v1/matters/{matter_id}/documents/{doc_id}")
    def get_document(
        matter_id: str,
        doc_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        return _doc_dict(_document(matter_id, doc_id, s))

    # --- jobs ---------------------------------------------------------------

    def _create_job(matter_id: str, doc_id: str, kind: str, s: Session, **kw) -> Job:
        job = Job(matter_id=matter_id, document_id=doc_id, kind=kind, **kw)
        s.add(job)
        s.commit()
        return job

    def _execute_job(job_id: str, kind: str) -> None:
        """Run the queued job in an isolated worker process (PR 17).

        The worker performs all status transitions; sync_job() is the
        crash/timeout backstop that guarantees a terminal status.
        Timeout budget derives from engine Caps per kind (PR 18).
        """
        s = session_factory()
        try:
            res = run_job(cfg, s, job_id, kind=kind, storage=storage)
            sync_job(s, job_id, res)
        finally:
            s.close()

    @app.post("/v1/matters/{matter_id}/documents/{doc_id}/inspect-jobs")
    def inspect_job(
        matter_id: str,
        doc_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "inspect", s, user)
        doc = _document(matter_id, doc_id, s)
        job = _create_job(matter_id, doc.id, "inspect", s)
        _execute_job(job.id, kind="inspect")
        s.expire_all()
        return _job_dict(_job(matter_id, job.id, s))

    @app.post("/v1/matters/{matter_id}/documents/{doc_id}/sanitize-jobs")
    def sanitize_job(
        matter_id: str,
        doc_id: str,
        body: SanitizeBody | None = None,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "sanitize", s, user)
        doc = _document(matter_id, doc_id, s)
        body = body or SanitizeBody()
        layer_b: dict | None = None
        attest_claims: dict | None = None
        jti: str | None = None
        if body.layer_b is not None:
            if not cfg.watermark_tools_enabled:
                raise HTTPException(403, "watermark tools are disabled")
            claims = verify_attestation(
                cfg,
                body.layer_b.token,
                matter_id=matter_id,
                doc_sha256=doc.sha256,
            )
            if claims is None:
                raise HTTPException(403, "invalid or expired attestation token")
            # The token binds a specific principal; only that principal may
            # consume it (otherwise any sanitize-perm holder could spend
            # someone else's authorization).
            if claims.get("sub") != user:
                raise HTTPException(403, "attestation token was issued to another principal")
            jti = claims["jti"]
            layer_b = {
                "strength": claims["strength"],
                "label": claims["label"],
                "subject": claims["sub"],
                "jti": jti,
            }
            attest_claims = claims
        job = Job(
            matter_id=matter_id,
            document_id=doc.id,
            kind="sanitize",
            policy_id=body.policy_id,
            reason=body.reason[:500],
            attestation=bool(body.signature_break_attestation),
            finding_decisions=dict(body.finding_decisions),
            layer_b=layer_b,
        )
        s.add(job)
        s.flush()  # assigns job.id (Job.id's default is Python-side)
        if jti is not None:
            # Single-use, race-free: jti is the primary key of a dedicated
            # table (0005 migration), inserted in the *same transaction* as
            # the job row it authorizes. A concurrent duplicate use of the
            # same token — a second thread, a second gunicorn worker, or a
            # replay of a token whose in-memory record didn't survive a
            # restart — collides with the unique constraint here instead of
            # racing a read-then-write check. app.security's in-memory
            # _consumed_jtis set (checked inside verify_attestation above)
            # is only the fast path for the common single-attempt case;
            # this is the durable backstop.
            s.add(AttestationUse(jti=jti, job_id=job.id, matter_id=matter_id))
            try:
                s.flush()
            except IntegrityError as e:
                s.rollback()
                raise HTTPException(403, "attestation token already used") from e
        if layer_b is not None and attest_claims is not None:
            # Consume only once the job + attestation_uses rows are staged
            # in this (not-yet-committed) transaction: a rollback above must
            # not have already burned the token in-memory with no durable
            # record to show for it.
            consume_attestation(attest_claims)
            append_event(
                s,
                matter_id=matter_id,
                actor_id=user,
                action="attest.used",
                payload={"jti": jti, "job_id": job.id, "strength": layer_b["strength"]},
            )
        s.commit()
        _execute_job(job.id, kind="sanitize")
        s.expire_all()
        return _job_dict(_job(matter_id, job.id, s))

    @app.get("/v1/matters/{matter_id}/jobs")
    def list_jobs(
        matter_id: str,
        document_id: str = "",
        user: str = Depends(principal),
        s: Session = Depends(db_session),
        limit: int = 100,
    ):
        limit = min(max(1, limit), 500)  # server-capped, never unbounded
        _require(matter_id, "read", s, user)
        _matter(matter_id, s)
        q = s.query(Job).filter_by(matter_id=matter_id)
        if document_id:
            q = q.filter_by(document_id=document_id)
        jobs = (
            q.order_by(Job.created_utc.desc())
            .limit(limit)
            .all()
        )
        # List view omits the full result payload (it can be large for
        # inspect jobs); the detail route carries it.
        return {"jobs": [_job_dict(j, include_result=False) for j in jobs]}

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}")
    def get_job(
        matter_id: str,
        job_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        return _job_dict(_job(matter_id, job_id, s))

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}/manifest")
    def job_manifest(
        matter_id: str,
        job_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        job = _job(matter_id, job_id, s)
        if job.kind != "sanitize" or not job.result_json:
            raise HTTPException(404, "no manifest for this job")
        return JSONResponse(job.result_json.get("manifest", {}))

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}/bundle")
    def job_bundle(
        matter_id: str,
        job_id: str,
        include_original: bool = False,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s, user)
        job = _job(matter_id, job_id, s)
        if job.status != "done" or not job.bundle_dir:
            raise HTTPException(409, f"job is {job.status}; no bundle")
        original_ref = None
        original_name = None
        if include_original:
            _require(matter_id, "download_original", s, user)
            doc = s.get(Document, job.document_id)
            original_ref = doc.storage_path
            original_name = doc.filename
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            bundle = Path(job.bundle_dir)
            for rel in ("manifest.json",):
                p = bundle / rel
                if p.exists():
                    zf.write(p, arcname=rel)
            deriv_dir = bundle / "derivative"
            # A truncated/failed worker output can lack the derivative tree
            # entirely — that's a 409 ("no bundle"), not an unhandled 500.
            if not deriv_dir.is_dir():
                raise HTTPException(409, f"job bundle is incomplete: {deriv_dir} missing")
            for p in sorted(deriv_dir.iterdir()):
                zf.write(p, arcname=f"derivative/{p.name}")
            report = {
                "verification": (job.result_json or {}).get("manifest", {}).get("verification"),
                "findings_before": (job.result_json or {})
                .get("manifest", {})
                .get("findings_before"),
            }
            zf.writestr("report.json", json.dumps(report, indent=2, sort_keys=True))
            if original_ref and storage.exists(original_ref):
                zf.writestr(f"original/{original_name}", storage.read(original_ref))
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="bundle.download",
            payload={"job_id": job.id, "include_original": include_original},
        )
        s.commit()
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{job.id}-bundle.zip"'},
        )

    @app.put("/v1/matters/{matter_id}/acl")
    def put_acl(
        matter_id: str,
        body: AclBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "admin", s, user)
        _matter(matter_id, s)
        try:
            grant(s, matter_id, body.user_id, body.perm)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="acl.grant",
            payload={"user_id": body.user_id, "perm": body.perm},
        )
        s.commit()
        return {"ok": True, "user_id": body.user_id, "perm": body.perm}

    @app.delete("/v1/matters/{matter_id}/acl")
    def delete_acl(
        matter_id: str,
        body: AclBody,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "admin", s, user)
        _matter(matter_id, s)
        revoke(s, matter_id, body.user_id, body.perm)
        append_event(
            s,
            matter_id=matter_id,
            actor_id=user,
            action="acl.revoke",
            payload={"user_id": body.user_id, "perm": body.perm},
        )
        s.commit()
        return {"ok": True, "revoked": {"user_id": body.user_id, "perm": body.perm}}

    @app.get("/v1/matters/{matter_id}/audit")
    def list_audit(
        matter_id: str,
        user: str = Depends(principal),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "admin", s, user)
        rows = (
            s.query(AuditEvent)
            .filter(AuditEvent.matter_id == matter_id)
            .order_by(AuditEvent.seq)
            .all()
        )
        ok, detail = verify_chain(rows)
        return {
            "chain_ok": ok,
            "chain_detail": detail,
            "events": [
                {
                    "id": e.id,
                    "seq": e.seq,
                    "action": e.action,
                    "actor_id": e.actor_id,
                    "payload": e.payload,
                    "prev_hash": e.prev_hash,
                    "row_hash": e.row_hash,
                    "at": e.at,
                }
                for e in rows
            ],
        }

    # --- helpers ------------------------------------------------------------

    def _matter(matter_id: str, s: Session) -> Matter:
        m = s.get(Matter, matter_id)
        if not m:
            raise HTTPException(404, "matter not found")
        return m

    def _document(matter_id: str, doc_id: str, s: Session) -> Document:
        d = s.get(Document, doc_id)
        if not d or d.matter_id != matter_id:
            raise HTTPException(404, "document not found")
        return d

    def _job(matter_id: str, job_id: str, s: Session) -> Job:
        j = s.get(Job, job_id)
        if not j or j.matter_id != matter_id:
            raise HTTPException(404, "job not found")
        return j

    def _matter_dict(m: Matter) -> dict:
        return {"id": m.id, "name": m.name, "created_utc": m.created_utc}

    def _doc_dict(d: Document) -> dict:
        return {
            "id": d.id,
            "matter_id": d.matter_id,
            "filename": d.filename,
            "sha256": d.sha256,
            "bytes": d.bytes,
            "created_utc": d.created_utc,
        }

    def _job_dict(j: Job, *, include_result: bool = True) -> dict:
        out = {
            "id": j.id,
            "matter_id": j.matter_id,
            "document_id": j.document_id,
            "kind": j.kind,
            "policy_id": j.policy_id,
            "status": j.status,
            "error": j.error,
            "attestation": j.attestation,
            "layer_b": j.layer_b,
            "worker_image": j.worker_image,
            "created_utc": j.created_utc,
            "finished_utc": j.finished_utc,
        }
        if include_result and j.result_json:
            out["result"] = j.result_json
        return out

    return app
