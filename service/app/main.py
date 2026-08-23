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
from sqlalchemy import text
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
from .models import AuditEvent, Document, Job, Matter, _now, _uuid
from .oidc import OidcError
from .runner import run_job, sync_job
from .security import (
    LoginThrottle,
    ensure_local_password,
    issue_session,
    revoke_all_sessions,
    session_subject,
    verify_password,
)


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
    """
    rows = s.query(Job).filter(Job.status.in_(("queued", "running"))).all()
    if not rows:
        return 0
    for j in rows:
        j.status = "failed"
        j.error = "interrupted by an application restart"
        j.finished_utc = _now()
    s.commit()
    return len(rows)


def _log_startup_posture(cfg: Config, swept: int) -> None:
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
        orphaned_jobs_failed=swept,
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


def _client_host(request: Request) -> str:
    # Socket peer only — X-Forwarded-For is client-controlled and would let
    # an attacker rotate fake IPs past the throttle. Proxy deployments that
    # need real-IP accounting should rate-limit at the proxy.
    return request.client.host if request.client else "unknown"


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
    _log_startup_posture(cfg, swept)

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
    def health(s: Session = Depends(db_session)):
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

    # --- auth ---------------------------------------------------------------

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
        # secure=True whenever the request actually arrived over TLS; not
        # hardcoded True because this app has no TLS termination of its own
        # today (loopback-bound plain HTTP is the documented v1 deployment)
        # and a hardcoded secure flag would just make the cookie never get
        # sent at all rather than add any real protection.
        response.set_cookie(
            "cc_session", issue_session(cfg),
            httponly=True, samesite="strict", secure=request.url.scheme == "https",
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
                raise HTTPException(502, f"identity provider unavailable: {e}") from e

        @app.get("/v1/auth/oidc/callback")
        def oidc_callback(request: Request, response: Response, code: str = "", state: str = ""):
            if not code or not state:
                raise HTTPException(400, "missing code/state")
            try:
                nonce = oidc_mod.parse_state(cfg, state)  # CSRF: signed + fresh
                id_token = oidc_mod.exchange_code(
                    cfg, oidc_mod.redirect_uri_for(cfg, request), code
                )
                claims = oidc_mod.validated_claims(cfg, id_token, nonce)
            except OidcError as e:
                raise HTTPException(401, f"SSO sign-in refused: {e}") from e
            if not oidc_mod.allowed_principal(cfg, claims):
                # Fail closed: not on the allowlist. Same message shape for
                # all denials; no enumeration help.
                raise HTTPException(403, "principal not permitted")
            sub = str(claims["sub"])
            response.set_cookie(
                "cc_session",
                issue_session(cfg, oidc_mod.principal_for(sub)),
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https",
            )
            return {"ok": True, "subject": oidc_mod.principal_for(sub)}

    @app.post("/v1/auth/logout", dependencies=[Depends(principal)])
    def logout(response: Response):
        """Clear the session cookie client-side. The HMAC token itself stays
        valid until its TTL — use /v1/auth/revoke-sessions when a cookie may
        have leaked and must die server-side."""
        response.delete_cookie("cc_session", httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/v1/auth/revoke-sessions", dependencies=[Depends(principal)])
    def revoke_sessions(response: Response):
        """Rotate the cookie secret: every issued session token fails
        signature verification from now on (including this caller's)."""
        revoke_all_sessions(cfg)
        response.delete_cookie("cc_session", httponly=True, samesite="strict")
        return {"ok": True}

    # --- matters ------------------------------------------------------------

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
        matter = _matter(matter_id, s)
        _require(matter_id, "read", s, user)
        return _matter_dict(matter)

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
        dest = cfg.data_root / "matters" / matter_id / "docs" / doc.id / "original" / name
        try:
            stored, _created = custody_mod.write_once(dest, data)
        except custody_mod.CustodyError as e:
            raise HTTPException(409, str(e)) from e
        doc.storage_path = str(stored)
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
            res = run_job(cfg, s, job_id, kind=kind)
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
        job = _create_job(
            matter_id,
            doc.id,
            "sanitize",
            s,
            policy_id=body.policy_id,
            reason=body.reason[:500],
            attestation=bool(body.signature_break_attestation),
            finding_decisions=dict(body.finding_decisions),
        )
        _execute_job(job.id, kind="sanitize")
        s.expire_all()
        return _job_dict(_job(matter_id, job.id, s))

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
        original_path = None
        if include_original:
            _require(matter_id, "download_original", s, user)
            doc = s.get(Document, job.document_id)
            original_path = Path(doc.storage_path)
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
            if original_path and original_path.exists():
                zf.write(original_path, arcname=f"original/{original_path.name}")
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

    def _job_dict(j: Job) -> dict:
        out = {
            "id": j.id,
            "matter_id": j.matter_id,
            "document_id": j.document_id,
            "kind": j.kind,
            "policy_id": j.policy_id,
            "status": j.status,
            "error": j.error,
            "attestation": j.attestation,
            "worker_image": j.worker_image,
            "created_utc": j.created_utc,
            "finished_utc": j.finished_utc,
        }
        if j.result_json:
            out["result"] = j.result_json
        return out

    return app
