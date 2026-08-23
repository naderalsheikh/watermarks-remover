"""FastAPI application factory and /v1 routes (single-tenant profile)."""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import zipfile
from pathlib import Path

import custody as custody_mod  # WORM storage only — never parses documents
from common import MAX_INPUT_BYTES  # a size constant, not a parser
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

# PR 17 doctrine: this module must NOT import engine_api / custody or call
# inspect_bytes/clean_to_bundle — untrusted bytes are parsed only inside
# isolated worker processes (see app.runner). A test enforces the ban.
from .acl import OPERATOR, bootstrap_operator, grant, has_perm, revoke
from .audit import append_event, verify_chain
from .config import Config
from .db import make_engine, make_session_factory
from .malware import get_scanner
from .migrate import upgrade_head
from .models import AuditEvent, Document, Job, Matter, _uuid
from .runner import run_job, sync_job
from .security import ensure_local_password, issue_session, valid_session, verify_password


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
    user_id: str = OPERATOR
    perm: str


log = logging.getLogger("counselclear")


def _log_startup_posture(cfg: Config) -> None:
    """One-time, non-secret operational summary at boot — this app shipped
    with zero logging until now, which meant an operator running it
    unisolated or with a no-op malware scanner had no way to notice short
    of reading the source. Never logs the password, hash, or cookie secret."""
    log.info(
        "counselclear starting: data_root=%s worker_mode=%s",
        cfg.data_root, cfg.worker_mode,
    )
    if cfg.worker_mode != "docker":
        log.warning(
            "worker_mode=%s: sanitize/inspect jobs run as a plain child "
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
    ensure_local_password(cfg)
    engine = make_engine(cfg)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    session_factory = make_session_factory(engine)
    _log_startup_posture(cfg)

    # Set COUNSELCLEAR_DISABLE_DOCS=1 for any deployment reachable beyond
    # loopback: /docs and /openapi.json carry no auth check today.
    docs_disabled = os.environ.get("COUNSELCLEAR_DISABLE_DOCS", "").strip() == "1"
    app = FastAPI(
        title="CounselClear",
        version="product-mvp",
        docs_url=None if docs_disabled else "/docs",
        redoc_url=None if docs_disabled else "/redoc",
        openapi_url=None if docs_disabled else "/openapi.json",
    )

    @app.get("/health")
    def health():
        return {"ok": True}

    def db_session():
        s = session_factory()
        try:
            yield s
        finally:
            s.close()

    def authed(request: Request) -> None:
        token = request.cookies.get("cc_session")
        if not valid_session(cfg, token):
            raise HTTPException(401, "authentication required")

    def _require(matter_id: str, perm: str, s: Session) -> None:
        if not has_perm(s, matter_id, OPERATOR, perm):
            raise HTTPException(403, f"missing permission: {perm}")

    # --- auth ---------------------------------------------------------------

    @app.post("/v1/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        if not verify_password(cfg, body.password):
            raise HTTPException(403, "invalid credentials")
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

    # --- matters ------------------------------------------------------------

    @app.post("/v1/matters", dependencies=[Depends(authed)])
    def create_matter(body: MatterBody, s: Session = Depends(db_session)):
        matter = Matter(name=body.name)
        s.add(matter)
        s.flush()
        bootstrap_operator(s, matter.id)
        append_event(
            s,
            matter_id=matter.id,
            actor_id=OPERATOR,
            action="matter.create",
            payload={"name": body.name},
        )
        s.commit()
        return _matter_dict(matter)

    @app.get("/v1/matters/{matter_id}", dependencies=[Depends(authed)])
    def get_matter(matter_id: str, s: Session = Depends(db_session)):
        matter = _matter(matter_id, s)
        _require(matter_id, "read", s)
        return _matter_dict(matter)

    # --- documents ----------------------------------------------------------

    @app.post("/v1/matters/{matter_id}/documents", dependencies=[Depends(authed)])
    async def upload_document(
        matter_id: str,
        file: UploadFile = File(...),
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "upload", s)
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
            actor_id=OPERATOR,
            action="document.upload",
            payload={"filename_ext": Path(name).suffix, "sha256": doc.sha256, "bytes": doc.bytes},
        )
        s.commit()
        return _doc_dict(doc)

    @app.get(
        "/v1/matters/{matter_id}/documents/{doc_id}",
        dependencies=[Depends(authed)],
    )
    def get_document(matter_id: str, doc_id: str, s: Session = Depends(db_session)):
        _require(matter_id, "read", s)
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

    @app.post(
        "/v1/matters/{matter_id}/documents/{doc_id}/inspect-jobs",
        dependencies=[Depends(authed)],
    )
    def inspect_job(matter_id: str, doc_id: str, s: Session = Depends(db_session)):
        _require(matter_id, "inspect", s)
        doc = _document(matter_id, doc_id, s)
        job = _create_job(matter_id, doc.id, "inspect", s)
        _execute_job(job.id, kind="inspect")
        s.expire_all()
        return _job_dict(_job(matter_id, job.id, s))

    @app.post(
        "/v1/matters/{matter_id}/documents/{doc_id}/sanitize-jobs",
        dependencies=[Depends(authed)],
    )
    def sanitize_job(
        matter_id: str,
        doc_id: str,
        body: SanitizeBody | None = None,
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "sanitize", s)
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

    @app.get("/v1/matters/{matter_id}/jobs/{job_id}", dependencies=[Depends(authed)])
    def get_job(matter_id: str, job_id: str, s: Session = Depends(db_session)):
        _require(matter_id, "read", s)
        return _job_dict(_job(matter_id, job_id, s))

    @app.get(
        "/v1/matters/{matter_id}/jobs/{job_id}/manifest",
        dependencies=[Depends(authed)],
    )
    def job_manifest(matter_id: str, job_id: str, s: Session = Depends(db_session)):
        _require(matter_id, "read", s)
        job = _job(matter_id, job_id, s)
        if job.kind != "sanitize" or not job.result_json:
            raise HTTPException(404, "no manifest for this job")
        return JSONResponse(job.result_json.get("manifest", {}))

    @app.get(
        "/v1/matters/{matter_id}/jobs/{job_id}/bundle",
        dependencies=[Depends(authed)],
    )
    def job_bundle(
        matter_id: str,
        job_id: str,
        include_original: bool = False,
        s: Session = Depends(db_session),
    ):
        _require(matter_id, "read", s)
        job = _job(matter_id, job_id, s)
        if job.status != "done" or not job.bundle_dir:
            raise HTTPException(409, f"job is {job.status}; no bundle")
        original_path = None
        if include_original:
            _require(matter_id, "download_original", s)
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
            actor_id=OPERATOR,
            action="bundle.download",
            payload={"job_id": job.id, "include_original": include_original},
        )
        s.commit()
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{job.id}-bundle.zip"'},
        )

    @app.put("/v1/matters/{matter_id}/acl", dependencies=[Depends(authed)])
    def put_acl(matter_id: str, body: AclBody, s: Session = Depends(db_session)):
        _require(matter_id, "admin", s)
        _matter(matter_id, s)
        try:
            grant(s, matter_id, body.user_id, body.perm)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        append_event(
            s,
            matter_id=matter_id,
            actor_id=OPERATOR,
            action="acl.grant",
            payload={"user_id": body.user_id, "perm": body.perm},
        )
        s.commit()
        return {"ok": True, "user_id": body.user_id, "perm": body.perm}

    @app.delete("/v1/matters/{matter_id}/acl", dependencies=[Depends(authed)])
    def delete_acl(matter_id: str, body: AclBody, s: Session = Depends(db_session)):
        _require(matter_id, "admin", s)
        _matter(matter_id, s)
        revoke(s, matter_id, body.user_id, body.perm)
        append_event(
            s,
            matter_id=matter_id,
            actor_id=OPERATOR,
            action="acl.revoke",
            payload={"user_id": body.user_id, "perm": body.perm},
        )
        s.commit()
        return {"ok": True, "revoked": {"user_id": body.user_id, "perm": body.perm}}

    @app.get("/v1/matters/{matter_id}/audit", dependencies=[Depends(authed)])
    def list_audit(matter_id: str, s: Session = Depends(db_session)):
        _require(matter_id, "admin", s)
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
