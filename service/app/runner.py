"""Job runners (PR 17): the API never parses untrusted bytes.

Two modes:
- subprocess (default): spawn ``python -m app.worker run-job`` in a child
  process. Isolation boundary = process.
- docker: per-job container with --network none, read-only rootfs, tmpfs,
  dropped capabilities and a digest-pinned image recorded on the job row.

**Neither mode gives the worker database access or any path outside its own
job directory.** ``run_job`` stages a fresh ``{data_root}/matters/{matter}/
jobs/{job}/`` directory containing only a copy of the one document being
processed (``input/``); the worker writes its outcome to ``output/
result.json`` (and, for sanitize, ``output/bundle/``). In docker mode *only
that directory* is mounted — not the shared SQLite database, not other
matters, not other jobs. The worker process performs no job-status writes at
all; ``sync_job`` (run in the trusted parent, after the subprocess/container
exits) reads ``result.json`` and is the sole writer of the Job row. A worker
that crashes or times out before writing that file leaves sync_job's
crash-backstop path to record "failed".

This replaces an earlier design where the worker held a live database
session and the whole data root was mounted into the container — that let a
compromised parser (the entire threat model this isolation exists for) read
or corrupt every matter's files and the audit chain directly.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from .config import Config
from .models import Document, Job, _now

SERVICE_DIR = Path(__file__).resolve().parents[1]

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

# Hard ceiling: a sanitize must finish or die well under this in tests;
# production overrides via COUNSELCLEAR_WORKER_TIMEOUT_S.


@dataclass
class RunnerResult:
    rc: int
    stderr_tail: str
    timed_out: bool
    output_dir: Path | None = None


def job_root(cfg: Config, matter_id: str, job_id: str) -> Path:
    return cfg.data_root / "matters" / matter_id / "jobs" / job_id


def build_subprocess_cmd(
    *, input_path: Path, output_dir: Path, kind: str, policy_id: str,
    attest: bool, matter_id: str, decisions: dict[str, str] | None = None,
    layer_b: dict | None = None,
) -> list[str]:
    cmd = [
        sys.executable, "-m", "app.worker", "run-job",
        "--kind", kind,
        "--input", str(input_path),
        "--output-dir", str(output_dir),
        "--policy", policy_id,
        "--matter-id", matter_id,
    ]
    if attest:
        cmd.append("--attest")
    if decisions:
        cmd += ["--decisions", json.dumps(decisions)]
    if layer_b:
        # Only the strength crosses the process boundary; the attestation
        # record itself stays in the API DB (Job.layer_b). The worker's
        # meaning-lock gate is what makes the strength safe to use.
        cmd += ["--layer-b", layer_b["strength"]]
    return cmd


def build_docker_cmd(
    cfg: Config, *, mount_root: Path, input_path: Path, output_dir: Path,
    kind: str, policy_id: str, attest: bool, matter_id: str,
    decisions: dict[str, str] | None = None, layer_b: dict | None = None,
) -> list[str]:
    image = cfg.worker_image
    if not _DIGEST_RE.search(image):
        raise ValueError(
            "COUNSELCLEAR_WORKER_IMAGE must be digest-pinned "
            "(repo@sha256:<64 hex>); refusing to run unpinned images"
        )
    # Container-side paths mirror the host layout under mount_root exactly,
    # so the same --input/--output-dir args work in both modes.
    c_input = "/data" / input_path.relative_to(mount_root)
    c_output = "/data" / output_dir.relative_to(mount_root)
    network = "none"
    if layer_b:
        # Layer B jobs need egress to the rewrite endpoint. PR 20 doctrine:
        # join the dedicated rewrite-proxy network (whose only peer is the
        # loopback-bound rewrite proxy); never the default bridge. The proxy
        # name must be resolvable from the worker container.
        network = os.environ.get("COUNSELCLEAR_REWRITE_NETWORK", "counselclear-rewrite")
    cmd = [
        "docker",
        "run",
        "--rm",
    ]
    if cfg.worker_runtime:
        # Optional hardened OCI runtime (e.g. gVisor's "runsc"): the
        # deployment registers the runtime with Docker; we only select it.
        cmd += ["--runtime", cfg.worker_runtime]
    cmd += [
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "1g",
        "--tmpfs",
        # S108 is about host /tmp usage; this string names the container's
        # tmpfs mount, deliberately noexec and size-capped.
        "/tmp:rw,size=64m,noexec",  # noqa: S108
        "-v",
        # Only this one job's own directory — not cfg.data_root. It has no
        # database, no other matter's documents, nothing but this job's
        # staged input and its own output tree.
        f"{mount_root}:/data",
        "-e",
        f"COUNSELCLEAR_WORKER_IMAGE={image}",
    ]
    if layer_b:
        # Layer B jobs need the rewrite endpoint env inside the container:
        # backend/model/base-url/api-key plus the loopback/proxy override.
        # Only the WATERMARKS_REWRITE_* namespace crosses — nothing else.
        for k, v in sorted(os.environ.items()):
            if k.startswith("WATERMARKS_REWRITE_"):
                cmd += ["-e", f"{k}={v}"]
    cmd += [
        image,
        "python",
        "-m",
        "app.worker",
        "run-job",
        "--kind",
        kind,
        "--input",
        str(c_input),
        "--output-dir",
        str(c_output),
        "--policy",
        policy_id,
        "--matter-id",
        matter_id,
    ]
    if attest:
        cmd.append("--attest")
    if decisions:
        cmd += ["--decisions", json.dumps(decisions)]
    if layer_b:
        # Same product semantics as the subprocess path: the worker must
        # actually run the rewrite (its meaning-lock gate fails the job on
        # a miss) — otherwise the audit chain would record an attestation
        # that was never exercised.
        cmd += ["--layer-b", layer_b["strength"]]
    return cmd


def job_budget_s(kind: str, caps=None) -> int:
    """Per-kind wall-clock budget derived from the engine Caps (PR 18).

    This reads the engine's limit constants only — no parsing happens on
    the API side. The budget covers worker startup, the pre-parse malware
    scan and (for sanitize) inspect + apply + verify inside one process.
    """
    from engine_api import Caps

    c = caps or Caps()
    if kind == "inspect":
        return c.inspect_timeout_s * 2 + 30
    return c.inspect_timeout_s + c.apply_timeout_s + c.verify_timeout_s + 60


def run_job(cfg: Config, s: Session, job_id: str, kind: str = "sanitize", storage=None) -> RunnerResult:
    """Blocking execution of one queued job in an isolated worker.

    Stages ``{job_root}/input/{name}`` (a copy of the document — the real
    write-once original at ``doc.storage_path`` is never handed to the
    worker directly) and ``{job_root}/output/`` (where the worker writes
    ``result.json`` and, for sanitize, ``bundle/``). Only ``job_root`` is
    exposed to the worker, in either mode. ``storage`` is the custody
    backend (PR 21); it defaults to local write-once so callers that
    predate the storage layer keep working unchanged.
    """
    from .storage import LocalStorage

    if storage is None:
        storage = LocalStorage(cfg.data_root)
    job = s.get(Job, job_id)
    doc = s.get(Document, job.document_id)
    if job is None or doc is None:
        raise RuntimeError(f"job {job_id} or its document is missing")

    # PR 20: a Layer B job must not execute once the flag is off. The flag
    # was checked at attestation time; re-checking at dispatch closes the
    # window where the operator disables watermark tools after a job was
    # queued. Fails the job with a labeled error (sync_job records it).
    if job.layer_b and not cfg.watermark_tools_enabled:
        return RunnerResult(
            rc=0,
            stderr_tail="watermark tools disabled",
            timed_out=False,
            output_dir=job_root(cfg, job.matter_id, job.id) / "output",
        )

    root = job_root(cfg, job.matter_id, job.id)
    input_dir, output_dir = root / "input", root / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    staged_input = input_dir / doc.filename
    if not staged_input.exists():
        staged_input.write_bytes(storage.read(doc.storage_path))

    job.status = "running"
    job.worker_image = cfg.worker_image if cfg.worker_mode == "docker" else ""
    s.commit()

    common = dict(
        input_path=staged_input, output_dir=output_dir, kind=kind,
        policy_id=job.policy_id, attest=bool(job.attestation), matter_id=job.matter_id,
        decisions=job.finding_decisions or None,
        layer_b=job.layer_b or None,
    )  # type: ignore[arg-type]  # layer_b: dict | None (Pyright: attribute of None)

    try:
        # Building the command (build_docker_cmd in particular: it raises
        # ValueError on an unpinned/empty COUNSELCLEAR_WORKER_IMAGE — exactly
        # compose.yaml's own ${COUNSELCLEAR_WORKER_IMAGE:-} default) used to
        # sit outside this try block, after job.status was already committed
        # to "running". That exception then propagated all the way up through
        # the route handler as an unhandled 500 — sync_job was never reached,
        # so the job stayed "running" forever with no error recorded and no
        # way for the operator to tell it had failed. Reproduced directly
        # against the real HTTP path before this fix.
        if cfg.worker_mode == "docker":
            cmd = build_docker_cmd(cfg, mount_root=root, **common)
            env_args: list[str] = []
            cwd: str | None = None
        else:
            cmd = build_subprocess_cmd(**common)
            # Child needs `app` importable regardless of how the API started.
            env_args = [f"PYTHONPATH={SERVICE_DIR}"]
            cwd = str(SERVICE_DIR)

        env = dict(os.environ)
        for kv in env_args:
            k, _, v = kv.partition("=")
            env[k] = v + os.pathsep + env.get(k, "")
        timeout = min(cfg.worker_timeout_s, job_budget_s(kind))
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return RunnerResult(
            rc=proc.returncode,
            stderr_tail=(proc.stderr or "")[-1000:],
            timed_out=False,
            output_dir=output_dir,
        )
    except subprocess.TimeoutExpired as e:
        tail = ((e.stderr or b"").decode(errors="replace"))[-1000:]
        return RunnerResult(
            rc=-1, stderr_tail=tail or "worker timed out", timed_out=True, output_dir=output_dir,
        )
    except Exception as e:
        # Any other setup/launch failure (bad worker config, missing docker
        # binary, permission error, ...) is a failed job, not an unhandled
        # 500 with the job stuck at "running" forever.
        return RunnerResult(
            rc=-1,
            stderr_tail=f"{type(e).__name__}: {e}"[-1000:],
            timed_out=False,
            output_dir=output_dir,
        )
    finally:
        # The real original stays at doc.storage_path; this was only ever a
        # transient copy staged for the worker's scoped mount/args.
        shutil.rmtree(input_dir, ignore_errors=True)


def sync_job(s: Session, job_id: str, res: RunnerResult) -> None:
    """Reconcile after a worker exit. The worker itself never touches the
    database — this reads back ``result.json`` (the worker's only output
    channel) and is the sole writer of the Job row. A worker that crashed
    or timed out before writing that file falls back to the crash backstop."""
    job = s.get(Job, job_id)
    if job is None:
        return
    if job.status in ("done", "refused", "failed"):
        return

    result_path = res.output_dir / "result.json" if res.output_dir else None
    payload = None
    if result_path and result_path.is_file():
        try:
            payload = json.loads(result_path.read_text())
        except (OSError, json.JSONDecodeError):
            payload = None

    if payload is not None:
        job.status = payload.get("status", "failed")
        job.error = str(payload.get("error") or "")[:1000]
        job.result_json = payload.get("result")
        job.bundle_dir = str(payload.get("bundle_dir") or "")
    else:
        job.status = "failed"
        reason = "worker timed out" if res.timed_out else f"worker exited rc={res.rc}"
        job.error = f"{reason}: {res.stderr_tail}".strip()[:1000]
    job.finished_utc = _now()
    s.commit()
