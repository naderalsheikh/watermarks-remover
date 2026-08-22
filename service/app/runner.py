"""Job runners (PR 17): the API never parses untrusted bytes.

Two modes:
- subprocess (default): spawn ``python -m app.worker run-job`` in a child
  process. Isolation boundary = process.
- docker: per-job container with --network none, read-only rootfs, tmpfs,
  dropped capabilities and a digest-pinned image recorded on the job row.

Either way the worker process performs every job status transition; the
API only reconciles a terminal state afterwards (sync_job).
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from .config import Config
from .models import Job, _now

SERVICE_DIR = Path(__file__).resolve().parents[1]

_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

# Hard ceiling: a sanitize must finish or die well under this in tests;
# production overrides via COUNSELCLEAR_WORKER_TIMEOUT_S.


@dataclass
class RunnerResult:
    rc: int
    stderr_tail: str
    timed_out: bool


def _base_env(extra_image: str = "") -> dict[str, str]:
    env = {
        "COUNSELCLEAR_WORKER_IMAGE": extra_image,
    }
    return {k: v for k, v in env.items() if v}


def build_subprocess_cmd(cfg: Config, job_id: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "app.worker",
        "run-job",
        "--data-root",
        str(cfg.data_root),
        "--job",
        job_id,
    ]


def build_docker_cmd(cfg: Config, job_id: str) -> list[str]:
    image = cfg.worker_image
    if not _DIGEST_RE.search(image):
        raise ValueError(
            "COUNSELCLEAR_WORKER_IMAGE must be digest-pinned "
            "(repo@sha256:<64 hex>); refusing to run unpinned images"
        )
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
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
        f"{cfg.data_root}:/data",
        "-e",
        "COUNSELCLEAR_DATA_ROOT=/data",
        "-e",
        f"COUNSELCLEAR_WORKER_IMAGE={image}",
        image,
        "python",
        "-m",
        "app.worker",
        "run-job",
        "--data-root",
        "/data",
        "--job",
        job_id,
    ]


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


def run_job(cfg: Config, job_id: str, kind: str = "sanitize") -> RunnerResult:
    """Blocking execution of one queued job in an isolated worker."""
    cmd = build_subprocess_cmd(cfg, job_id)
    env_args: list[str] = []
    cwd: str | None = None
    if cfg.worker_mode == "docker":
        cmd = build_docker_cmd(cfg, job_id)
    else:
        # Child needs `app` importable regardless of how the API was started.
        env_args = [f"PYTHONPATH={SERVICE_DIR}"]
        cwd = str(SERVICE_DIR)

    import os

    env = dict(os.environ)
    for kv in env_args:
        k, _, v = kv.partition("=")
        env[k] = v + os.pathsep + env.get(k, "")
    timeout = min(cfg.worker_timeout_s, job_budget_s(kind))
    try:
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
        )
    except subprocess.TimeoutExpired as e:
        tail = ((e.stderr or b"").decode(errors="replace"))[-1000:]
        return RunnerResult(rc=-1, stderr_tail=tail or "worker timed out", timed_out=True)


def sync_job(s: Session, job_id: str, res: RunnerResult) -> None:
    """Reconcile after a worker exit. The worker normally records the
    terminal status itself; this is the crash/timeout backstop."""
    job = s.get(Job, job_id)
    if job is None:
        return
    if job.status in ("done", "refused", "failed"):
        return
    job.status = "failed"
    reason = "worker timed out" if res.timed_out else f"worker exited rc={res.rc}"
    job.error = f"{reason}: {res.stderr_tail}".strip()[:1000]
    job.finished_utc = _now()
    s.commit()
