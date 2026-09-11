"""Job runners (PR 17): the API never parses untrusted bytes.

Two modes:
- subprocess (default): spawn ``python -m app.worker run-job`` in a child
  process. Isolation boundary = process.
- docker: per-job container with --network none, read-only rootfs, tmpfs,
  dropped capabilities and a digest-pinned image recorded on the job row.

``run_job`` passes only paths in a fresh ``{data_root}/matters/{matter}/
jobs/{job}/`` directory containing only a copy of the one document being
processed (``input/``); the worker writes its outcome to ``output/
result.json`` (and, for sanitize, ``output/bundle/``). In docker mode *only
that directory* is mounted — not the shared SQLite database, not other
matters, not other jobs. The worker process performs no job-status writes at
all; ``sync_job`` (run in the trusted parent, after the subprocess/container
exits) validates ``result.json`` and its artifacts and is the sole writer of
the Job row. A worker
that crashes or times out before writing that file leaves sync_job's
crash-backstop path to record "failed".

The subprocess development mode does not enforce a filesystem or secret
boundary: the child retains the launching user's privileges. Docker mode
provides the scoped mount and restricted environment described above.

This replaces an earlier design where the worker held a live database
session and the whole data root was mounted into the container — that let a
compromised parser (the entire threat model this isolation exists for) read
or corrupt every matter's files and the audit chain directly.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from sqlalchemy.orm import Session

from .config import Config
from .models import Batch, Document, Job, _now

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


def _confined_basename(name: object) -> bool:
    """Accept a native filename without permitting either platform's escapes.

    A backslash can be literal user content on POSIX (including in existing
    document names). Preserve that contract only when its Windows path
    interpretation is also relative and has no traversal/alias components.
    Windows itself still requires a single native basename.
    """
    if not isinstance(name, str) or not name or "\x00" in name or ":" in name:
        return False
    if Path(name).name != name or "/" in name:
        return False
    windows = PureWindowsPath(name)
    if windows.drive or windows.root:
        return False
    return all(part and not part.endswith((".", " ")) for part in name.split("\\"))


def build_subprocess_cmd(
    *,
    input_path: Path,
    output_dir: Path,
    kind: str,
    policy_id: str,
    attest: bool,
    matter_id: str,
    operator_id: str = "operator",
    decisions: dict[str, str] | None = None,
    legal_justifications: dict | None = None,
    layer_b: dict | None = None,
) -> list[str]:
    cmd = [
        sys.executable,
        "-m",
        "app.worker",
        "run-job",
        "--kind",
        kind,
        "--input",
        str(input_path),
        "--output-dir",
        str(output_dir),
        "--policy",
        policy_id,
        "--matter-id",
        matter_id,
        "--operator-id",
        operator_id,
    ]
    if attest:
        cmd.append("--attest")
    if decisions:
        cmd += ["--decisions", json.dumps(decisions)]
    if legal_justifications:
        cmd += ["--legal-justifications", json.dumps(legal_justifications)]
    if layer_b:
        # Only the strength crosses the process boundary; the attestation
        # record itself stays in the API DB (Job.layer_b). The worker's
        # meaning-lock gate is what makes the strength safe to use.
        cmd += ["--layer-b", layer_b["strength"]]
    return cmd


def build_docker_cmd(
    cfg: Config,
    *,
    mount_root: Path,
    input_path: Path,
    output_dir: Path,
    kind: str,
    policy_id: str,
    attest: bool,
    matter_id: str,
    operator_id: str = "operator",
    decisions: dict[str, str] | None = None,
    legal_justifications: dict | None = None,
    layer_b: dict | None = None,
) -> list[str]:
    image = cfg.worker_image
    if not _DIGEST_RE.search(image):
        raise ValueError(
            "COUNSELCLEAR_WORKER_IMAGE must be digest-pinned "
            "(repo@sha256:<64 hex>); refusing to run unpinned images"
        )
    # Container-side paths mirror the host layout under mount_root exactly,
    # so the same --input/--output-dir args work in both modes.
    c_input = PurePosixPath("/data", *input_path.relative_to(mount_root).parts)
    c_output = PurePosixPath("/data", *output_dir.relative_to(mount_root).parts)
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
        "--entrypoint",
        "python3",
    ]
    # POSIX bind mounts must be writable by the same UID that staged the
    # job. Docker Desktop on Windows has no host POSIX UID/GID; keep the
    # image's configured unprivileged USER there.
    geteuid, getegid = getattr(os, "geteuid", None), getattr(os, "getegid", None)
    if geteuid is not None and getegid is not None:
        cmd += ["--user", f"{geteuid()}:{getegid()}"]
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
        "-e",
        f"COUNSELCLEAR_IMAGE_DIGEST={image}",
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
        "--operator-id",
        operator_id,
    ]
    if attest:
        cmd.append("--attest")
    if decisions:
        cmd += ["--decisions", json.dumps(decisions)]
    if legal_justifications:
        cmd += ["--legal-justifications", json.dumps(legal_justifications)]
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


def run_job(
    cfg: Config, s: Session, job_id: str, kind: str = "sanitize", storage=None
) -> RunnerResult:
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
    doc = s.get(Document, job.document_id) if job is not None else None
    if job is None or doc is None:
        raise RuntimeError(f"job {job_id} or its document is missing")

    # PR 20: a Layer B job must not execute once the flag is off. The flag
    # was checked at attestation time; re-checking at dispatch closes the
    # window where the operator disables watermark tools after a job was
    # queued. Fails the job with a labeled error (sync_job records it).
    if job.layer_b and not cfg.watermark_tools_enabled:
        return RunnerResult(
            rc=-1,
            stderr_tail="watermark tools disabled",
            timed_out=False,
            output_dir=job_root(cfg, job.matter_id, job.id) / "output",
        )

    root = job_root(cfg, job.matter_id, job.id)
    claim = s.info.get("job_claim")
    if claim is not None:
        from .job_queue import require_lease

        require_lease(s, job, claim)
        root = root / "attempts" / f"{claim.attempt}-{claim.token}"
    input_dir, output_dir = root / "input", root / "output"
    staged_input = input_dir / doc.filename

    job.status = "running"
    if job.worker_mode is None:  # Jobs admitted before execution pinning.
        job.worker_image = cfg.worker_image if cfg.worker_mode == "docker" else ""
    s.commit()

    batch = s.get(Batch, job.batch_id) if job.batch_id else None
    actor = job.requested_by or (batch.requested_by if batch else "operator")
    common = dict(
        input_path=staged_input,
        output_dir=output_dir,
        kind=kind,
        policy_id=job.policy_id,
        attest=bool(job.attestation),
        matter_id=job.matter_id,
        operator_id=actor,
        decisions=job.finding_decisions or None,
        legal_justifications=job.legal_justifications or None,
        layer_b=job.layer_b or None,
    )  # type: ignore[arg-type]  # layer_b: dict | None (Pyright: attribute of None)

    try:
        if job.worker_mode is not None:
            if job.worker_mode != cfg.worker_mode:
                raise ValueError("worker mode changed since admission; refusing execution")
            cfg = copy.copy(cfg)
            cfg.worker_image = job.worker_image
        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        _output_directory(input_dir)
        _output_directory(output_dir)
        if not _confined_basename(doc.filename):
            raise ValueError("stored document filename is not a basename")
        original = storage.read(doc.storage_path)
        if len(original) != doc.bytes or hashlib.sha256(original).hexdigest() != doc.sha256:
            raise ValueError("custody original differs from its recorded hash or size")
        if staged_input.exists() or staged_input.is_symlink():
            _output_file(staged_input)
            if staged_input.read_bytes() != original:
                raise ValueError("staged input differs from the custody original")
        else:
            with staged_input.open("xb") as stream:
                stream.write(original)
        del original
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
            rc=-1,
            stderr_tail=tail or "worker timed out",
            timed_out=True,
            output_dir=output_dir,
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


_MAX_RESULT_BYTES = 16 * 1024 * 1024


def _output_directory(path: Path) -> None:
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError("worker output contains a non-directory or symbolic link")


def _output_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("worker output contains a non-regular file or link")


def _read_output_json(path: Path) -> dict:
    _output_file(path)
    # The size cap bounds the trusted parent's result-channel allocation.
    with path.open("rb") as stream:
        data = stream.read(_MAX_RESULT_BYTES + 1)
    if len(data) > _MAX_RESULT_BYTES:
        raise ValueError("worker JSON output exceeds size limit")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("worker JSON output must be an object")
    return value


def _validated_bundle(output_dir: Path, payload: dict, job: Job, doc: Document) -> Path:
    """Map the worker protocol to the parent's fixed path after worker exit.

    Never resolve an arbitrary path supplied by the worker. The two exact
    absolute spellings accommodate host/container path conventions; new
    workers emit only ``bundle``. This does not support old workers that
    retain plaintext originals: API and worker must be upgraded together.
    None of these spellings selects a different directory.
    Every file the download/audit paths may later read must be a confined
    regular file, including additional derivative entries and report HTML.
    """
    bundle = output_dir / "bundle"
    declared = payload.get("bundle_dir")
    if not isinstance(declared, str) or declared not in {
        "bundle",
        str(bundle),
        "/data/output/bundle",
    }:
        raise ValueError("worker reported an invalid bundle path")
    _output_directory(bundle)
    artifacts = {p.name for p in bundle.iterdir()}
    if "original" in artifacts:
        raise ValueError("incompatible worker bundle; upgrade API and pinned worker image together")
    if artifacts != {"derivative", "manifest.json", "report.html"}:
        raise ValueError("worker bundle has missing or unexpected artifacts")
    derivative_dir = bundle / "derivative"
    _output_directory(derivative_dir)
    _output_file(bundle / "report.html")
    manifest = _read_output_json(bundle / "manifest.json")
    result = payload["result"]
    if result.get("manifest") != manifest:
        raise ValueError("worker result and stored manifest disagree")
    if result.get("verification_pass") is not True or not isinstance(
        manifest.get("verification"), dict
    ):
        raise ValueError("worker bundle lacks passing verification")
    if manifest["verification"].get("pass") is not True:
        raise ValueError("worker bundle verification did not pass")
    original = manifest.get("original")
    derivative = manifest.get("derivative")
    policy = manifest.get("policy")
    if not all(isinstance(value, dict) for value in (original, derivative, policy)):
        raise ValueError("worker manifest lacks custody metadata")
    if (
        any(
            original.get(key) != value
            for key, value in {
                "filename": doc.filename,
                "sha256": doc.sha256,
                "bytes": doc.bytes,
            }.items()
        )
        or policy.get("id") != job.policy_id
    ):
        raise ValueError("worker manifest does not match the job's original or policy")
    if job.requested_by is not None and (
        manifest.get("operator") != {"id": job.requested_by}
        or manifest.get("matter") != {"id": job.matter_id}
    ):
        raise ValueError("worker manifest does not match the admitted operator or matter")
    if job.worker_mode == "docker":
        processor = manifest.get("processor")
        if not isinstance(processor, dict) or processor.get("image_digest") != job.worker_image:
            raise ValueError("worker manifest does not match the admitted image")
    name = result.get("derivative")
    if not _confined_basename(name):
        raise ValueError("worker reported an invalid derivative name")
    if derivative.get("filename") != name:
        raise ValueError("worker derivative name differs from manifest")
    if {p.name for p in derivative_dir.iterdir()} != {name}:
        raise ValueError("worker bundle must contain exactly the declared derivative")
    path = derivative_dir / name
    _output_file(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    if derivative.get("sha256") != digest.hexdigest() or derivative.get("bytes") != size:
        raise ValueError("worker derivative differs from its custody hash or size")
    return bundle


def _validated_result(output_dir: Path, job: Job, doc: Document | None) -> tuple[dict, str]:
    _output_directory(output_dir)
    payload = _read_output_json(output_dir / "result.json")
    if payload.get("status") not in {"done", "refused", "failed"}:
        raise ValueError("worker reported an invalid terminal status")
    if not isinstance(payload.get("error", ""), str):
        raise ValueError("worker error must be text")
    result = payload.get("result")
    if payload["status"] != "done":
        if result is not None or payload.get("bundle_dir"):
            raise ValueError("unsuccessful worker result contains artifacts")
        return payload, ""
    if not isinstance(result, dict):
        raise ValueError("completed worker result must be an object")
    if job.kind == "sanitize":
        if doc is None:
            raise ValueError("job original is missing")
        return payload, str(_validated_bundle(output_dir, payload, job, doc))
    if job.kind != "inspect" or payload.get("bundle_dir"):
        raise ValueError("worker result does not match the job kind")
    if not isinstance(result.get("findings"), list) or not all(
        isinstance(finding, dict) for finding in result["findings"]
    ):
        raise ValueError("inspect worker findings must be a list of objects")
    return payload, ""


def sync_job(s: Session, job_id: str, res: RunnerResult, *, commit: bool = True) -> None:
    """Reconcile after a worker exit. The worker itself never touches the
    database — this reads back ``result.json`` (the worker's only output
    channel) and is the sole writer of the Job row. A worker that crashed
    or timed out before writing that file falls back to the crash backstop."""
    job = s.get(Job, job_id)
    if job is None:
        return
    if job.status in ("done", "refused", "failed"):
        return

    payload = None
    bundle_dir = ""
    validation_error = ""
    if res.output_dir is not None and res.rc == 0 and not res.timed_out:
        try:
            payload, bundle_dir = _validated_result(
                res.output_dir,
                job,
                s.get(Document, job.document_id),
            )
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            validation_error = f"invalid worker output: {exc}"

    if payload is not None:
        job.status = payload["status"]
        job.error = str(payload.get("error") or "")[:1000]
        job.result_json = payload.get("result")
        job.bundle_dir = bundle_dir
    else:
        job.status = "failed"
        reason = "worker timed out" if res.timed_out else f"worker exited rc={res.rc}"
        job.error = (validation_error or f"{reason}: {res.stderr_tail}").strip()[:1000]
        job.result_json = None
        job.bundle_dir = ""
    job.finished_utc = _now()
    if commit:
        s.commit()
    else:
        s.flush()
