"""One-shot worker: inspect or sanitize a file already on disk.

Two entry modes:

1. Engine CLI (useful by hand / compose run)::

       python -m app.worker inspect /data/matter.docx
       python -m app.worker sanitize /data/matter.docx -o /data/out --policy external_sharing

2. Job mode for the API's runner (PR 17)::

       python -m app.worker run-job --data-root /data --job <id>

   Performs every status transition on the jobs row: queued -> running ->
   done | refused | failed. Refusals (policy) and failures (parse errors)
   are recorded outcomes, not crashes; exit code 0 means "terminal status
   was recorded". The API process never parses untrusted bytes itself.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from engine_api import clean_to_bundle, inspect_bytes


def _run_job(data_root: str, job_id: str) -> int:
    from .config import Config
    from .db import make_engine, make_session_factory
    from .models import Document, Job, _now

    cfg = Config(data_root)
    s = make_session_factory(make_engine(cfg))()
    job = s.get(Job, job_id)
    if job is None:
        print(f"job {job_id} not found", file=sys.stderr)
        return 3
    if job.status != "queued":
        print(f"job {job_id} is {job.status}, not queued", file=sys.stderr)
        return 3

    job.status = "running"
    # Provenance: which isolated image executed this (docker sets the env;
    # empty string means a plain subprocess of the same tree).
    job.worker_image = os.environ.get("COUNSELCLEAR_WORKER_IMAGE", "")
    s.commit()

    doc = s.get(Document, job.document_id)

    def finish(status: str, error: str = "") -> int:
        job.status = status
        job.error = error[:1000]
        job.finished_utc = _now()
        s.commit()
        s.close()
        return 0

    try:
        if job.kind == "inspect":
            data = Path(doc.storage_path).read_bytes()
            res = inspect_bytes(data, doc.filename)
            job.result_json = {
                "kind": res.kind,
                "format": res.format,
                "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in res.findings],
                "unsupported_reason": res.unsupported_reason,
            }
            return finish("done")

        if job.kind == "sanitize":
            bundle_dir = cfg.data_root / "matters" / job.matter_id / "jobs" / job.id / "bundle"
            result = clean_to_bundle(
                Path(doc.storage_path),
                bundle_dir,
                policy_id=job.policy_id,
                operator_id="operator",
                matter_id=job.matter_id,
                signature_break_attestation=bool(job.attestation),
            )
            job.bundle_dir = str(bundle_dir)
            job.result_json = {
                "derivative": Path(result["derivative"]).name,
                "manifest": result["manifest_data"],
                "verification_pass": result["verification"]["pass"],
            }
            return finish("done")

        return finish("failed", f"unknown job kind: {job.kind}")
    except Exception as e:
        import custody as custody_mod

        msg = str(e)
        if isinstance(e, custody_mod.CustodyError):
            # Policy refusals are first-class outcomes; anything else failed.
            status = "refused" if msg.startswith("plan refused") else "failed"
        else:
            status = "failed"
            msg = f"{type(e).__name__}: {e}"
        return finish(status, msg)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode")

    jp = sub.add_parser("run-job", help="execute one queued job from the store")
    jp.add_argument("--data-root", required=True)
    jp.add_argument("--job", required=True)

    p.add_argument("verb", choices=("inspect", "sanitize"), nargs="?")
    p.add_argument("path", type=Path, nargs="?")
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--policy", default="external_sharing")
    p.add_argument("--attest", action="store_true")
    p.add_argument("--name", default=None)
    args = p.parse_args(argv)

    if args.mode == "run-job":
        return _run_job(args.data_root, args.job)

    if not args.verb or not args.path:
        p.error("either run-job or verb+path is required")

    data = args.path.read_bytes()
    name = args.name or args.path.name
    if args.verb == "inspect":
        res = inspect_bytes(data, name)
        json.dump(
            {
                "kind": res.kind,
                "format": res.format,
                "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in res.findings],
                "unsupported_reason": res.unsupported_reason,
                "processor": {
                    "git_sha": res.processor.git_sha,
                    "tools": res.processor.tools,
                },
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0
    if not args.output:
        print("sanitize requires --output", file=sys.stderr)
        return 2
    bundle = clean_to_bundle(
        args.path,
        args.output,
        policy_id=args.policy,
        signature_break_attestation=args.attest,
    )
    json.dump({"ok": True, "bundle": bundle}, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0 if bundle["verification"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
