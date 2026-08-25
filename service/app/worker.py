"""One-shot worker: inspect or sanitize a file already on disk.

Two entry modes:

1. Engine CLI (useful by hand / compose run)::

       python -m app.worker inspect /data/matter.docx
       python -m app.worker sanitize /data/matter.docx -o /data/out --policy external_sharing

2. Job mode for the API's runner (PR 17)::

       python -m app.worker run-job --kind inspect|sanitize --input /data/input/x.docx
           --output-dir /data/output [--policy external_sharing] [--attest]

   This process has **no database access whatsoever** — it never imports
   `.db`/`.models`, and its only filesystem access is the two paths given on
   the command line. That's deliberate: the runner (app.runner, run in the
   trusted parent process, never inside the isolated worker) mounts *only* a
   fresh per-job directory containing a copy of the one document being
   processed, so a compromised parser can reach neither the shared database
   nor any other matter's files. The worker reports its outcome by writing
   ``{output_dir}/result.json`` — the parent reads that file back and is the
   sole writer of the Job row (see runner.sync_job). A worker that crashes
   or times out before writing that file leaves the parent's crash backstop
   to record "failed"; a worker that writes it always exits 0, because
   "terminal status was recorded" is success from this process's point of
   view even when the recorded status is refused/failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from engine_api import clean_to_bundle, inspect_bytes
from policies import DEFAULT_POLICIES, policy_subtype_for_finding


def _write_result(output_dir: Path, payload: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    tmp = output_dir / "result.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
    tmp.replace(output_dir / "result.json")


def _run_job(*, kind: str, input_path: Path, output_dir: Path, policy_id: str, attest: bool,
             matter_id: str | None = None, decisions: dict[str, str] | None = None,
             layer_b: str | None = None) -> int:
    """Pure: no DB, no network, no filesystem access outside the two given
    paths. Always exits 0 once result.json is written — the *content* of
    that file (status: done|refused|failed) is the real outcome."""
    from .malware import get_scanner  # defense-in-depth (PR 18): re-scan here too

    name = input_path.name

    def finish(status: str, error: str = "", result: dict | None = None,
               bundle_dir: str = "") -> int:
        _write_result(output_dir, {
            "status": status,
            "error": error[:1000],
            "result": result,
            "bundle_dir": bundle_dir,
        })
        return 0

    try:
        data = input_path.read_bytes()
    except OSError as e:
        return finish("failed", f"input unreadable: {e}")

    verdict = get_scanner().scan(data, name)
    if not verdict.clean:
        return finish("refused", f"malware scan ({verdict.scanner}): {verdict.detail}")

    try:
        if kind == "inspect":
            res = inspect_bytes(data, name)
            findings = []
            for f in res.findings:
                if hasattr(f, "to_dict"):
                    d = f.to_dict()
                    # production is the only default policy with "approve"
                    # cells; a finding's policy_subtype/requires_approval
                    # here tells the sanitize UI, up front, which findings
                    # a per-finding decision would apply to -- computed at
                    # inspect time so the sanitize panel doesn't need to
                    # re-derive the same alias mapping (or duplicate it in
                    # TypeScript, which would drift from policies.py).
                    pst = policy_subtype_for_finding(f)
                    d["policy_subtype"] = pst
                    d["requires_approval"] = bool(pst and DEFAULT_POLICIES["production"].get(pst) == "approve")
                else:
                    d = f
                findings.append(d)
            return finish("done", result={
                "kind": res.kind,
                "format": res.format,
                "findings": findings,
                "unsupported_reason": res.unsupported_reason,
            })

        if kind == "sanitize":
            bundle_dir = output_dir / "bundle"
            result = clean_to_bundle(
                input_path,
                bundle_dir,
                policy_id=policy_id,
                operator_id="operator",
                matter_id=matter_id,
                signature_break_attestation=attest,
                decisions=decisions,
                layer_b_strength=layer_b,
            )
            return finish(
                "done",
                bundle_dir=str(bundle_dir),
                result={
                    "derivative": Path(result["derivative"]).name,
                    "manifest": result["manifest_data"],
                    "verification_pass": result["verification"]["pass"],
                },
            )

        return finish("failed", f"unknown job kind: {kind}")
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

    jp = sub.add_parser(
        "run-job",
        help="execute one job against an already-staged input/output directory pair "
             "(no database access — see module docstring)",
    )
    jp.add_argument("--kind", required=True, choices=("inspect", "sanitize"))
    jp.add_argument("--input", required=True, type=Path)
    jp.add_argument("--output-dir", required=True, type=Path)
    jp.add_argument("--policy", default="external_sharing")
    jp.add_argument("--attest", action="store_true")
    jp.add_argument("--matter-id", default=None)
    jp.add_argument(
        "--decisions", default=None,
        help="JSON object {subtype: 'approve'|'keep'} for approve-default policy cells "
             "(e.g. production's comments_and_notes) — without this every such cell "
             "resolves to keep, per plan_actions' own no_decision default",
    )
    jp.add_argument(
        "--layer-b", default=None, choices=("preserve", "paraphrase"),
        help="PR 20: run a Layer B (statistical watermark) rewrite at this strength; "
             "a meaning-lock miss fails the job instead of falling back to the original",
    )

    p.add_argument("verb", choices=("inspect", "sanitize"), nargs="?")
    p.add_argument("path", type=Path, nargs="?")
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--policy", default="external_sharing")
    p.add_argument("--attest", action="store_true")
    p.add_argument("--name", default=None)
    args = p.parse_args(argv)

    if args.mode == "run-job":
        decisions = json.loads(args.decisions) if args.decisions else None
        return _run_job(
            kind=args.kind,
            input_path=args.input,
            output_dir=args.output_dir,
            policy_id=args.policy,
            attest=args.attest,
            matter_id=args.matter_id,
            decisions=decisions,
            layer_b=args.layer_b,
        )

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
