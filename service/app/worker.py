"""One-shot worker: inspect or sanitize a file already on disk.

The API process can exec this so untrusted parse happens out of the
request thread. Compose ``legal`` profile runs it with ``--network none``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scripts_path import SCRIPTS  # noqa: F401


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("verb", choices=("inspect", "sanitize"))
    p.add_argument("path", type=Path)
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--policy", default="external_sharing")
    p.add_argument("--attest", action="store_true")
    p.add_argument("--name", default=None)
    args = p.parse_args(argv)

    from engine_api import clean_to_bundle, inspect_bytes

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
