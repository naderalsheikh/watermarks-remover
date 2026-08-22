#!/usr/bin/env python3
"""CounselClear product CLI.

Inspect and sanitize without mutating the original. Unknown or unsupported
formats exit 2 on both inspect and sanitize (unlike the prototype scripts).
There is no ``--in-place``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine_api import Caps, inspect_bytes


def _load(path: Path) -> bytes:
    if not path.is_file():
        raise SystemExit(f"not a file: {path}")
    data = path.read_bytes()
    if len(data) > Caps().max_input_bytes:
        raise SystemExit(f"refusing input larger than {Caps().max_input_bytes} bytes")
    return data


def _unsupported(result) -> bool:
    if result.kind == "unknown":
        return True
    if result.unsupported_reason:
        return True
    return any(
        getattr(f, "subtype", None) in {"macros_vba", "unsupported"}
        or getattr(f, "category", None) == "active_content"
        for f in result.findings
    )


def cmd_inspect(args: argparse.Namespace) -> int:
    data = _load(args.path)
    result = inspect_bytes(data, args.path.name)
    payload = {
        "kind": result.kind,
        "format": result.format,
        "source_sha256": result.source_sha256,
        "unsupported_reason": result.unsupported_reason,
        "processor": {
            "git_sha": result.processor.git_sha,
            "image_digest": result.processor.image_digest,
            "tools": result.processor.tools,
        },
        "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in result.findings],
    }
    if args.json:
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print(f"{args.path.name}  kind={result.kind}  format={result.format}")
        if result.unsupported_reason:
            print(result.unsupported_reason)
        for f in payload["findings"]:
            if isinstance(f, dict):
                print(
                    f"  [{f.get('risk_level')}] {f.get('category')}/{f.get('subtype')}"
                    f"  {f.get('action_recommended')}"
                )
            else:
                print(f"  {f}")
        if not payload["findings"]:
            print("  (no structured findings)")
    if _unsupported(result):
        return 2
    return 1 if result.findings else 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    from custody import CustodyError
    from engine_api import clean_to_bundle

    data = _load(args.path)
    result = inspect_bytes(data, args.path.name)
    if _unsupported(result) and not args.attest:
        print("unsupported or unsigned-refuse without --attest", file=sys.stderr)
        return 2
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    try:
        bundle = clean_to_bundle(
            args.path,
            out,
            policy_id=args.policy,
            operator_id=args.operator,
            matter_id=args.matter,
            signature_break_attestation=args.attest,
        )
    except CustodyError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except TimeoutError as e:
        print(f"timeout: {e}", file=sys.stderr)
        return 2
    print(f"derivative {bundle['derivative']}")
    print(f"manifest   {bundle['manifest']}")
    if not bundle["verification"]["pass"]:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="structured inspect; unknown/unsupported = 2")
    ins.add_argument("path", type=Path)
    ins.add_argument("--json", action="store_true")
    ins.set_defaults(func=cmd_inspect)

    san = sub.add_parser("sanitize", help="policy sanitize into a write-once bundle")
    san.add_argument("path", type=Path)
    san.add_argument("-o", "--output", type=Path, required=True)
    san.add_argument("--policy", default="external_sharing")
    san.add_argument("--operator", default="operator")
    san.add_argument("--matter", default=None)
    san.add_argument(
        "--attest",
        action="store_true",
        help="attest that breaking a digital signature is intended",
    )
    san.set_defaults(func=cmd_sanitize)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
