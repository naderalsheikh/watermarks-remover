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
    if args.html:
        from datetime import UTC, datetime

        from report_html import render_report_html

        html_report = render_report_html(
            subject_name=args.path.name,
            kind=result.kind,
            format=result.format,
            findings=result.findings,
            mode="inspect",
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        args.html.write_text(html_report, encoding="utf-8")
        print(f"report {args.html}")
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


def cmd_intake(args: argparse.Namespace) -> int:
    """Batch, read-only inspect over a directory of documents received from
    a counterparty (a production, deal-room upload, vendor submission, …).

    Never cleans or mutates anything. Gated by --i-am-authorized: this
    command refuses to run without it, on the same footing as --attest for
    breaking a signature — see skills/remove-ai-marks/references/ethics.md
    ("Documents received from a counterparty") for what this command is and
    isn't for. Identity values (author/company names) stay redacted unless
    --reveal-identities is also passed explicitly.
    """
    if not args.i_am_authorized:
        print(
            "refusing: pass --i-am-authorized to confirm you are authorized to "
            "analyze these files (e.g. a production, deal-room upload, or vendor "
            "submission within an engagement you're on) — see "
            "skills/remove-ai-marks/references/ethics.md",
            file=sys.stderr,
        )
        return 2
    root = args.path
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    from datetime import UTC, datetime

    from audit_dir import DEFAULT_SKIP_DIRS, walk_files
    from report_html import render_intake_report

    identities_mod = None
    if args.reveal_identities:
        import authoring_identity as identities_mod

    records: list[dict] = []
    for path in walk_files(root, DEFAULT_SKIP_DIRS):
        rel = str(path.relative_to(root))
        try:
            if path.stat().st_size > Caps().max_input_bytes:
                records.append({"name": rel, "error": "too large"})
                continue
            data = path.read_bytes()
            result = inspect_bytes(data, path.name)
            identities = (
                identities_mod.extract_identities(data, result.format)
                if identities_mod
                else None
            )
            records.append({
                "name": rel,
                "kind": result.kind,
                "format": result.format,
                "findings": result.findings,
                "identities": identities,
            })
        except Exception as e:  # keep the intake going on one bad file
            records.append({"name": rel, "error": str(e)})

    html_report = render_intake_report(
        root_label=str(root),
        records=records,
        reveal_identities=args.reveal_identities,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        matter_label=args.matter,
    )
    args.output.write_text(html_report, encoding="utf-8")
    print(f"report {args.output}")

    if args.json_out:
        payload = {
            "root": str(root),
            "reveal_identities": args.reveal_identities,
            "matter": args.matter,
            "files": [
                {
                    **{k: v for k, v in r.items() if k != "findings"},
                    "findings": [
                        f.to_dict() if hasattr(f, "to_dict") else f
                        for f in r.get("findings", [])
                    ],
                }
                for r in records
            ],
        }
        args.json_out.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"data   {args.json_out}")

    # Same convention as audit_dir.py: an incomplete scan is a more important
    # signal than "findings present" and gets its own exit code, taking
    # precedence over the findings result.
    from common import EXIT_PARTIAL

    if any("error" in r for r in records):
        return EXIT_PARTIAL
    return 1 if any(r.get("findings") for r in records) else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="structured inspect; unknown/unsupported = 2")
    ins.add_argument("path", type=Path)
    ins.add_argument("--json", action="store_true")
    ins.add_argument("--html", type=Path, metavar="OUT",
                      help="also write a self-contained HTML report to OUT")
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

    intake = sub.add_parser(
        "intake",
        help="read-only batch inspect over documents received from a counterparty",
    )
    intake.add_argument("path", type=Path, help="directory to scan recursively")
    intake.add_argument("-o", "--output", type=Path, required=True, help="HTML report path")
    intake.add_argument("--json-out", type=Path, default=None, help="also write JSON data here")
    intake.add_argument("--matter", default=None)
    intake.add_argument(
        "--reveal-identities",
        action="store_true",
        help="show real author/company names instead of redacted placeholders",
    )
    intake.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="required: confirms you're authorized to analyze these files",
    )
    intake.set_defaults(func=cmd_intake)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
