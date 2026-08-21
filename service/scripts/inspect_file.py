#!/usr/bin/env python3
"""Unified inspect: text, images, and document containers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    MAX_INPUT_BYTES,
    classify_finding_confidence,
    emit_json,
    eprint,
)
from engine_api import inspect_exit_code, inspect_path
from text_unicode import human_report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", type=Path, help="File to inspect")
    p.add_argument("--json", action="store_true")
    p.add_argument("--aggressive", action="store_true", help="Text: flag confusables")
    p.add_argument(
        "--as",
        dest="force_type",
        choices=("text", "image", "container", "av", "auto"),
        default="auto",
    )
    p.add_argument(
        "--force-text",
        action="store_true",
        help="Scan as text even when the bytes look like a binary container",
    )
    args = p.parse_args()

    if not args.path.is_file():
        eprint(f"not a file: {args.path}")
        return 2

    if args.path.stat().st_size > MAX_INPUT_BYTES:
        eprint(f"refusing input larger than {MAX_INPUT_BYTES} bytes: {args.path}")
        return 2

    result = inspect_path(
        args.path,
        force_kind=args.force_type,
        aggressive=args.aggressive,
        force_text=args.force_text,
    )
    file_label = str(args.path.resolve())
    kind = result.kind
    report = result.report

    if kind == "unknown":
        note = report.get("note") or result.unsupported_reason or ""
        if args.json:
            emit_json({"kind": "unknown", "path": file_label, "note": note})
        else:
            print(f"File: {file_label}")
            print("Kind: unknown")
            print(note)
        return inspect_exit_code(result)

    if args.json:
        emit_json({"kind": kind, "path": file_label, **report})
        return inspect_exit_code(result)

    print(f"File: {file_label}")
    print(f"Kind: {kind}")
    if kind == "text":
        print(human_report(result.raw))
        return inspect_exit_code(result)

    print(f"Path: {report.get('path')}")
    print(f"Format: {report.get('format')}")
    print(f"C2PA: {report.get('has_c2pa')}")
    print(f"AI metadata: {report.get('has_ai_metadata')}")
    for f in report.get("findings") or []:
        print(f"  - [{classify_finding_confidence(f)}] {f}")
    return inspect_exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
