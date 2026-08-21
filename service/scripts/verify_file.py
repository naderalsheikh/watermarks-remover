"""Verify a derivative against its original under a named policy.

Product gate (PR 13): re-inspects both sides, checks targeted subtypes are
gone, validates format, enforces policy-scoped structural invariants, and
prints the VerifyResult JSON. Exit codes: 0 pass, 1 verification failed,
2 usage/plan error.

Example:
    python verify_file.py original.docx SPA.external.docx --policy external_sharing
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from engine_api import inspect_bytes  # noqa: E402
from policies import PolicyError, plan_actions  # noqa: E402
from verify import verify_derivative  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("original", type=Path)
    p.add_argument("derivative", type=Path)
    p.add_argument("--policy", default="external_sharing",
                   choices=("external_sharing", "privacy_only", "production",
                            "evidence_preservation"))
    p.add_argument("--attest-signature-break", action="store_true")
    args = p.parse_args()

    for label, path in (("original", args.original), ("derivative", args.derivative)):
        if not path.is_file():
            print(f"not a file ({label}): {path}", file=sys.stderr)
            return 2

    original = args.original.read_bytes()
    derivative = args.derivative.read_bytes()

    result = inspect_bytes(original, args.original.name)
    try:
        plan = plan_actions(
            result,
            args.policy,
            signature_break_attestation=args.attest_signature_break,
        )
    except PolicyError as e:
        print(f"plan refused: {e}", file=sys.stderr)
        return 2

    report = verify_derivative(original, derivative, plan)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
