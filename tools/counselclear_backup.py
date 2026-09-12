#!/usr/bin/env python3
"""Cold backup of a LOCAL/SQLite CounselClear data root.

Produces a snapshot directory that tools/counselclear_restore_drill.py can
restore, self-checked with that same tool's own copy-integrity and drained
logic -- so "this backup verified" and "this restore drill will not refuse
the copy or the drained-state check" share one definition instead of two
separately maintained ones. That is narrower than "will restore cleanly":
the restore drill's own audit-chain, original/mail-submission byte, release
certificate and signing-key checks are its job, not this tool's, and still
need a real restore rehearsal (with --volume-key-file) to qualify recovery.

    python tools/counselclear_backup.py \\
        --source /srv/counselclear/data \\
        --destination /srv/counselclear/backups/2026-09-12T03-00 \\
        --report /srv/counselclear/backups/2026-09-12T03-00.json

Stop the API process first -- this is an explicit, unenforced precondition,
not something this tool detects for you. A WAL-mode SQLite database gives
readers and writers separate locks by design, so there is no way to *ask*
whether another process holds the write lock without attempting a write
yourself, and attempting a write -- even an immediately rolled-back one --
still causes SQLite to run its own connection-close checkpoint/recovery
against whatever file you opened. That is a real mutation of the source,
not a harmless probe, so this tool never opens --source's database at all,
for reading or writing, in any form: not to check it is drained, not to
checkpoint it, not even to test the precondition above. Every file under
--source is copied with plain filesystem operations only (stat, copy,
digest), never through sqlite3.connect. Only the *destination* copy --
which this tool created and owns -- is ever opened, checkpointed, or
integrity-checked (tools/counselclear_restore_drill.py's own
_open_database/_check_drained do that, and this tool calls them directly
rather than reimplementing them). Every check that concerns --source itself
(no symlinks anywhere in the tree, it looks like a data root,
--destination does not already exist) is a plain filesystem check that runs
before source is read at all, so a refusal on any of *those* grounds never
follows a copy or any access to source's database. A refusal can still
happen afterward, once the copy exists: a failed digest comparison during
the copy, or a drained/integrity problem the restore drill's own checks
find in the *destination* -- those are refusals about the copy this tool
made, not about source, and source is unaffected either way.

Keep the API process stopped for the whole run: the same precondition
COUNSELCLEAR_PRODUCTION.md already documents for a PostgreSQL cold backup
("Stop the existing service, preserve a cold backup"). If it is not
actually stopped, this tool cannot tell and will copy whatever bytes were
on disk at the time -- possibly an inconsistent snapshot despite reporting
"verified", since a torn read of a live WAL-mode database is not
guaranteed to fail its own integrity check.

What this does *not* establish: a byte-level check that every original and
mail submission still decrypts to its recorded hash -- that needs the
volume key and is tools/counselclear_restore_drill.py's job. Running the
restore drill against a real, separate destination is the recommended
periodic deeper rehearsal; a "verified" backup report only means the copy
is faithful, internally consistent, and drained, not that a restore has
actually been exercised.

Exit status: 0 verified, 2 refused (precondition), 3 verification failed,
1 unexpected error -- the same convention as the restore drill.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import counselclear_restore_drill as drill  # noqa: E402 - path set up above

EXIT_OK = drill.EXIT_OK
EXIT_ERROR = drill.EXIT_ERROR
EXIT_REFUSED = drill.EXIT_REFUSED
EXIT_FAILED = drill.EXIT_FAILED


@dataclass
class BackupReport:
    source: str
    destination: str
    outcome: str = "incomplete"
    exit_code: int = EXIT_ERROR
    refusal: str | None = None
    failures: list[str] = field(default_factory=list)
    copied_files: int = 0
    copied_bytes: int = 0
    database: dict[str, Any] = field(default_factory=dict)
    destination_removed: bool = False
    scope: dict[str, Any] = field(
        default_factory=lambda: {
            "qualifies": (
                "a drained, internally consistent, byte-verified copy of a LOCAL/SQLite "
                "data root, restorable by tools/counselclear_restore_drill.py"
            ),
            "does_not_qualify": [
                "byte-level verification that originals/mail submissions still decrypt "
                "correctly -- run the restore drill with --volume-key-file for that",
                "S3 object storage",
                "PostgreSQL",
                "stopping the API process for you, or detecting whether it is still "
                "running -- --source's database is never opened to check; this is an "
                "operator precondition, not a verified one",
                "key material recovery or provisioning",
                "anything outside --source: COUNSELCLEAR_VOLUME_KEY_FILE lives outside "
                "the data root by design and is not copied by this tool; back it up "
                "separately (and OIDC client secret / TSA endpoint choice / worker image "
                "digest pin, which are deployment configuration, not files under the "
                "data root at all) or this backup cannot be recovered",
            ],
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "refusal": self.refusal,
            "failures": list(self.failures),
            "copied_files": self.copied_files,
            "copied_bytes": self.copied_bytes,
            "database": self.database,
            "destination_removed": self.destination_removed,
            "scope": self.scope,
        }


def run_backup(source: Path, destination: Path, *, keep_on_failure: bool = False) -> BackupReport:
    source, destination = Path(source), Path(destination)
    report = BackupReport(str(source), str(destination))
    created = False
    con: sqlite3.Connection | None = None
    try:
        # _preflight runs first and is pure filesystem inspection (stat,
        # lstat, os.walk) -- no file content is read and --source's
        # database is never opened, so a symlinked db file or an
        # already-existing destination is refused before any access that
        # could follow a symlink or touch a live database. _preflight,
        # _copy_tree, _open_database and _check_drained are the restore
        # drill's own, already-reviewed logic: no symlinks, no non-regular
        # files, destination must be new, byte-for-byte copy with a digest
        # comparison, WAL checkpoint + integrity check on the COPY only,
        # and the same conservative drained/mail-eligibility check the
        # restore drill requires at restore time. Reusing them here means
        # a backup can never declare itself "verified" in a way the
        # restore drill would then refuse for being non-drained or
        # internally inconsistent -- and --source itself is never opened
        # through sqlite3 at any point in this function.
        files = drill._preflight(source, destination, report)
        destination.mkdir(parents=False, exist_ok=False)
        created = True
        drill._copy_tree(source, destination, files, report)
        con = drill._open_database(destination, report)
        drill._check_drained(con, report)
        con.close()
        con = None
        report.outcome = "verified"
        report.exit_code = EXIT_OK
    except drill.Refused as exc:
        report.outcome = "refused"
        report.refusal = str(exc)
        report.exit_code = EXIT_REFUSED
    except drill.VerificationFailed as exc:
        report.outcome = "failed"
        report.failures.append(str(exc))
        report.exit_code = EXIT_FAILED
    except BaseException:
        report.outcome = "error"
        report.exit_code = EXIT_ERROR
        raise
    finally:
        if con is not None:
            con.close()
        if created and report.exit_code != EXIT_OK and not keep_on_failure:
            report.destination_removed = drill._remove_tree(destination)
            if not report.destination_removed:
                report.failures.append(
                    "destination could not be removed after failure; inspect and delete it manually"
                )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--source", required=True, type=Path, help="the API's stopped data root")
    parser.add_argument(
        "--destination", required=True, type=Path, help="new backup directory; must not exist"
    )
    parser.add_argument("--report", type=Path, default=None, help="write the JSON report here")
    parser.add_argument(
        "--keep-on-failure",
        action="store_true",
        help="leave the destination in place after a refusal or failure",
    )
    args = parser.parse_args(argv)

    try:
        report_path = drill.validate_report_path(args.report, args.source, args.destination, None)
    except drill.Refused as exc:
        refusal = BackupReport(str(args.source), str(args.destination))
        refusal.outcome, refusal.refusal, refusal.exit_code = "refused", str(exc), EXIT_REFUSED
        print(json.dumps(refusal.to_dict(), indent=2, sort_keys=True))
        return EXIT_REFUSED

    try:
        report = run_backup(args.source, args.destination, keep_on_failure=args.keep_on_failure)
    except Exception as exc:  # unexpected: report the class, never a secret
        print(f"backup error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    text = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if report_path is not None:
        drill._write_report(report_path, text)
    print(text)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
