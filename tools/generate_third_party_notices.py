#!/usr/bin/env python3
"""Regenerate service/THIRD-PARTY-NOTICES.md from installed distribution metadata.

The published container image redistributes the packages pinned in
``service/requirements-app.txt``, which makes their attribution terms
CounselClear's problem. A hand-maintained notices file is the kind that goes
stale the first time someone bumps a pin, so this reads the metadata of the
actually-installed distributions instead, and
``tests/test_image_license_compliance.py`` fails when the generated file no
longer matches the pin list.

Run after changing service/requirements-app.txt:

    .venv/bin/python tools/generate_third_party_notices.py

Stdlib-only apart from reading installed metadata, and it never guesses: a
package whose licence cannot be determined from metadata is emitted as
"(undeclared)" so a human notices, rather than silently defaulting to
something permissive.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.metadata as md
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REQUIREMENTS = REPO / "service" / "requirements-app.txt"
OUTPUT = REPO / "service" / "THIRD-PARTY-NOTICES.md"

_PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==")


def pinned_packages(requirements: Path = REQUIREMENTS) -> list[str]:
    """Distribution names from the pin file, extras stripped.

    ``psycopg[binary]==3.2.13`` pins two distributions -- psycopg and
    psycopg-binary -- and both are LGPL, so the extra is expanded rather
    than dropped; missing it would understate the copyleft surface.
    """
    names: list[str] = []
    for raw in requirements.read_text(encoding="utf-8").splitlines():
        pin = raw.strip()
        if not pin or pin.startswith("#"):
            continue
        m = _PIN_RE.match(pin)
        if not m:
            continue
        base = m.group(1)
        names.append(base)
        extras = re.search(r"\[([^\]]*)\]", pin)
        if extras:
            for raw_extra in extras.group(1).split(","):
                extra = raw_extra.strip()
                if not extra:
                    continue
                candidate = f"{base}-{extra}"
                try:
                    md.distribution(candidate)
                except md.PackageNotFoundError:
                    continue
                names.append(candidate)
    return names


def describe(name: str) -> tuple[str, str, str]:
    """(canonical name, version, licence) for one installed distribution."""
    dist = md.distribution(name)
    meta = dist.metadata
    licence = meta.get("License-Expression") or meta.get("License") or ""
    if not licence or len(licence) > 60:
        classifiers = [
            c for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")
        ]
        licence = classifiers[-1].split("::")[-1].strip() if classifiers else "(undeclared)"
    return meta["Name"], meta["Version"], licence


def apache_notice_texts(names: list[str]) -> list[tuple[str, str]]:
    """NOTICE file contents for Apache-licensed dists that ship one.

    Apache-2.0 §4(d) requires these to travel with a redistribution, and it
    is the one attribution duty in this stack that cannot be satisfied by a
    licence table alone.
    """
    out: list[tuple[str, str]] = []
    for name in names:
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue
        for entry in dist.files or []:
            if entry.name == "NOTICE":
                try:
                    text = dist.locate_file(entry).read_text(encoding="utf-8").strip()
                except OSError:
                    continue
                if text:
                    out.append((dist.metadata["Name"], text))
                break
    return out


def render(names: list[str]) -> str:
    rows = []
    for name in names:
        try:
            rows.append(describe(name))
        except md.PackageNotFoundError:
            rows.append((name, "(not installed)", "(undeclared)"))
    table = "\n".join(f"| `{n}` | {v} | {lic} |" for n, v, lic in rows)
    notices = apache_notice_texts(names)
    notice_block = (
        "\n\n".join(
            "> " + "\n> ".join(text.splitlines()) for _pkg, text in notices
        )
        or "_No Apache-licensed component in this stack ships a NOTICE file._"
    )
    copyleft = [n for n, _v, lic in rows if "GPL" in lic.upper()]
    return _TEMPLATE.format(
        table=table,
        notice_block=notice_block,
        copyleft=", ".join(f"`{c}`" for c in copyleft) or "none",
        date=datetime.date.today().isoformat(),
    )


_TEMPLATE = """# Third-party notices

CounselClear's published container image redistributes the Python packages
below. This file exists to satisfy their attribution terms. It is generated
from the metadata of the exact pinned versions in
`service/requirements-app.txt` rather than written by hand, and
`tests/test_image_license_compliance.py` fails if the two drift apart.

Nothing here restricts how CounselClear itself may be used. It records what
travels inside the image and under what terms.

| Package | Version | Licence |
|---|---|---|
{table}

Full licence texts ship inside each package's own distribution directory in
the image, which is where the authoritative text for each one lives.

## Apache-2.0 NOTICE propagation

Apache-2.0 §4(d) requires a redistributed work to carry the NOTICE text of
any Apache-licensed component that ships one:

{notice_block}

## Copyleft components

{copyleft}

`psycopg` is LGPL-3.0-only -- the only copyleft terms in the shipped stack,
and the only ones imposing an obligation beyond retaining a notice.

CounselClear uses it as a PostgreSQL driver imported at runtime through
Python's normal import machinery. It is not statically linked, not vendored
and not modified, and a recipient may replace it in the image with their own
build of the same library, which is what LGPL-3.0 §4(d)(1) exists to
guarantee.

The driver ships even in SQLite-only deployments so that setting
`COUNSELCLEAR_DATABASE_URL` to a `postgresql+psycopg://` URL works without a
rebuild (see the comment beside the pin). A deployment that wants no
copyleft component in its image can drop the `psycopg[binary]` pin and
rebuild; SQLite mode never imports it.

## CounselClear itself

Licensed MIT -- see `LICENSE`, shipped at `/app/LICENSE` in the image.

---

_Generated {date} by `tools/generate_third_party_notices.py`. Regenerate
whenever `service/requirements-app.txt` changes._
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed file is stale instead of rewriting it",
    )
    args = ap.parse_args(argv)

    rendered = render(pinned_packages())
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        # The trailing generation date changes daily and is not a staleness
        # signal on its own -- only the substance is compared.
        if _substance(current) != _substance(rendered):
            print(
                "THIRD-PARTY-NOTICES.md is stale; run "
                "tools/generate_third_party_notices.py"
            )
            return 1
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(REPO)}")
    return 0


def _substance(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.startswith("_Generated ")
    ).strip()


if __name__ == "__main__":
    sys.exit(main())
