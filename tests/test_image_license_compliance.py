"""The published image must carry the licence it distributes.

CounselClear's release workflow publishes a Docker image built from
`service/Dockerfile.counselclear`. That image contains substantial portions
of this MIT-licensed codebase -- all of `service/app/` and most of
`service/scripts/` -- which makes it a distribution, and MIT is explicit:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

A LICENSE that exists only in the git repository does not satisfy that for
an artifact someone pulls from a registry. The image shipped without it
until 2026-09-05.

This matters more here than it would elsewhere. The product is sold on the
truthfulness of its records to firms whose own diligence will read the
container; shipping a licence-non-compliant artifact is exactly the finding
that undermines the pitch, and it is a one-line fix.

Enforced statically because a Docker build is not available in this test
environment. These assertions pin the three facts a correct build depends
on: the licence file is present in the build context, the context permits
it, and the Dockerfile copies it.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ROOT_LICENSE = REPO / "LICENSE"
CONTEXT_LICENSE = REPO / "service" / "LICENSE"
DOCKERFILE = REPO / "service" / "Dockerfile.counselclear"
DOCKERIGNORE = REPO / "service" / "Dockerfile.counselclear.dockerignore"


def test_build_context_licence_is_byte_identical_to_the_root_one():
    """The build context is `service/` (release-images.yml), which the
    repo-root LICENSE sits outside of, so a copy has to live there. A copy
    is a drift risk, and this is the guard: relicensing or updating the
    copyright line at the root must not silently leave the image shipping
    the old terms."""
    assert ROOT_LICENSE.is_file(), "repo root LICENSE is missing"
    assert CONTEXT_LICENSE.is_file(), (
        "service/LICENSE is missing -- the Docker build context is service/, "
        "so the repo-root LICENSE is unreachable from the Dockerfile"
    )
    assert CONTEXT_LICENSE.read_bytes() == ROOT_LICENSE.read_bytes(), (
        "service/LICENSE has drifted from the repo-root LICENSE; the image "
        "would ship terms that differ from the ones this repo declares"
    )


def test_dockerfile_copies_the_licence_into_the_image():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY LICENSE /app/LICENSE" in text, (
        "the published image would contain substantial portions of this "
        "MIT-licensed Software with no copyright notice"
    )


def test_dockerignore_does_not_exclude_the_licence():
    """The per-Dockerfile ignore file denies `*` and re-allows specific
    paths. A COPY of a denied path fails the build, so the allowance and
    the COPY have to stay in step."""
    lines = [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert "*" in lines, "expected a deny-by-default context"
    assert "!LICENSE" in lines, (
        "LICENSE is excluded from the build context, so COPY LICENSE would fail the image build"
    )


def test_licence_is_still_mit_with_a_copyright_line():
    """If the project ever relicenses, this test should fail and force the
    distribution obligations to be re-reasoned rather than inherited."""
    text = ROOT_LICENSE.read_text(encoding="utf-8")
    assert "MIT License" in text
    assert "Copyright (c)" in text
    assert "substantial portions of the Software" in text


# --- redistributed dependencies ----------------------------------------------
#
# The image also redistributes ten third-party packages. Most are permissive
# and satisfied by attribution, but two obligations are concrete rather than
# theoretical: Apache-2.0 §4(d) requires boto3's NOTICE text to travel with
# the redistribution, and psycopg is LGPL-3.0-only -- the only copyleft terms
# in the stack, shipped even in SQLite deployments so a Postgres URL works
# without a rebuild.

NOTICES = REPO / "service" / "THIRD-PARTY-NOTICES.md"
GENERATOR = REPO / "tools" / "generate_third_party_notices.py"


def test_notices_file_is_not_stale():
    """Generated from installed metadata, not hand-maintained -- a
    hand-written notices file goes stale the first time someone bumps a pin,
    and a stale one is worse than none because it asserts something false."""
    import subprocess

    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_pinned_dependency_appears_in_the_notices():
    import re

    pins = REPO / "service" / "requirements-app.txt"
    text = NOTICES.read_text(encoding="utf-8")
    for raw in pins.read_text(encoding="utf-8").splitlines():
        pin = raw.strip()
        if not pin or pin.startswith("#"):
            continue
        name = re.match(r"^([A-Za-z0-9._-]+)", pin)
        assert name, pin
        assert f"`{name.group(1)}`" in text or name.group(1).lower() in text.lower(), (
            f"{name.group(1)} ships in the image but is absent from THIRD-PARTY-NOTICES.md"
        )


def test_apache_notice_text_is_propagated():
    """The one attribution duty a licence table alone cannot discharge."""
    text = NOTICES.read_text(encoding="utf-8")
    assert "Amazon.com, Inc. or its affiliates" in text


def test_copyleft_component_is_named_and_explained():
    """psycopg's LGPL terms must be stated, not buried in a table row: it is
    the only component whose licence constrains how the image may be
    redistributed, and a recipient's right to replace it is the thing that
    makes shipping it compliant."""
    text = NOTICES.read_text(encoding="utf-8")
    assert "LGPL-3.0-only" in text
    assert "psycopg" in text
    assert "replace it" in text


def test_notices_ship_inside_the_image():
    docker = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY THIRD-PARTY-NOTICES.md /app/THIRD-PARTY-NOTICES.md" in docker
    lines = [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert "!THIRD-PARTY-NOTICES.md" in lines
