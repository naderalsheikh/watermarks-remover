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
    text = DOCKERFILE.read_text()
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
        for line in DOCKERIGNORE.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert "*" in lines, "expected a deny-by-default context"
    assert "!LICENSE" in lines, (
        "LICENSE is excluded from the build context, so COPY LICENSE would "
        "fail the image build"
    )


def test_licence_is_still_mit_with_a_copyright_line():
    """If the project ever relicenses, this test should fail and force the
    distribution obligations to be re-reasoned rather than inherited."""
    text = ROOT_LICENSE.read_text()
    assert "MIT License" in text
    assert "Copyright (c)" in text
    assert "substantial portions of the Software" in text
