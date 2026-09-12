"""The quarantine claims in research/README.md, bound to a test.

`research/` holds harnesses for four external projects, two of which the
repo may not redistribute commercially: CtrlRegen (no upstream licence --
all rights reserved) and Reverse-SynthID (non-commercial research licence).
`research/README.md` answers a licence question with three prose claims:
nothing there is copied into the commercial image, no upstream source is
vendored, and the product spine does not import any of it.

Those claims were true when written and enforced by nothing. One `COPY
research` in the commercial Dockerfile, or one convenience import from a
harness into `service/app/`, would falsify them with no test failing and
the README still asserting them -- the shape this repo treats as worse
than saying nothing, because a claim bound to a missing test stops the
next reader from checking.

Scope: this pins the *isolation*, not the licences themselves. Whether the
upstream terms are what the README says they are is a legal question no
test settles.
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RESEARCH = REPO / "research"

# The commercial image. Everything CounselClear redistributes is built here.
COMMERCIAL_DOCKERFILE = REPO / "service" / "Dockerfile.counselclear"

# The three directories research/README.md names as "the CounselClear
# product spine". The no-reference claim is scoped to exactly these.
README_SPINE = (
    REPO / "service" / "app",
    REPO / "tools",
    REPO / "web" / "app",
    REPO / "web" / "lib",
)

# Everything COPYd into the commercial image. Wider than README_SPINE by
# `service/scripts/`, which the README does not name but the image ships.
# service/scripts/ DOES mention these projects -- inspect_image.py and
# clean_image.py carry `--synthid-dir` / `--ctrlregen-dir` flags inherited
# from upstream watermarks-remover. That is not a quarantine breach: the
# flags take a path the operator supplies at runtime, and the code neither
# imports a harness nor hardcodes a research/ path. Those two properties
# are what the tests below pin for this wider set; the no-mention claim is
# not asserted here, because the README does not make it.
SHIPPED = (*README_SPINE, REPO / "service" / "scripts")

SPINE_SUFFIXES = (".py", ".ts", ".tsx")

# Module basenames under research/harnesses/, which is the only directory
# there holding importable Python.
HARNESS_MODULES = sorted(p.stem for p in (RESEARCH / "harnesses").glob("*.py"))

# Named in research/README.md as the quarantined upstreams.
QUARANTINED_PROJECTS = ("ctrlregen", "markllm", "markdiffusion", "synthid")


def _sources(roots):
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix in SPINE_SUFFIXES and "node_modules" not in path.parts:
                yield path


def test_harness_modules_were_found():
    """Guard the guard: if research/harnesses/ moves, the import test below
    would silently pass over an empty list and prove nothing."""
    assert len(HARNESS_MODULES) >= 5, HARNESS_MODULES


def test_commercial_image_copies_nothing_from_research():
    """research/README.md claim 1."""
    assert COMMERCIAL_DOCKERFILE.exists(), COMMERCIAL_DOCKERFILE
    offenders = [
        line.strip()
        for line in COMMERCIAL_DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if re.match(r"\s*(COPY|ADD)\b", line, re.IGNORECASE)
        and re.search(r"\bresearch\b", line, re.IGNORECASE)
    ]
    assert offenders == [], (
        "service/Dockerfile.counselclear copies from research/, contradicting "
        "research/README.md's 'Excluded from Commercial Builds & Images'. "
        f"Offending instructions: {offenders}"
    )


def test_commercial_image_build_context_excludes_research():
    """The COPY test only holds if `research/` cannot arrive by another
    route. `.dockerignore` is the backstop; the image is also built from
    the `service/` context (see Makefile), which does not contain
    research/ at all."""
    ignore = (
        (REPO / ".dockerignore").read_text(encoding="utf-8")
        if (REPO / ".dockerignore").exists()
        else ""
    )
    copies_repo_root = any(
        re.match(r"\s*(COPY|ADD)\s+\.(\s|/)", line, re.IGNORECASE)
        for line in COMMERCIAL_DOCKERFILE.read_text(encoding="utf-8").splitlines()
    )
    if copies_repo_root:
        assert "research" in ignore, (
            "the commercial Dockerfile copies the whole context but "
            ".dockerignore does not exclude research/"
        )


@pytest.mark.parametrize("module", HARNESS_MODULES)
def test_spine_does_not_import_a_research_harness(module):
    """research/README.md claim 3, per harness module, over everything the
    commercial image ships -- wider than the README's own scope."""
    pattern = re.compile(
        rf"^\s*(?:from\s+{re.escape(module)}\b|import\s+{re.escape(module)}\b)",
        re.MULTILINE,
    )
    offenders = [
        str(p.relative_to(REPO))
        for p in _sources(SHIPPED)
        if p.suffix == ".py" and pattern.search(p.read_text(errors="ignore", encoding="utf-8"))
    ]
    assert offenders == [], (
        f"the product spine imports the quarantined harness {module!r} "
        f"from {offenders}; research/README.md claims it does not"
    )


@pytest.mark.parametrize("project", QUARANTINED_PROJECTS)
def test_spine_does_not_reference_a_quarantined_project(project):
    """Broader than the import check: catches a subprocess call, a sidecar
    URL, or a path string reaching a quarantined upstream without an
    `import` statement -- the shape the pre-quarantine tree actually had
    (a /detect branch reading WATERMARKS_SYNTHID_SCORER_URL).

    Scoped to README_SPINE, which is what research/README.md claims. See
    the SHIPPED comment for why service/scripts/ is excluded here and
    covered by test_shipped_code_never_hardcodes_a_research_path instead."""
    offenders = [
        str(p.relative_to(REPO))
        for p in _sources(README_SPINE)
        if re.search(project, p.read_text(errors="ignore", encoding="utf-8"), re.IGNORECASE)
    ]
    assert offenders == [], (
        f"the product spine references quarantined project {project!r} in "
        f"{offenders}; research/README.md claims the spine 'does not import "
        "or depend upon any harness in this directory'"
    )


def test_research_readme_carries_the_quarantine_notice():
    """The notice is what makes the directory's status legible to someone
    who arrives at a file rather than at the repo root."""
    text = (RESEARCH / "README.md").read_text(encoding="utf-8")
    assert "NOT PART OF COUNSELCLEAR COMMERCIAL DISTRIBUTION" in text
    for project in ("CtrlRegen", "Reverse-SynthID"):
        assert project in text, f"{project} is unlisted in research/README.md"


def test_no_upstream_source_is_vendored():
    """research/README.md claim 2. The harnesses import from user-supplied
    checkouts at runtime; a vendored upstream would show up as a source
    tree under research/, not as a setup script."""
    vendored = [
        str(p.relative_to(REPO))
        for p in RESEARCH.rglob("*")
        if p.is_dir()
        and p.name in ("noai-watermark", "MarkLLM", "MarkDiffusion", "reverse-SynthID")
    ]
    assert vendored == [], f"upstream source vendored under research/: {vendored}"


def test_shipped_code_never_hardcodes_a_research_path():
    """The property that keeps service/scripts/'s `--synthid-dir` and
    `--ctrlregen-dir` flags outside the quarantine boundary: they resolve a
    path the operator supplies, so the shipped image carries an optional
    integration point and never a dependency on this repo's research tree.
    A hardcoded research/ path would turn one into the other."""
    offenders = [
        str(p.relative_to(REPO))
        for p in _sources(SHIPPED)
        if re.search(
            r"""['"]\s*(?:\.{1,2}/)*research/""", p.read_text(errors="ignore", encoding="utf-8")
        )
    ]
    assert offenders == [], (
        "shipped code hardcodes a path into research/, making the "
        f"quarantined tree a runtime dependency: {offenders}"
    )
