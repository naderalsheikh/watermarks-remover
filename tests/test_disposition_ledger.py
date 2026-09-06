"""The disposition vocabulary, bound to an actual test.

`custody.py` and `main.py` both carried comments citing THIS FILE as the
regression test pinning their retaining-action lists equal. The file did not
exist, and the lists were not equal. Under the product's own doctrine
(counselclear-strategy.md §5) a vocabulary is only as good as the test
behind it, and a citation to a missing file is worse than no comment: it
stops the next reader from checking.

Found by an adversarial audit of the 2026-09-05 surface, against code
written the same day.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "service" / "scripts"), str(REPO / "service")):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.main import RETAINING_ACTIONS
from custody import _RETAINING_ACTIONS, build_dispositions
from policies import _NON_REMOVING_ACTIONS


def test_the_three_retaining_action_lists_relate_as_intended():
    """They are NOT equal, and the difference is deliberate.

    `custody._RETAINING_ACTIONS` carries `refuse` because it classifies a
    planned action; the other two describe actions that leave a finding in a
    DERIVATIVE, and a refused job produces no derivative at all. The lists
    must therefore agree on the three derivative-bearing actions and differ
    only by `refuse` -- which is exactly what the old comment got wrong when
    it called them equal.
    """
    derivative_bearing = {"keep", "flag", "inspect_only"}
    assert set(_NON_REMOVING_ACTIONS) == derivative_bearing
    assert set(RETAINING_ACTIONS) == derivative_bearing
    assert set(_RETAINING_ACTIONS) == derivative_bearing | {"refuse"}
    # main.py deliberately re-declares rather than imports (PR 17 isolation:
    # the control plane must not import the engine), so drift between those
    # two is the failure this assertion exists to catch.
    assert set(RETAINING_ACTIONS) == set(_NON_REMOVING_ACTIONS)


@pytest.mark.parametrize(
    ("action", "still_present", "expected"),
    [
        ("strip", False, "removed_confirmed"),
        ("sanitize", False, "removed_confirmed"),
        ("strip", True, "retained_unplanned"),
        ("flag", True, "retained_as_planned"),
        ("keep", True, "retained_as_planned"),
        ("inspect_only", True, "retained_as_planned"),
    ],
)
def test_postcondition_table(action, still_present, expected):
    (row,) = build_dispositions(
        plan_actions={"hidden_text": {"action": action, "reason": "policy_default"}},
        subtypes_before=["hidden_text"],
        subtypes_after=["hidden_text"] if still_present else [],
    )
    assert row["postcondition"] == expected


def test_a_finding_the_policy_promised_to_KEEP_and_lost_is_not_a_success():
    """The audit's finding #6, fixed here.

    A retaining action whose finding disappears used to be labelled
    `removed_confirmed` -- a success. It is the opposite: the operator asked
    for the finding to be preserved and the engine destroyed it. That
    matters most under `evidence_preservation` and `privacy_only`, whose
    entire product is not touching things, and where a recipient needing the
    provenance to validate a document had no way to learn from the manifest
    that it was removed against policy.
    """
    (row,) = build_dispositions(
        plan_actions={"c2pa": {"action": "keep", "reason": "policy_default"}},
        subtypes_before=["c2pa"],
        subtypes_after=[],
    )
    assert row["postcondition"] == "removed_unplanned", (
        "a finding the policy promised to keep, which vanished, must never "
        "be recorded as a confirmed removal"
    )
    assert row["present_after"] is False


def test_no_observation_is_never_reported_as_removal():
    (row,) = build_dispositions(
        plan_actions={"hidden_text": {"action": "strip", "reason": "policy_default"}},
        subtypes_before=["hidden_text"],
        subtypes_after=None,
    )
    assert row["postcondition"] == "not_verifiable"
    assert row["present_after"] is None


def test_every_postcondition_value_is_in_the_published_schema():
    """The ledger travels inside every packet, so its vocabulary is part of
    the published contract, not an internal enum."""
    import json

    schema = json.loads(
        (REPO / "service" / "scripts" / "schemas" / "manifest.schema.json").read_text()
    )
    allowed = set(schema["$defs"]["disposition"]["properties"]["postcondition"]["enum"])
    produced = set()
    for action in ("strip", "keep", "flag", "inspect_only"):
        for after in ([], ["x"], None):
            for row in build_dispositions(
                plan_actions={"x": {"action": action, "reason": "policy_default"}},
                subtypes_before=["x"],
                subtypes_after=after,
            ):
                produced.add(row["postcondition"])
    assert produced <= allowed, produced - allowed
