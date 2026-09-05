"""Policy engine (PR 11): plan_actions / apply_actions.

Four frozen v1 default policies encode the subtype -> action matrix from
the design doc. ``plan_actions`` turns an inspect result plus optional
operator decisions into an :class:`ActionPlan`:

- omitted decision on an ``approve`` default resolves to ``keep`` and is
  recorded with reason ``no_decision``
- a digital-signature finding under a refuse-unless-attested policy
  raises :class:`PolicyError` unless ``signature_break_attestation`` is set
- macro-enabled files are refused outright by the three mutating policies
- ``evidence_preservation`` plans are all-keep; calling ``apply_actions``
  with one raises (evidence never produces derivatives)

``apply_actions`` executes a plan against bytes, verifying
``source_sha256`` first. It composes the existing cleaners via per-subtype
gates; required-but-unimplemented PDF content actions raise rather than
ship a silently partial derivative.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import container_meta
from av_meta import clean_av
from common import subprocess_preexec_fn
from findings import Finding, findings_for_report
from report_html import SUBTYPE_LABELS
from text_unicode import clean_text

SUBTYPES = (
    "authoring_props",
    "jpeg_gps",
    "comments_and_notes",
    "headers_footers",
    "hidden_structure",
    "hidden_text",
    "embeddings_ole",
    "custom_xml",
    "external_links",
    "pdf_js_actions",
    "pdf_acroform",
    "pdf_attachments",
    "pdf_annots",
    "tracked_changes",
    "pdf_incremental",
    "c2pa",
    "layer_a_body",
    "layer_a_non_body",
    "cms_or_xml_dsig",
    "macros_vba",
)

ACTIONS = frozenset(
    {
        "strip",
        "sanitize",
        "accept_all",
        "rebuild",
        "approve",
        "flag",
        "keep",
        "refuse",
        "inspect_only",
    }
)

LEGAL_JUSTIFICATION_BASES = frozenset(
    {
        "unspecified",
        "privilege",
        "work_product",
        "pii_confidentiality",
        "relevance",
        "court_order",
        "client_instruction",
        "litigation_hold",
        "gdpr_access",
        "other",
    }
)

UNSPECIFIED_LEGAL_JUSTIFICATION = {"basis": "unspecified", "note": ""}

# privacy_only blanks only these authoring fields (plus GPS via jpeg_gps);
# other fields are blanked only when their value matches PII.
PRIVACY_PROP_FIELDS = container_meta._PRIVACY_PROP_FIELDS


class PolicyError(RuntimeError):
    """Plan/apply refusal: job cannot start or cannot execute honestly."""


DEFAULT_POLICIES: dict[str, dict[str, str]] = {
    "external_sharing": {
        "authoring_props": "strip",
        "jpeg_gps": "strip",
        "comments_and_notes": "strip",
        "headers_footers": "flag",
        "hidden_structure": "flag",
        # Lane B: was "flag" until the engine gained a remover. A document
        # released to a counterparty must not carry concealed text, and the
        # release gate could only ever force someone to acknowledge that it
        # did. Flipping this also makes production's "approve" resolve to a
        # real removal through _APPROVE_RESOLVES_TO, retiring the
        # "your approval cannot be honoured" refusal for this subtype.
        #
        # The removal is PARTIAL by design -- w:vanish yes, white-on-white
        # no, because whether white text is invisible depends on background
        # shading this engine does not resolve. _WHITE_ONLY_HIDDEN_REFUSAL
        # below keeps that honest rather than letting "strip" overclaim.
        "hidden_text": "strip",
        "embeddings_ole": "strip",
        "custom_xml": "strip",
        "external_links": "strip",
        # PR 48: was "strip" -- the engine has no PDF annotation/attachment/
        # active-content object-graph editor (only OOXML strips, exiftool/
        # qpdf metadata rewrites, and byte-preserving embedded-image
        # strips exist). "strip" claimed an action that always ended in
        # _apply_pdf's own refusal when the content was present; "refuse"
        # says what actually happens. See _PDF_UNSTRIPPABLE_SUBTYPES below.
        "pdf_js_actions": "refuse",
        "pdf_acroform": "flag",
        "pdf_attachments": "refuse",
        "pdf_annots": "refuse",
        "tracked_changes": "accept_all",
        "pdf_incremental": "rebuild",
        "c2pa": "strip",
        "layer_a_body": "sanitize",
        "layer_a_non_body": "keep",
        "cms_or_xml_dsig": "refuse_unless_attest",
        "macros_vba": "refuse",
    },
    "privacy_only": {
        "authoring_props": "strip_listed",
        "jpeg_gps": "strip",
        "comments_and_notes": "keep",
        "headers_footers": "keep",
        "hidden_structure": "keep",
        "hidden_text": "keep",
        "embeddings_ole": "keep",
        "custom_xml": "keep",
        "external_links": "keep",
        "pdf_js_actions": "keep",
        "pdf_acroform": "keep",
        "pdf_attachments": "keep",
        "pdf_annots": "keep",
        "tracked_changes": "keep",
        "pdf_incremental": "keep",
        "c2pa": "keep",
        "layer_a_body": "sanitize",
        "layer_a_non_body": "keep",
        "cms_or_xml_dsig": "keep",
        "macros_vba": "refuse",
    },
    "production": {
        "authoring_props": "strip",
        "jpeg_gps": "strip",
        "comments_and_notes": "approve",
        "headers_footers": "flag",
        "hidden_structure": "approve",
        "hidden_text": "approve",
        "embeddings_ole": "approve",
        "custom_xml": "strip",
        "external_links": "approve",
        # PR 48: same reasoning as external_sharing above. pdf_attachments/
        # pdf_annots stay "approve" -- _APPROVE_RESOLVES_TO derives from
        # external_sharing's own row (now "refuse"), so an operator who
        # approves one of these still gets a real, honestly-labeled
        # refusal rather than a silent no-op -- just no longer one framed
        # as a successful strip.
        "pdf_js_actions": "refuse",
        "pdf_acroform": "approve",
        "pdf_attachments": "approve",
        "pdf_annots": "approve",
        "tracked_changes": "approve",
        "pdf_incremental": "rebuild",
        "c2pa": "strip_if_authorized",
        "layer_a_body": "sanitize",
        "layer_a_non_body": "approve",
        "cms_or_xml_dsig": "refuse_unless_attest",
        "macros_vba": "refuse",
    },
    "evidence_preservation": {
        "authoring_props": "keep",
        "jpeg_gps": "keep",
        "comments_and_notes": "keep",
        "headers_footers": "keep",
        "hidden_structure": "keep",
        "hidden_text": "keep",
        "embeddings_ole": "keep",
        "custom_xml": "keep",
        "external_links": "keep",
        "pdf_js_actions": "keep",
        "pdf_acroform": "keep",
        "pdf_attachments": "keep",
        "pdf_annots": "keep",
        "tracked_changes": "keep",
        "pdf_incremental": "keep",
        "c2pa": "keep",
        "layer_a_body": "keep",
        "layer_a_non_body": "keep",
        "cms_or_xml_dsig": "keep",
        "macros_vba": "inspect_only",
    },
}

POLICY_IDS = tuple(DEFAULT_POLICIES)

# approval of an approve-default subtype executes the sharing-path action
_APPROVE_RESOLVES_TO = {
    st: DEFAULT_POLICIES["external_sharing"][st] for st in SUBTYPES if st != "cms_or_xml_dsig"
}

# macros_vba: the only actions that do not end in a derivative labeled clean.
# (inspect_only is evidence_preservation, which never calls apply_actions.)
_MACROS_ALLOWED = {"refuse", "inspect_only"}

# Policies that put a derivative in someone else's hands, and therefore
# carry the release gate below. privacy_only and evidence_preservation are
# excluded by intent, not by oversight: neither is a release path.
_RELEASE_GATE_POLICIES = frozenset({"external_sharing", "production"})

# Greppable, like PDF_CONTENT_REFUSAL_MARKER and RELEASE_GATE_MARKER: the
# engine can remove w:vanish text but not white-on-white, whose invisibility
# depends on run/paragraph/cell shading and page background that this engine
# never resolves. Removing on a colour match alone would delete legitimately
# visible white-on-dark text. When a document's ONLY concealment is
# white-applied, "strip" would silently do nothing, the re-inspect would
# still find the finding, and the job would die at the verify gate with an
# opaque message. This refusal says what is actually true, and names the
# one-flag remedy.
WHITE_ONLY_HIDDEN_REFUSAL = (
    "hidden text is white-on-white, which this engine cannot remove safely"
)

# Stable, greppable marker so the API, the UI and the tests can tell this
# refusal apart from a macro refusal or an unattested-signature refusal --
# same reasoning as PDF_CONTENT_REFUSAL_MARKER below. This one is
# RECOVERABLE: the operator re-runs with the acknowledgement, and the
# Release supersede path (predecessor_release_id) already models that.
RELEASE_GATE_MARKER = "release blocked: findings not acknowledged"

# Policies whose PDF path requires real tooling (design KD 6). privacy_only
# is excluded: it takes the GPS/Author-only exiftool path and deliberately
# does not rebuild the document.
_PDF_STRICT_TOOLING_POLICIES = {"external_sharing", "production"}

# structured Finding subtypes that name a different policy row
_FINDING_SUBTYPE_ALIASES = {
    "office_tracked_changes": "tracked_changes",
    "hidden_text_formatting": "hidden_text",
    "defined_names_hidden_range": "hidden_structure",
    "ai_generator_metadata": "c2pa",  # provenance family; rides c2pa action
}

# legacy string-finding prefixes (fallback when no report payload is present).
# Keep in sync with the prefixes findings.py's structured adapter actually
# matches (findings_from_container_report) — this table drifted out of sync
# with real emitted prefixes before (pdf-attachments: / hidden-sheet: etc.
# were never emitted; see tests/test_policies_prefix_subtypes.py).
_PREFIX_SUBTYPES = {
    "authoring-props:": "authoring_props",
    "docx-comments:": "comments_and_notes",
    "docx-tracked-changes:": "tracked_changes",
    "docx-hidden-text:": "hidden_text",
    "docx-embeddings:": "embeddings_ole",
    "xlsx-comments:": "comments_and_notes",
    "xlsx-threaded-comments:": "comments_and_notes",
    "xlsx-external-links:": "external_links",
    "xlsx-hidden-sheets:": "hidden_structure",
    "xlsx-hidden-rows-cols:": "hidden_structure",
    "xlsx-hidden-names:": "hidden_structure",
    "pptx-comments:": "comments_and_notes",
    "pptx-notes:": "comments_and_notes",
    "pptx-hidden-slides:": "hidden_structure",
    "macros-office:": "macros_vba",
    "macros_vba:": "macros_vba",
    "digital_signature:": "cms_or_xml_dsig",
    "pdf-js:": "pdf_js_actions",
    "pdf-openaction:": "pdf_js_actions",
    "pdf-aa:": "pdf_js_actions",
    "pdf-acroform:": "pdf_acroform",
    "pdf-annots:": "pdf_annots",
    "pdf-embeddedfiles:": "pdf_attachments",
    "pdf-incremental-updates:": "pdf_incremental",
    "pdf-incremental:": "pdf_incremental",
    "layer-a:": "layer_a_body",
}


def validate_policy(doc: Any, *, base_id: str | None = None) -> dict[str, str]:
    """Validate an overlay policy document. Raises PolicyError on unknown
    subtype keys, unknown actions, or weakening macros/dsig to strip/sanitize
    (a 400 at save time in the product API)."""
    if not isinstance(doc, dict):
        raise PolicyError("policy overlay must be an object")
    resolved = dict(DEFAULT_POLICIES[base_id]) if base_id else {}
    for key, value in doc.items():
        if key not in SUBTYPES:
            raise PolicyError(f"unknown policy subtype: {key}")
        if value not in ACTIONS:
            raise PolicyError(f"unknown action for {key}: {value}")
        if key in ("macros_vba", "cms_or_xml_dsig") and value in ("strip", "sanitize"):
            raise PolicyError(f"{key} may not be weakened to {value}")
        # macros_vba is the design's one unconditional refusal: no attestation
        # weakens it. Banning only strip/sanitize left `keep` open, which is a
        # *worse* outcome than strip — the plan gate below stops refusing, the
        # cleaner is called anyway, and nothing drops vbaProject.bin, so the
        # macro ships inside a derivative labeled clean.
        if key == "macros_vba" and value not in _MACROS_ALLOWED:
            raise PolicyError(
                f"macros_vba may only be {' or '.join(sorted(_MACROS_ALLOWED))}, not {value}: "
                "a macro-bearing package never yields a derivative labeled clean"
            )
        resolved[key] = value
    return resolved


@dataclass
class ActionPlan:
    policy_id: str
    source_sha256: str
    kind: str
    actions: dict[str, dict[str, Any]] = field(default_factory=dict)
    present_subtypes: set[str] = field(default_factory=set)
    unmapped_findings: list[str] = field(default_factory=list)
    signature_break_attestation: bool = False

    def requires_execution(self) -> bool:
        """True when any subtype resolves to something other than keep/flag/
        inspect_only — i.e. a derivative would differ from the original."""
        passive = {"keep", "flag", "inspect_only"}
        return any(eff["action"] not in passive for eff in self.actions.values())


def policy_subtype_for_finding(f: Finding) -> str | None:
    """Map one structured Finding to its policy-engine subtype (SUBTYPES),
    via the same alias table plan_actions uses internally through
    _collect_subtypes below. None means the finding has no policy-subtype
    mapping (an unmapped/unsupported shape) -- there is nothing a caller
    could put in a `finding_decisions` dict for it. Public (unlike
    _collect_subtypes) because the inspect worker uses it too, to tell the
    UI up front which findings a per-finding Production decision applies
    to -- see worker.py's inspect branch and docs/COUNSELCLEAR_DESIGN.md's
    Structured findings section."""
    st = _FINDING_SUBTYPE_ALIASES.get(f.subtype, f.subtype)
    return st if st in SUBTYPES else None


def _collect_subtypes(result: Any) -> tuple[list[str], list[str]]:
    """Return (policy subtypes seen, unmapped finding strings)."""
    subtypes: list[str] = []
    unmapped: list[str] = []
    kind = getattr(result, "kind", None)
    report = getattr(result, "report", None)
    raw_findings = getattr(result, "findings", None)
    if isinstance(result, dict):
        kind = result.get("kind")
        report = result.get("report")
        raw_findings = result.get("findings")
    found: list[Finding] = []
    if raw_findings and hasattr(raw_findings[0], "subtype"):
        found = [f for f in raw_findings if isinstance(f, Finding)]
    elif kind and isinstance(report, dict):
        try:
            found = findings_for_report(str(kind), report)
        except Exception:
            found = []
    for f in found:
        st = policy_subtype_for_finding(f)
        if st:
            subtypes.append(st)
        else:
            unmapped.append(f"{f.category}/{f.subtype}")
    strings = raw_findings
    for s in strings or []:
        if isinstance(s, Finding):
            continue
        if isinstance(s, dict):
            st = s.get("subtype")
            if st in SUBTYPES:
                subtypes.append(st)
                continue
            unmapped.append(str(s.get("notes") or st or s)[:120])
            continue
        matched = False
        low = str(s).lower()
        for prefix, st in _PREFIX_SUBTYPES.items():
            if low.startswith(prefix):
                subtypes.append(st)
                matched = True
                break
        if not matched:
            unmapped.append(str(s)[:120])
    return subtypes, unmapped


def _normalize_legal_justifications(raw: Any) -> dict[str, dict[str, str]]:
    """Validate {subtype: {basis, note}} without importing pydantic here.

    This is intentionally operator-supplied, not policy-derived. When no
    basis is supplied for a surviving finding, the plan records
    basis="unspecified" rather than inventing privilege/work-product/etc.
    from a sanitizer policy default.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError("legal_justifications must be an object")
    out: dict[str, dict[str, str]] = {}
    for st, item in raw.items():
        if st not in SUBTYPES:
            raise PolicyError(f"legal_justification for unknown subtype: {st}")
        if not isinstance(item, dict):
            raise PolicyError(f"legal_justification for {st} must be an object")
        basis = item.get("basis", "unspecified")
        note = item.get("note", "")
        if not isinstance(basis, str) or basis not in LEGAL_JUSTIFICATION_BASES:
            allowed = "|".join(sorted(LEGAL_JUSTIFICATION_BASES))
            raise PolicyError(f"legal_justification basis for {st} must be one of {allowed}")
        if note is None:
            note = ""
        if not isinstance(note, str):
            raise PolicyError(f"legal_justification note for {st} must be a string")
        out[st] = {"basis": basis, "note": note[:1000]}
    return out


def plan_actions(
    result: Any,
    policy: str | dict[str, str] = "external_sharing",
    decisions: dict[str, str] | None = None,
    *,
    signature_break_attestation: bool = False,
    legal_justifications: dict[str, Any] | None = None,
    source_sha256: str | None = None,
) -> ActionPlan:
    """Build an ActionPlan from an inspect result + policy + decisions."""
    decisions = decisions or {}

    if isinstance(policy, str):
        if policy not in DEFAULT_POLICIES:
            raise PolicyError(f"unknown policy id: {policy}")
        policy_id = policy
        doc = dict(DEFAULT_POLICIES[policy])
    else:
        base = (
            policy.get("base", "external_sharing") if isinstance(policy.get("base"), str) else None
        )
        policy_id = str(policy.get("id", base or "custom"))
        # Pass through every key except the two envelope fields so that an
        # unknown subtype (a typo) raises instead of being silently discarded
        # and reverting to the base policy without telling anyone.
        overlay = {k: v for k, v in policy.items() if k not in ("id", "base")}
        doc = validate_policy(overlay, base_id=base or "external_sharing")

    for st, d in decisions.items():
        if st not in SUBTYPES:
            raise PolicyError(f"decision for unknown subtype: {st}")
        if d not in ("approve", "keep"):
            raise PolicyError(f"decision must be approve|keep, got {st}={d}")
    legal_basis_by_subtype = _normalize_legal_justifications(legal_justifications)

    seen, unmapped = _collect_subtypes(result)

    sha = (
        source_sha256
        or getattr(result, "source_sha256", None)
        or (result.get("source_sha256") if isinstance(result, dict) else None)
    )
    kind = getattr(result, "kind", None) or (result.get("kind") if isinstance(result, dict) else "")
    if sha is None:
        raise PolicyError("plan requires source_sha256 (from inspect result)")

    # Hard gates before anything else.
    # Deliberately checks `decisions` before refusing: this refusal's whole
    # value is that it names a one-flag remedy, and a gate that then rejects
    # that very flag is a dead end advertising an exit. The operator who
    # acknowledges falls through to the strip->flag downgrade below.
    if (
        "hidden_text" in seen
        and doc["hidden_text"] == "strip"
        and decisions.get("hidden_text") != "keep"
    ):
        inspect_report = getattr(result, "report", None)
        if isinstance(result, dict):
            inspect_report = result.get("report")
        legal = ((inspect_report or {}).get("details") or {}).get("docx_legal") or {}
        if int(legal.get("hidden_vanish") or 0) == 0 and int(
            legal.get("hidden_white_applied_runs") or 0
        ):
            raise PolicyError(
                f"{WHITE_ONLY_HIDDEN_REFUSAL}: "
                f"{legal['hidden_white_applied_runs']} white-font run(s) and no "
                "w:vanish text. Whether white text is invisible depends on the "
                "shading behind it, which this engine does not resolve, so "
                "removing it could delete legitimately visible white-on-dark "
                "text. Acknowledge it instead to release with the finding "
                'disclosed (finding_decisions: {"hidden_text": "keep"}), or '
                "remove the concealment in the source document."
            )

    if "macros_vba" in seen and doc["macros_vba"] != "inspect_only":
        # Not `== "refuse"`: any macro action that still reaches apply_actions
        # would ship vbaProject.bin inside a derivative labeled clean.
        raise PolicyError("macro-enabled file refused by policy (no derivative path)")
    if (
        "cms_or_xml_dsig" in seen
        and doc["cms_or_xml_dsig"] == "refuse_unless_attest"
        and not signature_break_attestation
    ):
        raise PolicyError(
            "digitally signed file: signature-break attestation required before planning"
        )

    plan = ActionPlan(
        policy_id=policy_id,
        source_sha256=str(sha),
        kind=str(kind or ""),
        present_subtypes=set(seen),
        unmapped_findings=unmapped,
        signature_break_attestation=bool(signature_break_attestation),
    )
    for st in SUBTYPES:
        default = doc[st]
        if default == "approve":
            d = decisions.get(st)
            if d == "approve":
                plan.actions[st] = {
                    "action": _APPROVE_RESOLVES_TO[st],
                    "reason": "operator_approved",
                }
            elif d == "keep":
                plan.actions[st] = {"action": "keep", "reason": "operator_kept"}
            else:
                plan.actions[st] = {"action": "keep", "reason": "no_decision"}
        elif default == "strip" and st == "hidden_text" and decisions.get(st) == "keep" and st in seen:
            # The one subtype where an operator may decline a strip.
            #
            # hidden_text's remover is deliberately partial: it deletes
            # w:vanish runs and leaves white-on-white text alone. A document
            # whose concealment is white-only therefore has no removal path,
            # and without this branch it would have no RELEASE path either
            # -- every outward-facing policy resolves hidden_text to strip,
            # so refusing would be a dead end rather than a decision.
            #
            # Scoped to hidden_text on purpose, not offered for strip
            # generally: an operator must not be able to decline the
            # comments or authoring-props strip, where removal is complete
            # and the default is the whole point. The downgrade lands as a
            # flag with the gate's own operator_acknowledged reason, so it
            # is recorded, limitation-bearing and certificate-visible.
            plan.actions[st] = {"action": "flag", "reason": "operator_acknowledged"}
        elif default == "flag" and decisions.get(st) == "keep" and st in seen:
            # An operator ACKNOWLEDGING a flagged finding that is actually
            # present. Before this, `decisions` was consulted only for
            # approve-default cells: a decision sent for a flag-default
            # subtype was accepted by the validation loop above and then
            # silently discarded, so an operator could record a decision
            # about hidden text and have it vanish without a word.
            #
            # "acknowledged", deliberately not "kept": under a policy whose
            # only action for this subtype is flag, the operator is not
            # choosing between removal and retention -- there is no removal
            # path (see docs/counselclear-custody-truthfulness-plan.md Lane
            # B). Calling it a choice would overstate what they did. They
            # confirmed they know the finding rides along.
            plan.actions[st] = {"action": "flag", "reason": "operator_acknowledged"}
        elif default == "refuse_unless_attest":
            attested = signature_break_attestation and st == "cms_or_xml_dsig"
            plan.actions[st] = {
                "action": "rebuild",
                "reason": "attested_signature_break" if attested else "not_present",
            }
        else:
            reason = "policy_default"
            if st == "cms_or_xml_dsig" and "cms_or_xml_dsig" in seen:
                reason = "attested_signature_break" if signature_break_attestation else reason
            plan.actions[st] = {"action": default, "reason": reason}
        if st in seen and plan.actions[st]["action"] in ("keep", "flag", "inspect_only"):
            plan.actions[st]["legal_justification"] = legal_basis_by_subtype.get(
                st, dict(UNSPECIFIED_LEGAL_JUSTIFICATION)
            )

    # The release gate (docs/counselclear-custody-truthfulness-plan.md Lane
    # B). A finding the policy FLAGGED is one the engine noticed and
    # deliberately left in the derivative. Under an outward-facing policy
    # that is a decision with consequences outside the building, and it was
    # being made by a default table with no human in the loop -- the
    # operator was never asked, and until the Lane A pass the certificate
    # did not even say it had happened.
    #
    # So: a flagged finding that is actually PRESENT blocks the job unless
    # the operator has acknowledged it by name. This is a refusal, not a
    # failure -- PolicyError is what engine_api turns into "plan refused",
    # which the worker records as status `refused` and the Release surfaces
    # as a refusal record with reasons. "Packet or refusal" already covers
    # this shape; no new lifecycle vocabulary is needed.
    #
    # Scope, deliberately narrow:
    #   - outward-facing policies only. privacy_only and
    #     evidence_preservation exist to leave documents alone and are not
    #     release paths.
    #   - `flag` only. A `keep` reached through the composition rule (e.g.
    #     layer_a_non_body under external_sharing) is not the policy
    #     noticing and declining to act; gating on it would refuse a
    #     release over a stray zero-width space in a footer. An
    #     approve-default `no_decision` keep is a real gap, but it already
    #     carries its own marker and limitation, and widening to it is a
    #     separate, larger behaviour change.
    #   - present findings only. A flag row for a subtype the document does
    #     not carry has nothing to acknowledge.
    if policy_id in _RELEASE_GATE_POLICIES:
        # Two shapes of "survives with no human in the loop":
        #
        #   flag, not acknowledged   -- the policy noticed and declined to
        #                               act, and nobody was asked.
        #   no_decision              -- an approve-default cell the operator
        #                               was never asked about, kept.
        #
        # Both are gated, and the second is not optional. Gating only `flag`
        # left a hole big enough to walk a release through: hidden_text is
        # flag under external_sharing but approve under production, so an
        # operator facing the gate could pick the production profile and the
        # very same finding would sail out as a no_decision keep. A gate you
        # can route around by changing profile is not a gate.
        #
        # A `policy_default` KEEP is deliberately not gated -- that is the
        # composition rule (layer_a_non_body under external_sharing), not
        # the policy declining to act on something it noticed, and gating it
        # would refuse a release over a stray zero-width space in a footer.
        blocked = sorted(
            st
            for st in seen
            if (
                plan.actions.get(st, {}).get("action") == "flag"
                and plan.actions[st].get("reason") != "operator_acknowledged"
            )
            or plan.actions.get(st, {}).get("reason") == "no_decision"
        )
        if blocked:
            # Two ways to arrive here, and they deserve different words.
            #
            # An operator who APPROVED the finding asked for it to be
            # REMOVED and cannot have it: this policy has no removal path
            # for the subtype. That is the more dangerous of the two --
            # they are not merely uninformed, they hold a false belief
            # about what the derivative contains. Shipping it with a
            # disclosure buried in the action records would leave them
            # believing they had it removed, so the gate refuses and says
            # plainly that the approval could not be honoured.
            approved = [
                st for st in blocked if plan.actions[st].get("reason") == "operator_approved"
            ]
            never_asked = [
                st for st in blocked if plan.actions[st].get("reason") == "no_decision"
            ]
            unasked = [st for st in blocked if st not in approved and st not in never_asked]
            parts = []
            if never_asked:
                parts.append(
                    "present and never reviewed — "
                    + ", ".join(f"{SUBTYPE_LABELS.get(st, st)} ({st})" for st in never_asked)
                    + f". The {policy_id} policy leaves these to the operator and no "
                    "decision was supplied, so they would be kept unreviewed"
                )
            if approved:
                parts.append(
                    "approved for removal but NOT REMOVABLE under this policy — "
                    + ", ".join(f"{SUBTYPE_LABELS.get(st, st)} ({st})" for st in approved)
                    + ". The engine has no removal path for these; your approval "
                    "cannot be honoured. Acknowledge instead if the finding may "
                    "travel in the derivative"
                )
            if unasked:
                parts.append(
                    "flagged and not acknowledged — "
                    + ", ".join(f"{SUBTYPE_LABELS.get(st, st)} ({st})" for st in unasked)
                    + f". The {policy_id} policy flags these rather than removing "
                    "them, so they would travel in the derivative"
                )
            raise PolicyError(
                f"{RELEASE_GATE_MARKER}: "
                + "; ".join(parts)
                + ". Acknowledge each one by name to proceed (finding_decisions: {"
                + ", ".join(f'"{st}": "keep"' for st in blocked)
                + "}), ideally with a legal basis; the acknowledgement and any "
                "basis are recorded on the certificate."
            )
    return plan


# --- execution ---------------------------------------------------------------


@dataclass
class ActionRecord:
    subtype: str
    action: str
    detail: str
    legal_justification: dict[str, str] | None = None
    # True when this record documents a finding that WAS PRESENT before
    # sanitization and SURVIVES into the derivative (kept / flagged /
    # inspect-only). The certificate's limitations list is derived from
    # this flag, not from matching marker substrings inside ``detail``:
    # string matching caught only the three approve-default markers, so a
    # policy "flag" outcome -- a knowingly retained finding -- produced no
    # limitation at all and the certificate could truthfully-looking claim
    # "No limitations flagged for this job" while the same manifest said
    # "finding remains in derivative". A retained finding is definitionally
    # a limitation; this makes that structural rather than lexical.
    #
    # Deliberately NOT set on the "nothing was found, nothing was done"
    # keeps (`text unchanged`, `av unchanged`, `privacy: image unchanged`):
    # those are not retained findings and flagging them would produce the
    # opposite defect -- limitations noise that trains a reader to skip the
    # section.
    retained_finding: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "subtype": self.subtype,
            "action": self.action,
            "detail": self.detail,
        }
        if self.legal_justification is not None:
            d["legal_justification"] = dict(self.legal_justification)
        if self.retained_finding:
            d["retained_finding"] = True
        return d


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    # Same RLIMIT_AS/RLIMIT_FSIZE + timeout guard as every other exiftool/qpdf
    # call in the codebase (container_meta.py) — a crafted input file must not
    # be able to run this subprocess out of memory or disk just because the
    # call happens to be on the privacy_only path.
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=120,
            preexec_fn=subprocess_preexec_fn,
        )
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(
            cmd, 1, stdout=e.stdout or b"", stderr=(e.stderr or b"") + b"\ntimed out after 120s"
        )


def _exiftool_privacy_jpeg(src: Path, dest: Path) -> list[str]:
    """GPS-only strip (privacy_only): keeps C2PA and non-GPS EXIF."""
    et = shutil.which("exiftool")
    if et is None:
        raise PolicyError("privacy_only jpeg_gps strip requires exiftool")
    proc = _run([et, "-overwrite_original", "-gps:all=", "-o", str(dest), str(src)])
    if proc.returncode != 0 or not dest.exists():
        raise PolicyError(f"exiftool GPS strip failed: {proc.stderr.decode()[:200]}")
    return ["jpeg_gps: exiftool -gps:all= (non-GPS metadata kept, C2PA kept)"]


def _exiftool_privacy_pdf(src: Path, dest: Path) -> list[str]:
    """Blank only /Author (privacy_only authoring_props field list)."""
    et = shutil.which("exiftool")
    if et is None:
        raise PolicyError("privacy_only pdf authoring_props requires exiftool")
    proc = _run([et, "-overwrite_original", "-Author=", "-o", str(dest), str(src)])
    if proc.returncode != 0 or not dest.exists():
        raise PolicyError(f"exiftool /Author blank failed: {proc.stderr.decode()[:200]}")
    return ["authoring_props: /Author blanked; all other structure kept"]


def _ooxml_kwargs(plan: ActionPlan) -> dict[str, Any]:
    a = {st: eff["action"] for st, eff in plan.actions.items()}
    privacy_props = a["authoring_props"] == "strip_listed"
    kwargs: dict[str, Any] = {
        "also_layer_a_text": a["layer_a_body"] == "sanitize",
        "layer_a_scope": "body",  # composition rule: non-body parts follow their own actions
        "prop_fields": PRIVACY_PROP_FIELDS if privacy_props else None,
        "drop_custom_xml": a["custom_xml"] == "strip",
        "pii_blank_extra": privacy_props,
    }
    return kwargs, a


# PR 48: subtypes with no PDF object-graph editor at all -- no code
# anywhere in container_meta.py touches /Annots, /EmbeddedFiles,
# /OpenAction, /JS, /AA, or /AcroForm. Default policies now say "refuse"
# for the three that are actually reachable (pdf_js_actions/pdf_annots/
# pdf_attachments); pdf_acroform stays here too, defensively, in case a
# custom policy overlay ever sets it to "strip" or "refuse" directly --
# the engine can't strip it either way, so both values must still refuse
# rather than silently ship. This list names what the engine can't do,
# not which single action value triggers the check.
_PDF_UNSTRIPPABLE_SUBTYPES = (
    "pdf_js_actions",
    "pdf_annots",
    "pdf_attachments",
    "pdf_acroform",
)

# Stable, greppable marker distinguishing "the engine has no
# implementation for this yet" from a deliberate policy refusal (macros,
# an unattested signature). No structured reason code exists end-to-end
# today -- job.error is a plain string all the way from the worker
# subprocess's result.json through to the API response (service/app/
# runner.py's sync_job just copies payload["error"] verbatim) -- so the
# frontend matches on this exact substring instead. Known technical debt:
# a real reason-code field would need a Job column/migration to carry it
# through that boundary; out of scope for this pass. Keep this constant
# and web/app/matters/job/page.tsx's copy of the same string in sync.
PDF_CONTENT_REFUSAL_MARKER = "pdf content removal not implemented"


def _apply_pdf(
    data: bytes, plan: ActionPlan, a: dict[str, str]
) -> tuple[bytes, list[ActionRecord]]:
    # only refuse for content the document actually carries. "strip" is
    # still checked alongside "refuse" so a custom overlay that sets one
    # of these to "strip" (the pre-PR-48 default's own value) still
    # refuses instead of silently doing nothing -- the engine's inability
    # to strip this content doesn't depend on which honest-vs-dishonest
    # label a policy gives it.
    needed = [
        st
        for st in _PDF_UNSTRIPPABLE_SUBTYPES
        if a[st] in ("strip", "refuse") and st in plan.present_subtypes
    ]
    if needed:
        labels = ", ".join(SUBTYPE_LABELS.get(st, st) for st in needed)
        raise PolicyError(
            f"{PDF_CONTENT_REFUSAL_MARKER}: this policy requires removing {labels} from "
            "this PDF, but that removal isn't implemented; no derivative was produced "
            "rather than releasing a partial result"
        )
    privacy_pdf = a["authoring_props"] == "strip_listed"
    rebuild = a["pdf_incremental"] == "rebuild"
    if privacy_pdf and not rebuild:
        with tempfile.TemporaryDirectory(prefix="wm-policy-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "in.pdf"
            dest = tmpdir / "out.pdf"
            src.write_bytes(data)
            msgs = _exiftool_privacy_pdf(src, dest)
            out = dest.read_bytes()
            records = [ActionRecord("authoring_props", "strip_listed", m) for m in msgs]
            # Embedded-image GPS: privacy_only's whole stated purpose is
            # location removal, so -- unlike the generic "this policy
            # doesn't touch embedded images at all" gap other policies can
            # have -- this path deliberately reaches into embedded JPEGs,
            # but *only* for GPS tags (container_meta.strip_pdf_image_gps),
            # never the rest of EXIF and never C2PA/JUMBF provenance.
            # privacy_only must not falsely imply it stripped provenance
            # just because it stripped location (docs/pdf-deep-image-
            # metadata.md).
            before_meta, _before_prov = container_meta.pdf_deep_image_scan(out)
            if before_meta:
                gps_out, images_modified, rewrite_notes = container_meta.strip_pdf_image_gps(out)
                if images_modified:
                    out = gps_out
                    after_meta, after_prov = container_meta.pdf_deep_image_scan(out)
                    detail = (
                        f"removed GPS location from {images_modified} embedded image(s) "
                        "(byte-preserving: scan data untouched)"
                    )
                    if after_meta:
                        detail += (
                            "; other embedded metadata (e.g. camera/author fields) was "
                            "left untouched, matching privacy_only's scope"
                        )
                    if after_prov:
                        detail += (
                            "; C2PA/JUMBF provenance was left untouched "
                            "(privacy_only preserves provenance)"
                        )
                    if rewrite_notes:
                        detail += "; " + "; ".join(rewrite_notes)
                    records.append(ActionRecord("embedded_image_metadata", "strip", detail))
                else:
                    records.append(
                        ActionRecord(
                            "embedded_image_metadata",
                            "flag",
                            "embedded-image metadata present (may include GPS) but not "
                            "stripped: exiftool unavailable, or every image's /Length "
                            "is an indirect reference, skipped rather than guessed at "
                            "(see docs/pdf-deep-image-metadata.md)",
                        )
                    )
            return out, records
    with tempfile.TemporaryDirectory(prefix="wm-policy-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "in.pdf"
        dest = tmpdir / "out.pdf"
        src.write_bytes(data)
        _, meta = container_meta.clean_pdf(src, dest)
        # Design KD 6: a sharing/production PDF is only clean when exiftool
        # AND a successful qpdf structural rewrite both ran. clean_pdf has
        # three degraded outcomes it reports rather than raises —
        # mode="copy" (no exiftool: the file is copied verbatim, metadata
        # intact), mode="stdlib-xmp" (best-effort byte surgery), and
        # structural_rewrite=False (exiftool's incremental update leaves the
        # original /Info bytes recoverable). Every one of those previously
        # sailed through as a clean derivative because nothing inspected
        # `meta`. Missing tooling is a failed job, not a warning.
        if plan.policy_id in _PDF_STRICT_TOOLING_POLICIES:
            mode = str(meta.get("mode", ""))
            if mode != "exiftool" or not meta.get("structural_rewrite"):
                raise PolicyError(
                    f"pdf clean did not meet the {plan.policy_id} tooling bar "
                    f"(mode={mode or 'unknown'}, "
                    f"structural_rewrite={bool(meta.get('structural_rewrite'))}): "
                    "exiftool and a successful qpdf --linearize are both required, "
                    "otherwise the original metadata stays recoverable in the output"
                )
        records = [
            ActionRecord(
                "pdf_incremental" if k == "structural_rewrite" else "authoring_props", k, str(v)
            )
            for k, v in meta.items()
            if k in ("structural_rewrite", "info_clear", "mode")
        ]
        # docs/pdf-deep-image-metadata.md: clean_pdf already ran the
        # byte-preserving embedded-image strip above (it's unconditional,
        # not policy-gated — an image's own EXIF/C2PA isn't something any
        # policy chooses to keep). Without this, the strip happens for
        # real but is invisible in the manifest — the exact "surface it
        # honestly" gap this product can't afford for an evidentiary tool.
        deep = meta.get("deep_images") or {}
        if deep.get("images_stripped"):
            records.append(
                ActionRecord(
                    "embedded_image_metadata",
                    "strip",
                    f"stripped embedded-image metadata from {deep['images_stripped']} "
                    "image(s) inside the PDF (byte-preserving: scan data untouched)"
                    + (
                        ", including C2PA/JUMBF provenance"
                        if deep.get("provenance_present_before")
                        else ""
                    ),
                )
            )
        elif deep.get("metadata_present"):
            records.append(
                ActionRecord(
                    "embedded_image_metadata",
                    "flag",
                    "embedded-image metadata remains: the image's /Length is an "
                    "indirect reference, skipped rather than guessed at "
                    "(see docs/pdf-deep-image-metadata.md)",
                )
            )
        return dest.read_bytes(), records


NO_DECISION_MARKER = "no operator decision was supplied"
# Distinct from NO_DECISION_MARKER on purpose: a finding an operator looked
# at and chose to keep is a reviewed outcome, not a gap -- flagging it with
# the same "not reviewed" language (and the same red no-decision banner /
# audit no_decision_count) would be dishonest in the opposite direction, so
# the UI must be able to tell the two apart by string.
OPERATOR_KEPT_MARKER = "reviewed and kept by operator"
# A third, narrower case: _APPROVE_RESOLVES_TO maps every approve-default
# subtype to the sharing-path action for that subtype. When that action is
# itself non-removing, an operator who explicitly approves the subtype --
# choosing strip, not keep -- gets reason "operator_approved" and a
# structural no-op they did not ask for and would not expect from clicking
# "Approve".
#
# This originally fired only for action == "keep", on the stated belief
# that layer_a_non_body was "the only subtype where this can happen". That
# was true of "keep" and false of the case as a whole: enumerating every
# approve-default row against _APPROVE_RESOLVES_TO gives FOUR subtypes,
# three of which resolve to "flag" and so produced no disclosure at all --
#
#   production: hidden_structure -> flag
#               hidden_text      -> flag
#               pdf_acroform     -> flag
#               layer_a_non_body -> keep   (the only one previously covered)
#
# hidden_text is the one that matters: an operator approving it under
# production is asking for concealed text to be removed, gets a flag, and
# -- before this -- saw nothing on the certificate saying their approval
# had not been acted on. The gate is the ACTION being non-removing, never
# a hardcoded subtype list, so a policy edit that makes a fourth subtype
# resolve this way is covered without touching this code.
_NON_REMOVING_ACTIONS = frozenset({"keep", "flag", "inspect_only"})
# The release gate's positive outcome: an operator was shown a flagged
# finding and confirmed it travels. Deliberately NOT worded as a choice --
# under a policy whose only action for the subtype is flag, there is no
# alternative to choose, so "kept by operator" would credit the operator
# with a decision the product never offered them.
OPERATOR_ACKNOWLEDGED_MARKER = "acknowledged by operator before release"
APPROVED_BUT_NO_OP_MARKER = "approved, but this subtype has no strip action under this policy"


def _surviving_finding_records(plan: ActionPlan, existing: set[tuple[str, str]]) -> list[ActionRecord]:
    """Explicit records for present findings that survive the derivative.

    This covers the older approve-default keep disclosures plus policy
    flag/inspect-only outcomes. Legal basis is operator-supplied when
    present; otherwise it remains explicitly unspecified.
    """
    records = []
    for st in sorted(plan.present_subtypes):
        eff = plan.actions.get(st, {})
        reason, action = eff.get("reason"), eff.get("action")
        legal_justification = eff.get("legal_justification")
        if action in ("flag", "inspect_only") and (st, str(action)) in existing:
            continue
        if reason == "no_decision":
            records.append(
                ActionRecord(
                    st,
                    "keep",
                    f"kept: {NO_DECISION_MARKER} for this approve-default finding "
                    "(per-finding review is not yet available in this build)",
                    legal_justification=legal_justification,
                    retained_finding=True,
                )
            )
        elif reason == "operator_kept":
            records.append(
                ActionRecord(
                    st,
                    "keep",
                    f"kept: {OPERATOR_KEPT_MARKER} for this approve-default finding",
                    legal_justification=legal_justification,
                    retained_finding=True,
                )
            )
        elif reason == "operator_approved" and action in _NON_REMOVING_ACTIONS:
            # The record carries the action that actually ran, not a
            # flattened "keep": a manifest that reported an approved-then-
            # flagged finding as "keep" would be wrong about what the
            # policy did, which is the same class of defect the marker
            # exists to prevent.
            records.append(
                ActionRecord(
                    st,
                    action,
                    f"{'kept' if action == 'keep' else action}: "
                    f"{APPROVED_BUT_NO_OP_MARKER} ({st}); the operator approved this "
                    "finding for removal and it was NOT removed",
                    legal_justification=legal_justification,
                    retained_finding=True,
                )
            )
        elif action == "flag" and reason == "operator_acknowledged":
            # Distinguished from the bare policy flag below, and worth the
            # separate record: the difference between "a default table left
            # this in" and "a named operator was shown it and confirmed it
            # travels" is the whole point of the release gate. Both are
            # limitations; only one of them had a human in the loop.
            records.append(
                ActionRecord(
                    st,
                    "flag",
                    f"flagged by policy; {OPERATOR_ACKNOWLEDGED_MARKER} and the "
                    "finding remains in derivative",
                    legal_justification=legal_justification,
                    retained_finding=True,
                )
            )
        elif action == "flag":
            records.append(
                ActionRecord(
                    st,
                    "flag",
                    "flagged by policy; finding remains in derivative",
                    legal_justification=legal_justification,
                    retained_finding=True,
                )
            )
        elif action == "inspect_only":
            records.append(
                ActionRecord(
                    st,
                    "inspect_only",
                    "inspect-only policy; finding remains in original",
                    legal_justification=legal_justification,
                    retained_finding=True,
                )
            )
    return records


def apply_actions(data: bytes, plan: ActionPlan) -> tuple[bytes, list[ActionRecord]]:
    """Execute a plan. Returns (cleaned_bytes, records)."""
    cleaned, records = _apply_actions_impl(data, plan)
    existing = {(r.subtype, r.action) for r in records}
    records.extend(_surviving_finding_records(plan, existing))
    return cleaned, records


def _apply_actions_impl(data: bytes, plan: ActionPlan) -> tuple[bytes, list[ActionRecord]]:
    if hashlib.sha256(data).hexdigest() != plan.source_sha256:
        raise PolicyError("input changed since inspection (sha256 mismatch)")
    if plan.policy_id == "evidence_preservation":
        raise PolicyError("evidence_preservation never produces derivatives")

    records: list[ActionRecord] = []
    a = {st: eff["action"] for st, eff in plan.actions.items()}
    kind = plan.kind

    if kind == "text":
        if a["layer_a_body"] == "sanitize":
            cleaned, stats = clean_text(data.decode("utf-8", errors="surrogateescape"))
            records.append(
                ActionRecord(
                    "layer_a_body",
                    "sanitize",
                    f"removed={stats['removed_count']} replaced={stats['replaced_count']}",
                )
            )
            return cleaned.encode("utf-8", errors="surrogateescape"), records
        return data, [ActionRecord("layer_a_body", "keep", "text unchanged")]

    if kind == "image":
        fmt = container_meta.detect_image_format(data)
        privacy = a["authoring_props"] == "strip_listed"
        if privacy:
            # GPS-only path; no GPS concept in other formats -> unchanged
            if fmt == "jpeg" and a["jpeg_gps"] == "strip":
                with tempfile.TemporaryDirectory(prefix="wm-policy-") as tmp:
                    tmpdir = Path(tmp)
                    src = tmpdir / "in.jpeg"
                    dest = tmpdir / "out.jpeg"
                    src.write_bytes(data)
                    msgs = _exiftool_privacy_jpeg(src, dest)
                    return dest.read_bytes(), [ActionRecord("jpeg_gps", "strip", m) for m in msgs]
            return data, [ActionRecord("file_metadata", "keep", "privacy: image unchanged")]
        # sharing/production: full metadata strip via existing byte-level strippers
        stripper = {
            "png": lambda b: container_meta.strip_png(b, strip_all_text=True),
            "jpeg": lambda b: container_meta.strip_jpeg(b, strip_all_app=True),
        }.get(fmt)
        if stripper is None:
            with tempfile.TemporaryDirectory(prefix="wm-policy-") as tmp:
                tmpdir = Path(tmp)
                src = tmpdir / f"in.{fmt or 'bin'}"
                dest = tmpdir / "out.bin"
                src.write_bytes(data)
                container_meta.clean_image(src, dest, strip_all_metadata=True)
                return (
                    dest.read_bytes(),
                    [ActionRecord("file_metadata", "strip", "full metadata strip")],
                )
        cleaned, msgs = stripper(data)
        return cleaned, [ActionRecord("file_metadata", "strip", "; ".join(msgs[:3]))]

    if kind == "av":
        if a["authoring_props"] == "keep" and a["jpeg_gps"] == "keep":
            return data, [ActionRecord("file_metadata", "keep", "av unchanged")]
        with tempfile.TemporaryDirectory(prefix="wm-policy-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "in.bin"
            dest = tmpdir / "out.bin"
            src.write_bytes(data)
            clean_av(src, dest, strip_all_metadata=True)
            return dest.read_bytes(), [ActionRecord("file_metadata", "strip", "av metadata strip")]

    if kind == "container":
        fmt = container_meta.detect_container_format(Path("input"), data)
        if fmt == "pdf":
            return _apply_pdf(data, plan, a)
        if fmt in ("docx", "xlsx", "pptx"):
            kwargs, a2 = _ooxml_kwargs(plan)
            if fmt == "docx":
                cleaned, msgs = container_meta.clean_docx(
                    data,
                    accept_all=a2["tracked_changes"] == "accept_all",
                    strip_embeddings=a2["embeddings_ole"] == "strip",
                    strip_comments=a2["comments_and_notes"] == "strip",
                    # DOCX-only, so passed here rather than through the
                    # shared _ooxml_kwargs: clean_xlsx and clean_pptx take
                    # the same kwargs dict and neither accepts this one.
                    # There is no such thing as an XLSX/PPTX w:vanish run.
                    strip_hidden_text=a2["hidden_text"] == "strip",
                    **kwargs,
                )
            elif fmt == "xlsx":
                cleaned, msgs = container_meta.clean_xlsx(
                    data,
                    strip_comments=a2["comments_and_notes"] == "strip",
                    strip_external_links=a2["external_links"] == "strip",
                    **kwargs,
                )
            else:
                cleaned, msgs = container_meta.clean_pptx(
                    data,
                    strip_notes=a2["comments_and_notes"] == "strip",
                    strip_comments=a2["comments_and_notes"] == "strip",
                    **kwargs,
                )
            for m in msgs[:12]:
                st = (
                    "hidden_text"
                    if m.startswith("hidden-text:")
                    else "tracked_changes"
                    if "accept-all" in m
                    else "comments_and_notes"
                    if "comment" in m.lower() or "notes" in m.lower()
                    # "scrub authoring exhaust: ..." and "scrub <part> field
                    # ..." are both authoring_props outcomes; the exhaust
                    # line is matched first only because it is the more
                    # specific string, not because the order matters.
                    else "authoring_props"
                    if "scrub" in m
                    else "layer_a_body"
                    if m.startswith("layer A")
                    else "custom_xml"
                )
                records.append(ActionRecord(st, a2.get(st, "executed"), m))
            return cleaned, records
        # other containers (odt/html/md/svg): v1 executes sharing semantics only
        mutating = any(v in ("strip", "accept_all", "sanitize") for v in a.values())
        if not mutating:
            return data, [ActionRecord("file_metadata", "keep", f"{fmt} unchanged")]
        with tempfile.TemporaryDirectory(prefix="wm-policy-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / f"in.{fmt}"
            dest = tmpdir / f"out.{fmt}"
            src.write_bytes(data)
            container_meta.clean_container(src, dest, fmt=fmt)
            return dest.read_bytes(), [
                ActionRecord("file_metadata", "strip", f"{fmt} sharing-clean executed")
            ]

    raise PolicyError(f"apply_actions: unsupported kind {kind!r}")
