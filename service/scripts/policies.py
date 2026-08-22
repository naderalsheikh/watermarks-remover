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
        "hidden_text": "flag",
        "embeddings_ole": "strip",
        "custom_xml": "strip",
        "external_links": "strip",
        "pdf_js_actions": "strip",
        "pdf_acroform": "flag",
        "pdf_attachments": "strip",
        "pdf_annots": "strip",
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
        "pdf_js_actions": "strip",
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
        resolved[key] = value
    return resolved


@dataclass
class ActionPlan:
    policy_id: str
    source_sha256: str
    kind: str
    actions: dict[str, dict[str, str]] = field(default_factory=dict)
    present_subtypes: set[str] = field(default_factory=set)
    unmapped_findings: list[str] = field(default_factory=list)
    signature_break_attestation: bool = False

    def requires_execution(self) -> bool:
        """True when any subtype resolves to something other than keep/flag/
        inspect_only — i.e. a derivative would differ from the original."""
        passive = {"keep", "flag", "inspect_only"}
        return any(eff["action"] not in passive for eff in self.actions.values())


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
        st = _FINDING_SUBTYPE_ALIASES.get(f.subtype, f.subtype)
        if st in SUBTYPES:
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


def plan_actions(
    result: Any,
    policy: str | dict[str, str] = "external_sharing",
    decisions: dict[str, str] | None = None,
    *,
    signature_break_attestation: bool = False,
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
        doc = validate_policy(
            {k: v for k, v in policy.items() if k in SUBTYPES}, base_id=base or "external_sharing"
        )

    for st, d in decisions.items():
        if st not in SUBTYPES:
            raise PolicyError(f"decision for unknown subtype: {st}")
        if d not in ("approve", "keep"):
            raise PolicyError(f"decision must be approve|keep, got {st}={d}")

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
    if "macros_vba" in seen and doc["macros_vba"] == "refuse":
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
    return plan


# --- execution ---------------------------------------------------------------


@dataclass
class ActionRecord:
    subtype: str
    action: str
    detail: str


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


_PDF_CONTENT_STRIP_SUBTYPES = (
    "pdf_js_actions",
    "pdf_annots",
    "pdf_attachments",
    "pdf_acroform",
)


def _apply_pdf(
    data: bytes, plan: ActionPlan, a: dict[str, str]
) -> tuple[bytes, list[ActionRecord]]:
    # only refuse for content the document actually carries
    needed = [
        st for st in _PDF_CONTENT_STRIP_SUBTYPES if a[st] == "strip" and st in plan.present_subtypes
    ]
    if needed:
        raise PolicyError(
            f"engine does not implement pdf content strip for: {', '.join(needed)};"
            " refusing to ship a partial derivative"
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
            return dest.read_bytes(), [
                ActionRecord("authoring_props", "strip_listed", m) for m in msgs
            ]
    with tempfile.TemporaryDirectory(prefix="wm-policy-") as tmp:
        tmpdir = Path(tmp)
        src = tmpdir / "in.pdf"
        dest = tmpdir / "out.pdf"
        src.write_bytes(data)
        _, meta = container_meta.clean_pdf(src, dest)
        return dest.read_bytes(), [
            ActionRecord(
                "pdf_incremental" if k == "structural_rewrite" else "authoring_props", k, str(v)
            )
            for k, v in meta.items()
            if k in ("structural_rewrite", "info_clear", "mode")
        ]


def apply_actions(data: bytes, plan: ActionPlan) -> tuple[bytes, list[ActionRecord]]:
    """Execute a plan. Returns (cleaned_bytes, records)."""
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
                    "tracked_changes"
                    if "accept-all" in m
                    else "comments_and_notes"
                    if "comment" in m.lower() or "notes" in m.lower()
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
