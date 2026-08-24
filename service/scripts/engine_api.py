"""Pure engine contract: inspect and clean without HTTP or CLI argv.

PR 1 extracts today's orchestration. ``inspect_bytes`` / ``clean_bytes`` call
existing ``classify_bytes`` plus inspect/clean helpers. ``format_dispatch`` is
not replaced. Policy, structured findings, and custody land in later PRs.

``inspect_path`` / ``clean_path`` preserve on-disk path identity for the CLI
(JSON ``path``, in-place ``.bak`` sources). ``inspect_http`` / ``detect_bytes``
/ ``clean_bytes`` match the HTTP ``/inspect``, ``/detect``, and ``/clean`` cores.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Literal

from av_meta import clean_av, inspect_av
from common import (
    MAX_INPUT_BYTES,
    ROUTER_ADVICE,
    looks_binary,
    read_text_input,
    safe_write_text,
)
from container_meta import (
    MAX_ZIP_DECOMPRESSED_BYTES,
    clean_container,
    detect_container_format,
    extract_ooxml_plaintext,
    inspect_container,
)
from findings import Finding, findings_for_report
from format_dispatch import classify, classify_bytes
from image_meta import clean_image, detect_format, inspect_image, run_synthid_score
from score_stylometry import score_text_stylometry
from text_detectors import run_all_text_detectors, run_text_detectors
from text_unicode import clean_text, inspect_text

Kind = Literal["text", "image", "container", "av", "unknown"]

UNKNOWN_NOTE_BYTES = "unrecognized format; use a filename with a known extension"
UNKNOWN_NOTE_PATH = (
    "unrecognized format; pass --as text|image|container|av or --force-text to override"
)
UNKNOWN_CLEAN_ERROR = (
    "unrecognized file format; use a filename with a known extension "
    "(e.g. notes.txt) or a supported image/container name"
)
BINARY_AS_TEXT_INSPECT = "refusing to inspect bytes that look like a binary container as text"
BINARY_AS_TEXT_CLEAN = "refusing to clean bytes that look like a binary container as text"
BINARY_AS_TEXT_DETECT = "refusing to detect bytes that look like a binary container as text"

_CONTAINER_EXT = {
    "svg": ".svg",
    "pdf": ".pdf",
    "docx": ".docx",
    "xlsx": ".xlsx",
    "pptx": ".pptx",
    "odt": ".odt",
    "epub": ".epub",
    "html": ".html",
    "markdown": ".md",
}


@dataclass(frozen=True)
class Caps:
    """Resource bounds. PR 1 lands the type; later PRs enforce timeouts."""

    max_input_bytes: int = MAX_INPUT_BYTES
    max_zip_decompressed_bytes: int = MAX_ZIP_DECOMPRESSED_BYTES
    max_archive_depth: int = 2
    inspect_timeout_s: int = 120
    apply_timeout_s: int = 180
    verify_timeout_s: int = 300
    max_verify_pages: int = 30


@cache
def _git_sha() -> str:
    pinned = os.environ.get("COUNSELCLEAR_GIT_SHA") or os.environ.get("WATERMARKS_GIT_SHA")
    if pinned:
        return pinned.strip()
    root = Path(__file__).resolve().parents[2]
    git = shutil.which("git")
    if not git or not (root / ".git").exists():
        return "unknown"
    try:
        r = subprocess.run(
            [git, "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    sha = (r.stdout or "").strip()
    return sha if r.returncode == 0 and sha else "unknown"


@cache
def _tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    flags = {"qpdf": "--version", "exiftool": "-ver", "c2patool": "--version"}
    for cmd, flag in flags.items():
        path = shutil.which(cmd)
        if not path:
            continue
        try:
            r = subprocess.run([path, flag], capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            versions[cmd] = "present"
            continue
        line = ((r.stdout or r.stderr) or "").strip().splitlines()
        versions[cmd] = line[0][:80] if line else "present"
    return versions


@dataclass(frozen=True)
class ProcessorInfo:
    """Build pin: git SHA, optional image digest, probed tool versions."""

    git_sha: str = field(default_factory=_git_sha)
    image_digest: str | None = field(
        default_factory=lambda: os.environ.get("COUNSELCLEAR_IMAGE_DIGEST") or None
    )
    tools: dict[str, str] = field(default_factory=_tool_versions)


@dataclass(frozen=True)
class InspectResult:
    """Inspect outcome. ``findings`` are canonical Finding objects (PR 3).

    Prototype reports still carry ``findings: list[str]`` as a derived view.
    """

    kind: Kind
    format: str
    findings: list[Finding]
    processor: ProcessorInfo
    source_sha256: str
    unsupported_reason: str | None = None
    report: dict[str, Any] = field(default_factory=dict)
    raw: object | None = None

    @property
    def finding_strings(self) -> list[str]:
        out: list[str] = []
        for f in self.findings:
            if isinstance(f, str):
                out.append(f)
            else:
                out.append(f.notes or f.value_redacted or f"{f.category}/{f.subtype}")
        return out


def _processor() -> ProcessorInfo:
    return ProcessorInfo()


def _write_bundle_report(
    out_dir: Path,
    *,
    original_name: str,
    kind: str,
    format: str,
    findings: list[Any],
    policy_id: str,
    actions: list[str],
    verification: dict[str, Any],
    original_sha256: str,
    derivative_name: str,
    derivative_sha256: str,
    processor: dict[str, Any],
) -> Path:
    """Render + write report.html (write-once, same as manifest.json)."""
    from datetime import UTC, datetime

    import custody as custody_mod
    from report_html import render_report_html

    html_report = render_report_html(
        subject_name=original_name,
        kind=kind,
        format=format,
        findings=findings,
        mode="sanitize",
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        policy_id=policy_id,
        actions=actions,
        checks=verification.get("checks"),
        verification_pass=verification.get("pass"),
        original_sha256=original_sha256,
        derivative_name=derivative_name,
        derivative_sha256=derivative_sha256,
        processor=processor,
    )
    path, _created = custody_mod.write_once(
        out_dir / "report.html", html_report.encode("utf-8")
    )
    return path


def _run_capped(fn, timeout_s: int):
    """Run *fn* in a worker thread; raise TimeoutError when Caps budget is hit.

    Returns control to the caller at *timeout_s* even if the worker is still
    running. Python cannot forcibly kill a thread, so a runaway call keeps
    executing in the background, but this function itself no longer blocks
    the caller for that duration — using ``ThreadPoolExecutor`` as a context
    manager would join the worker on ``__exit__`` before a TimeoutError could
    ever propagate, silently defeating the cap.
    """
    if timeout_s <= 0:
        return fn()
    pool = ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(fn)
    try:
        return fut.result(timeout=timeout_s)
    finally:
        pool.shutdown(wait=False)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tmp_path(tmpdir: Path, *parts: str) -> Path:
    """Join *parts* under *tmpdir* and refuse anything that escapes it."""
    path = tmpdir.joinpath(*parts)
    if path.parent != tmpdir:
        raise ValueError("unsafe filename")
    return path


def _findings_of(kind: Kind, report: dict[str, Any]) -> list[Finding]:
    try:
        return findings_for_report(kind, report)
    except Exception:
        return []


def _format_of(kind: Kind, report: dict[str, Any], name: str) -> str:
    if kind == "unknown":
        return "unknown"
    if kind == "text":
        ext = Path(name).suffix.lower().lstrip(".")
        return ext or "txt"
    return str(report.get("format") or "unknown")


def _inspect_result(
    kind: Kind,
    report: dict[str, Any],
    data: bytes,
    name: str,
    *,
    unsupported_reason: str | None = None,
    raw: object | None = None,
) -> InspectResult:
    return InspectResult(
        kind=kind,
        format=_format_of(kind, report, name),
        findings=_findings_of(kind, report),
        processor=_processor(),
        source_sha256=_sha256(data),
        unsupported_reason=unsupported_reason,
        report=report,
        raw=raw,
    )


def inspect_exit_code(result: InspectResult) -> int:
    """Match ``inspect_file.py``: unknown is 0; findings / C2PA / Layer A are 1."""
    if result.kind == "unknown":
        return 0
    if result.kind == "text":
        return 0 if not result.report.get("suspicious_total") else 1
    residual = bool(result.report.get("has_c2pa") or result.report.get("has_ai_metadata"))
    if result.kind in ("image", "av"):
        return 1 if residual else 0
    if residual or result.report.get("suspicious_total"):
        return 1
    return 0


def clean_exit_code(result: dict[str, Any]) -> int:
    """Match ``clean_file.py``: text is 0; residual C2PA/AI is 1 unless degraded."""
    if result.get("kind") == "text":
        return 0
    residual = bool(result.get("still_has_c2pa") or result.get("still_has_ai_metadata"))
    degraded = bool((result.get("meta") or {}).get("degraded"))
    return 1 if (residual and not degraded) else 0


def inspect_bytes(data: bytes, name: str, caps: Caps | None = None) -> InspectResult:
    """Classify and inspect in-memory bytes (library contract).

    Stylometry, sampling detectors, and body preview stay on ``inspect_http``.
    """
    caps = caps or Caps()
    if len(data) > caps.max_input_bytes:
        raise ValueError(f"input exceeds max_input_bytes ({caps.max_input_bytes})")

    def _run() -> InspectResult:
        return _inspect_bytes_uncapped(data, name)

    try:
        return _run_capped(_run, caps.inspect_timeout_s)
    except TimeoutError as e:
        raise TimeoutError(f"inspect exceeded {caps.inspect_timeout_s}s") from e


def _inspect_bytes_uncapped(data: bytes, name: str) -> InspectResult:
    label = name or "input"
    kind = classify_bytes(data, Path(label).suffix)
    if kind == "unknown":
        return _inspect_result(
            "unknown",
            {"note": UNKNOWN_NOTE_BYTES},
            data,
            label,
            unsupported_reason=UNKNOWN_NOTE_BYTES,
        )
    if kind == "text":
        if looks_binary(data):
            raise ValueError(BINARY_AS_TEXT_INSPECT)
        raw_text = data.decode("utf-8", errors="surrogateescape")
        raw = inspect_text(raw_text)
        return _inspect_result("text", raw.to_dict(), data, label, raw=raw)

    with tempfile.TemporaryDirectory(prefix="wm-inspect-") as tmp:
        path = _tmp_path(Path(tmp), Path(label).name if Path(label).name else "input")
        path.write_bytes(data)
        if kind == "image":
            raw = inspect_image(path)
        elif kind == "av":
            raw = inspect_av(path)
        else:
            raw = inspect_container(path)
        return _inspect_result(kind, raw.to_dict(), data, label, raw=raw)


def inspect_path(
    path: Path,
    *,
    force_kind: str = "auto",
    aggressive: bool = False,
    force_text: bool = False,
) -> InspectResult:
    """Inspect a file on disk. Matches ``inspect_file.py`` after argv/size checks.

    Uses ``classify(path)`` (not ``classify_bytes``) so header-only sniffing and
    JSON ``path`` identity stay identical to the CLI.
    """
    kind: Kind = force_kind if force_kind != "auto" else classify(path)  # type: ignore[assignment]
    data = path.read_bytes()
    label = str(path)
    if kind == "unknown":
        if force_kind == "text" or force_text:
            kind = "text"
        else:
            return _inspect_result(
                "unknown",
                {"note": UNKNOWN_NOTE_PATH},
                data,
                label,
                unsupported_reason=UNKNOWN_NOTE_PATH,
            )

    if kind == "text":
        text = read_text_input(str(path), allow_binary=force_text, advice=ROUTER_ADVICE)
        raw = inspect_text(text, aggressive=aggressive)
        return _inspect_result("text", raw.to_dict(), data, label, raw=raw)

    if kind == "image":
        raw = inspect_image(path)
    elif kind == "av":
        raw = inspect_av(path)
    else:
        raw = inspect_container(path)
    return _inspect_result(kind, raw.to_dict(), data, label, raw=raw)


def _body_text(data: bytes, name: str, kind: str) -> str | None:
    """Plain wording for sampling-watermark detectors (not a full renderer)."""
    if kind == "text":
        if looks_binary(data):
            return None
        return data.decode("utf-8", errors="surrogateescape")
    if kind == "container":
        fmt = detect_container_format(Path(name or "input"), data)
        if fmt in ("docx", "xlsx", "pptx"):
            text = extract_ooxml_plaintext(data, fmt)
            return text or None
        if fmt in ("markdown", "html"):
            return data.decode("utf-8", errors="surrogateescape")
    return None


def _wording_detections(text: str) -> list[dict[str, Any]]:
    detections = run_all_text_detectors(text)
    s_rep = score_text_stylometry(text, path="<wording>")
    detections.append({"detector": "stylometry", "available": True, **s_rep.to_dict()})
    return detections


def inspect_http(data: bytes, name: str, run_detect: bool = False) -> dict[str, Any]:
    """HTTP ``/inspect`` payload, including stylometry and optional detectors."""
    kind = classify_bytes(data, Path(name).suffix)
    if kind == "unknown":
        return {
            "ok": True,
            "kind": "unknown",
            "report": {"note": UNKNOWN_NOTE_BYTES},
            "suspicious": False,
        }
    with tempfile.TemporaryDirectory(prefix="wm-inspect-") as tmp:
        path = _tmp_path(Path(tmp), name or "input")
        path.write_bytes(data)
        if kind == "text":
            if looks_binary(data):
                raise ValueError(BINARY_AS_TEXT_INSPECT)
            raw_text = data.decode("utf-8", errors="surrogateescape")
            report = inspect_text(raw_text).to_dict()
            s_rep = score_text_stylometry(raw_text, path=name or "<text>")
            report["stylometry"] = s_rep.to_dict()
            if run_detect:
                report["text_detectors"] = run_all_text_detectors(raw_text)
        elif kind == "image":
            report = inspect_image(path).to_dict()
        elif kind == "av":
            report = inspect_av(path).to_dict()
        else:
            report = inspect_container(path).to_dict()
            fmt = report.get("format")
            if fmt in ("docx", "xlsx", "pptx"):
                body_text = extract_ooxml_plaintext(data, fmt)
                if body_text.strip():
                    report["stylometry"] = score_text_stylometry(
                        body_text, path=name or "<container>"
                    ).to_dict()
                    report["body_chars"] = len(body_text)
                    report["body_words"] = report["stylometry"].get("word_count")
                    if run_detect:
                        report["text_detectors"] = run_all_text_detectors(body_text)
    body = _body_text(data, name, kind)
    if body:
        report.setdefault("body_chars", len(body))
        report.setdefault("body_words", len(body.split()))
        report["body_preview"] = body[:600]
        if "stylometry" not in report:
            report["stylometry"] = score_text_stylometry(body, path=name or "<text>").to_dict()
        if run_detect and "text_detectors" not in report:
            report["text_detectors"] = run_all_text_detectors(body)
    detected_wm = any(
        entry.get("available") and entry.get("is_watermarked")
        for entry in report.get("text_detectors") or []
    )
    suspicious = (
        bool(report.get("suspicious_total"))
        or bool(report.get("has_c2pa") or report.get("has_ai_metadata"))
        or bool(report.get("stylometry", {}).get("score", 0.0) >= 0.65)
        or detected_wm
    )
    findings = []
    try:
        findings = [f.to_dict() for f in findings_for_report(kind, report)]
    except Exception:
        findings = []
    if findings:
        report["structured_findings"] = findings
    return {
        "ok": True,
        "kind": kind,
        "report": report,
        "suspicious": suspicious,
        "findings": findings,
    }


def detect_bytes(data: bytes, name: str) -> dict[str, Any]:
    """HTTP ``/detect`` payload."""
    kind = classify_bytes(data, Path(name).suffix)
    with tempfile.TemporaryDirectory(prefix="wm-detect-") as tmp:
        path = _tmp_path(Path(tmp), name or "input")
        path.write_bytes(data)
        if kind == "text":
            if looks_binary(data):
                raise ValueError(BINARY_AS_TEXT_DETECT)
            raw_text = data.decode("utf-8", errors="surrogateescape")
            detections: list[dict[str, Any]] = run_all_text_detectors(raw_text)
            s_rep = score_text_stylometry(raw_text, path=name or "<text>")
            detections.append({"detector": "stylometry", "available": True, **s_rep.to_dict()})
            return {"ok": True, "kind": kind, "detections": detections}
        if kind == "image":
            score = run_synthid_score(path)
            if score is None:
                score = {
                    "detector": "synthid",
                    "available": False,
                    "error": (
                        "no SynthID scorer configured (set "
                        "WATERMARKS_SYNTHID_SCORER_URL or REVERSE_SYNTHID_DIR)"
                    ),
                }
            else:
                score.setdefault("detector", "synthid")
            return {"ok": True, "kind": kind, "detections": [score]}
        if kind == "av":
            return {
                "ok": True,
                "kind": kind,
                "detections": [],
                "report": inspect_av(path).to_dict(),
            }
        report = inspect_container(path).to_dict()
        body = _body_text(data, name, kind)
        detections = _wording_detections(body) if body else []
        if not detections:
            detections = [
                {
                    "detector": "wording",
                    "available": False,
                    "error": "no extractable body text for sampling-watermark detectors",
                }
            ]
        return {
            "ok": True,
            "kind": kind,
            "detections": detections,
            "report": report,
        }


def clean_bytes(
    data: bytes, name: str, options: dict[str, Any] | None = None
) -> tuple[bytes, dict[str, Any]]:
    """In-memory clean. Matches HTTP ``/clean`` including optional detect extras."""
    options = options or {}
    kind = classify_bytes(data, Path(name).suffix)
    if kind == "unknown":
        raise ValueError(UNKNOWN_CLEAN_ERROR)

    with tempfile.TemporaryDirectory(prefix="wm-clean-") as tmp:
        tmpdir = Path(tmp)
        src = _tmp_path(tmpdir, name or "input")
        src.write_bytes(data)
        if kind == "text":
            if looks_binary(data):
                raise ValueError(BINARY_AS_TEXT_CLEAN)
            text = data.decode("utf-8", errors="surrogateescape")
            detect_before = bool(options.get("detect_before"))
            detect_after = bool(options.get("detect_after"))
            detector_reports: dict[str, Any] = {}
            if detect_before:
                detector_reports["before"] = run_text_detectors(text)
            cleaned, stats = clean_text(
                text,
                nfkc=bool(options.get("nfkc")),
                aggressive_homoglyphs=bool(options.get("aggressive_homoglyphs")),
            )
            if detect_after:
                detector_reports["after"] = run_text_detectors(cleaned)
            cleaned_bytes = cleaned.encode("utf-8", errors="surrogateescape")
            report: dict[str, Any] = {"kind": "text", "stats": stats, "length": len(cleaned)}
            if bool(stats.get("removed_count") or stats.get("replaced_count")):
                from text_unicode import diff_entries

                report["unicode_diff"] = diff_entries(text, cleaned)
            if detector_reports:
                report["text_detectors"] = detector_reports
        elif kind == "image":
            ext = Path(name).suffix
            if not ext:
                fmt_name = detect_format(data)
                ext = f".{fmt_name}" if fmt_name != "unknown" else ".png"
            dest = _tmp_path(tmpdir, f"out{ext}")
            strip_all = not bool(options.get("keep_non_ai_metadata"))
            if "strip_all_metadata" in options:
                strip_all = bool(options["strip_all_metadata"])
            remove_pixel = options.get("remove_pixel")
            if remove_pixel not in (None, "ctrlregen", "diffusion"):
                raise ValueError("remove_pixel must be one of: ctrlregen, diffusion")
            result = clean_image(
                src,
                dest,
                strip_all_metadata=strip_all,
                remove_pixel=remove_pixel,
            )
            if bool(options.get("detect_before")) and result.get("synthid_before") is None:
                result["synthid_before"] = run_synthid_score(src)
            if bool(options.get("detect_after")) and result.get("synthid_after") is None:
                result["synthid_after"] = run_synthid_score(dest)
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "image", **result}
        elif kind == "av":
            dest = _tmp_path(tmpdir, f"out{Path(name).suffix or '.bin'}")
            strip_all = not bool(options.get("keep_non_ai_metadata"))
            if "strip_all_metadata" in options:
                strip_all = bool(options["strip_all_metadata"])
            result = clean_av(src, dest, strip_all_metadata=strip_all)
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "av", **result}
        else:
            ext = Path(name).suffix
            container_fmt = None
            if not ext:
                container_fmt = detect_container_format(Path("input"), data)
                ext = _CONTAINER_EXT.get(container_fmt, "")
            dest = _tmp_path(tmpdir, f"out{ext}")
            result = clean_container(
                src,
                dest,
                fmt=container_fmt,
                also_layer_a_text=bool(options.get("also_layer_a_text", True)),
                layer_a_scope=str(options.get("layer_a_scope", "body")),
            )
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "container", **result}
            fmt_known = container_fmt
            if fmt_known is None:
                with contextlib.suppress(Exception):
                    fmt_known = detect_container_format(Path("input"), data)
            if (
                fmt_known in ("docx", "xlsx", "pptx")
                and bool(options.get("also_layer_a_text", True))
                and options.get("review_diff", True)
            ):
                from container_meta import ooxml_review_diff

                report["unicode_diff"] = ooxml_review_diff(data, cleaned_bytes, fmt_known)
        report.pop("input", None)
        report.pop("output", None)

    return cleaned_bytes, report


def clean_path(
    src: Path,
    dest: Path,
    *,
    kind: Kind,
    container_fmt: str | None = None,
    nfkc: bool = False,
    aggressive_homoglyphs: bool = False,
    keep_non_ai_metadata: bool = False,
    text: str | None = None,
    input_path: Path | None = None,
) -> dict[str, Any]:
    """Clean ``src`` onto ``dest``. Matches ``clean_file.py`` after I/O setup."""
    if kind == "text":
        if text is None:
            raise ValueError("text kind requires decoded text")
        cleaned, stats = clean_text(
            text,
            nfkc=nfkc,
            aggressive_homoglyphs=aggressive_homoglyphs,
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        safe_write_text(dest, cleaned)
        return {
            "kind": "text",
            "input": str(input_path or src),
            "output": str(dest),
            "stats": stats,
        }

    if kind == "image":
        result = clean_image(
            src,
            dest,
            strip_all_metadata=not keep_non_ai_metadata,
        )
        return {"kind": "image", **result}

    if kind == "av":
        result = clean_av(
            src,
            dest,
            strip_all_metadata=not keep_non_ai_metadata,
        )
        return {"kind": "av", **result}

    result = clean_container(src, dest, fmt=container_fmt)
    return {"kind": "container", **result}


# --- Custodial bundle (PR 12) ------------------------------------------------


def _layer_b_rewrite(
    original: bytes, cleaned: bytes, name: str, kind: str, strength: str
) -> dict[str, Any]:
    """PR 20: statistical-watermark rewrite with product-hard semantics.

    Runs between apply_actions and verify_derivative, so the single
    verification gate sees the final bytes (Layer A cannot regress) and the
    meaning lock compares the rewrite against the Layer A-cleaned text it
    actually received. Product semantics differ from the CLI: any lock
    miss or rewrite failure raises CustodyError (the worker maps it to a
    failed job); the original is never silently substituted.
    """
    import custody as custody_mod
    from rewrite_text import meaning_lock_ok, rewrite

    if kind != "text":
        raise custody_mod.CustodyError(
            f"layer b requires a text document, got kind={kind!r}"
        )
    try:
        text = cleaned.decode("utf-8")
    except UnicodeDecodeError as e:
        raise custody_mod.CustodyError(f"layer b input is not utf-8 text: {e}") from e

    # The worker inherits the operator's rewrite env (subprocess mode
    # passes os.environ; docker mode passes the WATERMARKS_REWRITE_*
    # whitelist). print-prompt is the CLI's offline default and meaningless
    # here — refuse instead of "rewriting" to the same text.
    backend = os.environ.get("WATERMARKS_REWRITE_BACKEND", "print-prompt")
    if backend == "print-prompt":
        raise custody_mod.CustodyError(
            "layer b requires WATERMARKS_REWRITE_BACKEND (ollama / openai-compatible); "
            "print-prompt is a CLI-only diagnostic mode"
        )
    # Loopback is the default posture. The docker rewrite-proxy network
    # names the proxy by hostname, so a deployment that uses it must
    # explicitly allow remote endpoints (same opt-in as the CLI).
    allow_remote = os.environ.get("WATERMARKS_REWRITE_ALLOW_REMOTE", "") == "1"
    try:
        result, info = rewrite(
            text,
            backend=backend,
            model=os.environ.get("WATERMARKS_REWRITE_MODEL"),
            base_url=os.environ.get("WATERMARKS_REWRITE_BASE_URL", "http://127.0.0.1:11434"),
            api_key=os.environ.get("WATERMARKS_REWRITE_API_KEY"),
            strength=strength,
            lang="en",
            original_lang="en",
            timeout=float(os.environ.get("WATERMARKS_REWRITE_TIMEOUT_S", "120")),
            layer_a_after=True,
            temperature=float(os.environ.get("WATERMARKS_REWRITE_TEMPERATURE", "0.3")),
            candidates=int(os.environ.get("WATERMARKS_REWRITE_CANDIDATES", "1")),
            max_loops=int(os.environ.get("WATERMARKS_REWRITE_LOOPS", "1")),
            allow_remote=allow_remote,
            reasoning_effort=os.environ.get("WATERMARKS_REWRITE_REASONING_EFFORT", "none"),
        )
    except custody_mod.CustodyError:
        raise
    except SystemExit as e:
        # rewrite_text._check_remote refuses non-loopback endpoints with
        # SystemExit (its CLI semantics). In the product path that must be a
        # labeled job failure, not an uncaught exit that crashes the worker
        # before result.json is written.
        raise custody_mod.CustodyError(f"layer b rewrite refused: {e}") from e
    except Exception as e:
        # Any rewrite failure (transport, provider, parsing) fails the job
        # with a Layer B-labeled error — never a silent fallback to the
        # original text.
        raise custody_mod.CustodyError(f"layer b rewrite failed: {type(e).__name__}: {e}") from e
    if info.get("mode") == "unchanged" or not meaning_lock_ok(text, result):
        raise custody_mod.CustodyError(
            "layer b meaning-lock miss: every rewrite candidate changed operative "
            "meaning (modals, numbers, citations, or quoted terms)"
        )
    if result == text:
        # Defensive: the only paths that return the input unchanged are the
        # lock-miss fallback (handled above) and print-prompt (refused
        # above); anything else reaching here means the rewrite silently
        # no-op'd, which must fail the job rather than ship an unrewritten
        # derivative as if Layer B had run.
        raise custody_mod.CustodyError("layer b rewrite produced no change")
    return {
        "cleaned": result.encode("utf-8"),
        "strength": strength,
        "backend": backend,
        "attempts_made": info.get("attempts_made", 0),
        "passed": info.get("passed"),
        "mode": info.get("mode", "rewritten"),
        "meaning_lock_ok": True,
    }


def clean_to_bundle(
    src: Path,
    out_dir: Path,
    *,
    policy_id: str = "external_sharing",
    operator_id: str | None = None,
    matter_id: str | None = None,
    signature_break_attestation: bool = False,
    decisions: dict[str, str] | None = None,
    layer_b_strength: str | None = None,
) -> dict[str, Any]:
    """Inspect -> plan -> apply -> verify -> store write-once + manifest.

    Product path (PR 13): the derivative is produced by
    ``policies.apply_actions`` under ``policy_id``, gated by
    ``verify.verify_derivative`` BEFORE anything is written. A failed gate
    or refused plan raises and leaves ``out_dir`` untouched. ``decisions``
    is the per-subtype approve/keep map for policies with "approve"-default
    cells (production's comments_and_notes, hidden_structure, and friends
    all default to "approve" — without an explicit decision they resolve
    to "keep", so production is otherwise a no-op sanitize). Layout:
    ``{out_dir}/original/{name}``, ``{out_dir}/derivative/
    {stem}.{policy}.{ext}``, ``{out_dir}/manifest.json``. Never touches
    ``src``; refuses any bundle path resolving onto the input. Re-running a
    completed job with identical inputs short-circuits on the existing
    manifest; conflicting content raises :class:`CustodyError`.
    """
    import custody as custody_mod
    from policies import PolicyError, apply_actions, plan_actions
    from verify import verify_derivative

    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(str(src))
    out_dir = Path(out_dir)
    data = src.read_bytes()

    result = inspect_bytes(data, src.name)
    try:
        plan = plan_actions(
            result,
            policy_id,
            decisions,
            signature_break_attestation=signature_break_attestation,
        )
        cleaned, records = _run_capped(lambda: apply_actions(data, plan), Caps().apply_timeout_s)
    except PolicyError as e:
        raise custody_mod.CustodyError(f"plan refused: {e}") from e

    layer_b: dict[str, Any] | None = None
    if layer_b_strength is not None:
        # PR 20: statistical-watermark rewrite, gated by the signed
        # attestation upstream. Product semantics differ from the CLI's
        # best-effort fallback: a meaning-lock miss (or any other rewrite
        # failure) raises CustodyError, which the worker maps to a failed
        # job — the original is never silently substituted.
        layer_b = _layer_b_rewrite(
            data, cleaned, src.name, result.kind, layer_b_strength
        )
        cleaned = layer_b["cleaned"]

    verification = verify_derivative(
        data,
        cleaned,
        plan,
        pre_present=set(plan.present_subtypes),
        name=src.name,
    )
    if not verification["pass"]:
        failed = [c["name"] for c in verification["checks"] if not c["pass"]]
        raise custody_mod.CustodyError(f"verification failed: {', '.join(failed)}")

    # ff.visual_compare_gate: PDF render-and-compare, warn-only (PR 14)
    from verify_render import feature_enabled, visual_compare

    if feature_enabled() and (data.startswith(b"%PDF-") or cleaned.startswith(b"%PDF-")):
        verification["visual_compare"] = visual_compare(
            data, cleaned, original_report=result.report
        )

    original_dest = out_dir / "original" / src.name
    deriv_rel = custody_mod.derivative_name(src.name, policy_id)
    derivative_dest = out_dir / "derivative" / deriv_rel

    # Check for a collision with the input BEFORE writing anything: write_once
    # locks its target read-only even on the idempotent same-content path, so
    # checking only after the write could chmod the caller's own input file.
    try:
        src_resolved: Path | None = src.resolve()
    except OSError:
        src_resolved = None
    if src_resolved is not None:
        for p in (original_dest, derivative_dest):
            try:
                if p.resolve() == src_resolved:
                    raise custody_mod.CustodyError(
                        f"bundle path collides with the original input: {p}"
                    )
            except OSError:
                continue

    original_path, _orig_created = custody_mod.write_once(original_dest, data)
    derivative_path, _deriv_created = custody_mod.write_once(derivative_dest, cleaned)

    actions = [f"{r.subtype}:{r.action}: {r.detail}" for r in records] or list(
        result.finding_strings
    )

    proc = _processor()
    processor_dict: dict[str, Any] = {
        "git_sha": proc.git_sha,
        "image_digest": proc.image_digest,
        "tools": dict(proc.tools),
    }
    orig_sha = custody_mod.sha256_bytes(data)
    deriv_sha = custody_mod.sha256_bytes(cleaned)

    # Idempotent completion: a manifest already binding these exact hashes
    # means this exact job finished before; keep the original timestamp.
    import json as _json

    manifest_path = out_dir / "manifest.json"
    if manifest_path.is_file():
        try:
            existing = _json.loads(manifest_path.read_text())
        except ValueError:
            existing = None
        if (
            isinstance(existing, dict)
            and existing.get("original", {}).get("sha256") == orig_sha
            and existing.get("derivative", {}).get("sha256") == deriv_sha
        ):
            existing_report = out_dir / "report.html"
            return {
                "bundle": str(out_dir),
                "original": str(original_path),
                "derivative": str(derivative_path),
                "manifest": str(manifest_path),
                "manifest_data": existing,
                "verification": verification,
                "report_html": str(existing_report) if existing_report.is_file() else None,
            }

    manifest = custody_mod.emit_manifest(
        original_name=src.name,
        original_sha256=orig_sha,
        original_bytes=len(data),
        derivative_name_=deriv_rel,
        derivative_sha256=deriv_sha,
        derivative_bytes=len(cleaned),
        policy_id=policy_id,
        actions=actions,
        processor=processor_dict,
        findings_before=result.finding_strings,
        verification=verification,
        operator_id=operator_id,
        matter_id=matter_id,
        layer_b=layer_b,
    )
    manifest_path, _m_created = custody_mod.write_manifest(out_dir, manifest)
    report_path = _write_bundle_report(
        out_dir,
        original_name=src.name,
        kind=result.kind,
        format=result.format,
        findings=result.findings,
        policy_id=policy_id,
        actions=actions,
        verification=verification,
        original_sha256=orig_sha,
        derivative_name=deriv_rel,
        derivative_sha256=deriv_sha,
        processor=processor_dict,
    )

    return {
        "bundle": str(out_dir),
        "original": str(original_path),
        "derivative": str(derivative_path),
        "manifest": str(manifest_path),
        "manifest_data": manifest,
        "verification": verification,
        "report_html": str(report_path),
    }
