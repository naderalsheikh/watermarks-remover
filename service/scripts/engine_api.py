"""Pure engine contract: inspect and clean without HTTP or CLI argv.

PR 1 extracts today's orchestration. ``inspect_bytes`` / ``clean_bytes`` call
existing ``classify_bytes`` plus inspect/clean helpers. ``format_dispatch`` is
not replaced. Policy, structured findings, and custody land in later PRs.

``inspect_path`` / ``clean_path`` preserve on-disk path identity for the CLI
(JSON ``path``, in-place ``.bak`` sources). ``inspect_http`` / ``detect_bytes``
/ ``clean_bytes`` match the HTTP ``/inspect``, ``/detect``, and ``/clean`` cores.
"""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class ProcessorInfo:
    """Build pin. Stub until the product shell records git SHA / image digest."""

    git_sha: str = "unknown"
    image_digest: str | None = None
    tools: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class InspectResult:
    """Inspect outcome. ``findings`` stay strings until PR 3's Finding schema."""

    kind: Kind
    format: str
    findings: list[str]
    processor: ProcessorInfo
    source_sha256: str
    unsupported_reason: str | None = None
    report: dict[str, Any] = field(default_factory=dict)
    raw: object | None = None


def _processor() -> ProcessorInfo:
    return ProcessorInfo()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tmp_path(tmpdir: Path, *parts: str) -> Path:
    """Join *parts* under *tmpdir* and refuse anything that escapes it."""
    path = tmpdir.joinpath(*parts)
    if path.parent != tmpdir:
        raise ValueError("unsafe filename")
    return path


def _findings_of(kind: Kind, report: dict[str, Any]) -> list[str]:
    if kind == "text":
        return [str(h.get("label", "")) for h in report.get("hits") or [] if h.get("label")]
    return [str(f) for f in report.get("findings") or []]


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
    ``caps`` is accepted for the stable contract; PR 1 does not enforce timeouts.
    """
    _ = caps or Caps()
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
    return {"ok": True, "kind": kind, "report": report, "suspicious": suspicious}


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
            )
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "container", **result}
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
