"""PDF render-and-compare — warn-only visual diff (PR 14).

Rasterizes original and derivative PDFs page-by-page with ``pdftoppm``
(poppler) at 150 dpi and compares mean absolute per-channel pixel delta
after a 1px box blur (anti-aliasing tolerance). Regions covered by annot /
form-field bboxes the plan stripped are masked out of the denominator.

Doctrine: this is a WARNING, never a gate. A high delta is recorded on the
result so an operator can look; it must not fail the job (Accept All,
metadata rewrites and annot stripping legitimately move pixels). The
``ff.visual_compare_gate`` flag stays off until thresholds are calibrated.

Pure-stdlib pixel math (PPM P6 parsing, blur, delta) so the engine carries
no numpy/Pillow dependency. Renderer absence degrades to
``{"available": False}``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

VISUAL_COMPARE_VERSION = 1
DPI = 150
THRESHOLD_MEAN_ABS = 3.0 / 255.0
THRESHOLD_FRACTION = 0.005

from verify import _PDF_PAGE_RE  # noqa: E402


class RenderError(RuntimeError):
    pass


def feature_enabled() -> bool:
    """ff.visual_compare_gate — off by default until calibrated."""
    return os.environ.get("COUNSELCLEAR_VISUAL_COMPARE", "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def find_renderer() -> str | None:
    return shutil.which("pdftoppm")


def pdf_page_count(data: bytes) -> int:
    return len(_PDF_PAGE_RE.findall(data))


def select_pages(page_count: int, cap: int = 30) -> list[int]:
    """First 10 + last 5 + up to 15 uniformly sampled from the middle."""
    if page_count <= cap:
        return list(range(1, page_count + 1))
    chosen = sorted(set(range(1, 11)) | set(range(page_count - 4, page_count + 1)))
    mid_start, mid_end = 11, page_count - 5
    middle_needed = cap - len(chosen)
    pages = list(chosen)
    if middle_needed > 0 and mid_end >= mid_start:
        span = mid_end - mid_start + 1
        step = max(1, span // middle_needed)
        for p in range(mid_start, mid_end + 1, step):
            if len(pages) >= cap:
                break
            pages.append(p)
    return sorted(set(pages))[:cap]


def parse_ppm(data: bytes) -> tuple[int, int, bytes]:
    """Parse binary PPM (P6). Returns (width, height, rgb_bytes)."""
    if not data.startswith(b"P6"):
        raise RenderError("not a P6 PPM")
    fields: list[bytes] = []
    i = 2
    while len(fields) < 3:
        while i < len(data) and data[i : i + 1].isspace():
            i += 1
        if data[i : i + 1] == b"#":
            while i < len(data) and data[i] != 0x0A:
                i += 1
            continue
        start = i
        while i < len(data) and not data[i : i + 1].isspace():
            i += 1
        fields.append(data[start:i])
    i += 1  # single whitespace after maxval
    w, h, _maxval = int(fields[0]), int(fields[1]), int(fields[2])
    pix = data[i : i + w * h * 3]
    if len(pix) != w * h * 3:
        raise RenderError("truncated PPM")
    return w, h, pix


def box_blur_1px(width: int, height: int, pix: bytes) -> bytearray:
    """Separable 3x3 mean with edge clamping (anti-aliasing tolerance)."""
    src = bytearray(pix)
    tmp = bytearray(len(src))
    out = bytearray(len(src))
    for y in range(height):
        row = y * width
        for x in range(width):
            xl = x - 1 if x > 0 else 0
            xr = x + 1 if x < width - 1 else width - 1
            base = (row + x) * 3
            for c in range(3):
                tmp[base + c] = (
                    src[(row + xl) * 3 + c]
                    + src[base + c]
                    + src[(row + xr) * 3 + c]
                ) // 3
    for y in range(height):
        yt = y - 1 if y > 0 else 0
        yb = y + 1 if y < height - 1 else height - 1
        for x in range(width):
            base = (y * width + x) * 3
            for c in range(3):
                out[base + c] = (
                    tmp[(yt * width + x) * 3 + c]
                    + tmp[base + c]
                    + tmp[(yb * width + x) * 3 + c]
                ) // 3
    return out


def _masked(
    x: int, y: int, boxes: list[tuple[int, int, int, int]]
) -> bool:
    return any(x0 <= x <= x1 and y0 <= y <= y1 for x0, y0, x1, y1 in boxes)


def compare_pixels(
    width: int,
    height: int,
    a: bytes,
    b: bytes,
    mask_boxes: list[tuple[int, int, int, int]] | None = None,
) -> dict[str, float]:
    """Mean abs per-channel delta after 1px blur + fraction over threshold,
    computed on the unmasked pixel population. Raises RenderError on
    dimension mismatch (caller checks first)."""
    boxes = mask_boxes or []
    ba = box_blur_1px(width, height, a)
    bb = box_blur_1px(width, height, b)
    total = 0.0
    n = 0
    over = 0
    # blur spreads energy ~2px past an exact bbox; pad masks accordingly
    padded = [
        (max(0, x0 - 2), max(0, y0 - 2), min(width - 1, x1 + 2), min(height - 1, y1 + 2))
        for x0, y0, x1, y1 in boxes
    ]
    for y in range(height):
        for x in range(width):
            if _masked(x, y, padded):
                continue
            base = (y * width + x) * 3
            d = (
                abs(ba[base] - bb[base])
                + abs(ba[base + 1] - bb[base + 1])
                + abs(ba[base + 2] - bb[base + 2])
            ) / 765.0  # 3 channels * 255
            total += d
            n += 1
            if d > THRESHOLD_MEAN_ABS:
                over += 1
    if n == 0:
        return {"mean_abs": 0.0, "fraction_over": 0.0}
    return {"mean_abs": total / n, "fraction_over": over / n}


def bbox_mask_boxes(
    report: dict[str, Any], page: int, width: int, height: int
) -> list[tuple[int, int, int, int]]:
    """Pixel-space masks from annot/form bboxes on ``page`` (1-based)."""
    boxes: list[tuple[int, int, int, int]] = []
    scale = DPI / 72.0
    try:
        from findings import findings_for_report

        kind = report.get("kind") if isinstance(report, dict) else None
        if not kind:
            return boxes
        for f in findings_for_report(str(kind), report):
            if f.subtype not in ("pdf_annots", "pdf_acroform"):
                continue
            loc = getattr(f, "location", None)
            if loc is None or getattr(loc, "page", None) not in (page, page - 1):
                continue
            bbox = getattr(loc, "bbox", None)
            if not bbox or len(bbox) != 4:
                continue
            x0, y0n, x1, y1n = bbox
            # PDF origin bottom-left; raster origin top-left
            px0 = max(0, int(x0 * scale))
            px1 = min(width - 1, int(x1 * scale))
            py0 = max(0, int((y0n) * scale))
            py1 = min(height - 1, int((y1n) * scale))
            if px1 > px0 and py1 > py0:
                boxes.append((px0, py0, px1, py1))
    except Exception:  # noqa: S110 - bbox extraction is best-effort; never block the warn
        pass
    return boxes


def rasterize_page(
    pdf_path: Path, page: int, renderer: str, out_dir: Path
) -> tuple[int, int, bytes]:
    prefix = out_dir / f"pg{page}"
    proc = subprocess.run(
        [
            renderer,
            "-r",
            str(DPI),
            "-f",
            str(page),
            "-l",
            str(page),
            "-singlefile",
            str(pdf_path),
            str(prefix),
        ],
        capture_output=True,
        check=False,
    )
    ppm = Path(f"{prefix}.ppm")
    if proc.returncode != 0 or not ppm.exists():
        raise RenderError(f"pdftoppm failed on page {page}: {proc.stderr.decode()[:160]}")
    w, h, pix = parse_ppm(ppm.read_bytes())
    ppm.unlink()
    return w, h, pix


def visual_compare(
    original: bytes,
    derivative: bytes,
    *,
    original_report: dict[str, Any] | None = None,
    caps_max_pages: int = 30,
) -> dict[str, Any]:
    """Warn-only page comparison. Never raises for visual deltas; returns a
    result dict suitable for embedding under VerifyResult['visual_compare']."""
    result: dict[str, Any] = {
        "visual_compare_version": VISUAL_COMPARE_VERSION,
        "available": False,
        "warn": False,
        "note": "",
        "pages": [],
    }
    renderer = find_renderer()
    if renderer is None:
        result["note"] = "pdftoppm not available; visual compare skipped"
        return result
    if not derivative.startswith(b"%PDF-"):
        result["note"] = "derivative is not a PDF; skipped"
        return result
    pages_o = pdf_page_count(original)
    pages_d = pdf_page_count(derivative)
    if not pages_o or pages_o != pages_d:
        result["note"] = f"page count mismatch/unknown ({pages_o} vs {pages_d}); skipped"
        result["warn"] = bool(pages_o and pages_d and pages_o != pages_d)
        return result

    selected = select_pages(pages_o, caps_max_pages)
    with tempfile.TemporaryDirectory(prefix="wm-render-") as tmp:
        tmpdir = Path(tmp)
        po = tmpdir / "original.pdf"
        pd_ = tmpdir / "derivative.pdf"
        po.write_bytes(original)
        pd_.write_bytes(derivative)
        for page in selected:
            try:
                w, h, pix_o = rasterize_page(po, page, renderer, tmpdir)
                w2, h2, pix_d = rasterize_page(pd_, page, renderer, tmpdir)
            except RenderError as e:
                result["pages"].append({"page": page, "error": str(e)})
                result["warn"] = True
                continue
            if (w, h) != (w2, h2):
                result["pages"].append(
                    {"page": page, "error": f"dimension drift {w}x{h} -> {w2}x{h2}"}
                )
                result["warn"] = True
                continue
            masks = (
                bbox_mask_boxes(original_report or {}, page, w, h)
                if original_report
                else []
            )
            metrics = compare_pixels(w, h, pix_o, pix_d, masks)
            entry = {"page": page, **metrics, "masked_boxes": len(masks)}
            entry["warn"] = metrics["fraction_over"] > THRESHOLD_FRACTION
            if entry["warn"]:
                result["warn"] = True
            result["pages"].append(entry)
    result["available"] = True
    if result["warn"]:
        result["note"] = "visual deltas above warn threshold; operator review advised"
    else:
        result["note"] = "no significant visual deltas on compared pages"
    return result
