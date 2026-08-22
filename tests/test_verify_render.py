"""PR 14 — PDF render-and-compare (warn-only visual diff)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from verify_render import (
    THRESHOLD_FRACTION,
    compare_pixels,
    feature_enabled,
    parse_ppm,
    pdf_page_count,
    select_pages,
    visual_compare,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


def _ppm(width: int, height: int, rgb: bytes) -> bytes:
    header = f"P6\n{width} {height}\n255\n".encode()
    return header + rgb


def test_parse_ppm_roundtrip():
    pix = bytes(range(24))  # 4x2 pixels x3 channels
    w, h, out = parse_ppm(_ppm(4, 2, pix))
    assert (w, h) == (4, 2) and out == pix


def test_parse_ppm_rejects_truncated_and_wrong_magic():
    with pytest.raises(Exception):  # noqa: B017 - parser raises RenderError
        parse_ppm(b"P5\n1 1\n255\n\x00")
    with pytest.raises(Exception):  # noqa: B017
        parse_ppm(_ppm(4, 4, b"\x00" * 8))


def test_constant_image_blurs_to_itself():
    from verify_render import box_blur_1px

    w = h = 5
    pix = bytes([100, 150, 200]) * (w * h)
    out = box_blur_1px(w, h, pix)
    assert bytes(out) == pix


def test_spike_spreads_under_blur():
    from verify_render import box_blur_1px

    w = h = 3
    pix = bytearray(b"\x00\x00\x00" * (w * h))
    pix[(1 * w + 1) * 3] = 90  # center red spike
    out = box_blur_1px(w, h, bytes(pix))
    assert out[0] > 0  # corner picked up some energy
    assert out[(1 * w + 1) * 3] < 90  # spike diluted


def test_identical_images_zero_delta():
    pix = bytes(range(3 * 16)) * 4
    m = compare_pixels(4, 4, pix, pix)
    assert m["mean_abs"] == 0.0 and m["fraction_over"] == 0.0


def test_changed_block_exceeds_thresholds_and_masks_suppress():
    w = h = 20
    a = bytes([128] * (w * h * 3))
    b = bytearray(a)
    for y in range(10):
        for x in range(10):
            i = (y * w + x) * 3
            b[i : i + 3] = b"\xff\x00\x00"
    m = compare_pixels(w, h, a, bytes(b))
    assert m["fraction_over"] > THRESHOLD_FRACTION
    masked = compare_pixels(w, h, a, bytes(b), [(0, 0, 9, 9)])
    assert masked["fraction_over"] == 0.0 and masked["mean_abs"] == 0.0


def test_masked_region_removed_from_denominator():
    # fully-masked image has no unmasked pixels: zero metrics, no crash
    a = bytes([10] * (6 * 6 * 3))
    b = bytes([240] * (6 * 6 * 3))
    m = compare_pixels(6, 6, a, b, [(0, 0, 5, 5)])
    assert m == {"mean_abs": 0.0, "fraction_over": 0.0}


def test_select_pages_caps_and_samples():
    assert select_pages(12) == list(range(1, 13))
    pages = select_pages(60)
    assert len(pages) == 30
    assert pages[0] == 1 and pages[-1] == 60
    assert any(20 <= p <= 40 for p in pages)  # middle sampling present
    assert select_pages(9) == [1, 2, 3, 4, 5, 6, 7, 8, 9]


def test_page_count_helper():
    stub = (
        b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n"
        b"2 0 obj << /Type /Page /Parent 1 0 R >> endobj\n"
        b"3 0 obj << /Type /Pages /Kids [2 0 R] >> endobj\n"
    )
    assert pdf_page_count(stub) == 1  # /Pages must not count as /Page


def test_feature_flag_defaults_off():
    import os

    old = os.environ.pop("COUNSELCLEAR_VISUAL_COMPARE", None)
    try:
        assert feature_enabled() is False
        os.environ["COUNSELCLEAR_VISUAL_COMPARE"] = "1"
        assert feature_enabled() is True
    finally:
        if old is not None:
            os.environ["COUNSELCLEAR_VISUAL_COMPARE"] = old
        else:
            os.environ.pop("COUNSELCLEAR_VISUAL_COMPARE", None)


@pytest.mark.skipif(
    __import__("shutil").which("pdftoppm") is None, reason="poppler not installed"
)
def test_visual_compare_incremental_pdf_no_visual_warn():
    original = (FIXTURES / "incremental.pdf").read_bytes()
    import sys as _sys

    _sys.path.insert(0, str(SCRIPTS))
    from engine_api import inspect_bytes
    from policies import apply_actions, plan_actions

    res = inspect_bytes(original, "incremental.pdf")
    plan = plan_actions(res, "external_sharing")
    cleaned, _records = apply_actions(original, plan)
    report = visual_compare(original, cleaned, original_report=res.report)
    assert report["available"] is True
    assert report["warn"] is False
    assert report["pages"] and all("mean_abs" in p for p in report["pages"])
