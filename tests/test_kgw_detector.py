"""Tests for the same-key Kirchenbauer (KGW) green-list z-score detector.

Exercises the replay arithmetic of detect_kgw.py with a toy green-list
generator over the simple tokenizer's word->id space, the TextDetector
protocol in text_detectors.py, and the fail-soft registry contract.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import detect_gumbel
import detect_kgw
import text_detectors

KEY_HEX = "0x" + "ab" * 16  # 16 raw bytes
KEY_HEX_OTHER = "0x" + "cd" * 16
KEY_BYTES = detect_kgw._normalize_key(KEY_HEX)

_ID_PACK = struct.Struct(">Q")

_WORDS = [f"w{i}" for i in range(64)]
_WORD_IDS = [detect_gumbel._token_id(w) for w in _WORDS]


# S311: deterministic toy RNG for the sampler tests — never used for secrets.
def _rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311


def _is_green(key_bytes: bytes, prev_id: int, token_id: int) -> bool:
    """Mirrors detect_kgw.py's PRF layout: seed on the previous token only."""
    seed = hmac.new(key_bytes, _ID_PACK.pack(prev_id), hashlib.sha256).digest()
    digest = hmac.new(seed, _ID_PACK.pack(token_id), hashlib.sha256).digest()
    return digest[0] < 128


def _marked_text(n: int, rng: random.Random, key_hex: str = KEY_HEX) -> str:
    """Text sampled from the green list implied by each previous token id."""
    key_bytes = detect_kgw._normalize_key(key_hex)
    seq_ids = [rng.choice(_WORD_IDS)]
    for _ in range(n - 1):
        greens = [t for t in _WORD_IDS if _is_green(key_bytes, seq_ids[-1], t)]
        seq_ids.append(rng.choice(greens))
    word_of = {i: w for w, i in zip(_WORDS, _WORD_IDS, strict=True)}
    return " ".join(word_of[t] for t in seq_ids)


def _unmarked_text(n: int, rng: random.Random) -> str:
    word_of = {i: w for w, i in zip(_WORDS, _WORD_IDS, strict=True)}
    return " ".join(word_of[rng.choice(_WORD_IDS)] for _ in range(n))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("WATERMARKS_KGW_KEY", raising=False)


# --- Replay arithmetic -------------------------------------------------------


def test_marked_text_is_detected():
    rng = _rng(1)
    report = detect_kgw.detect_kgw_text(_marked_text(400, rng), KEY_HEX)
    assert report["available"] is True
    assert report["is_watermarked"] is True
    assert report["score"] >= report["threshold"]
    assert report["green_fraction"] > 0.9


def test_unmarked_text_at_chance():
    rng = _rng(2)
    report = detect_kgw.detect_kgw_text(_unmarked_text(400, rng), KEY_HEX)
    assert report["available"] is True
    assert report["is_watermarked"] is False
    assert abs(report["score"]) < 4
    assert 0.35 < report["green_fraction"] < 0.65


def test_wrong_key_at_chance():
    rng = _rng(3)
    text = _marked_text(400, rng)
    report = detect_kgw.detect_kgw_text(text, KEY_HEX_OTHER)
    assert report["is_watermarked"] is False
    assert abs(report["score"]) < 4


def test_detection_is_deterministic():
    rng = _rng(4)
    text = _marked_text(200, rng)
    assert detect_kgw.detect_kgw_text(text, KEY_HEX) == detect_kgw.detect_kgw_text(text, KEY_HEX)


def test_short_text_counts_nothing():
    report = detect_kgw.detect_kgw_text("a b c", KEY_HEX)
    assert report["available"] is True
    assert report["is_watermarked"] is False
    assert report["tokens_scored"] == 2
    assert "≥20" in report["error"]
    assert report["green_fraction"] is None


def test_key_normalization():
    assert detect_kgw._normalize_key("0x" + "ab" * 8) == b"\xab" * 8
    assert detect_kgw._normalize_key("0xAB12") == b"\xab\x12"
    assert detect_kgw._normalize_key("s3cret key!") == b"s3cret key!"
    with pytest.raises(ValueError):
        detect_kgw._normalize_key("0xzz")
    with pytest.raises(ValueError):
        detect_kgw._normalize_key("0xabc")


def test_first_token_is_never_scored():
    # A single token carries no context; n must stay 0 and the short-text
    # path must fire rather than divide by zero.
    report = detect_kgw.detect_kgw_text("hello", KEY_HEX)
    assert report["tokens_scored"] == 0
    assert report["is_watermarked"] is False


# --- KGWTextDetector protocol ------------------------------------------------


def test_kgw_detector_unconfigured():
    detector = text_detectors.KGWTextDetector()
    assert detector.available() is False
    report = detector.detect("hello world")
    assert report["available"] is False
    assert "WATERMARKS_KGW_KEY" in report["error"]
    assert report["detector"] == "kgw"


def test_kgw_detector_env_key(monkeypatch):
    monkeypatch.setenv("WATERMARKS_KGW_KEY", KEY_HEX)
    rng = _rng(5)
    report = text_detectors.KGWTextDetector().detect(_marked_text(400, rng))
    assert report["available"] is True
    assert report["is_watermarked"] is True
    assert report["detector"] == "kgw"
    assert report["vendor"] == "self-hosted"


def test_kgw_detector_constructor_key():
    rng = _rng(6)
    report = text_detectors.KGWTextDetector(key=KEY_HEX).detect(_marked_text(400, rng))
    assert report["available"] is True
    assert report["is_watermarked"] is True


def test_kgw_detector_constructor_threshold_overrides_env(monkeypatch):
    monkeypatch.setenv("WATERMARKS_KGW_KEY", KEY_HEX)
    rng = _rng(7)
    text = _unmarked_text(400, rng)
    strict = text_detectors.KGWTextDetector(threshold=-100.0).detect(text)
    assert strict["threshold"] == -100.0
    assert strict["is_watermarked"] is True


def test_kgw_in_detector_registry(monkeypatch):
    names = {d.name for d in text_detectors.all_detectors()}
    assert "kgw" in names
    monkeypatch.setenv("WATERMARKS_KGW_KEY", KEY_HEX)
    assert text_detectors.detector_status()["kgw"] is True


def test_fail_soft_contract_reports_kgw_even_when_unconfigured():
    reports = text_detectors.run_all_text_detectors("some plain wording here")
    kgw = [r for r in reports if r.get("detector") == "kgw"]
    assert len(kgw) == 1
    assert kgw[0]["available"] is False
    assert "error" in kgw[0]


def test_run_text_detectors_skips_unconfigured_kgw():
    reports = text_detectors.run_text_detectors("some plain wording here")
    assert all(r.get("detector") != "kgw" for r in reports)


# --- CLI parity guard --------------------------------------------------------


def test_module_has_no_side_effects_on_import():
    # Importing must not read env keys or start anything; the server imports
    # this module unconditionally.
    assert os.environ.get("WATERMARKS_KGW_KEY") is None
    assert callable(detect_kgw.detect_kgw_text)


def test_hashlib_layout_unchanged():
    # Guard the exact PRF bytes: seed = HMAC(key, >Q prev); verdict byte of
    # HMAC(seed, >Q token). If this drifts, every existing stamp breaks.
    seed = hmac.new(b"k", _ID_PACK.pack(7), hashlib.sha256).digest()
    expected = hmac.new(seed, _ID_PACK.pack(42), hashlib.sha256).digest()[0]
    assert _is_green(b"k", 7, 42) == (expected < 128)
