"""PR 1 extract + structured findings on InspectResult."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from engine_api import (
    Caps,
    InspectResult,
    ProcessorInfo,
    clean_bytes,
    inspect_bytes,
    inspect_http,
)
from findings import Finding

FIXTURE = ROOT / "tests" / "fixtures" / "sample_watermarked.txt"


def test_caps_and_processor_pin():
    caps = Caps()
    assert caps.max_input_bytes > 0
    proc = ProcessorInfo()
    assert proc.git_sha
    assert proc.git_sha != ""
    assert isinstance(proc.tools, dict)


def test_inspect_bytes_findings_are_structured():
    data = FIXTURE.read_bytes()
    result = inspect_bytes(data, "sample_watermarked.txt")
    assert isinstance(result, InspectResult)
    assert result.kind == "text"
    assert result.source_sha256 == hashlib.sha256(data).hexdigest()
    assert result.findings
    assert all(isinstance(f, Finding) for f in result.findings)
    assert any(f.subtype == "layer_a_body" for f in result.findings)
    assert result.finding_strings


def test_inspect_bytes_unknown_is_not_an_error():
    result = inspect_bytes(b"no magic, no extension", "input")
    assert result.kind == "unknown"
    assert result.unsupported_reason
    assert result.findings == []


def test_clean_bytes_strips_text_layer_a():
    data = "Hello\u200bWorld\u00ad!".encode("utf-8")
    cleaned, report = clean_bytes(data, "note.txt")
    assert cleaned.decode("utf-8") == "HelloWorld!"
    assert report["kind"] == "text"
    assert report["stats"]["removed_count"] == 2


def test_clean_bytes_unknown_raises():
    with pytest.raises(ValueError, match="unrecognized file format"):
        clean_bytes(b"no magic, no extension", "input")


def test_run_capped_returns_control_at_timeout_not_after_runaway_finishes():
    # ThreadPoolExecutor used as a context manager joins the worker on
    # __exit__ before a TimeoutError can propagate, so the caller used to
    # block for the full runaway duration instead of the documented budget.
    import time

    from engine_api import _run_capped

    start = time.monotonic()
    with pytest.raises(TimeoutError):
        _run_capped(lambda: time.sleep(2.0), timeout_s=1)
    elapsed = time.monotonic() - start
    assert elapsed < 1.5, f"blocked for {elapsed:.2f}s waiting on a 1s-capped call"


def test_inspect_http_includes_structured_findings_without_detect():
    data = "Hello\u200bWorld\u00ad!".encode("utf-8")
    body = inspect_http(data, "note.txt")
    assert body["ok"] is True
    assert "text_detectors" not in body["report"]
    assert body["findings"]
    assert body["findings"][0]["subtype"] == "layer_a_body"


def test_inspect_http_detect_is_opt_in():
    data = "Hello\u200bWorld!".encode("utf-8")
    off = inspect_http(data, "note.txt", run_detect=False)
    on = inspect_http(data, "note.txt", run_detect=True)
    assert "text_detectors" not in off["report"]
    assert "text_detectors" in on["report"]
