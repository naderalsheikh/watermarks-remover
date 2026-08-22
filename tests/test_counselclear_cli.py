"""Product CLI exit codes: unknown/unsupported = 2."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import counselclear


def test_inspect_unknown_exits_2(tmp_path, capsys):
    blob = tmp_path / "x.bin"
    blob.write_bytes(b"no magic here")
    assert counselclear.main(["inspect", str(blob)]) == 2


def test_inspect_findings_exit_1_json(capsys):
    path = ROOT / "tests" / "fixtures" / "sample_watermarked.txt"
    rc = counselclear.main(["inspect", "--json", str(path)])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "text"
    assert payload["findings"]
    assert payload["findings"][0]["subtype"]


def test_sanitize_writes_bundle(tmp_path):
    src = tmp_path / "note.txt"
    src.write_text("Hello\u200bWorld", encoding="utf-8")
    out = tmp_path / "bundle"
    rc = counselclear.main(["sanitize", str(src), "-o", str(out), "--policy", "privacy_only"])
    assert rc == 0
    assert (out / "manifest.json").is_file()
    assert list((out / "derivative").iterdir())
