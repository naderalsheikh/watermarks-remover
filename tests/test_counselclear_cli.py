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
    assert (out / "report.html").is_file()


def test_inspect_html_flag_writes_report(tmp_path):
    path = ROOT / "tests" / "fixtures" / "sample_watermarked.txt"
    report = tmp_path / "report.html"
    rc = counselclear.main(["inspect", str(path), "--html", str(report)])
    assert rc == 1
    assert report.is_file()
    html = report.read_text(encoding="utf-8")
    assert "sample_watermarked.txt" in html
    assert html.startswith("<!doctype html>")


FIXTURES_LEGAL = ROOT / "tests" / "fixtures" / "legal"


def test_intake_refuses_without_authorization_flag(tmp_path, capsys):
    out = tmp_path / "intake.html"
    rc = counselclear.main(["intake", str(FIXTURES_LEGAL), "-o", str(out)])
    assert rc == 2
    assert not out.exists()
    assert "--i-am-authorized" in capsys.readouterr().err


def test_intake_refuses_non_directory(tmp_path, capsys):
    not_a_dir = tmp_path / "x.txt"
    not_a_dir.write_text("hi")
    out = tmp_path / "intake.html"
    rc = counselclear.main(
        ["intake", str(not_a_dir), "-o", str(out), "--i-am-authorized"]
    )
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err


def test_intake_writes_report_and_redacts_identities_by_default(tmp_path):
    out = tmp_path / "intake.html"
    rc = counselclear.main(
        ["intake", str(FIXTURES_LEGAL), "-o", str(out), "--i-am-authorized"]
    )
    assert rc == 1  # the fixture corpus has findings
    html = out.read_text(encoding="utf-8")
    assert "Jane Associate" not in html  # identity not revealed by default
    assert "redacted by default" in html


def test_intake_reveal_identities_and_json_out(tmp_path):
    out = tmp_path / "intake.html"
    data = tmp_path / "intake.json"
    rc = counselclear.main([
        "intake", str(FIXTURES_LEGAL), "-o", str(out), "--json-out", str(data),
        "--i-am-authorized", "--reveal-identities", "--matter", "M-1",
    ])
    assert rc == 1
    html = out.read_text(encoding="utf-8")
    assert "Jane Associate" in html
    assert "M-1" in html

    payload = json.loads(data.read_text(encoding="utf-8"))
    assert payload["reveal_identities"] is True
    assert payload["matter"] == "M-1"
    spa = next(f for f in payload["files"] if f["name"] == "spa.docx")
    assert spa["identities"]["Author"] == "Jane Associate"


def test_intake_tolerates_one_bad_file_and_reports_partial(tmp_path, monkeypatch):
    src = tmp_path / "docs"
    src.mkdir()
    (src / "ok.txt").write_text(f"Hello{chr(0x200B)}World", encoding="utf-8")
    (src / "bad.txt").write_text("also text", encoding="utf-8")

    real_inspect_bytes = counselclear.inspect_bytes

    def flaky(data, name, *a, **kw):
        if name == "bad.txt":
            raise ValueError("simulated parser failure")
        return real_inspect_bytes(data, name, *a, **kw)

    monkeypatch.setattr(counselclear, "inspect_bytes", flaky)

    out = tmp_path / "intake.html"
    rc = counselclear.main(["intake", str(src), "-o", str(out), "--i-am-authorized"])

    from common import EXIT_PARTIAL

    assert rc == EXIT_PARTIAL
    html = out.read_text(encoding="utf-8")
    assert "ok.txt" in html
    assert "bad.txt" in html
    assert "simulated parser failure" in html
    assert "1 unreadable" in html
