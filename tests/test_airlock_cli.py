"""tools/counselclear_airlock.py — the local Airlock CLI (PR 34): a thin
HTTP client of the existing API, no second engine/control-plane write
path. Unit tests drive run_airlock() against a FakeClient (no network);
the one integration test drives the real Client class against a real
uvicorn-served app (no live server the operator has to manage by hand).
"""

from __future__ import annotations

import io
import json
import socket
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
for p in (str(TOOLS), str(REPO / "service"), str(REPO / "service" / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

import counselclear_airlock as airlock

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


# --- FakeClient: duck-types the Client surface run_airlock() actually calls -----


class FakeClient:
    def __init__(self, *, job_status: str, job_error: str = ""):
        self.job_status = job_status
        self.job_error = job_error
        self.calls: list[str] = []

    def upload_document(self, matter_id: str, path: Path) -> dict:
        self.calls.append("upload_document")
        return {"id": "doc1", "filename": path.name, "sha256": "0" * 64, "bytes": path.stat().st_size}

    def sanitize(self, matter_id: str, doc_id: str, *, policy_id: str, reason: str) -> dict:
        self.calls.append("sanitize")
        return {"id": "job1", "status": "queued"}

    def wait_for_terminal(self, matter_id: str, job_id: str, *, timeout_s: float) -> dict:
        self.calls.append("wait_for_terminal")
        if self.job_status == "__timeout__":
            raise airlock.AirlockError(f"job {job_id} did not reach a terminal state within {timeout_s:.0f}s")
        return {"id": job_id, "status": self.job_status, "error": self.job_error}

    def get_manifest(self, matter_id: str, job_id: str) -> dict | None:
        self.calls.append("get_manifest")
        return {
            "policy": {"id": "external_sharing", "version": 1},
            "derivative": {"sha256": "d" * 64, "filename": "doc.sanitized.docx"},
            "actions": [
                "custom_xml:strip: no artifacts found",
                "comments_and_notes:keep: kept: no operator decision was supplied for this "
                "approve-default finding",
            ],
            "findings_before": ["docx-comments: 1 comment(s)"],
            "verification": {"pass": True, "checks": []},
        }

    def get_bundle_zip(self, matter_id: str, job_id: str) -> bytes | None:
        self.calls.append("get_bundle_zip")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", "{}")
            zf.writestr("derivative/doc.sanitized.docx", b"fake derivative bytes")
        return buf.getvalue()

    def get_certificate_html(self, matter_id: str, job_id: str) -> bytes:
        self.calls.append("get_certificate_html")
        return b"<!doctype html><html><body>certificate</body></html>"


def _real_file(tmp_path: Path) -> Path:
    p = tmp_path / "input.docx"
    p.write_bytes((FIXTURES / "spa.docx").read_bytes())
    return p


# --- unit tests: success / refused / failed / timeout / bad policy --------------


def test_run_airlock_success_writes_derivative_manifest_certificate_and_summary(tmp_path):
    client = FakeClient(job_status="done")
    out = tmp_path / "out"
    result = airlock.run_airlock(
        client,
        matter_id="m1",
        file_path=_real_file(tmp_path),
        policy_id="external_sharing",
        reason="test",
        output_dir=out,
        timeout_s=5,
    )
    assert result.status == "done"
    assert (out / "doc.sanitized.docx").read_bytes() == b"fake derivative bytes"
    assert json.loads((out / "manifest.json").read_text())["derivative"]["sha256"] == "d" * 64
    assert (out / "certificate.html").read_bytes().startswith(b"<!doctype html>")
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert summary["status"] == "done"
    assert summary["job_id"] == "job1"
    assert summary["document_id"] == "doc1"
    assert set(summary["files_written"]) == {
        "doc.sanitized.docx", "manifest.json", "certificate.html", "AIRLOCK_RESULT.json",
    }
    # The no-decision action from the fake manifest must surface as a
    # limitation, not get silently absorbed into "success".
    assert len(result.limitations) == 1
    assert "no operator decision was supplied" in result.limitations[0]
    assert client.calls == [
        "upload_document", "sanitize", "wait_for_terminal",
        "get_manifest", "get_bundle_zip", "get_certificate_html",
    ]


def test_run_airlock_refused_job_writes_certificate_and_summary_without_derivative(tmp_path):
    client = FakeClient(job_status="refused", job_error="plan refused: macro-enabled file")
    out = tmp_path / "out"
    result = airlock.run_airlock(
        client,
        matter_id="m1",
        file_path=_real_file(tmp_path),
        policy_id="external_sharing",
        reason="test",
        output_dir=out,
        timeout_s=5,
    )
    assert result.status == "refused"
    assert not (out / "manifest.json").exists()
    assert not any(out.glob("*.docx"))
    assert (out / "certificate.html").exists()  # certificate always attempted
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert summary["status"] == "refused"
    assert summary["error"] == "plan refused: macro-enabled file"
    assert any("refused" in item for item in summary["limitations"])
    # done-only steps must never fire for a refused job.
    assert "get_manifest" not in client.calls
    assert "get_bundle_zip" not in client.calls
    assert "get_certificate_html" in client.calls


def test_run_airlock_failed_job_writes_certificate_and_summary_without_derivative(tmp_path):
    client = FakeClient(job_status="failed", job_error="worker exited rc=1: boom")
    out = tmp_path / "out"
    result = airlock.run_airlock(
        client,
        matter_id="m1",
        file_path=_real_file(tmp_path),
        policy_id="privacy_only",
        reason="test",
        output_dir=out,
        timeout_s=5,
    )
    assert result.status == "failed"
    assert not (out / "manifest.json").exists()
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert "worker exited rc=1: boom" in summary["limitations"][0]
    assert (out / "certificate.html").exists()


def test_run_airlock_timeout_raises_and_writes_nothing(tmp_path):
    client = FakeClient(job_status="__timeout__")
    out = tmp_path / "out"
    with pytest.raises(airlock.AirlockError, match="did not reach a terminal state"):
        airlock.run_airlock(
            client,
            matter_id="m1",
            file_path=_real_file(tmp_path),
            policy_id="external_sharing",
            reason="test",
            output_dir=out,
            timeout_s=5,
        )
    # A timeout means no job outcome to report -- no partial/misleading
    # AIRLOCK_RESULT.json left behind.
    assert not (out / "AIRLOCK_RESULT.json").exists()


def test_run_airlock_rejects_unsupported_policy_before_any_network_call(tmp_path):
    client = FakeClient(job_status="done")
    with pytest.raises(airlock.AirlockError, match="not supported"):
        airlock.run_airlock(
            client,
            matter_id="m1",
            file_path=_real_file(tmp_path),
            policy_id="production",
            reason="test",
            output_dir=tmp_path / "out",
            timeout_s=5,
        )
    assert client.calls == []


# --- doctrine guard: no engine imports from a tools/ HTTP client ----------------


def test_airlock_cli_never_imports_the_engine_or_app_internals():
    """The whole point of building this as an HTTP client: it must not pull
    in the engine (service/scripts) or the control plane's own internals
    (service/app) -- only stdlib. A real dependency on either would mean
    this script is quietly a second write path, not a thin client."""
    src = (TOOLS / "counselclear_airlock.py").read_text()
    code = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
    for banned in (
        "engine_api", "clean_to_bundle", "inspect_bytes", "import policies",
        "import sqlalchemy", "from sqlalchemy", "import fastapi", "from fastapi",
        "from app.", "import app.", "from app import",
        "import requests",
    ):
        assert banned not in code, f"counselclear_airlock.py must not reference {banned}"


# --- integration: real Client against a real uvicorn-served app -----------------


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def live_server(tmp_path, monkeypatch):
    """A real API process (uvicorn, in a background thread) so the
    integration test below exercises the CLI's actual urllib.request HTTP
    calls end to end, not a mock -- the closest thing to "no live server
    the operator has to manage by hand" that still proves the real wire
    protocol works."""
    import uvicorn

    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "airlockpw123")
    from app.main import create_app

    app = create_app(tmp_path / "data")
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            airlock.Client(base_url, timeout_s=1)._raw("GET", "/health")
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("live_server never came up")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)


def test_airlock_cli_end_to_end_against_a_real_server(tmp_path, live_server):
    client = airlock.Client(live_server)
    client.login("airlockpw123")
    matter = client._json("POST", "/v1/matters", payload={"name": "Airlock Integration"})

    out = tmp_path / "out"
    result = airlock.run_airlock(
        client,
        matter_id=matter["id"],
        file_path=_real_file(tmp_path),
        policy_id="external_sharing",
        reason="integration test",
        output_dir=out,
        timeout_s=30,
    )

    assert result.status == "done"
    assert (out / "manifest.json").exists()
    assert (out / "certificate.html").read_bytes().startswith(b"<!doctype html>")
    assert any(out.glob("*.docx"))
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert summary["matter_id"] == matter["id"]
    assert summary["status"] == "done"
