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

    def get_release_packet_zip(self, matter_id: str, job_id: str) -> bytes | None:
        self.calls.append("get_release_packet_zip")
        manifest = {
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
        release_packet = {
            "spec_version": "1.0", "job_id": job_id, "matter_id": matter_id,
            "policy": {"id": "external_sharing", "version": 1, "digest": None},
            "anchor": {"type": "none", "digest": None, "reference": None},
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("report.json", json.dumps({"verification": manifest["verification"]}))
            zf.writestr("certificate.html", "<!doctype html><html><body>certificate</body></html>")
            zf.writestr("release_packet.json", json.dumps(release_packet))
            zf.writestr("README.txt", "CounselClear release packet\n")
            zf.writestr("derivative/doc.sanitized.docx", b"fake derivative bytes")
        return buf.getvalue()

    def get_certificate_html(self, matter_id: str, job_id: str) -> bytes:
        self.calls.append("get_certificate_html")
        return b"<!doctype html><html><body>certificate</body></html>"


def _real_file(tmp_path: Path) -> Path:
    p = tmp_path / "input.docx"
    p.write_bytes((FIXTURES / "spa.docx").read_bytes())
    return p


def _named_file(tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    p.write_bytes((FIXTURES / "spa.docx").read_bytes())
    return p


class FakeBatchClient:
    """Like FakeClient, but resolves the job outcome per input file (keyed
    by filename) so one instance can drive a batch with mixed outcomes --
    done, refused, failed, a poll timeout, and (via upload_failures) a
    hard per-file AirlockError that never even reaches a job status."""

    def __init__(
        self,
        statuses_by_filename: dict[str, str],
        errors_by_filename: dict[str, str] | None = None,
        upload_failures: set[str] | None = None,
    ):
        self.statuses_by_filename = statuses_by_filename
        self.errors_by_filename = errors_by_filename or {}
        self.upload_failures = upload_failures or set()
        self.calls: list[str] = []
        self._job_counter = 0
        self._doc_to_filename: dict[str, str] = {}
        self._job_to_filename: dict[str, str] = {}

    def upload_document(self, matter_id: str, path: Path) -> dict:
        self.calls.append("upload_document")
        if path.name in self.upload_failures:
            raise airlock.AirlockError(f"upload failed for {path.name}: simulated network error")
        doc_id = f"doc-{path.name}"
        self._doc_to_filename[doc_id] = path.name
        return {"id": doc_id, "filename": path.name, "sha256": "0" * 64, "bytes": path.stat().st_size}

    def sanitize(self, matter_id: str, doc_id: str, *, policy_id: str, reason: str) -> dict:
        self.calls.append("sanitize")
        self._job_counter += 1
        job_id = f"job-{self._job_counter}"
        self._job_to_filename[job_id] = self._doc_to_filename[doc_id]
        return {"id": job_id, "status": "queued"}

    def wait_for_terminal(self, matter_id: str, job_id: str, *, timeout_s: float) -> dict:
        self.calls.append("wait_for_terminal")
        filename = self._job_to_filename[job_id]
        status = self.statuses_by_filename[filename]
        if status == "__timeout__":
            raise airlock.AirlockError(f"job {job_id} did not reach a terminal state within {timeout_s:.0f}s")
        return {"id": job_id, "status": status, "error": self.errors_by_filename.get(filename, "")}

    def get_release_packet_zip(self, matter_id: str, job_id: str) -> bytes | None:
        self.calls.append("get_release_packet_zip")
        manifest = {
            "policy": {"id": "external_sharing", "version": 1},
            "derivative": {"sha256": "d" * 64, "filename": "doc.sanitized.docx"},
            "actions": [],
            "findings_before": [],
            "verification": {"pass": True, "checks": []},
        }
        release_packet = {
            "spec_version": "1.0", "job_id": job_id, "matter_id": matter_id,
            "policy": {"id": "external_sharing", "version": 1, "digest": None},
            "anchor": {"type": "none", "digest": None, "reference": None},
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("report.json", json.dumps({"verification": manifest["verification"]}))
            zf.writestr("certificate.html", "<!doctype html><html><body>certificate</body></html>")
            zf.writestr("release_packet.json", json.dumps(release_packet))
            zf.writestr("README.txt", "CounselClear release packet\n")
            zf.writestr("derivative/doc.sanitized.docx", b"fake derivative bytes")
        return buf.getvalue()

    def get_certificate_html(self, matter_id: str, job_id: str) -> bytes:
        self.calls.append("get_certificate_html")
        return b"<!doctype html><html><body>certificate</body></html>"


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
    assert (out / "report.json").exists()
    assert (out / "certificate.html").read_bytes().startswith(b"<!doctype html>")
    assert json.loads((out / "release_packet.json").read_text())["job_id"] == "job1"
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert summary["status"] == "done"
    assert summary["job_id"] == "job1"
    assert summary["document_id"] == "doc1"
    assert set(summary["files_written"]) == {
        "doc.sanitized.docx", "manifest.json", "report.json", "certificate.html",
        "release_packet.json", "README.txt", "AIRLOCK_RESULT.json",
    }
    # The no-decision action from the fake manifest must surface as a
    # limitation, not get silently absorbed into "success".
    assert len(result.limitations) == 1
    assert "no operator decision was supplied" in result.limitations[0]
    # One release-packet call gets derivative + manifest + report +
    # certificate together -- not three separate requests for the same
    # content (get_certificate_html is refused/failed-only, see below).
    assert client.calls == [
        "upload_document", "sanitize", "wait_for_terminal", "get_release_packet_zip",
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
    assert "get_release_packet_zip" not in client.calls
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


# --- batch mode: mixed success/refused/failed/timeout/error outcomes -----------


def test_run_airlock_batch_mixed_success_and_refused(tmp_path):
    files = [_named_file(tmp_path, "good.docx"), _named_file(tmp_path, "bad.docx")]
    client = FakeBatchClient(
        statuses_by_filename={"good.docx": "done", "bad.docx": "refused"},
        errors_by_filename={"bad.docx": "plan refused: macro-enabled file"},
    )
    out = tmp_path / "out"
    batch = airlock.run_airlock_batch(
        client, matter_id="m1", files=files, policy_id="external_sharing",
        reason="test", output_dir=out, timeout_s=5,
    )
    assert [item.status for item in batch.items] == ["done", "refused"]
    assert batch.items[0].output_dir == "001-good"
    assert batch.items[1].output_dir == "002-bad"
    assert (out / "001-good" / "doc.sanitized.docx").exists()
    assert not (out / "002-bad" / "doc.sanitized.docx").exists()
    assert (out / "002-bad" / "certificate.html").exists()
    assert "plan refused" in batch.items[1].limitations[0]
    assert batch.counts == {"done": 1, "refused": 1, "failed": 0, "error": 0}

    summary = json.loads((out / "BATCH_RESULT.json").read_text())
    assert summary["total"] == 2
    assert summary["counts"] == {"done": 1, "refused": 1, "failed": 0, "error": 0}
    assert summary["anchor_note"] == "release packets in this batch are not externally anchored"
    assert summary["items"][0]["input_file"] == "good.docx"
    assert summary["items"][0]["error"] == ""
    assert summary["items"][1]["error"] == "plan refused: macro-enabled file"


def test_run_airlock_batch_failed_job_is_recorded_not_raised(tmp_path):
    files = [_named_file(tmp_path, "crash.docx")]
    client = FakeBatchClient(
        statuses_by_filename={"crash.docx": "failed"},
        errors_by_filename={"crash.docx": "worker exited rc=1: boom"},
    )
    batch = airlock.run_airlock_batch(
        client, matter_id="m1", files=files, policy_id="privacy_only",
        reason="test", output_dir=tmp_path / "out", timeout_s=5,
    )
    assert batch.items[0].status == "failed"
    assert "worker exited rc=1: boom" in batch.items[0].limitations[0]


def test_run_airlock_batch_timeout_recorded_as_error_not_aborted(tmp_path):
    files = [_named_file(tmp_path, "slow.docx"), _named_file(tmp_path, "good.docx")]
    client = FakeBatchClient(statuses_by_filename={"slow.docx": "__timeout__", "good.docx": "done"})
    batch = airlock.run_airlock_batch(
        client, matter_id="m1", files=files, policy_id="external_sharing",
        reason="test", output_dir=tmp_path / "out", timeout_s=5,
    )
    # The timeout on file 1 must not abort processing of file 2.
    assert batch.items[0].status == "error"
    assert "did not reach a terminal state" in batch.items[0].error
    assert batch.items[1].status == "done"


def test_run_airlock_batch_hard_upload_failure_recorded_as_error(tmp_path):
    files = [_named_file(tmp_path, "broken.docx"), _named_file(tmp_path, "good.docx")]
    client = FakeBatchClient(
        statuses_by_filename={"good.docx": "done"},
        upload_failures={"broken.docx"},
    )
    batch = airlock.run_airlock_batch(
        client, matter_id="m1", files=files, policy_id="external_sharing",
        reason="test", output_dir=tmp_path / "out", timeout_s=5,
    )
    assert batch.items[0].status == "error"
    assert "upload failed" in batch.items[0].error
    assert batch.items[0].job_id == ""
    assert batch.items[1].status == "done"


def test_run_airlock_batch_full_partial_mixed_outcome(tmp_path):
    """Acceptance: a batch spanning every outcome in one run -- done,
    refused, failed, poll timeout, and a hard per-file error -- each
    recorded independently, none aborting the rest."""
    names = ["a_done.docx", "b_refused.docx", "c_failed.docx", "d_timeout.docx", "e_error.docx"]
    files = [_named_file(tmp_path, n) for n in names]
    client = FakeBatchClient(
        statuses_by_filename={
            "a_done.docx": "done",
            "b_refused.docx": "refused",
            "c_failed.docx": "failed",
            "d_timeout.docx": "__timeout__",
        },
        errors_by_filename={
            "b_refused.docx": "plan refused: macro-enabled file",
            "c_failed.docx": "worker exited rc=1: boom",
        },
        upload_failures={"e_error.docx"},
    )
    out = tmp_path / "out"
    batch = airlock.run_airlock_batch(
        client, matter_id="m1", files=files, policy_id="external_sharing",
        reason="test", output_dir=out, timeout_s=5,
    )
    assert [item.status for item in batch.items] == ["done", "refused", "failed", "error", "error"]
    assert batch.counts == {"done": 1, "refused": 1, "failed": 1, "error": 2}
    assert len(batch.items) == 5
    # every item still gets its own numbered output dir, even the two errors
    assert [item.output_dir for item in batch.items] == [
        "001-a_done", "002-b_refused", "003-c_failed", "004-d_timeout", "005-e_error",
    ]


def test_run_airlock_batch_rejects_unsupported_policy_before_any_file(tmp_path):
    files = [_named_file(tmp_path, "x.docx")]
    client = FakeBatchClient(statuses_by_filename={"x.docx": "done"})
    with pytest.raises(airlock.AirlockError, match="not supported"):
        airlock.run_airlock_batch(
            client, matter_id="m1", files=files, policy_id="production",
            reason="test", output_dir=tmp_path / "out", timeout_s=5,
        )
    assert client.calls == []


def test_run_airlock_batch_rejects_empty_file_list(tmp_path):
    client = FakeBatchClient(statuses_by_filename={})
    with pytest.raises(airlock.AirlockError, match="no input files"):
        airlock.run_airlock_batch(
            client, matter_id="m1", files=[], policy_id="external_sharing",
            reason="test", output_dir=tmp_path / "out", timeout_s=5,
        )


# --- CLI (main()) argument handling for batch mode ------------------------------


def test_main_rejects_file_and_folder_together(tmp_path, capsys):
    with pytest.raises(SystemExit):
        airlock.main([
            "--matter-id", "m1", "--file", str(tmp_path), "--folder", str(tmp_path),
            "--output-dir", str(tmp_path / "out"), "--password", "x",
        ])


def test_main_folder_mode_errors_cleanly_when_folder_missing(tmp_path, capsys):
    rc = airlock.main([
        "--matter-id", "m1", "--folder", str(tmp_path / "nope"),
        "--output-dir", str(tmp_path / "out"), "--password", "x",
    ])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_main_folder_mode_errors_cleanly_when_folder_empty(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = airlock.main([
        "--matter-id", "m1", "--folder", str(empty),
        "--output-dir", str(tmp_path / "out"), "--password", "x",
    ])
    assert rc == 1
    assert "no regular files" in capsys.readouterr().err


def test_main_files_mode_errors_cleanly_when_a_file_is_missing(tmp_path, capsys):
    present = _named_file(tmp_path, "present.docx")
    rc = airlock.main([
        "--matter-id", "m1", "--files", str(present), str(tmp_path / "absent.docx"),
        "--output-dir", str(tmp_path / "out"), "--password", "x",
    ])
    assert rc == 1
    assert "absent.docx" in capsys.readouterr().err


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
    assert (out / "report.json").exists()
    assert (out / "certificate.html").read_bytes().startswith(b"<!doctype html>")
    assert (out / "release_packet.json").exists()
    assert any(out.glob("*.docx"))
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert summary["matter_id"] == matter["id"]
    assert summary["status"] == "done"

    # PR 37: the CLI's own extracted output directory, written verbatim
    # from a real server's real release packet, passes the real verifier
    # -- not a synthetic fixture.
    import counselclear_verify_release_packet as verifier

    report = verifier.verify_release_packet(out)
    assert report.valid, report.to_text()
    assert report.anchor_type == "none"


def test_airlock_cli_batch_end_to_end_against_a_real_server_mixed_folder(tmp_path, live_server):
    """PR 38: a real folder with one file that sanitizes cleanly and one
    that gets refused (macro-enabled), driven through the actual batch
    CLI entry point (main(), not run_airlock_batch() directly) against a
    real server."""
    client = airlock.Client(live_server)
    client.login("airlockpw123")
    matter = client._json("POST", "/v1/matters", payload={"name": "Airlock Batch Integration"})

    folder = tmp_path / "intake"
    folder.mkdir()
    (folder / "a_clean.docx").write_bytes((FIXTURES / "spa.docx").read_bytes())
    (folder / "b_macro.docm").write_bytes((FIXTURES / "macro.docm").read_bytes())

    out = tmp_path / "out"
    rc = airlock.main([
        "--base-url", live_server,
        "--password", "airlockpw123",
        "--matter-id", matter["id"],
        "--folder", str(folder),
        "--policy", "external_sharing",
        "--reason", "batch integration test",
        "--output-dir", str(out),
        "--timeout-s", "30",
    ])

    # Mixed outcome (one done, one refused) -> exit code 2, same convention
    # as a single refused/failed job in single-file mode.
    assert rc == 2

    summary = json.loads((out / "BATCH_RESULT.json").read_text())
    assert summary["total"] == 2
    assert summary["counts"]["done"] == 1
    assert summary["counts"]["error"] == 0
    statuses = {item["input_file"]: item["status"] for item in summary["items"]}
    assert statuses["a_clean.docx"] == "done"
    assert statuses["b_macro.docm"] == "refused"

    done_item = next(item for item in summary["items"] if item["status"] == "done")
    done_dir = out / done_item["output_dir"]
    assert (done_dir / "release_packet.json").exists()
    assert any(done_dir.glob("*.docx"))

    refused_item = next(item for item in summary["items"] if item["status"] == "refused")
    refused_dir = out / refused_item["output_dir"]
    assert (refused_dir / "certificate.html").exists()
    assert not any(refused_dir.glob("*.docm"))

    import counselclear_verify_release_packet as verifier

    report = verifier.verify_release_packet(done_dir)
    assert report.valid, report.to_text()
