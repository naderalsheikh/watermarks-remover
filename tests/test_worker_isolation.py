"""PR 17 — isolated per-job workers.

Doctrine under test: the API process never parses untrusted bytes. Jobs
execute in a worker subprocess (or hardened docker container in
production), the worker owns every status transition, and the API only
reconciles terminal state.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "service" / "scripts"), str(REPO / "service")):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.config import Config
from app.runner import build_docker_cmd, build_subprocess_cmd

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw17")
    from app.main import create_app

    app = create_app(tmp_path / "data")
    c = TestClient(app)
    assert c.post("/v1/auth/login", json={"password": "pw17"}).status_code == 200
    return c


def _upload(client, name: str):
    matter = client.post("/v1/matters", json={"name": "m"}).json()["id"]
    doc = client.post(
        f"/v1/matters/{matter}/documents",
        files={
            "file": (
                name,
                (FIXTURES / name).read_bytes(),
                "application/octet-stream",
            )
        },
    ).json()
    return matter, doc["id"]


# --- doctrine guard -------------------------------------------------------------


def test_api_module_never_imports_parsers():
    src = (REPO / "service" / "app" / "main.py").read_text()
    code = "\n".join(line.split("#")[0] for line in src.splitlines())
    for banned in ("engine_api", "clean_to_bundle", "inspect_bytes"):
        assert banned not in code, f"main.py must not reference {banned}"


# --- end-to-end through the subprocess runner ------------------------------------


def test_sanitize_job_runs_in_worker_subprocess(client):
    matter, doc_id = _upload(client, "spa.docx")
    r = client.post(f"/v1/matters/{matter}/documents/{doc_id}/sanitize-jobs", json={}).json()
    assert r["status"] == "done", r["error"]
    assert r["result"]["verification_pass"] is True
    # subprocess mode records no image digest; provenance stays honest
    assert r["worker_image"] == ""

    bundle = client.get(f"/v1/matters/{matter}/jobs/{r['id']}/bundle")
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
        assert any(n.startswith("derivative/") for n in zf.namelist())


def test_refusal_survives_process_boundary(client):
    matter, doc_id = _upload(client, "signed.pdf")
    r = client.post(
        f"/v1/matters/{matter}/documents/{doc_id}/sanitize-jobs",
        json={"policy_id": "external_sharing"},
    ).json()
    # The policy refusal happens inside the worker process and lands on the
    # row as a first-class outcome — not a crash, not an API-side parse.
    assert r["status"] == "refused"
    assert "attestation" in r["error"]


def test_inspect_job_runs_in_worker_subprocess(client):
    matter, doc_id = _upload(client, "spa.txt")
    r = client.post(f"/v1/matters/{matter}/documents/{doc_id}/inspect-jobs").json()
    assert r["status"] == "done", r.get("error")


def test_worker_cli_rejects_nonqueued_job(tmp_path, monkeypatch):
    """run-job refuses to re-execute a job that already has an outcome."""
    import os
    import subprocess as sp

    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw17")
    from app.main import create_app

    root = tmp_path / "d"
    app = create_app(root)
    c = TestClient(app)
    assert c.post("/v1/auth/login", json={"password": "pw17"}).status_code == 200
    matter = c.post("/v1/matters", json={"name": "m"}).json()["id"]
    doc = c.post(
        f"/v1/matters/{matter}/documents",
        files={
            "file": ("spa.txt", (FIXTURES / "spa.txt").read_bytes(), "application/octet-stream")
        },
    ).json()
    job = c.post(f"/v1/matters/{matter}/documents/{doc['id']}/inspect-jobs").json()
    assert job["status"] == "done"

    env = dict(os.environ, PYTHONPATH=str(REPO / "service"))
    proc = sp.run(
        [
            sys.executable,
            "-m",
            "app.worker",
            "run-job",
            "--data-root",
            str(root),
            "--job",
            job["id"],
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO / "service"),
        check=False,
    )
    assert proc.returncode == 3
    assert "not queued" in (proc.stderr or "")


def test_sync_backstop_marks_failed_on_crash(tmp_path, monkeypatch):
    from app import runner
    from app.db import make_engine, make_session_factory
    from app.main import create_app
    from app.models import Job

    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw17")
    root = tmp_path / "data"
    create_app(root)  # brings schema up
    s = make_session_factory(make_engine(Config(root)))()
    job = Job(matter_id="m", document_id="d", kind="inspect", status="running")
    s.add(job)
    s.commit()

    runner.sync_job(s, job.id, runner.RunnerResult(rc=1, stderr_tail="boom", timed_out=False))
    s.expire_all()
    assert s.get(Job, job.id).status == "failed"
    assert "rc=1" in s.get(Job, job.id).error

    # terminal statuses are never overwritten by the backstop
    job = s.get(Job, job.id)
    job.status = "refused"
    s.commit()
    runner.sync_job(s, job.id, runner.RunnerResult(rc=1, stderr_tail="", timed_out=True))
    s.expire_all()
    assert s.get(Job, job.id).status == "refused"


# --- docker hardening ------------------------------------------------------------


def test_docker_cmd_is_hardened_and_digest_pinned():
    cfg = Config.__new__(Config)
    cfg.data_root = Path("/srv/cc")
    cfg.worker_image = "ghcr.io/acme/counselclear@sha256:" + "ab" * 32
    cmd = build_docker_cmd(cfg, "job123")
    joined = " ".join(cmd)
    for flag in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--tmpfs",
        "--pids-limit",
        "--memory",
    ):
        assert flag in joined, flag
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "/data" in joined and cfg.worker_image in cmd


def test_docker_mode_refuses_unpinned_image():
    cfg = Config.__new__(Config)
    cfg.data_root = Path("/srv/cc")
    cfg.worker_image = "counselclear:latest"
    with pytest.raises(ValueError, match="digest-pinned"):
        build_docker_cmd(cfg, "job123")


def test_config_rejects_unknown_worker_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("COUNSELCLEAR_WORKER_MODE", "fork-bomb")
    with pytest.raises(ValueError, match="COUNSELCLEAR_WORKER_MODE"):
        Config(tmp_path)


def test_build_subprocess_cmd_shape(tmp_path):
    cfg = Config(tmp_path)
    cmd = build_subprocess_cmd(cfg, "job42")
    assert cmd[:4] == [sys.executable, "-m", "app.worker", "run-job"]
    assert "--job" in cmd and "job42" in cmd
