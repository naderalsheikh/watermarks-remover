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


def test_worker_cli_is_pure_no_db_access(tmp_path):
    """run-job takes explicit --input/--output-dir, never a --data-root or
    --job to look up in a database — the whole point of PR 17 hardening
    (see runner.py's module docstring). Confirmed by running it against a
    bare filesystem with no app database anywhere near it."""
    import subprocess as sp

    src = tmp_path / "in" / "spa.txt"
    src.parent.mkdir(parents=True)
    src.write_bytes((FIXTURES / "spa.txt").read_bytes())
    out = tmp_path / "out"

    env = dict(__import__("os").environ, PYTHONPATH=str(REPO / "service"))
    proc = sp.run(
        [
            sys.executable, "-m", "app.worker", "run-job",
            "--kind", "inspect", "--input", str(src), "--output-dir", str(out),
        ],
        capture_output=True, text=True, env=env, cwd=str(REPO / "service"), check=False,
    )
    assert proc.returncode == 0, proc.stderr
    result = (out / "result.json").read_text()
    assert '"status": "done"' in result


def test_run_job_real_subprocess_timeout_is_recorded_as_failed(tmp_path, monkeypatch):
    """A genuine subprocess.TimeoutExpired (not a mocked subprocess.run) —
    the runner's own except-branch, exercised for real. Forces a fast, real
    timeout by swapping in a command that sleeps past a 1s worker budget."""
    from app import runner
    from app.db import make_engine, make_session_factory
    from app.migrate import upgrade_head
    from app.models import Document, Job, Matter

    monkeypatch.setenv("COUNSELCLEAR_WORKER_TIMEOUT_S", "1")
    cfg = Config(tmp_path)
    upgrade_head(f"sqlite:///{cfg.db_path}")
    s = make_session_factory(make_engine(cfg))()
    original = tmp_path / "orig.txt"
    original.write_bytes(b"hello")
    s.add(Matter(id="m1", name="m"))
    s.flush()
    s.add(Document(id="doc1", matter_id="m1", filename="orig.txt", sha256="0" * 64,
                   bytes=5, storage_path=str(original)))
    s.add(Job(id="j1", matter_id="m1", document_id="doc1", kind="inspect"))
    s.commit()

    monkeypatch.setattr(
        runner, "build_subprocess_cmd",
        lambda **kw: [sys.executable, "-c", "import time; time.sleep(30)"],
    )
    res = runner.run_job(cfg, s, "j1", kind="inspect")
    assert res.timed_out is True

    runner.sync_job(s, "j1", res)
    s.expire_all()
    job = s.get(Job, "j1")
    assert job.status == "failed"
    assert "timed out" in job.error


def test_sync_backstop_marks_failed_on_crash(tmp_path, monkeypatch):
    from app import runner
    from app.db import make_engine, make_session_factory
    from app.main import create_app
    from app.models import Document, Job, Matter

    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw17")
    root = tmp_path / "data"
    create_app(root)  # brings schema up
    s = make_session_factory(make_engine(Config(root)))()
    s.add(Matter(id="m", name="m"))
    s.flush()
    s.add(Document(id="d", matter_id="m", filename="f.txt", sha256="0" * 64,
                   bytes=0, storage_path=""))
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


def _docker_kwargs(mount_root: Path):
    return dict(
        mount_root=mount_root,
        input_path=mount_root / "input" / "x.docx",
        output_dir=mount_root / "output",
        kind="sanitize",
        policy_id="external_sharing",
        attest=False,
        matter_id="m1",
    )


def test_docker_cmd_is_hardened_and_digest_pinned(tmp_path):
    cfg = Config.__new__(Config)
    cfg.data_root = tmp_path / "srv" / "cc"
    cfg.worker_image = "ghcr.io/acme/counselclear@sha256:" + "ab" * 32
    cfg.worker_runtime = ""
    mount_root = cfg.data_root / "matters" / "m1" / "jobs" / "job123"
    cmd = build_docker_cmd(cfg, **_docker_kwargs(mount_root))
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


def test_docker_mount_is_scoped_to_one_job_not_the_whole_data_root(tmp_path):
    """The security property this whole refactor exists for: a compromised
    worker must not be able to reach the database or other matters' files."""
    cfg = Config.__new__(Config)
    cfg.data_root = tmp_path / "srv" / "cc"
    cfg.worker_image = "ghcr.io/acme/counselclear@sha256:" + "ab" * 32
    cfg.worker_runtime = ""
    mount_root = cfg.data_root / "matters" / "m1" / "jobs" / "job123"
    cmd = build_docker_cmd(cfg, **_docker_kwargs(mount_root))
    mount_flag = cmd[cmd.index("-v") + 1]
    host_mount = mount_flag.split(":")[0]
    assert host_mount == str(mount_root)
    assert host_mount != str(cfg.data_root)
    # The database lives at a sibling of matters/, never inside a job dir.
    assert "counselclear.sqlite3" not in mount_flag
    assert str(cfg.data_root / "matters" / "m2") not in mount_flag


def test_docker_mode_refuses_unpinned_image(tmp_path):
    cfg = Config.__new__(Config)
    cfg.data_root = tmp_path / "srv" / "cc"
    cfg.worker_image = "counselclear:latest"
    mount_root = cfg.data_root / "matters" / "m1" / "jobs" / "job123"
    with pytest.raises(ValueError, match="digest-pinned"):
        build_docker_cmd(cfg, **_docker_kwargs(mount_root))


def test_docker_cmd_selects_hardened_runtime_when_configured(tmp_path):
    """COUNSELCLEAR_WORKER_RUNTIME (e.g. gVisor's runsc) must translate to
    an explicit --runtime flag on the worker container."""
    cfg = Config.__new__(Config)
    cfg.data_root = tmp_path / "srv" / "cc"
    cfg.worker_image = "ghcr.io/acme/counselclear@sha256:" + "ab" * 32
    cfg.worker_runtime = "runsc"
    mount_root = cfg.data_root / "matters" / "m1" / "jobs" / "job123"
    cmd = build_docker_cmd(cfg, **_docker_kwargs(mount_root))
    assert cmd[cmd.index("--runtime") + 1] == "runsc"
    # ...and it stays a hardened container: network off either way.
    assert cmd[cmd.index("--network") + 1] == "none"


def test_config_rejects_unknown_worker_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("COUNSELCLEAR_WORKER_MODE", "fork-bomb")
    with pytest.raises(ValueError, match="COUNSELCLEAR_WORKER_MODE"):
        Config(tmp_path)


def test_build_subprocess_cmd_shape(tmp_path):
    cmd = build_subprocess_cmd(
        input_path=tmp_path / "in" / "x.docx", output_dir=tmp_path / "out",
        kind="inspect", policy_id="external_sharing", attest=False, matter_id="m1",
    )
    assert cmd[:4] == [sys.executable, "-m", "app.worker", "run-job"]
    assert "--input" in cmd and str(tmp_path / "in" / "x.docx") in cmd
    assert "--output-dir" in cmd and str(tmp_path / "out") in cmd
