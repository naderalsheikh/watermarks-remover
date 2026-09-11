"""The trusted parent confines and verifies an untrusted worker's artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "service"))

from app import runner
from app.config import Config
from app.db import make_engine, make_session_factory
from app.migrate import upgrade_head
from app.models import Document, Job, Matter
from app.worker import _run_job


@pytest.fixture()
def completed_worker(tmp_path):
    cfg = Config(tmp_path)
    upgrade_head(cfg.db_url())
    engine = make_engine(cfg)
    with make_session_factory(engine)() as session:
        data = b"A document with a zero\xe2\x80\x8bwidth marker.\n"
        session.add(Matter(id="m", name="Matter"))
        session.flush()
        session.add(
            Document(
                id="d",
                matter_id="m",
                filename="input.txt",
                sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data),
                storage_path="",
            )
        )
        job = Job(
            id="j",
            matter_id="m",
            document_id="d",
            kind="sanitize",
            policy_id="external_sharing",
            status="running",
        )
        session.add(job)
        session.commit()
        source = tmp_path / "input.txt"
        source.write_bytes(data)
        output = runner.job_root(cfg, "m", "j") / "output"
        assert (
            _run_job(
                kind="sanitize",
                input_path=source,
                output_dir=output,
                policy_id=job.policy_id,
                attest=False,
                matter_id="m",
            )
            == 0
        )
        payload = json.loads((output / "result.json").read_text())
        assert payload["status"] == "done", payload
        yield session, job, output, payload
    engine.dispose()


def _save(output, payload):
    (output / "result.json").write_text(json.dumps(payload))


def _reconcile(completed, *, rc=0, timed_out=False):
    session, job, output, _ = completed
    runner.sync_job(session, job.id, runner.RunnerResult(rc, "", timed_out, output))
    session.refresh(job)
    return job


@pytest.mark.parametrize("spelling", ["relative", "container", "host"])
def test_worker_path_is_mapped_to_trusted_host_bundle(completed_worker, spelling):
    _, _, output, payload = completed_worker
    payload["bundle_dir"] = {
        "relative": "bundle",
        "container": "/data/output/bundle",
        "host": str(output / "bundle"),
    }[spelling]
    _save(output, payload)
    job = _reconcile(completed_worker)
    assert job.status == "done", job.error
    assert job.bundle_dir == str(output / "bundle")


@pytest.mark.parametrize(
    "path",
    ["../bundle", "/etc", "/data/output/../../etc", "bundle/../bundle", "bundle/", "", 123, {}],
)
def test_worker_cannot_choose_another_bundle(completed_worker, path):
    _, _, output, payload = completed_worker
    payload["bundle_dir"] = path
    _save(output, payload)
    job = _reconcile(completed_worker)
    assert job.status == "failed"
    assert not job.bundle_dir and job.result_json is None


@pytest.mark.parametrize(
    "artifact",
    [
        "output",
        "result.json",
        "bundle",
        "bundle/manifest.json",
        "bundle/report.html",
        "bundle/derivative",
        "derivative_file",
    ],
)
def test_symlink_artifacts_are_never_published(completed_worker, tmp_path, artifact):
    _, _, output, payload = completed_worker
    path = output if artifact == "output" else output / artifact
    if artifact == "derivative_file":
        path = output / "bundle" / "derivative" / payload["result"]["derivative"]
    escaped = tmp_path / "outside-worker"
    path.rename(escaped)
    path.symlink_to(escaped, target_is_directory=escaped.is_dir())
    job = _reconcile(completed_worker)
    assert job.status == "failed", artifact
    assert not job.bundle_dir and job.result_json is None


def test_hardlinked_derivative_is_rejected(completed_worker, tmp_path):
    _, _, output, payload = completed_worker
    derivative = output / "bundle" / "derivative" / payload["result"]["derivative"]
    os.link(derivative, tmp_path / "other-matter-file")
    assert _reconcile(completed_worker).status == "failed"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO nodes require POSIX")
def test_special_file_is_rejected_without_blocking(completed_worker):
    _, _, output, _ = completed_worker
    report = output / "bundle" / "report.html"
    report.unlink()
    os.mkfifo(report)
    assert _reconcile(completed_worker).status == "failed"


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_derivative",
        "missing_manifest",
        "derivative_bytes",
        "result_manifest",
        "original_hash",
        "failed_verification",
        "derivative_traversal",
        "plaintext_original",
    ],
)
def test_incomplete_or_conflicting_bundles_are_rejected(completed_worker, mutation):
    _, _, output, payload = completed_worker
    bundle = output / "bundle"
    derivative = bundle / "derivative" / payload["result"]["derivative"]
    if mutation == "extra_derivative":
        (derivative.parent / "unaccounted.txt").write_text("not in manifest")
    elif mutation == "missing_manifest":
        (bundle / "manifest.json").unlink()
    elif mutation == "derivative_bytes":
        derivative.chmod(0o600)
        derivative.write_bytes(b"substituted")
    elif mutation == "result_manifest":
        payload["result"]["manifest"]["actions"] = []
    elif mutation == "original_hash":
        payload["result"]["manifest"]["original"]["sha256"] = "0" * 64
        (bundle / "manifest.json").chmod(0o600)
        (bundle / "manifest.json").write_text(json.dumps(payload["result"]["manifest"]))
    elif mutation == "failed_verification":
        payload["result"]["verification_pass"] = False
    elif mutation == "derivative_traversal":
        payload["result"]["derivative"] = "../../other-matter-file"
    elif mutation == "plaintext_original":
        (bundle / "original").mkdir()
        (bundle / "original" / "input.txt").write_text("retained plaintext")
    _save(output, payload)
    job = _reconcile(completed_worker)
    assert job.status == "failed", mutation
    assert not job.bundle_dir
    if mutation == "plaintext_original":
        assert "upgrade API and pinned worker image together" in job.error


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        "done",
        {"status": "queued"},
        {"status": []},
        {"status": "done", "result": []},
        {"status": "failed", "error": {}},
    ],
)
def test_malformed_payload_fails_closed(completed_worker, payload):
    _, _, output, _ = completed_worker
    _save(output, payload)
    assert _reconcile(completed_worker).status == "failed"


def test_oversize_result_is_bounded(completed_worker, monkeypatch):
    monkeypatch.setattr(runner, "_MAX_RESULT_BYTES", 10)
    assert _reconcile(completed_worker).status == "failed"


@pytest.mark.parametrize("rc,timed_out", [(1, False), (-1, True)])
def test_crashed_or_timed_out_worker_cannot_publish_a_success(completed_worker, rc, timed_out):
    assert _reconcile(completed_worker, rc=rc, timed_out=timed_out).status == "failed"


def test_historical_terminal_record_is_untouched(completed_worker):
    session, job, output, _ = completed_worker
    job.status = "done"
    job.bundle_dir = "/historical/bundle"
    job.result_json = {"historical": True}
    session.commit()
    shutil.rmtree(output)
    _reconcile(completed_worker)
    assert job.status == "done" and job.bundle_dir == "/historical/bundle"
    assert job.result_json == {"historical": True}


def test_disabled_layer_b_cannot_publish_stale_worker_output(completed_worker):
    session, job, output, _ = completed_worker
    cfg = Config(output.parents[4])
    cfg.watermark_tools_enabled = False
    job.layer_b = {"strength": "preserve"}
    session.commit()
    result = runner.run_job(cfg, session, job.id)
    runner.sync_job(session, job.id, result)
    session.refresh(job)
    assert job.status == "failed"
    assert "watermark tools disabled" in job.error
    assert not job.bundle_dir


@pytest.mark.parametrize("tamper", ["same_length", "length", "staged_input"])
def test_altered_custody_input_never_reaches_worker(completed_worker, monkeypatch, tamper):
    session, job, output, _ = completed_worker
    shutil.rmtree(output)
    cfg = Config(output.parents[4])
    doc = session.get(Document, job.document_id)
    source = cfg.data_root / "input.txt"
    doc.storage_path = str(source)
    session.commit()
    if tamper == "same_length":
        source.write_bytes(b"x" * doc.bytes)
    elif tamper == "length":
        source.write_bytes(b"short")
    else:
        staged = output.parent / "input" / doc.filename
        staged.parent.mkdir(parents=True)
        staged.write_bytes(b"substituted staged input")

    def forbidden_launch(*args, **kwargs):
        pytest.fail("an altered original must never be passed to a parser")

    monkeypatch.setattr(runner.subprocess, "run", forbidden_launch)
    result = runner.run_job(cfg, session, job.id)
    runner.sync_job(session, job.id, result)
    session.refresh(job)
    assert job.status == "failed"
    assert "differs" in job.error
    assert not (output.parent / "input").exists()
