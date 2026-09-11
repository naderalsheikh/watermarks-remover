"""Real subprocess and optional real-image worker/custody integration.

CI builds and pushes the CounselClear image to a local registry, then sets
COUNSELCLEAR_TEST_WORKER_IMAGE to its repo@sha256 digest. No Docker command
or parser is mocked; leaving the variable unset skips only the image test.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "service"))

from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import create_app
from app.models import Document, Job
from app.storage import storage_from_config


def _encrypted_custody_flow(tmp_path, monkeypatch, mode, image=""):
    monkeypatch.setenv("COUNSELCLEAR_WORKER_MODE", mode)
    monkeypatch.setenv("COUNSELCLEAR_WORKER_IMAGE", image)
    monkeypatch.setenv("COUNSELCLEAR_WORKER_RUNTIME", "")
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "worker-integration-password")
    monkeypatch.setenv("COUNSELCLEAR_STORAGE", "local")
    monkeypatch.setenv("COUNSELCLEAR_VOLUME_KEY_FILE", str(tmp_path / "volume.key"))
    monkeypatch.delenv("COUNSELCLEAR_CMK_ARN", raising=False)
    root = tmp_path / "data"
    original = (REPO / "tests" / "fixtures" / "legal" / "spa.docx").read_bytes()
    with TestClient(create_app(root)) as client:
        login = client.post("/v1/auth/login", json={"password": "worker-integration-password"})
        assert login.status_code == 200
        matter = client.post("/v1/matters", json={"name": "Encrypted worker test"}).json()["id"]
        response = client.post(
            f"/v1/matters/{matter}/documents",
            files={"file": ("spa.docx", original, "application/octet-stream")},
        )
        assert response.status_code == 200, response.text
        doc_id = response.json()["id"]
        inspect = client.post(f"/v1/matters/{matter}/documents/{doc_id}/inspect-jobs").json()
        assert inspect["status"] == "done", inspect
        response = client.post(f"/v1/matters/{matter}/documents/{doc_id}/sanitize-jobs", json={})
        assert response.status_code == 200, response.text
        job = response.json()
        assert job["status"] == "done", job
        assert job["worker_image"] == image
        assert job["result"]["verification_pass"] is True
        url = f"/v1/matters/{matter}/jobs/{job['id']}/bundle"
        packet = client.get(url)
        assert packet.status_code == 200, packet.text
        with zipfile.ZipFile(io.BytesIO(packet.content)) as archive:
            assert not any(name.startswith("original/") for name in archive.namelist())
            manifest = json.loads(archive.read("manifest.json"))
            derivative = archive.read("derivative/" + manifest["derivative"]["filename"])
            assert hashlib.sha256(derivative).hexdigest() == manifest["derivative"]["sha256"]
            assert manifest["original"]["sha256"] == hashlib.sha256(original).hexdigest()
            for required in (
                "release_packet.json",
                "certificate.html",
                "README.txt",
                "report.json",
            ):
                assert required in archive.namelist()
        assert client.get(url + "?include_original=true").status_code == 403
        granted = client.put(
            f"/v1/matters/{matter}/acl", json={"user_id": "operator", "perm": "download_original"}
        )
        assert granted.status_code == 200
        packet = client.get(url + "?include_original=true")
        assert packet.status_code == 200, packet.text
        with zipfile.ZipFile(io.BytesIO(packet.content)) as archive:
            assert archive.read("original/spa.docx") == original

        cfg = Config(root)
        engine = make_engine(cfg)
        with make_session_factory(engine)() as session:
            stored_doc = session.get(Document, doc_id)
            stored_job = session.get(Job, job["id"])
            assert storage_from_config(cfg).read(stored_doc.storage_path) == original
            assert Path(stored_doc.storage_path).read_bytes() != original
            attempt_root = root / "matters" / matter / "jobs" / job["id"] / "attempts"
            expected_bundle = Path(stored_job.bundle_dir)
            relative = expected_bundle.relative_to(attempt_root)
            assert len(relative.parts) == 3
            assert relative.parts[0].startswith(f"{stored_job.attempt_number}-")
            assert relative.parts[1:] == ("output", "bundle")
            assert not (expected_bundle / "original").exists()
        engine.dispose()
        jobs_dir = root / "matters" / matter / "jobs"
        for job_id in (inspect["id"], job["id"]):
            assert not list((jobs_dir / job_id).rglob("input"))
        # A raw original must not remain in any worker output after dispatch.
        assert all(path.read_bytes() != original for path in jobs_dir.rglob("*") if path.is_file())


def test_real_subprocess_preserves_encrypted_original_custody(tmp_path, monkeypatch):
    _encrypted_custody_flow(tmp_path, monkeypatch, "subprocess")


@pytest.mark.skipif(
    not os.environ.get("COUNSELCLEAR_TEST_WORKER_IMAGE"),
    reason="requires a built CounselClear image at an immutable repository digest",
)
def test_real_docker_image_inspect_sanitize_and_encrypted_custody(tmp_path, monkeypatch):
    _encrypted_custody_flow(
        tmp_path, monkeypatch, "docker", os.environ["COUNSELCLEAR_TEST_WORKER_IMAGE"]
    )
