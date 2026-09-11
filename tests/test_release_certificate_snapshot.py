"""Release certificates remain the exact artifact their result hashes bind."""

from __future__ import annotations

import copy
import hashlib
import io
import sys
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SERVICE = Path(__file__).resolve().parents[1] / "service"
for path in (SERVICE, SERVICE / "scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app import main
from app.audit import append_event
from app.dispatcher import sync_release
from app.models import AuditEvent, Document, Job, Matter, MatterAcl, Release
from app.runner import RunnerResult
from app.security import issue_session
from sqlalchemy.orm import Session
from test_release_model import _create_release, _matter, _upload
from test_release_model import env as release_env


@pytest.fixture
def env(tmp_path, monkeypatch):
    yield from release_env.__wrapped__(tmp_path, monkeypatch)


@pytest.fixture
def clock(monkeypatch):
    class Clock(datetime):
        current = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)

        @classmethod
        def now(cls, tz=None):
            return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)

    monkeypatch.setattr(main, "datetime", Clock)
    return Clock


def _release(env, filename="macro.docm"):
    c, _, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, filename)
    response = _create_release(c, mid, doc)
    assert response.status_code == 200, response.text
    return mid, response.json()


def _certificate(c, mid, job_id):
    return c.get(f"/v1/matters/{mid}/jobs/{job_id}/certificate")


@pytest.mark.parametrize("outcome", ["done", "refused", "failed"])
def test_snapshot_hash_survives_clock_reader_and_display_changes(
    env, monkeypatch, clock, tmp_path, outcome
):
    if outcome == "failed":
        monkeypatch.setattr(
            "app.dispatcher.run_job",
            lambda *args, **kwargs: RunnerResult(
                rc=1,
                stderr_tail="simulated worker failure",
                timed_out=False,
                output_dir=tmp_path / "absent-output",
            ),
        )
    c, sf, cfg = env
    mid, response = _release(env, "macro.docm" if outcome == "refused" else "spa.docx")
    job_id = response["job"]["id"]
    release_id = response["release"]["id"]
    result = response["release_result"]
    assert result["status"] == outcome
    assert "certificate_snapshot" not in response["release"]
    original = _certificate(c, mid, job_id)
    assert original.status_code == 200, original.text
    assert hashlib.sha256(original.content).hexdigest() == result["certificate_html_sha256"]

    clock.current += timedelta(days=3)
    with sf() as s:
        s.get(Matter, mid).name = "Renamed matter"
        s.add(MatterAcl(matter_id=mid, user_id="oidc:reader", perm="read"))
        s.commit()
    monkeypatch.setattr(
        main, "POLICIES", [dict(p, description="New policy label") for p in main.POLICIES]
    )
    monkeypatch.setattr(
        main,
        "RELEASE_PROFILES",
        [dict(p, label="New profile label") for p in main.RELEASE_PROFILES],
    )
    c.cookies.set("cc_session", issue_session(cfg, "oidc:reader"))
    later = _certificate(c, mid, job_id)
    assert later.status_code == 200, later.text
    assert later.content == original.content
    assert "Snapshot generated: 2026-09-11T12:00:00+00:00" in original.text
    assert "Release requested by <code>operator</code>" in original.text
    assert "A later download does not update that assessment" in original.text
    later_result = c.get(f"/v1/matters/{mid}/releases/{release_id}/result")
    assert later_result.status_code == 200, later_result.text
    assert later_result.json()["certificate_html_sha256"] == result["certificate_html_sha256"]
    assert later_result.json()["limitations"] == result["limitations"]
    with sf() as s:
        issuance = (
            s.query(AuditEvent)
            .filter(AuditEvent.matter_id == mid, AuditEvent.action == "certificate.issued")
            .order_by(AuditEvent.seq)
            .all()
        )
        assert len(issuance) == 2
        assert issuance[-1].actor_id == "oidc:reader"
        snapshot = s.get(Release, release_id).certificate_snapshot
        assert snapshot["html"].encode("utf-8") == original.content
    if outcome == "done":
        bundle = c.get(f"/v1/matters/{mid}/jobs/{job_id}/bundle")
        assert bundle.status_code == 200, bundle.text
        with zipfile.ZipFile(io.BytesIO(bundle.content)) as zf:
            assert zf.read("certificate.html") == original.content
        # A download updates last_anchor and audit observations, not this snapshot.
        assert _certificate(c, mid, job_id).content == original.content


@pytest.mark.parametrize(
    "mutation", ["audit_hash", "audit_deleted", "audit_added", "source", "html", "shape"]
)
def test_snapshot_rejects_changed_evidence_or_corruption(env, mutation):
    c, sf, _ = env
    mid, response = _release(env)
    job_id = response["job"]["id"]
    release_id = response["release"]["id"]
    with sf() as s:
        release = s.get(Release, release_id)
        original = copy.deepcopy(release.certificate_snapshot)
        job_event = next(
            ev
            for ev in s.query(AuditEvent)
            .filter(AuditEvent.matter_id == mid, AuditEvent.action == "job.sanitize")
            .all()
            if ev.payload["job_id"] == job_id
        )
        if mutation == "audit_hash":
            job_event.payload = {**job_event.payload, "status": "done"}
        elif mutation == "audit_deleted":
            s.delete(job_event)
        elif mutation == "audit_added":
            append_event(
                s,
                matter_id=mid,
                actor_id="operator",
                action="job.sanitize",
                payload=dict(job_event.payload),
            )
        elif mutation == "source":
            s.get(Job, job_id).error = "different terminal reason"
        elif mutation == "html":
            release.certificate_snapshot = {**original, "html": original["html"] + "tampered"}
        else:
            release.certificate_snapshot = {"version": 1, "html": "incomplete"}
        s.commit()
        stored = copy.deepcopy(release.certificate_snapshot)
    certificate = _certificate(c, mid, job_id)
    assert certificate.status_code == 409, certificate.text
    result = c.get(f"/v1/matters/{mid}/releases/{release_id}/result")
    assert result.status_code == 409, result.text
    with sf() as s:
        assert s.get(Release, release_id).certificate_snapshot == stored
        assert (
            s.query(AuditEvent)
            .filter(AuditEvent.matter_id == mid, AuditEvent.action == "certificate.issued")
            .count()
            == 0
        )


def test_existing_release_snapshots_lazily_at_actual_generation_time(env, clock):
    c, sf, _ = env
    mid, response = _release(env)
    release_id = response["release"]["id"]
    job_id = response["job"]["id"]
    with sf() as s:
        s.get(Release, release_id).certificate_snapshot = None
        s.commit()
    clock.current += timedelta(days=30)
    result = c.get(f"/v1/matters/{mid}/releases/{release_id}/result")
    assert result.status_code == 200, result.text
    certificate = _certificate(c, mid, job_id)
    assert certificate.status_code == 200, certificate.text
    assert "Snapshot generated: 2026-10-11T12:00:00+00:00" in certificate.text
    assert (
        hashlib.sha256(certificate.content).hexdigest() == result.json()["certificate_html_sha256"]
    )
    with sf() as s:
        assert s.get(Release, release_id).certificate_snapshot is not None


def test_nonterminal_release_stays_live_then_failed_without_execution_discloses_missing_evidence(
    env, clock
):
    c, sf, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "spa.docx")
    with sf() as s:
        job = Job(
            matter_id=mid,
            document_id=doc,
            kind="sanitize",
            policy_id="external_sharing",
            status="queued",
        )
        s.add(job)
        s.flush()
        release = Release(
            matter_id=mid,
            document_id=doc,
            job_id=job.id,
            policy_id="external_sharing",
            requested_by="operator",
            status="queued",
        )
        s.add(release)
        s.commit()
        job_id, release_id = job.id, release.id
    queued = _certificate(c, mid, job_id)
    assert queued.status_code == 200, queued.text
    assert "Snapshot generated" not in queued.text
    with sf() as s:
        assert s.get(Release, release_id).certificate_snapshot is None
        job = s.get(Job, job_id)
        job.status = "failed"
        job.error = "cancelled before dispatch"
        job.finished_utc = datetime.now(UTC).isoformat(timespec="seconds")
        s.commit()
        sync_release(s, job)
    clock.current += timedelta(days=1)
    failed = _certificate(c, mid, job_id)
    assert failed.status_code == 200, failed.text
    assert "UNAVAILABLE: no job execution audit event" in failed.text
    assert "No job audit integrity assessment is available" in failed.text
    result = c.get(f"/v1/matters/{mid}/releases/{release_id}/result")
    assert result.status_code == 200, result.text
    assert any("audit evidence is unavailable" in item for item in result.json()["limitations"])
    assert hashlib.sha256(failed.content).hexdigest() == result.json()["certificate_html_sha256"]


def test_legacy_job_certificate_remains_live(env, clock):
    c, _, _ = env
    mid = _matter(c)
    doc = _upload(c, mid, "macro.docm")
    response = c.post(f"/v1/matters/{mid}/documents/{doc}/sanitize-jobs", json={})
    assert response.status_code == 200, response.text
    job_id = response.json()["id"]
    first = _certificate(c, mid, job_id)
    clock.current += timedelta(seconds=2)
    second = _certificate(c, mid, job_id)
    assert first.status_code == second.status_code == 200
    assert first.content != second.content
    assert "Snapshot generated" not in second.text


def test_concurrent_first_snapshot_writers_both_return_persisted_winner(env):
    _, sf, _ = env
    _, response = _release(env)
    release_id = response["release"]["id"]
    with sf() as s:
        release = s.get(Release, release_id)
        template = copy.deepcopy(release.certificate_snapshot)
        release.certificate_snapshot = None
        s.commit()
    ready = threading.Barrier(2)

    def contend(label):
        with sf() as s:
            release = s.get(Release, release_id)
            assert release.certificate_snapshot is None
            s.commit()  # retain the stale object while releasing SQLite's read/write lock
            candidate = {**template, "html": label}
            candidate.pop("snapshot_sha256")
            candidate["snapshot_sha256"] = main._certificate_snapshot_checksum(candidate)
            ready.wait(timeout=30)
            return main._store_release_certificate_snapshot(s, release, candidate)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(contend, label) for label in ("first", "second")]
        chosen = [future.result(timeout=30) for future in futures]
    assert chosen[0] == chosen[1]
    assert chosen[0]["html"] in ("first", "second")
    with sf() as s:
        assert s.get(Release, release_id).certificate_snapshot == chosen[0]


@pytest.mark.parametrize("changed_source", ["job", "document", "release"])
def test_first_snapshot_rechecks_source_changes_at_commit_boundary(
    env, monkeypatch, changed_source
):
    c, sf, _ = env
    mid, response = _release(env)
    release_id = response["release"]["id"]
    job_id = response["job"]["id"]
    with sf() as s:
        s.get(Release, release_id).certificate_snapshot = None
        s.commit()
    real_refresh = Session.refresh
    changed = False

    def change_after_snapshot_commit(s, instance, *args, **kwargs):
        nonlocal changed
        if not changed and kwargs.get("attribute_names") == ["certificate_snapshot"]:
            changed = True
            # _store has committed the candidate and released its transaction,
            # but its caller still holds pre-commit source objects in memory.
            with sf() as editor:
                if changed_source == "job":
                    editor.get(Job, job_id).error = "concurrently corrected reason"
                elif changed_source == "document":
                    editor.get(Document, response["job"]["document_id"]).sha256 = "f" * 64
                else:
                    editor.get(Release, release_id).purpose = "concurrently corrected purpose"
                editor.commit()
        return real_refresh(s, instance, *args, **kwargs)

    monkeypatch.setattr(Session, "refresh", change_after_snapshot_commit)
    result = c.get(f"/v1/matters/{mid}/releases/{release_id}/result")
    assert changed
    assert result.status_code == 409, result.text
    assert "facts changed" in result.json()["detail"]
    with sf() as s:
        assert s.get(Release, release_id).certificate_snapshot is not None
