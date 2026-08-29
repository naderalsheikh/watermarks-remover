"""tools/counselclear_airlock.py — the local Airlock CLI (PR 34, Release-
native since PR 43): a thin HTTP client of the existing API, no second
engine/control-plane write path. Unit tests drive run_airlock() against a
FakeClient (no network); the live-server tests drive the real Client
class against a real uvicorn-served app (no live server the operator has
to manage by hand).
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


def _fake_limitations(status: str, error: str) -> list[str]:
    """Mirrors what the real server's _build_release_result actually
    computes (service/app/main.py) closely enough for a fake -- the CLI
    itself no longer derives this from a raw manifest, so the fakes are
    the one place it still needs modeling."""
    if status == "done":
        return [
            "comments_and_notes:keep: kept: no operator decision was supplied for this "
            "approve-default finding"
        ]
    return [f"job {status}: {error or 'no further detail recorded'}"]


def _fake_release_result(
    *,
    release_id: str,
    job_id: str,
    document_id: str,
    matter_id: str,
    status: str,
    policy_id: str,
    profile_id: str,
    recipient_type: str,
    recipient_name: str,
    purpose: str,
    intended_external: bool,
    reason: str,
) -> dict:
    """The shape of a real POST .../releases response's "release_result"
    key (service/app/main.py's _build_release_result) -- built from
    whatever the fake Client actually received, not hardcoded, so a test
    can verify a value (e.g. intended_external=False) really flows
    end to end from argv through to the written release_result.json."""
    return {
        "spec_version": "1.0",
        "release_id": release_id,
        "job_id": job_id,
        "document_id": document_id,
        "matter_id": matter_id,
        "status": status,
        "policy_id": policy_id,
        "profile_id": profile_id,
        "recipient_type": recipient_type,
        "recipient_name": recipient_name,
        "purpose": purpose,
        "intended_external": intended_external,
        "reason": reason,
        "original_sha256": "0" * 64,
        "created_at": "2026-08-27T00:00:00+00:00",
        "finished_at": "2026-08-27T00:00:05+00:00",
        "audit_refs": {"release_created_seq": 1, "release_terminal_seq": 2},
        "limitations": _fake_limitations(status, reason),
        "certificate_html_sha256": "c" * 64,
        "generated_at": "2026-08-27T00:00:05+00:00",
        "anchor": {"type": "none", "digest": None, "reference": None},
    }


# --- FakeClient: duck-types the Client surface run_airlock() actually calls -----


class FakeClient:
    def __init__(self, *, job_status: str, job_error: str = ""):
        self.job_status = job_status
        self.job_error = job_error
        self.calls: list[str] = []

    def upload_document(self, matter_id: str, path: Path) -> dict:
        self.calls.append("upload_document")
        return {"id": "doc1", "filename": path.name, "sha256": "0" * 64, "bytes": path.stat().st_size}

    def release(
        self,
        matter_id: str,
        doc_id: str,
        *,
        profile_id: str,
        recipient_type: str,
        recipient_name: str,
        purpose: str,
        intended_external: bool,
        reason: str,
    ) -> dict:
        self.calls.append("release")
        # A real POST .../releases is synchronous -- this fake models a
        # never-terminal response ("queued") only for the __timeout__
        # case, so wait_for_terminal's own poll-loop-timeout logic is
        # what's actually exercised, same as the old sanitize()-based
        # fake did.
        if self.job_status == "__timeout__":
            job = {"id": "job1", "status": "queued", "error": ""}
        else:
            job = {"id": "job1", "status": self.job_status, "error": self.job_error}
        release_result = _fake_release_result(
            release_id="rel1", job_id="job1", document_id=doc_id, matter_id=matter_id,
            status=job["status"], policy_id="external_sharing", profile_id=profile_id,
            recipient_type=recipient_type, recipient_name=recipient_name, purpose=purpose,
            intended_external=intended_external, reason=self.job_error or reason,
        )
        return {
            "release": {
                "id": "rel1", "profile_id": profile_id, "recipient_type": recipient_type,
                "intended_external": intended_external,
            },
            "job": job,
            "release_result": release_result,
        }

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

    def release(
        self,
        matter_id: str,
        doc_id: str,
        *,
        profile_id: str,
        recipient_type: str,
        recipient_name: str,
        purpose: str,
        intended_external: bool,
        reason: str,
    ) -> dict:
        self.calls.append("release")
        self._job_counter += 1
        job_id = f"job-{self._job_counter}"
        filename = self._doc_to_filename[doc_id]
        self._job_to_filename[job_id] = filename
        status = self.statuses_by_filename[filename]
        error = self.errors_by_filename.get(filename, "")
        if status == "__timeout__":
            job = {"id": job_id, "status": "queued", "error": ""}
        else:
            job = {"id": job_id, "status": status, "error": error}
        release_result = _fake_release_result(
            release_id=f"rel-{self._job_counter}", job_id=job_id, document_id=doc_id, matter_id=matter_id,
            status=job["status"], policy_id="external_sharing", profile_id=profile_id,
            recipient_type=recipient_type, recipient_name=recipient_name, purpose=purpose,
            intended_external=intended_external, reason=error or reason,
        )
        return {
            "release": {
                "id": f"rel-{self._job_counter}", "profile_id": profile_id,
                "recipient_type": recipient_type, "intended_external": intended_external,
            },
            "job": job,
            "release_result": release_result,
        }

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


# --- unit tests: success / refused / failed / timeout / bad profile -------------


def test_run_airlock_success_writes_derivative_manifest_certificate_and_summary(tmp_path):
    client = FakeClient(job_status="done")
    out = tmp_path / "out"
    result = airlock.run_airlock(
        client,
        matter_id="m1",
        file_path=_real_file(tmp_path),
        profile_id="counterparty_deal_room",
        recipient_type="opposing_counsel",
        recipient_name="Jane Doe",
        purpose="test",
        intended_external=True,
        reason="test",
        output_dir=out,
        timeout_s=5,
    )
    assert result.status == "done"
    assert result.release_id == "rel1"
    assert result.profile_id == "counterparty_deal_room"
    assert result.recipient_type == "opposing_counsel"
    assert (out / "doc.sanitized.docx").read_bytes() == b"fake derivative bytes"
    assert json.loads((out / "manifest.json").read_text())["derivative"]["sha256"] == "d" * 64
    assert (out / "report.json").exists()
    assert (out / "certificate.html").read_bytes().startswith(b"<!doctype html>")
    assert json.loads((out / "release_packet.json").read_text())["job_id"] == "job1"
    # release_result.json is written for a done release too -- the
    # lightweight, always-present companion, not just for refused/failed.
    release_result = json.loads((out / "release_result.json").read_text())
    assert release_result["release_id"] == "rel1"
    assert release_result["status"] == "done"
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert summary["status"] == "done"
    assert summary["job_id"] == "job1"
    assert summary["document_id"] == "doc1"
    assert summary["release_id"] == "rel1"
    assert summary["profile_id"] == "counterparty_deal_room"
    assert summary["recipient_type"] == "opposing_counsel"
    assert set(summary["files_written"]) == {
        "release_result.json", "doc.sanitized.docx", "manifest.json", "report.json",
        "certificate.html", "release_packet.json", "README.txt", "AIRLOCK_RESULT.json",
    }
    # The no-decision limitation (now sourced from release_result, not a
    # hand-parsed manifest) must surface, not get silently absorbed into
    # "success".
    assert len(result.limitations) == 1
    assert "no operator decision was supplied" in result.limitations[0]
    # One release call gets the job outcome + release_result together;
    # one release-packet call gets derivative + manifest + report +
    # certificate together -- not three separate requests for the same
    # content (get_certificate_html is refused/failed-only, see below).
    assert client.calls == [
        "upload_document", "release", "wait_for_terminal", "get_release_packet_zip",
    ]


def test_run_airlock_refused_job_writes_certificate_and_summary_without_derivative(tmp_path):
    client = FakeClient(job_status="refused", job_error="plan refused: macro-enabled file")
    out = tmp_path / "out"
    result = airlock.run_airlock(
        client,
        matter_id="m1",
        file_path=_real_file(tmp_path),
        profile_id="counterparty_deal_room",
        recipient_type="opposing_counsel",
        recipient_name="",
        purpose="",
        intended_external=True,
        reason="test",
        output_dir=out,
        timeout_s=5,
    )
    assert result.status == "refused"
    assert not (out / "manifest.json").exists()
    assert not any(out.glob("*.docx"))
    assert (out / "certificate.html").exists()  # certificate always attempted
    # release_result.json is the ONLY structured artifact for a refused
    # release -- no derivative, no zip -- but it must still exist.
    release_result = json.loads((out / "release_result.json").read_text())
    assert release_result["status"] == "refused"
    assert release_result["reason"] == "plan refused: macro-enabled file"
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
        profile_id="public_filing_anonymized",
        recipient_type="regulator",
        recipient_name="",
        purpose="",
        intended_external=True,
        reason="test",
        output_dir=out,
        timeout_s=5,
    )
    assert result.status == "failed"
    assert not (out / "manifest.json").exists()
    release_result = json.loads((out / "release_result.json").read_text())
    assert release_result["status"] == "failed"
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert "worker exited rc=1: boom" in summary["limitations"][0]
    assert (out / "certificate.html").exists()


def test_run_airlock_intended_external_flag_flows_through_to_release_result(tmp_path):
    client = FakeClient(job_status="done")
    out = tmp_path / "out"
    airlock.run_airlock(
        client,
        matter_id="m1",
        file_path=_real_file(tmp_path),
        profile_id="counterparty_deal_room",
        recipient_type="internal_reviewer",
        recipient_name="",
        purpose="",
        intended_external=False,
        reason="test",
        output_dir=out,
        timeout_s=5,
    )
    release_result = json.loads((out / "release_result.json").read_text())
    assert release_result["intended_external"] is False
    assert release_result["recipient_type"] == "internal_reviewer"


def test_run_airlock_timeout_raises_and_writes_nothing(tmp_path):
    client = FakeClient(job_status="__timeout__")
    out = tmp_path / "out"
    with pytest.raises(airlock.AirlockError, match="did not reach a terminal state"):
        airlock.run_airlock(
            client,
            matter_id="m1",
            file_path=_real_file(tmp_path),
            profile_id="counterparty_deal_room",
            recipient_type="opposing_counsel",
            recipient_name="",
            purpose="",
            intended_external=True,
            reason="test",
            output_dir=out,
            timeout_s=5,
        )
    # A timeout means no job outcome to report -- no partial/misleading
    # AIRLOCK_RESULT.json left behind.
    assert not (out / "AIRLOCK_RESULT.json").exists()


def test_run_airlock_rejects_unsupported_profile_before_any_network_call(tmp_path):
    client = FakeClient(job_status="done")
    with pytest.raises(airlock.AirlockError, match="not supported"):
        airlock.run_airlock(
            client,
            matter_id="m1",
            file_path=_real_file(tmp_path),
            profile_id="ediscovery_production",
            recipient_type="court",
            recipient_name="",
            purpose="",
            intended_external=True,
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
        client, matter_id="m1", files=files, profile_id="counterparty_deal_room",
        recipient_type="opposing_counsel", recipient_name="", purpose="", intended_external=True,
        reason="test", output_dir=out, timeout_s=5,
    )
    assert [item.status for item in batch.items] == ["done", "refused"]
    assert batch.items[0].output_dir == "001-good"
    assert batch.items[1].output_dir == "002-bad"
    assert batch.items[0].release_id == "rel-1"
    assert batch.items[1].release_id == "rel-2"
    assert (out / "001-good" / "doc.sanitized.docx").exists()
    assert (out / "001-good" / "release_result.json").exists()
    assert not (out / "002-bad" / "doc.sanitized.docx").exists()
    assert (out / "002-bad" / "certificate.html").exists()
    assert (out / "002-bad" / "release_result.json").exists()
    assert "plan refused" in batch.items[1].limitations[0]
    assert batch.counts == {"done": 1, "refused": 1, "failed": 0, "error": 0}

    summary = json.loads((out / "BATCH_RESULT.json").read_text())
    assert summary["total"] == 2
    assert summary["profile_id"] == "counterparty_deal_room"
    assert summary["recipient_type"] == "opposing_counsel"
    assert summary["counts"] == {"done": 1, "refused": 1, "failed": 0, "error": 0}
    assert summary["anchor_note"] == "release packets in this batch are not externally anchored"
    assert summary["items"][0]["input_file"] == "good.docx"
    assert summary["items"][0]["release_id"] == "rel-1"
    assert summary["items"][0]["error"] == ""
    assert summary["items"][1]["error"] == "plan refused: macro-enabled file"


def test_run_airlock_batch_failed_job_is_recorded_not_raised(tmp_path):
    files = [_named_file(tmp_path, "crash.docx")]
    client = FakeBatchClient(
        statuses_by_filename={"crash.docx": "failed"},
        errors_by_filename={"crash.docx": "worker exited rc=1: boom"},
    )
    batch = airlock.run_airlock_batch(
        client, matter_id="m1", files=files, profile_id="public_filing_anonymized",
        recipient_type="client", recipient_name="", purpose="", intended_external=True,
        reason="test", output_dir=tmp_path / "out", timeout_s=5,
    )
    assert batch.items[0].status == "failed"
    assert "worker exited rc=1: boom" in batch.items[0].limitations[0]


def test_run_airlock_batch_timeout_recorded_as_error_not_aborted(tmp_path):
    files = [_named_file(tmp_path, "slow.docx"), _named_file(tmp_path, "good.docx")]
    client = FakeBatchClient(statuses_by_filename={"slow.docx": "__timeout__", "good.docx": "done"})
    batch = airlock.run_airlock_batch(
        client, matter_id="m1", files=files, profile_id="counterparty_deal_room",
        recipient_type="opposing_counsel", recipient_name="", purpose="", intended_external=True,
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
        client, matter_id="m1", files=files, profile_id="counterparty_deal_room",
        recipient_type="opposing_counsel", recipient_name="", purpose="", intended_external=True,
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
        client, matter_id="m1", files=files, profile_id="counterparty_deal_room",
        recipient_type="opposing_counsel", recipient_name="", purpose="", intended_external=True,
        reason="test", output_dir=out, timeout_s=5,
    )
    assert [item.status for item in batch.items] == ["done", "refused", "failed", "error", "error"]
    assert batch.counts == {"done": 1, "refused": 1, "failed": 1, "error": 2}
    assert len(batch.items) == 5
    # every item still gets its own numbered output dir, even the two errors
    assert [item.output_dir for item in batch.items] == [
        "001-a_done", "002-b_refused", "003-c_failed", "004-d_timeout", "005-e_error",
    ]


def test_run_airlock_batch_rejects_unsupported_profile_before_any_file(tmp_path):
    files = [_named_file(tmp_path, "x.docx")]
    client = FakeBatchClient(statuses_by_filename={"x.docx": "done"})
    with pytest.raises(airlock.AirlockError, match="not supported"):
        airlock.run_airlock_batch(
            client, matter_id="m1", files=files, profile_id="ediscovery_production",
            recipient_type="court", recipient_name="", purpose="", intended_external=True,
            reason="test", output_dir=tmp_path / "out", timeout_s=5,
        )
    assert client.calls == []


def test_run_airlock_batch_rejects_empty_file_list(tmp_path):
    client = FakeBatchClient(statuses_by_filename={})
    with pytest.raises(airlock.AirlockError, match="no input files"):
        airlock.run_airlock_batch(
            client, matter_id="m1", files=[], profile_id="counterparty_deal_room",
            recipient_type="opposing_counsel", recipient_name="", purpose="", intended_external=True,
            reason="test", output_dir=tmp_path / "out", timeout_s=5,
        )


# --- CLI (main()) argument handling ----------------------------------------------


def test_main_rejects_file_and_folder_together(tmp_path, capsys):
    with pytest.raises(SystemExit):
        airlock.main([
            "--matter-id", "m1", "--file", str(tmp_path), "--folder", str(tmp_path),
            "--recipient-type", "opposing_counsel",
            "--output-dir", str(tmp_path / "out"), "--password", "x",
        ])


def test_main_requires_recipient_type(tmp_path, capsys):
    with pytest.raises(SystemExit):
        airlock.main([
            "--matter-id", "m1", "--file", str(_named_file(tmp_path, "x.docx")),
            "--output-dir", str(tmp_path / "out"), "--password", "x",
        ])
    assert "recipient-type" in capsys.readouterr().err


def test_main_rejects_unknown_recipient_type(tmp_path, capsys):
    with pytest.raises(SystemExit):
        airlock.main([
            "--matter-id", "m1", "--file", str(_named_file(tmp_path, "x.docx")),
            "--recipient-type", "not_a_real_type",
            "--output-dir", str(tmp_path / "out"), "--password", "x",
        ])


def test_main_no_longer_accepts_policy(tmp_path, capsys):
    """Clean cutover, not a deprecated alias (approved scope): --policy is
    simply not a recognized argument anymore."""
    with pytest.raises(SystemExit):
        airlock.main([
            "--matter-id", "m1", "--file", str(_named_file(tmp_path, "x.docx")),
            "--recipient-type", "opposing_counsel", "--policy", "external_sharing",
            "--output-dir", str(tmp_path / "out"), "--password", "x",
        ])
    assert "unrecognized arguments" in capsys.readouterr().err


def test_main_folder_mode_errors_cleanly_when_folder_missing(tmp_path, capsys):
    rc = airlock.main([
        "--matter-id", "m1", "--folder", str(tmp_path / "nope"),
        "--recipient-type", "opposing_counsel",
        "--output-dir", str(tmp_path / "out"), "--password", "x",
    ])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_main_folder_mode_errors_cleanly_when_folder_empty(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = airlock.main([
        "--matter-id", "m1", "--folder", str(empty),
        "--recipient-type", "opposing_counsel",
        "--output-dir", str(tmp_path / "out"), "--password", "x",
    ])
    assert rc == 1
    assert "no regular files" in capsys.readouterr().err


def test_main_files_mode_errors_cleanly_when_a_file_is_missing(tmp_path, capsys):
    present = _named_file(tmp_path, "present.docx")
    rc = airlock.main([
        "--matter-id", "m1", "--files", str(present), str(tmp_path / "absent.docx"),
        "--recipient-type", "opposing_counsel",
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
        profile_id="counterparty_deal_room",
        recipient_type="opposing_counsel",
        recipient_name="Jane Doe, Esq.",
        purpose="integration test",
        intended_external=True,
        reason="integration test",
        output_dir=out,
        timeout_s=30,
    )

    assert result.status == "done"
    assert result.release_id
    assert (out / "manifest.json").exists()
    assert (out / "report.json").exists()
    assert (out / "certificate.html").read_bytes().startswith(b"<!doctype html>")
    assert (out / "release_packet.json").exists()
    assert (out / "release_result.json").exists()
    assert any(out.glob("*.docx"))
    summary = json.loads((out / "AIRLOCK_RESULT.json").read_text())
    assert summary["matter_id"] == matter["id"]
    assert summary["status"] == "done"
    assert summary["release_id"] == result.release_id

    release_result = json.loads((out / "release_result.json").read_text())
    assert release_result["release_id"] == result.release_id
    assert release_result["status"] == "done"

    # PR 37/43: the CLI's own extracted output directory, written verbatim
    # from a real server's real release packet, passes the real verifier
    # -- not a synthetic fixture.
    import counselclear_verify_release_packet as verifier

    report = verifier.verify_release_packet(out)
    assert report.valid, report.to_text()
    # PR 57 (MUST-2): packets are signed now -- the anchor is the
    # operator's Ed25519 signature, and the CLI's key-less verification
    # run reports it as a no_key signature downgrade, not "none".
    assert report.anchor_type == "ed25519-operator"
    assert report.signature_status == "no_key"


def test_airlock_cli_batch_end_to_end_against_a_real_server_mixed_folder(tmp_path, live_server):
    """PR 38/43: a real folder with one file that sanitizes cleanly and
    one that gets refused (macro-enabled), driven through the actual
    batch CLI entry point (main(), not run_airlock_batch() directly)
    against a real server. Verifies both outcomes' artifacts with the
    real offline verifier -- the done item's full packet, and the
    refused item's standalone release_result.json."""
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
        "--profile", "counterparty_deal_room",
        "--recipient-type", "opposing_counsel",
        "--reason", "batch integration test",
        "--output-dir", str(out),
        "--timeout-s", "30",
    ])

    # Mixed outcome (one done, one refused) -> exit code 2, same convention
    # as a single refused/failed job in single-file mode.
    assert rc == 2

    summary = json.loads((out / "BATCH_RESULT.json").read_text())
    assert summary["total"] == 2
    assert summary["profile_id"] == "counterparty_deal_room"
    assert summary["recipient_type"] == "opposing_counsel"
    assert summary["counts"]["done"] == 1
    assert summary["counts"]["error"] == 0
    statuses = {item["input_file"]: item["status"] for item in summary["items"]}
    assert statuses["a_clean.docx"] == "done"
    assert statuses["b_macro.docm"] == "refused"

    done_item = next(item for item in summary["items"] if item["status"] == "done")
    done_dir = out / done_item["output_dir"]
    assert (done_dir / "release_packet.json").exists()
    assert (done_dir / "release_result.json").exists()
    assert any(done_dir.glob("*.docx"))

    refused_item = next(item for item in summary["items"] if item["status"] == "refused")
    refused_dir = out / refused_item["output_dir"]
    assert (refused_dir / "certificate.html").exists()
    assert (refused_dir / "release_result.json").exists()
    assert not any(refused_dir.glob("*.docm"))

    import counselclear_verify_release_packet as verifier

    packet_report = verifier.verify_release_packet(done_dir)
    assert packet_report.valid, packet_report.to_text()

    result_report = verifier.verify_release_result(refused_dir / "release_result.json")
    assert result_report.valid, result_report.to_text()
