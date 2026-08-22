"""PR 12 — custody: write-once storage, SHA-256 manifest, custodial bundle."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from custody import (
    CustodyError,
    derivative_name,
    emit_manifest,
    sha256_bytes,
    write_manifest,
    write_once,
)
from engine_api import clean_to_bundle

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "legal"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_sha256_known_vector():
    assert sha256_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert (
        sha256_bytes(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_write_once_creates_and_locks(tmp_path):
    dest = tmp_path / "original" / "SPA.docx"
    path, created = write_once(dest, b"v1")
    assert created and path.read_bytes() == b"v1"
    assert not os.access(path, os.W_OK)  # 0444
    assert stat.S_IMODE(path.stat().st_mode) & 0o222 == 0


def test_write_once_idempotent_identical_content(tmp_path):
    dest = tmp_path / "a.bin"
    write_once(dest, b"same")
    path2, created = write_once(dest, b"same")
    assert created is False and path2 == dest
    assert dest.read_bytes() == b"same"


def test_write_once_refuses_conflicting_content(tmp_path):
    dest = tmp_path / "a.bin"
    write_once(dest, b"first")
    with pytest.raises(CustodyError, match="write-once violation"):
        write_once(dest, b"second")
    assert dest.read_bytes() == b"first"


def test_write_once_refuses_directory_collision(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    with pytest.raises(CustodyError):
        write_once(d, b"x")


def test_write_once_lost_race_does_not_delete_concurrent_winner(tmp_path, monkeypatch):
    """A concurrent writer wins O_EXCL between our exists() check and our
    os.open() call. The loser must never unlink a file it didn't create."""
    dest = tmp_path / "race.bin"
    winner_data = b"winner-content"
    real_open = os.open

    def racy_open(path, flags, mode=0o777, *, dir_fd=None):
        if str(path) == str(dest) and (flags & os.O_EXCL):
            dest.write_bytes(winner_data)  # concurrent writer creates it first
            raise FileExistsError(17, "File exists")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", racy_open)
    path, created = write_once(dest, winner_data)
    assert created is False
    assert path == dest
    assert dest.read_bytes() == winner_data  # the winner's file must survive


def test_write_once_lost_race_with_conflicting_content_keeps_winner(tmp_path, monkeypatch):
    dest = tmp_path / "race2.bin"
    winner_data = b"winner-content"
    real_open = os.open

    def racy_open(path, flags, mode=0o777, *, dir_fd=None):
        if str(path) == str(dest) and (flags & os.O_EXCL):
            dest.write_bytes(winner_data)
            raise FileExistsError(17, "File exists")
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", racy_open)
    with pytest.raises(CustodyError, match="write-once violation"):
        write_once(dest, b"different-content")
    # the loser must not have deleted the winner's file on its way out
    assert dest.exists()
    assert dest.read_bytes() == winner_data


def test_bundle_collision_check_runs_before_any_write(tmp_path):
    """out_dir/original/<name> resolving onto src itself must be caught
    BEFORE write_once runs — not after it has already locked src read-only."""
    original_dir = tmp_path / "original"
    original_dir.mkdir()
    src = original_dir / "self.txt"
    src.write_bytes(b"hi there\n")
    mode_before = stat.S_IMODE(src.stat().st_mode)

    with pytest.raises(CustodyError, match="collides with the original"):
        clean_to_bundle(src, tmp_path)

    assert stat.S_IMODE(src.stat().st_mode) == mode_before  # src untouched
    assert os.access(src, os.W_OK)  # never locked read-only


def test_derivative_naming():
    assert derivative_name("SPA_v3.docx") == "SPA_v3.external.docx"
    assert derivative_name("SPA_v3.docx", "privacy_only") == "SPA_v3.privacy.docx"
    assert derivative_name("memo.txt", "custom_overlay") == "memo.cleaned.txt"
    assert derivative_name("noext") == "noext.external"


def test_emit_manifest_shape():
    m = emit_manifest(
        original_name="SPA_v3.docx",
        original_sha256="a" * 64,
        original_bytes=100,
        derivative_name_="SPA_v3.external.docx",
        derivative_sha256="b" * 64,
        derivative_bytes=90,
        policy_id="external_sharing",
        actions=["layer A text: removed=1"],
        processor={"git_sha": "unknown", "tools": {"qpdf": True}},
        findings_before=["text-unicode: ZWSP"],
        verification={"exit_code": 0},
        operator_id="user_1",
        matter_id="m-42",
    )
    assert m["manifest_version"] == 1 and m["product"] == "counselclear"
    assert m["original"]["filename"] == "SPA_v3.docx"
    assert m["derivative"]["sha256"] == "b" * 64
    assert m["policy"] == {"id": "external_sharing", "version": 1}
    assert m["operator"]["id"] == "user_1" and m["matter"]["id"] == "m-42"
    assert "timestamps" in m and m["attestation_kind"] == "checkbox"

    minimal = emit_manifest(
        original_name="x.txt",
        original_sha256="0" * 64,
        original_bytes=1,
        derivative_name_="x.external.txt",
        derivative_sha256="1" * 64,
        derivative_bytes=1,
        policy_id="external_sharing",
        actions=[],
        processor={},
    )
    assert "operator" not in minimal and "matter" not in minimal


def test_write_manifest_is_write_once(tmp_path):
    m = {"manifest_version": 1}
    p1, c1 = write_manifest(tmp_path, m)
    same = dict(m)
    _, c2 = write_manifest(tmp_path, same)
    with pytest.raises(CustodyError):
        write_manifest(tmp_path, {"manifest_version": 2})
    assert c1 and not c2
    on_disk = json.loads(p1.read_text())
    assert on_disk == m


def test_bundle_text_fixture_end_to_end(tmp_path):
    src = FIXTURES / "spa.txt"
    out = tmp_path / "bundle"
    result = clean_to_bundle(src, out, operator_id="u1", matter_id="m1")

    original = Path(result["original"])
    deriv = Path(result["derivative"])
    manifest_path = Path(result["manifest"])

    # never in place; original preserved byte-for-byte
    assert original.resolve() != src.resolve() and deriv.resolve() != src.resolve()
    assert src.read_bytes() == _load("spa.txt")
    assert original.read_bytes() == _load("spa.txt")

    cleaned = deriv.read_bytes()
    assert "\u200b" not in cleaned.decode("utf-8")

    m = json.loads(manifest_path.read_text())
    assert m["original"]["sha256"] == hashlib.sha256(_load("spa.txt")).hexdigest()
    assert m["derivative"]["sha256"] == hashlib.sha256(cleaned).hexdigest()
    assert m["derivative"]["bytes"] == len(cleaned)
    assert m["policy"]["id"] == "external_sharing"
    assert any("removed" in a for a in m["actions"])
    verification = result["verification"]
    assert verification["pass"] is True
    assert any(c["name"] == "reinspect_targeted_gone" for c in verification["checks"])
    assert isinstance(m["findings_before"], list)

    # files locked read-only
    for f in (original, deriv, manifest_path):
        assert stat.S_IMODE(f.stat().st_mode) & 0o222 == 0


def test_bundle_docx_privacy_and_refuses_rerun_with_drift(tmp_path):
    src = FIXTURES / "spa.docx"
    out = tmp_path / "b1"
    r1 = clean_to_bundle(src, out, policy_id="privacy_only", matter_id="m1")
    deriv = Path(r1["derivative"])
    assert deriv.name == "spa.privacy.docx"
    import zipfile

    with zipfile.ZipFile(deriv) as zf:
        names = zf.namelist()
        core = zf.read("docProps/core.xml").decode("utf-8")
    assert "word/comments.xml" in names  # privacy keeps comments
    assert "<dc:creator>Jane Associate</dc:creator>" not in core
    verification = r1["verification"]
    assert verification["pass"] is True
    m = json.loads(Path(r1["manifest"]).read_text())
    assert m["verification"]["pass"] is True

    # identical rerun: idempotent everywhere
    r2 = clean_to_bundle(src, out, policy_id="privacy_only", matter_id="m1")
    assert Path(r2["derivative"]).read_bytes() == deriv.read_bytes()

    # tampered stored original must never be overwritten by a rerun
    conflict_dir = tmp_path / "conflict"
    clean_to_bundle(src, conflict_dir)
    stored = conflict_dir / "original" / "spa.docx"
    stored.chmod(0o644)
    stored.write_bytes(b"tampered")
    with pytest.raises(CustodyError, match="write-once violation"):
        clean_to_bundle(src, conflict_dir)


def test_bundle_refuses_signed_pdf_without_attestation(tmp_path):
    src = FIXTURES / "signed.pdf"
    out = tmp_path / "signed-bundle"
    with pytest.raises(CustodyError, match="plan refused"):
        clean_to_bundle(src, out)
    assert not (out / "manifest.json").exists()
    r = clean_to_bundle(src, out, signature_break_attestation=True)
    assert Path(r["derivative"]).is_file()


def test_bundle_refuses_in_place_collision(tmp_path):
    # storing a bundle whose ORIGINAL slot is the input file itself
    src = tmp_path / "self.txt"
    src.write_bytes(b"hi there\n")
    staged = tmp_path / "staged"
    staged_result = clean_to_bundle(src, staged)
    stored_original = Path(staged_result["original"])
    with pytest.raises(CustodyError, match="collides with the original"):
        clean_to_bundle(stored_original, staged)


def test_bundle_writes_readable_html_report(tmp_path):
    src = FIXTURES / "spa.docx"
    out = tmp_path / "report-bundle"
    result = clean_to_bundle(src, out, policy_id="external_sharing")

    report_path = Path(result["report_html"])
    assert report_path.is_file()
    assert report_path.parent == out
    html = report_path.read_text(encoding="utf-8")
    assert "spa.docx" in html
    assert "external_sharing" in html
    assert stat.S_IMODE(report_path.stat().st_mode) & 0o222 == 0  # write-once, read-only

    # idempotent rerun: report.html is not regenerated (and must not raise —
    # a fresh timestamp would collide with write_once's content check)
    result2 = clean_to_bundle(src, out, policy_id="external_sharing")
    assert result2["report_html"] == result["report_html"]


def test_bundle_pdf_fixture_actions_recorded(tmp_path):
    src = FIXTURES / "incremental.pdf"
    out = tmp_path / "pdf-bundle"
    result = clean_to_bundle(src, out)
    m = result["manifest_data"]
    actions = " ".join(m["actions"])
    assert "exiftool" in actions or "qpdf" in actions
    deriv = Path(result["derivative"]).read_bytes()
    assert b"(Attorney A)" not in deriv
