"""Tests for the cleaners security hardening (safe argv, resource caps, safe writes)."""

from __future__ import annotations

import io
import os
import re
import struct
import sys
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import common
import container_meta
from common import (
    backup_path,
    read_text_input,
    safe_arg,
    safe_write_bytes,
    safe_write_text,
)
from container_meta import (
    _SVG_METADATA_CLOSE_RE,
    _SVG_METADATA_OPEN_RE,
    MAX_ZIP_DECOMPRESSED_BYTES,
    ZipBudgetExceeded,
    _check_zip_budget,
    _drop_tag_blocks,
    _pdf_structured_blob,
    _read_zip_member,
    clean_html,
    clean_odt,
    clean_svg,
    inspect_docx,
)


def test_safe_arg_prefixes_leading_dash():
    assert safe_arg("-@evil") == "./-@evil"
    assert safe_arg("--argfile") == "./--argfile"


def test_safe_arg_leaves_normal_paths_alone():
    assert safe_arg("photo.png") == "photo.png"
    assert safe_arg("dir/file.svg") == "dir/file.svg"
    assert safe_arg("/abs/path.pdf") == "/abs/path.pdf"
    assert safe_arg(".") == "."


def test_zip_budget_rejects_oversized_member():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        info = zf.infolist()[0]
    info.file_size = MAX_ZIP_DECOMPRESSED_BYTES + 1
    raised = False
    try:
        _check_zip_budget(info, [0])
    except ZipBudgetExceeded:
        raised = True
    assert raised


def _patch_zip_declared_size(data: bytes, new_size: int) -> bytes:
    """Rewrite the uncompressed-size field of every central-directory entry.

    Produces the crafted-archive shape zip-bomb guards must defend
    against: the central directory (which backs ZipInfo.file_size) claims
    ``new_size`` decompressed bytes while the real deflate payload and its
    CRC stay intact. The local headers are left untouched.
    """
    out = bytearray(data)
    pos = 0
    while True:
        pos = out.find(b"PK\x01\x02", pos)
        if pos == -1:
            break
        out[pos + 24 : pos + 28] = struct.pack("<I", new_size)
        pos += 4
    return bytes(out)


def test_zip_budget_charges_real_bytes_not_declared(monkeypatch):
    # The budget must be charged on bytes actually produced, not on the
    # central directory claim (ZipInfo.file_size is attacker-controlled).
    # Here the archive declares 150 KiB for a member that really carries
    # 128 KiB; the accounting must follow reality.
    monkeypatch.setattr(container_meta, "MAX_ZIP_DECOMPRESSED_BYTES", 1 << 20)
    payload = b"y" * (1 << 17)  # 128 KiB
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("word/document.xml", payload)
    crafted = _patch_zip_declared_size(buf.getvalue(), (1 << 17) + (1 << 16))
    with zipfile.ZipFile(io.BytesIO(crafted)) as zf:
        info = zf.infolist()[0]
        assert info.file_size == (1 << 17) + (1 << 16)  # declared claim
        budget = [0]
        out = _read_zip_member(zf, info, budget)
    assert out == payload
    assert budget[0] == len(payload)  # real bytes, not the declared claim


def test_zip_budget_accumulates_real_bytes_across_members(monkeypatch):
    # The cap is cumulative across members: several members under the cap
    # individually can still exhaust it together.
    monkeypatch.setattr(container_meta, "MAX_ZIP_DECOMPRESSED_BYTES", 1 << 20)
    payload = b"a" * (1 << 19)  # 512 KiB
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.xml", payload)
        zf.writestr("b.xml", payload)
        zf.writestr("c.xml", payload)  # 3 x 512 KiB > 1 MiB cap
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        budget = [0]
        infos = zf.infolist()
        _read_zip_member(zf, infos[0], budget)
        _read_zip_member(zf, infos[1], budget)
        with pytest.raises(ZipBudgetExceeded):
            _read_zip_member(zf, infos[2], budget)


def test_inspect_docx_with_ai_markers_does_not_crash():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr(
            "docProps/app.xml",
            "<Properties><Application>Claude AI Writer</Application></Properties>",
        )
        zf.writestr(
            "docProps/core.xml",
            "<cp:coreProperties><dc:creator>Anthropic</dc:creator></cp:coreProperties>",
        )
    has_c2pa, has_ai, findings, _ = inspect_docx(buf.getvalue())
    assert has_ai
    assert findings
    assert not has_c2pa or has_ai


# ---------------------------------------------------------------------------
# Safe (atomic, symlink-safe) writes
# ---------------------------------------------------------------------------


def _make_symlink(dest: Path, target: Path) -> None:
    """Create a symlink, skipping where the platform denies the privilege."""
    try:
        dest.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")


def test_safe_write_refuses_symlink_destination(tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("PRECIOUS DATA")
    dest = tmp_path / "out.txt"
    _make_symlink(dest, victim)
    with pytest.raises(OSError):
        safe_write_text(dest, "cleaned content")
    # The victim must be untouched and no temp litter may remain.
    assert victim.read_text() == "PRECIOUS DATA"
    assert not list(tmp_path.glob("*.tmp"))


def test_safe_write_atomically_replaces_existing_file(tmp_path: Path):
    dest = tmp_path / "out.txt"
    safe_write_text(dest, "first")
    safe_write_text(dest, "second")
    assert dest.read_text() == "second"
    # No stray temp files after a successful write.
    assert not list(tmp_path.glob("*.tmp"))


def test_safe_write_bytes_creates_parent_dirs(tmp_path: Path):
    dest = tmp_path / "a" / "b" / "out.bin"
    safe_write_bytes(dest, b"\x00\x01")
    assert dest.read_bytes() == b"\x00\x01"


def test_safe_write_bytes_without_fchmod(tmp_path: Path, monkeypatch):
    # os.fchmod is POSIX-only; on Windows the write must still go through.
    monkeypatch.delattr(os, "fchmod", raising=False)
    dest = tmp_path / "out.bin"
    safe_write_bytes(dest, b"payload")
    assert dest.read_bytes() == b"payload"
    assert not list(tmp_path.glob("*.tmp"))


def test_backup_path_creates_bak_copy(tmp_path: Path):
    src = tmp_path / "doc.md"
    src.write_text("body")
    bak = backup_path(src)
    assert bak.name == "doc.md.bak"
    assert bak.read_text() == "body"
    assert src.read_text() == "body"


def test_backup_path_refuses_symlinked_bak(tmp_path: Path):
    src = tmp_path / "doc.md"
    src.write_text("body")
    bak = tmp_path / "doc.md.bak"
    victim = tmp_path / "victim.txt"
    victim.write_text("PRECIOUS")
    _make_symlink(bak, victim)
    with pytest.raises(SystemExit):
        backup_path(src)
    assert victim.read_text() == "PRECIOUS"


# ---------------------------------------------------------------------------
# Input size caps (stdin + file)
# ---------------------------------------------------------------------------


def test_read_text_input_refuses_oversized_file(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(common, "MAX_INPUT_BYTES", 8)
    big = tmp_path / "big.txt"
    big.write_text("x" * 64)
    with pytest.raises(SystemExit):
        read_text_input(str(big))


def test_read_stdin_capped(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(common, "MAX_STDIN_BYTES", 16)
    monkeypatch.setattr(sys, "stdin", io.StringIO("x" * 64))
    with pytest.raises(SystemExit):
        read_text_input(None)


def test_read_stdin_under_cap_ok(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(common, "MAX_STDIN_BYTES", 1024)
    monkeypatch.setattr(sys, "stdin", io.StringIO("hello stdin"))
    assert read_text_input(None) == "hello stdin"


# ---------------------------------------------------------------------------
# Quadratic-regex DoS (GHSA-7vpp-96qp-j9wh): lazy .*? block stripping
# ---------------------------------------------------------------------------
#
# clean_svg / clean_odt (and the other tag-block scans below) used lazy
# ".*?</close>" regexes. With many opening tags and no closing tag, CPython
# rescans to end-of-input from every candidate start - quadratic, and the
# GIL stalls the whole single-process service. The scans are now linear;
# these tests assert both the timing fix and the preserved behavior.


def _assert_completes_fast(fn, *args, budget_s: float = 5.0):
    start = time.perf_counter()
    result = fn(*args)
    elapsed = time.perf_counter() - start
    assert elapsed < budget_s, f"took {elapsed:.1f}s (linear scan expected < {budget_s}s)"
    return result


def test_clean_svg_metadata_flood_is_linear():
    # ~256 KiB of unclosed <metadata> tags. The old lazy regex measured
    # ~25 s at this size; the linear scan is milliseconds.
    flood = b"<metadata>" * (256 * 1024 // 11)
    assert b"</metadata>" not in flood
    cleaned, actions = _assert_completes_fast(clean_svg, flood)
    # No closing tag exists, so nothing is stripped - the block is preserved.
    assert cleaned == flood
    assert not any(a.startswith("drop <metadata>") for a in actions)


def test_clean_svg_mixed_closed_and_unclosed_metadata():
    svg = b"<svg><metadata>c2pa Anthropic</metadata><metadata>open</svg>"
    cleaned, actions = clean_svg(svg)
    # The closed block is stripped; the unclosed one is preserved verbatim.
    assert b"<metadata>c2pa" not in cleaned
    assert b"<metadata>open</svg>" in cleaned
    assert any(a.startswith("drop <metadata>") for a in actions)


def test_clean_odt_generator_flood_is_linear():
    # GHSA-7vpp-96qp-j9wh PoC shape: an ODT whose meta.xml is ~512 KiB of
    # unclosed <meta:generator> tags (about 1.4 KiB on the wire after DEFLATE).
    payload = b"<meta:generator>" * (512 * 1024 // 16)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", b"application/vnd.oasis.opendocument.text")
        zf.writestr("content.xml", b"<x/>")
        zf.writestr("meta.xml", payload)
    cleaned, _actions = _assert_completes_fast(clean_odt, buf.getvalue())
    # Unclosed blocks are preserved: the payload round-trips untouched.
    with zipfile.ZipFile(io.BytesIO(cleaned)) as zf:
        assert zf.read("meta.xml") == payload


def test_clean_svg_comment_end_forms():
    # HTML comment end tags are "-->" or "--!>" (CodeQL bad-html-filtering
    # regexp). Comments in either form must be stripped when they carry AI
    # provenance markers and kept otherwise.
    svg = b"<svg><!-- Anthropic --!><!-- plain --></svg>"
    cleaned, actions = clean_svg(svg)
    assert b"Anthropic" not in cleaned
    assert b"plain" in cleaned
    assert any("comment" in a for a in actions)


def test_clean_html_jsonld_flood_is_linear():
    flood = '<script type="application/ld+json">' * (128 * 1024 // 39)
    assert "</script>" not in flood
    cleaned, _actions = _assert_completes_fast(clean_html, flood)
    assert cleaned == flood


def test_pdf_stream_and_xpacket_floods_are_linear():
    stream_flood = b"stream\n" * (256 * 1024 // 8)
    assert b"endstream" not in stream_flood
    blob = _assert_completes_fast(_pdf_structured_blob, stream_flood)
    assert blob == stream_flood + b"\n"

    xpacket_flood = b"<?xpacket begin" * (256 * 1024 // 15)
    assert b"<?xpacket end" not in xpacket_flood
    blob = _assert_completes_fast(_pdf_structured_blob, xpacket_flood)
    assert blob == xpacket_flood + b"\n"


def test_tag_block_scan_matches_lazy_regex_semantics():
    # The linear scan must strip exactly what the old lazy regex stripped,
    # on well- and malformed inputs alike (closed, unclosed, mixed, nested,
    # case variants, and a closing tag smuggled inside an attribute value).
    lazy = re.compile(r"<metadata\b[^>]*>.*?</metadata\s*>", re.I | re.DOTALL)
    samples = [
        "",
        "<metadata>a</metadata>",
        "<metadata>a</metadata><metadata>b</metadata>",
        "<metadata>unclosed",
        "<metadata>a</metadata><metadata>unclosed",
        "x<metadata>a</metadata>y",
        "<metadata foo='x'>a</metadata >",
        "<METADATA>a</METADATA>",
        "<metadata><metadata>nested</metadata>",
        "<metadata>a</metadata><metadata>b</metadata><metadata>c",
        "<metadata foo='" + "</metadata>" + "'>tail</metadata>",
    ]
    for sample in samples:
        expected, n_expected = re.subn(lazy, "", sample)
        got, n_got = _drop_tag_blocks(sample, _SVG_METADATA_OPEN_RE, _SVG_METADATA_CLOSE_RE)
        assert got == expected, (sample, expected, got)
        assert n_got == n_expected, (sample, n_expected, n_got)


def test_scrub_text_runs_is_linear_on_unclosed_runs():
    # (w:t)-style body scrubs share the same lazy pattern class; a run of
    # unclosed <w:t> tags must not blow up either.
    from container_meta import _scrub_docx_text

    flood = "<w:t>" * (128 * 1024 // 5)
    assert "</w:t>" not in flood
    start = time.perf_counter()
    out, removed, replaced = _scrub_docx_text(flood)
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0, f"took {elapsed:.1f}s"
    assert out == flood
    assert removed == 0 and replaced == 0


def test_reconfigure_stream_writes_utf8():
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="cp1252")
    common._reconfigure_stream(stream, "backslashreplace")
    stream.write("\u200b")
    stream.flush()
    assert buf.getvalue() == "\u200b".encode("utf-8")


# ---------------------------------------------------------------------------
# PR 18 — product path: scan-before-parse, nested-archive cap, Caps budgets
# ---------------------------------------------------------------------------

import sys as _sys

_APP = ROOT / "service"
for _p in (str(SCRIPTS), str(_APP)):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

from app.malware import Verdict, archive_depth, set_scanner
from app.runner import job_budget_s
from app.security import LoginThrottle


def _nested_zip(depth: int) -> bytes:
    """zip containing zip ... depth levels of PK nesting."""
    blob = b"PK\x03\x04-leaf-payload"
    for _ in range(depth - 1):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("inner.zip", blob)
        blob = buf.getvalue()
    return blob


def test_archive_depth_measures_and_caps():
    assert archive_depth(b"plain text") == 0
    one = _nested_zip(1)
    assert archive_depth(one, max_depth=4) == 1
    three = _nested_zip(3)
    assert archive_depth(three, max_depth=8) == 3
    # depth beyond the cap short-circuits; result still reports the breach
    assert archive_depth(three, max_depth=2) == 3


class _FlaggingScanner:
    def __init__(self, detail="EICAR test signature"):
        self.detail = detail

    def scan(self, data: bytes, name: str) -> Verdict:
        return Verdict(False, "stub-eicar", self.detail)


@pytest.fixture()
def _flagging_scanner():
    set_scanner(_FlaggingScanner())
    yield
    from app import malware

    malware._scanner = malware.DepthAndClamScanner()


def test_upload_path_refuses_flagged_file(tmp_path, monkeypatch, _flagging_scanner):
    """Upload-side gate: flagged content never becomes a document."""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw")
    from app.main import create_app
    from fastapi.testclient import TestClient

    c = TestClient(create_app(tmp_path / "d"))
    c.post("/v1/auth/login", json={"password": "pw"})
    m = c.post("/v1/matters", json={"name": "m"}).json()
    r = c.post(
        f"/v1/matters/{m['id']}/documents",
        files={"file": ("x.txt", b"harmless bytes really", "application/octet-stream")},
    )
    assert r.status_code == 422
    assert "stub-eicar" in r.json()["detail"]
    from app import malware

    malware._scanner = malware.DepthAndClamScanner()


def test_worker_scans_before_parse_defense_in_depth(tmp_path):
    """Even if a flagged file reached the store, the worker refuses pre-parse.

    The worker is a pure function now (PR: scoped per-job mount, no DB
    access — see app/runner.py's module docstring) so this exercises it
    directly against a staged input/output pair, the same shape the runner
    stages for a real job."""
    import json

    from app.worker import _run_job

    original = tmp_path / "input" / "crafty.docx"
    original.parent.mkdir(parents=True)
    original.write_bytes(b"PK\x03\x04 crafted-bytes")
    output_dir = tmp_path / "output"

    set_scanner(_FlaggingScanner())
    try:
        rc = _run_job(
            kind="inspect", input_path=original, output_dir=output_dir,
            policy_id="external_sharing", attest=False,
        )
    finally:
        from app import malware

        malware._scanner = malware.DepthAndClamScanner()

    assert rc == 0  # refusal is an outcome, not a crash
    payload = json.loads((output_dir / "result.json").read_text())
    assert payload["status"] == "refused"
    assert "malware scan" in payload["error"] and "stub-eicar" in payload["error"]
    # original untouched by construction
    assert original.read_bytes().startswith(b"PK\x03\x04")


def test_runner_time_budgets_derive_from_caps():
    from engine_api import Caps

    inspect_budget = job_budget_s("inspect", Caps())
    sanitize_budget = job_budget_s("sanitize", Caps())
    assert inspect_budget == Caps().inspect_timeout_s * 2 + 30
    assert sanitize_budget > inspect_budget  # apply+verify add real headroom

    tight = Caps(inspect_timeout_s=10, apply_timeout_s=20, verify_timeout_s=30)
    assert job_budget_s("inspect", tight) == 50
    assert job_budget_s("sanitize", tight) == 120


def test_run_job_uses_caps_budget_as_timeout(monkeypatch, tmp_path):
    """The subprocess timeout passed down is min(env ceiling, caps budget)."""
    from app import runner
    from app.config import Config
    from app.db import make_engine, make_session_factory
    from app.migrate import upgrade_head
    from app.models import Document, Job, Matter

    captured = {}

    class _Proc:
        returncode = 0
        stderr = ""

    def fake_run(cmd, **kw):
        captured["timeout"] = kw.get("timeout")
        return _Proc()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
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

    runner.run_job(cfg, s, "j1", kind="inspect")
    expect = min(cfg.worker_timeout_s, job_budget_s("inspect"))
    assert captured["timeout"] == expect


def test_deeply_nested_archive_upload_is_refused(tmp_path, monkeypatch):
    """End-to-end: a depth-4 nest trips the scanner's cap (default depth 2)."""
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "pw")
    from app.main import create_app
    from fastapi.testclient import TestClient

    c = TestClient(create_app(tmp_path / "d"))
    c.post("/v1/auth/login", json={"password": "pw"})
    m = c.post("/v1/matters", json={"name": "m"}).json()
    r = c.post(
        f"/v1/matters/{m['id']}/documents",
        files={
            "file": (
                "nested.zip",
                _nested_zip(4),
                "application/zip",
            )
        },
    )
    assert r.status_code == 422
    assert "archive-depth" in r.json()["detail"]


# --- LoginThrottle: bounded memory under low-and-slow scans ------------------
# A distributed scan hitting /v1/auth/login from many distinct addresses, each
# failing once or twice (below max_failures) and never returning, must not
# leave one permanent dict entry per address. Cold keys are swept
# opportunistically; live state (failures inside window_s, active lockout)
# is never evicted.


def test_login_throttle_sweeps_cold_keys(monkeypatch):
    """A low-and-slow scan from many distinct addresses must not leave one
    permanent dict entry per address: keys with no failures inside window_s
    and no active lockout are swept out."""
    import app.security as security_mod

    now = [1_000_000.0]
    monkeypatch.setattr(security_mod.time, "time", lambda: now[0])

    t = LoginThrottle(max_failures=5, window_s=300, lockout_s=300)
    for i in range(1000):
        key = f"10.0.{i // 256}.{i % 256}"
        t.record_failure(key)
        if i % 2:
            t.record_failure(key)  # 1-2 failures, always below max_failures

    assert len(t._failures) == 1000

    now[0] += 301  # every failure is now outside window_s
    t.allow("fresh-peer")  # any touch triggers the opportunistic sweep

    assert t._failures == {}
    assert t._locked_until == {}


def test_login_throttle_sweep_keeps_live_state(monkeypatch):
    """The opportunistic sweep must not evict addresses still inside their
    failure window or lockout — only truly cold entries."""
    import app.security as security_mod

    now = [2_000_000.0]
    monkeypatch.setattr(security_mod.time, "time", lambda: now[0])

    t = LoginThrottle(max_failures=3, window_s=300, lockout_s=600)
    t.record_failure("active")  # 1 failure, inside window
    for _ in range(3):
        t.record_failure("locked")  # hits max_failures -> locked out
    assert not t.allow("locked")

    now[0] += 100  # everything still live
    t.record_failure("other")
    assert "active" in t._failures
    assert "locked" in t._failures
    assert t._locked_until["locked"] > now[0]
    assert t.retry_after_s("locked") >= 1

    now[0] += 250  # window expired for "active" & "other"; "locked" still locked
    t.allow("other2")  # this touch crosses the sweep gate
    assert "active" not in t._failures
    assert "other" in t._failures  # failure at now-250 is inside window_s
    assert "locked" in t._locked_until  # lockout is live state, never evicted
    assert not t.allow("locked")

    now[0] += 400  # lockout expired too
    t.record_failure("other3")
    assert "locked" not in t._failures
    assert "locked" not in t._locked_until
    assert t.allow("locked")


# --- Config.rotate_cookie_secret: no missing-file window ----------------------
# revoke_all_sessions used to unlink() the secret file then call
# ensure_cookie_secret() to recreate it, leaving a window with no secret file
# at all. Anything racing that window (a concurrent login issuing a session,
# or a second concurrent revoke) would see the file missing and create its
# own — whichever caller wrote last could silently invalidate a session
# another caller had just handed a client. rotate_cookie_secret() replaces
# that with a single atomic os.replace().


def test_rotate_cookie_secret_changes_value_and_invalidates_old_sessions(tmp_path):
    from app.config import Config
    from app.security import issue_session, session_subject

    cfg = Config(tmp_path)
    tok = issue_session(cfg)
    assert session_subject(cfg, tok) == "operator"

    old_secret = cfg.ensure_cookie_secret()
    new_secret = cfg.rotate_cookie_secret()
    assert new_secret != old_secret
    assert cfg.secret_file.exists()
    assert cfg.ensure_cookie_secret() == new_secret  # rotation is durable

    # The pre-rotation token no longer validates.
    assert session_subject(cfg, tok) is None


def test_rotate_cookie_secret_never_leaves_file_missing(tmp_path, monkeypatch):
    """os.replace() is the only mutation of the real path — assert no code
    path in rotate_cookie_secret unlinks it first."""
    from app.config import Config

    cfg = Config(tmp_path)
    cfg.ensure_cookie_secret()

    real_unlink = os.unlink
    seen_secret_file_unlinked = []

    def spying_unlink(path, *a, **kw):
        if str(path) == str(cfg.secret_file):
            seen_secret_file_unlinked.append(path)
        return real_unlink(path, *a, **kw)

    monkeypatch.setattr(os, "unlink", spying_unlink)
    cfg.rotate_cookie_secret()
    assert seen_secret_file_unlinked == []
    assert cfg.secret_file.exists()


def test_revoke_all_sessions_uses_atomic_rotation(tmp_path):
    from app.config import Config
    from app.security import issue_session, revoke_all_sessions, session_subject

    cfg = Config(tmp_path)
    tok = issue_session(cfg)
    revoke_all_sessions(cfg)
    assert session_subject(cfg, tok) is None
    assert cfg.secret_file.exists()
