"""Opt-in deployment rehearsal: static export + nginx TLS + real API/worker.

CI supplies COUNSELCLEAR_TEST_WEB_ROOT and COUNSELCLEAR_TEST_WORKER_IMAGE.
This exercises real sockets and the shipped proxy configuration, not TestClient.
It does not drive browser JavaScript or qualify an external identity provider.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import zipfile
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

REPO = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    not os.environ.get("COUNSELCLEAR_TEST_WEB_ROOT"),
    reason="requires a built static web export and nginx; enabled in deployment CI",
)


def _ports():
    sockets = [socket.socket() for _ in range(3)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def _certificate(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private = root / "key.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    return ssl.create_default_context(cafile=str(root / "cert.pem"))


@contextmanager
def _process(command, *, cwd, env, log):
    with log.open("wb") as output:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=output, stderr=output)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _wait_ready(client, processes, logs):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            pytest.fail("Deployment process exited: " + "\n".join(p.read_text() for p in logs))
        try:
            if client.get("/health/ready").status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    pytest.fail("Deployment did not become ready: " + "\n".join(p.read_text() for p in logs))


def _poll(client, path):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        response = client.get(path)
        response.raise_for_status()
        body = response.json()
        item = body
        if item["status"] not in ("queued", "running"):
            assert item["status"] == "done", body
            return body
        time.sleep(0.3)
    pytest.fail(f"Admitted job did not finish: {path}")


def test_https_static_export_and_real_worker_packet(tmp_path):
    nginx = shutil.which("nginx")
    assert nginx, "nginx must be installed when deployment rehearsal is enabled"
    image = os.environ.get("COUNSELCLEAR_TEST_WORKER_IMAGE", "")
    assert "@sha256:" in image, "deployment rehearsal requires the actual pinned Docker image"
    web = Path(os.environ["COUNSELCLEAR_TEST_WEB_ROOT"]).resolve()
    assert (web / "index.html").is_file()
    api_port, tls_port, http_port = _ports()
    tls_context = _certificate(tmp_path)
    proxy_headers = tmp_path / "proxy-headers.conf"
    proxy_headers.write_text((REPO / "deploy/counselclear-proxy-headers.conf.example").read_text())
    server = (REPO / "deploy/nginx-counselclear.conf.example").read_text()
    for old, new in {
        "listen 443 ssl http2;": f"listen 127.0.0.1:{tls_port} ssl http2;",
        "listen 80;": f"listen 127.0.0.1:{http_port};",
        "counselclear.example.com": "localhost",
        "/etc/letsencrypt/live/localhost/fullchain.pem": str(tmp_path / "cert.pem"),
        "/etc/letsencrypt/live/localhost/privkey.pem": str(tmp_path / "key.pem"),
        "/opt/counselclear/web/out": str(web),
        "http://127.0.0.1:8443": f"http://127.0.0.1:{api_port}",
        "/etc/nginx/counselclear-proxy-headers.conf": str(proxy_headers),
    }.items():
        assert old in server, f"Review deployment template change: {old}"
        server = server.replace(old, new)
    config = tmp_path / "nginx.conf"
    # Prefix-local state keeps this rehearsal unprivileged and self-contained.
    config.write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log stderr;\n"
        "events {}\nhttp {\ninclude /etc/nginx/mime.types;\naccess_log off;\n"
        f"client_body_temp_path {tmp_path}/body;\nproxy_temp_path {tmp_path}/proxy;\n"
        + server
        + "\n}\n"
    )
    checked = subprocess.run(
        [nginx, "-t", "-p", str(tmp_path), "-c", str(config)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert checked.returncode == 0, checked.stdout + checked.stderr
    env = {k: v for k, v in os.environ.items() if not k.startswith("COUNSELCLEAR_")}
    env.update(
        PYTHONPATH=os.pathsep.join([str(REPO / "service"), str(REPO / "service/scripts")]),
        COUNSELCLEAR_DATA_ROOT=str(tmp_path / "data"),
        COUNSELCLEAR_LOCAL_PASSWORD="synthetic-deployment-password",  # noqa: S106 - isolated fixture
        COUNSELCLEAR_STORAGE="local",
        COUNSELCLEAR_VOLUME_KEY_FILE=str(tmp_path / "volume.key"),
        COUNSELCLEAR_WORKER_MODE="docker",
        COUNSELCLEAR_WORKER_IMAGE=image,
        COUNSELCLEAR_TSA_URL="off",
        COUNSELCLEAR_COOKIE_SECURE="auto",
        # Deliberately enable backend docs to verify the proxy still blocks them.
        COUNSELCLEAR_ENABLE_DOCS="1",
    )
    api_log, nginx_log = tmp_path / "api.log", tmp_path / "nginx.log"
    with (
        _process(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.asgi:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(api_port),
                "--proxy-headers",
                "--forwarded-allow-ips",
                "127.0.0.1",
            ],
            cwd=REPO / "service",
            env=env,
            log=api_log,
        ) as api,
        _process(
            [nginx, "-p", str(tmp_path), "-c", str(config), "-g", "daemon off;"],
            cwd=tmp_path,
            env=env,
            log=nginx_log,
        ) as proxy,
        httpx.Client(
            base_url=f"https://localhost:{tls_port}",
            verify=tls_context,
            trust_env=False,
            timeout=15,
        ) as client,
    ):
        _wait_ready(client, [api, proxy], [api_log, nginx_log])
        for route in ("/", "/login", "/matters/view?id=synthetic"):
            page = client.get(route)
            assert page.status_code == 200, page.text
            assert "text/html" in page.headers["content-type"]
        script = re.search(r'src="([^\"]+/_next/[^\"]+|/_next/[^\"]+)"', page.text)
        assert script, "Static export must reference its actual JavaScript assets"
        assert client.get(script[1]).status_code == 200
        assert client.get("/v1/matters").status_code == 401
        for route in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(route).status_code == 404
        with httpx.Client(trust_env=False) as plain:
            redirect = plain.get(
                f"http://127.0.0.1:{http_port}/login", headers={"Host": "localhost"}
            )
            assert redirect.status_code == 301
            assert redirect.headers["location"] == "https://localhost/login"
        login = client.post("/v1/auth/login", json={"password": "synthetic-deployment-password"})
        login.raise_for_status()
        cookie = login.headers["set-cookie"].lower()
        assert "; secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        matter_response = client.post("/v1/matters", json={"name": "HTTPS synthetic rehearsal"})
        matter_response.raise_for_status()
        matter = matter_response.json()["id"]
        original = (REPO / "tests/fixtures/legal/spa.docx").read_bytes()
        upload = client.post(
            f"/v1/matters/{matter}/documents",
            files={"file": ("spa.docx", original, "application/octet-stream")},
        )
        upload.raise_for_status()
        document = upload.json()["id"]
        base = f"/v1/matters/{matter}/documents/{document}"
        admission = client.post(
            base + "/inspect-jobs",
            headers={"Prefer": "respond-async", "Idempotency-Key": "https-inspect"},
        )
        assert admission.status_code == 202, admission.text
        inspected = _poll(client, admission.headers["location"])
        assert inspected["worker_image"] == image
        request = {"profile_id": "counterparty_deal_room", "recipient_type": "client"}
        released = client.post(
            base + "/releases",
            json=request,
            headers={"Prefer": "respond-async", "Idempotency-Key": "https-release"},
        )
        assert released.status_code == 202, released.text
        result = _poll(client, released.headers["location"])
        job = result["job_id"]
        packet = client.get(f"/v1/matters/{matter}/jobs/{job}/bundle")
        packet.raise_for_status()
        packet_path = tmp_path / "packet.zip"
        packet_path.write_bytes(packet.content)
        private = serialization.load_pem_private_key(
            (tmp_path / "data/auth/custody_signing_key.pem").read_bytes(),
            password=None,
        )
        fingerprint = hashlib.sha256(private.public_key().public_bytes_raw()).hexdigest()
        verified = subprocess.run(
            [
                sys.executable,
                str(REPO / "tools/counselclear_verify_release_packet.py"),
                "--key-fingerprint",
                fingerprint,
                str(packet_path),
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert verified.returncode == 0, verified.stdout + verified.stderr
        audit = client.get(f"/v1/matters/{matter}/audit")
        audit.raise_for_status()
        assert audit.json()["chain_ok"] is True
        client.post("/v1/auth/logout").raise_for_status()
        assert client.get("/v1/matters").status_code == 401

    # The API and proxy are stopped once the context managers above exit --
    # exercise the documented cold-backup/restore lifecycle against this
    # same real, Docker-worker-produced root: the reference-environment
    # acceptance case for backup/restore, distinct from the in-process
    # TestClient rehearsals in tests/test_backup.py and
    # tests/test_restore_drill.py.
    data_root = tmp_path / "data"
    backup_dest = tmp_path / "backup"
    backup_run = subprocess.run(
        [
            sys.executable,
            str(REPO / "tools/counselclear_backup.py"),
            "--source",
            str(data_root),
            "--destination",
            str(backup_dest),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert backup_run.returncode == 0, backup_run.stdout + backup_run.stderr

    restored_root = tmp_path / "restored"
    restore_run = subprocess.run(
        [
            sys.executable,
            str(REPO / "tools/counselclear_restore_drill.py"),
            "--source",
            str(backup_dest),
            "--destination",
            str(restored_root),
            "--old-data-root",
            str(data_root),
            "--volume-key-file",
            str(tmp_path / "volume.key"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert restore_run.returncode == 0, restore_run.stdout + restore_run.stderr

    # Boot the restored root as a second, independent process (no proxy
    # needed this time -- plain HTTP loopback is enough to prove the
    # application itself serves the same evidence after recovery) and
    # confirm it serves the same packet the original release produced.
    restored_env = dict(env)
    restored_env["COUNSELCLEAR_DATA_ROOT"] = str(restored_root)
    restored_port = _ports()[0]
    restored_log = tmp_path / "restored-api.log"
    with (
        _process(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.asgi:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(restored_port),
            ],
            cwd=REPO / "service",
            env=restored_env,
            log=restored_log,
        ) as restored_api,
        httpx.Client(
            base_url=f"http://127.0.0.1:{restored_port}", trust_env=False, timeout=15
        ) as restored_client,
    ):
        _wait_ready(restored_client, [restored_api], [restored_log])
        relogin = restored_client.post(
            "/v1/auth/login", json={"password": "synthetic-deployment-password"}
        )
        relogin.raise_for_status()
        restored_packet = restored_client.get(f"/v1/matters/{matter}/jobs/{job}/bundle")
        restored_packet.raise_for_status()
        # The bundle is rebuilt into a fresh zip container on every
        # download (not served from a stored blob), so its raw bytes
        # legitimately differ between two downloads even with nothing
        # recovered in between -- comparing the whole zip byte-for-byte
        # is the wrong check. Compare the canonical evidence instead, the
        # same way tests/test_restore_drill.py's own restore test does:
        # manifest.json content and that the certificate is present.
        with zipfile.ZipFile(io.BytesIO(packet.content)) as zf:
            original_manifest = json.loads(zf.read("manifest.json"))
        with zipfile.ZipFile(io.BytesIO(restored_packet.content)) as zf:
            assert json.loads(zf.read("manifest.json")) == original_manifest
            assert "certificate.html" in zf.namelist()
