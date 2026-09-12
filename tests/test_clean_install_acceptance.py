"""Clean-install acceptance: the actual shipped compose.yaml cc-api
container plus the static web export, driven through the documented
`docker compose up` installation procedure -- not a native checkout API
process with separately built assets (that path is already covered by
tests/test_deployment_http_smoke.py).

CI supplies COUNSELCLEAR_TEST_WEB_ROOT (a built web/out), a real Docker
daemon, `docker compose`, nginx, and passwordless sudo (needed only to
read/relocate the container's UID-10001-owned files on the host during
the backup/restore rehearsal below -- see the long comment there).

Topology and honesty boundary: compose.yaml's containerized cc-api has no
Docker socket by design (docs/COUNSELCLEAR_PRODUCTION.md section 3 -- giving it
one was deliberately rejected, since a single cc-api compromise would
then be host-root-equivalent). COUNSELCLEAR_WORKER_MODE therefore stays
at its real shipped default, `subprocess`, inside this container: the
same clamscan/exiftool/qpdf toolchain baked into the image, running as a
plain child process of cc-api -- a real worker, genuinely scanning and
sanitizing, just not Docker-per-job-isolated. Per-job Docker isolation is
a DIFFERENT documented topology (native cc-api host process + Docker
workers) and is what tests/test_deployment_http_smoke.py already proves.
This test proves the topology `docker compose up` actually gives an
operator out of the box; it does not re-prove Docker worker isolation,
and does not claim to.
"""

from __future__ import annotations

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
FIXTURES = REPO / "tests" / "fixtures" / "legal"
COMPOSE = REPO / "compose.yaml"
PASSWORD = "synthetic-clean-install-pw"  # noqa: S105 - test-only local password
PROJECT = "cc-clean-install-ci"
_DOCKER = shutil.which("docker") or "docker"

pytestmark = pytest.mark.skipif(
    not os.environ.get("COUNSELCLEAR_TEST_WEB_ROOT"),
    reason=(
        "requires a built static web export, a real Docker daemon, docker compose, "
        "nginx, and passwordless sudo; enabled in deployment CI"
    ),
)

# --- compose.yaml faithfulness -----------------------------------------------
#
# These are the exact substrings this test relies on being true of the real,
# shipped compose.yaml. If one of these fails, compose.yaml changed in a way
# that invalidates an assumption below -- fix the assumption, not the check.
_REQUIRED_COMPOSE_SUBSTRINGS = (
    "cc-data:/data",
    '"127.0.0.1:8443:8443"',
    "read_only: true",
    'user: "10001:10001"',
    "COUNSELCLEAR_WORKER_MODE: ${COUNSELCLEAR_WORKER_MODE:-subprocess}",
    "COUNSELCLEAR_CLAMAV_DB_DIR: /clamav-defs",
    "CC_VERSION: ${COUNSELCLEAR_VERSION:-dev}",
)


def _ports(n=3):
    sockets = [socket.socket() for _ in range(n)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def _certificate(root: Path):
    """Self-signed loopback TLS cert, same construction as
    tests/test_deployment_http_smoke.py's identically-named helper."""
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
def _nginx_process(command, *, cwd, env, log):
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


def _front_with_nginx(tmp_path: Path, nginx: str, api_port: int):
    """The exact same deploy/nginx-counselclear.conf.example templating
    tests/test_deployment_http_smoke.py uses, pointed at a container's
    published port instead of a native process's. Returns (tls_context,
    tls_port, config_path)."""
    tls_port, http_port = _ports(2)
    tls_context = _certificate(tmp_path)
    proxy_headers = tmp_path / "proxy-headers.conf"
    proxy_headers.write_text((REPO / "deploy/counselclear-proxy-headers.conf.example").read_text())
    web = Path(os.environ["COUNSELCLEAR_TEST_WEB_ROOT"]).resolve()
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
    return tls_context, tls_port, config


def _compose(*args, files, env, timeout=600):
    cmd = [_DOCKER, "compose"]
    for f in files:
        cmd += ["-f", str(f)]
    cmd += ["-p", PROJECT, *args]
    return subprocess.run(
        cmd, cwd=REPO, env=env, capture_output=True, text=True, check=False, timeout=timeout
    )


def _volume_override(path: Path, data_dir: Path, *, clamav_db_dir: str = "") -> None:
    """Two deliberate overrides of the real compose.yaml, both explained in
    the module docstring / callers:

    - cc-data's storage moves from an anonymous named volume to a host
      bind mount, so this test (and the backup/restore tools it drives)
      can read the data root from the host side. A named volume's actual
      on-disk location is a Docker-internal implementation detail this
      test should not depend on; redefining the *volume itself* to bind
      to a host path (rather than touching cc-api's own `volumes:` list,
      which would need list-merge semantics this test cannot rely on) is
      the standard, version-stable way to do this.
    - COUNSELCLEAR_CLAMAV_DB_DIR, hardcoded in the base file to
      /clamav-defs (a volume only tests/test_deployment_http_smoke.py's
      sibling cc-freshclam sidecar ever populates), is cleared so clamscan
      falls back to the image's own build-time freshclam seed instead of
      an empty directory. Bringing up cc-freshclam here would need live
      egress to database.clamav.net -- a flaky CI dependency this test
      avoids, at the cost of not exercising *live* definition updates
      (which is a real, separate operational requirement documented in
      COUNSELCLEAR_PRODUCTION.md and unrelated to whether clamscan itself
      runs for real, which it does, against real build-time definitions).
    """
    path.write_text(
        "services:\n"
        "  cc-api:\n"
        "    environment:\n"
        f"      COUNSELCLEAR_CLAMAV_DB_DIR: {clamav_db_dir!r}\n"
        "volumes:\n"
        "  cc-data:\n"
        "    driver: local\n"
        "    driver_opts:\n"
        "      type: none\n"
        "      o: bind\n"
        f"      device: {data_dir}\n"
    )


def _wait_ready(container_name: str, log_tail_cmd, *, port: int = 8443):
    """Poll the container's own plain-HTTP port directly (uvicorn inside
    speaks HTTP; nginx/TLS is a separate layer in front, checked later)."""
    deadline = time.monotonic() + 90
    last_error = None
    while time.monotonic() < deadline:
        inspect = subprocess.run(
            [_DOCKER, "inspect", "-f", "{{.State.Status}}", container_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if inspect.returncode == 0 and inspect.stdout.strip() not in ("running", "created"):
            pytest.fail(
                f"container {container_name} is {inspect.stdout.strip()!r}, not running: "
                + subprocess.run(
                    log_tail_cmd, capture_output=True, text=True, timeout=10, check=False
                ).stdout
            )
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=5) as c:
                if c.get("/health/ready").status_code == 200:
                    return
        except httpx.TransportError as exc:
            last_error = exc
        time.sleep(0.5)
    logs = subprocess.run(
        log_tail_cmd, capture_output=True, text=True, timeout=10, check=False
    ).stdout
    pytest.fail(f"container {container_name} did not become ready ({last_error}): {logs}")


def _release(client, matter, document, *, profile_id="counterparty_deal_room"):
    r = client.post(
        f"/v1/matters/{matter}/documents/{document}/releases",
        json={"profile_id": profile_id, "recipient_type": "client"},
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_clean_install_boots_shipped_container_and_static_ui(tmp_path):
    docker = shutil.which("docker")
    assert docker, "docker must be installed for the clean-install rehearsal"
    nginx = shutil.which("nginx")
    assert nginx, "nginx must be installed for the clean-install rehearsal"
    sudo = shutil.which("sudo")
    assert sudo, "passwordless sudo is required to inspect/relocate the container's data root"
    web = Path(os.environ["COUNSELCLEAR_TEST_WEB_ROOT"]).resolve()
    assert (web / "index.html").is_file()

    compose_text = COMPOSE.read_text()
    for expected in _REQUIRED_COMPOSE_SUBSTRINGS:
        assert expected in compose_text, f"compose.yaml no longer declares: {expected!r}"

    version = f"ci-clean-install-{int(time.time())}"
    base_env = {
        **os.environ,
        "COUNSELCLEAR_LOCAL_PASSWORD": PASSWORD,
        "COUNSELCLEAR_VERSION": version,
        "COUNSELCLEAR_TSA_URL": "off",
        "COUNSELCLEAR_ENABLE_DOCS": "1",
        "COUNSELCLEAR_WORKER_IMAGE": "",
        "COUNSELCLEAR_WORKER_MODE": "",  # stay on the real shipped default: subprocess
        "COUNSELCLEAR_DATABASE_URL": "",
    }
    container = f"{PROJECT}-cc-api-1"

    def _teardown(files):
        _compose("down", "--remove-orphans", files=files, env=base_env, timeout=120)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o777)
    override = tmp_path / "override.yml"
    _volume_override(override, data_dir)
    files = [COMPOSE, override]

    _teardown(files)  # in case a previous, aborted run left this project up
    try:
        built = _compose("build", "cc-api", files=files, env=base_env, timeout=900)
        assert built.returncode == 0, built.stdout + built.stderr

        up = _compose("up", "-d", "cc-api", files=files, env=base_env)
        assert up.returncode == 0, up.stdout + up.stderr

        log_cmd = [_DOCKER, "logs", "--tail", "200", container]
        _wait_ready(container, log_cmd)

        tls_context, tls_port, nginx_config = _front_with_nginx(tmp_path, nginx, 8443)
        nginx_log = tmp_path / "nginx.log"
        with (
            _nginx_process(
                [nginx, "-p", str(tmp_path), "-c", str(nginx_config), "-g", "daemon off;"],
                cwd=tmp_path,
                env=base_env,
                log=nginx_log,
            ),
            httpx.Client(
                base_url=f"https://localhost:{tls_port}",
                verify=tls_context,
                trust_env=False,
                timeout=15,
            ) as client,
        ):
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    if client.get("/health/ready").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.3)
            else:
                pytest.fail("nginx did not become ready in front of the container")

            # --- version/build identity -------------------------------------
            root = client.get("/v1")
            assert root.status_code == 200
            assert root.json()["version"] == version

            # --- browser routes ----------------------------------------------
            for route in ("/", "/login"):
                page = client.get(route)
                assert page.status_code == 200, page.text
                assert "text/html" in page.headers["content-type"]
            script = re.search(r'src="([^"]+/_next/[^"]+|/_next/[^"]+)"', page.text)
            assert script, "Static export must reference its actual JavaScript assets"
            assert client.get(script[1]).status_code == 200
            assert client.get("/v1/matters").status_code == 401
            for route in ("/docs", "/redoc", "/openapi.json"):
                # The shipped nginx config fails these closed at the edge
                # unconditionally (deploy/nginx-counselclear.conf.example),
                # regardless of the backend's own COUNSELCLEAR_ENABLE_DOCS
                # (set to 1 above) -- this proves the proxy layer, not the
                # app's own opt-in gate (that is covered by tests/test_app.py).
                assert client.get(route).status_code == 404

            # --- fresh configuration/startup: login, matter, upload ---------
            login = client.post("/v1/auth/login", json={"password": PASSWORD})
            login.raise_for_status()
            # This is the specific behavior the compose.yaml command override
            # above fixes: without --proxy-headers, uvicorn never learns the
            # browser connected over HTTPS, and COUNSELCLEAR_COOKIE_SECURE=auto
            # would silently issue a cookie missing Secure.
            cookie = login.headers["set-cookie"].lower()
            assert "; secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
            matter = client.post("/v1/matters", json={"name": "Clean install rehearsal"}).json()[
                "id"
            ]

            clean_bytes = (FIXTURES / "spa.docx").read_bytes()
            clean_upload = client.post(
                f"/v1/matters/{matter}/documents",
                files={"file": ("spa.docx", clean_bytes, "application/octet-stream")},
            )
            assert clean_upload.status_code == 200, clean_upload.text
            clean_doc = clean_upload.json()["id"]

            # --- successful release, real (subprocess, in-container) worker -
            released = _release(client, matter, clean_doc)
            assert released["job"]["status"] == "done", released
            job_id = released["job"]["id"]
            packet = client.get(f"/v1/matters/{matter}/jobs/{job_id}/bundle")
            assert packet.status_code == 200, packet.text
            with zipfile.ZipFile(io.BytesIO(packet.content)) as zf:
                original_manifest = json.loads(zf.read("manifest.json"))
                assert "certificate.html" in zf.namelist()
            cert_page = client.get(f"/v1/matters/{matter}/jobs/{job_id}/certificate")
            assert cert_page.status_code == 200 and "released" in cert_page.text.lower()

            public_key = client.get("/v1/custody-public-key")
            assert public_key.status_code == 200
            key_id = public_key.json()["key_id"]
            key_path = tmp_path / "deployment-public-key.pem"
            key_path.write_text(public_key.json()["public_key_pem"])
            packet_path = tmp_path / "packet.zip"
            packet_path.write_bytes(packet.content)
            verified = subprocess.run(
                [
                    sys.executable,
                    str(REPO / "tools/counselclear_verify_release_packet.py"),
                    "--key-fingerprint",
                    key_id,
                    str(packet_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            assert verified.returncode == 0, verified.stdout + verified.stderr

            # --- refused release: a genuine macro-enabled document ----------
            macro_bytes = (FIXTURES / "macro.docm").read_bytes()
            macro_upload = client.post(
                f"/v1/matters/{matter}/documents",
                files={"file": ("macro.docm", macro_bytes, "application/octet-stream")},
            )
            assert macro_upload.status_code == 200, macro_upload.text
            macro_doc = macro_upload.json()["id"]
            refused = _release(client, matter, macro_doc)
            assert refused["job"]["status"] == "refused", refused
            refused_job_id = refused["job"]["id"]
            refused_cert = client.get(f"/v1/matters/{matter}/jobs/{refused_job_id}/certificate")
            assert refused_cert.status_code == 200
            assert "refused" in refused_cert.text.lower()
            assert "macro" in refused_cert.text.lower()

            audit_before = client.get(f"/v1/matters/{matter}/audit")
            audit_before.raise_for_status()
            assert audit_before.json()["chain_ok"] is True

            # --- stop / restart: the same container, state persists --------
            stopped = _compose("stop", "cc-api", files=files, env=base_env)
            assert stopped.returncode == 0, stopped.stdout + stopped.stderr
            started = _compose("start", "cc-api", files=files, env=base_env)
            assert started.returncode == 0, started.stdout + started.stderr
            _wait_ready(container, log_cmd)

            relogin = client.post("/v1/auth/login", json={"password": PASSWORD})
            relogin.raise_for_status()
            assert client.get(f"/v1/matters/{matter}/documents/{clean_doc}").status_code == 200
            assert client.get(f"/v1/matters/{matter}/audit").json()["chain_ok"] is True
            client.post("/v1/auth/logout").raise_for_status()

        # --- backup, then restore into a replacement root -------------------
        #
        # cc-api runs as UID 10001 inside a read-only container; every file
        # it created under the host-bound /data (in particular
        # auth/custody_signing_key.pem, mode 0600) is owned by UID 10001 on
        # the host too -- a bind mount does not remap ownership. This test's
        # own process cannot read those files directly, so the backup and
        # restore tools below run under passwordless sudo (root can read
        # anything regardless of owner), and the restored root's ownership
        # is fixed back to 10001:10001 before a fresh container is asked to
        # use it -- exactly what an operator relocating a data root onto a
        # replacement container host would also need to do.
        stopped = _compose("stop", "cc-api", files=files, env=base_env)
        assert stopped.returncode == 0, stopped.stdout + stopped.stderr

        backup_dir = tmp_path / "backup"
        backup_run = subprocess.run(
            [
                sudo,
                "-n",
                sys.executable,
                str(REPO / "tools/counselclear_backup.py"),
                "--source",
                str(data_dir),
                "--destination",
                str(backup_dir),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        assert backup_run.returncode == 0, backup_run.stdout + backup_run.stderr
        backup_report = json.loads(backup_run.stdout)
        assert backup_report["outcome"] == "verified", backup_report

        restored_dir = tmp_path / "restored"
        restore_run = subprocess.run(
            [
                sudo,
                "-n",
                sys.executable,
                str(REPO / "tools/counselclear_restore_drill.py"),
                "--source",
                str(backup_dir),
                "--destination",
                str(restored_dir),
                # /data, not the host path: that is what cc-api's own
                # COUNSELCLEAR_DATA_ROOT recorded inside its database.
                "--old-data-root",
                "/data",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        assert restore_run.returncode == 0, restore_run.stdout + restore_run.stderr
        restore_report = json.loads(restore_run.stdout)
        assert restore_report["outcome"] == "verified", restore_report

        chown = subprocess.run(
            [sudo, "-n", "chown", "-R", "10001:10001", str(restored_dir)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert chown.returncode == 0, chown.stdout + chown.stderr

        _teardown(files)
        restored_override = tmp_path / "restored-override.yml"
        _volume_override(restored_override, restored_dir)
        restored_files = [COMPOSE, restored_override]
        restored_env = dict(base_env)

        built = _compose("build", "cc-api", files=restored_files, env=restored_env, timeout=300)
        assert built.returncode == 0, built.stdout + built.stderr
        up = _compose("up", "-d", "cc-api", files=restored_files, env=restored_env)
        assert up.returncode == 0, up.stdout + up.stderr
        _wait_ready(container, log_cmd)

        restored_tls_dir = tmp_path / "restored-tls"
        restored_tls_dir.mkdir(exist_ok=True)
        tls_context2, tls_port2, nginx_config2 = _front_with_nginx(restored_tls_dir, nginx, 8443)
        nginx_log2 = tmp_path / "restored-nginx.log"
        with (
            _nginx_process(
                [nginx, "-p", str(restored_tls_dir), "-c", str(nginx_config2), "-g", "daemon off;"],
                cwd=restored_tls_dir,
                env=base_env,
                log=nginx_log2,
            ),
            httpx.Client(
                base_url=f"https://localhost:{tls_port2}",
                verify=tls_context2,
                trust_env=False,
                timeout=15,
            ) as client,
        ):
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    if client.get("/health/ready").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.3)
            else:
                pytest.fail("nginx did not become ready in front of the restored container")

            relogin = client.post("/v1/auth/login", json={"password": PASSWORD})
            relogin.raise_for_status()

            restored_packet = client.get(f"/v1/matters/{matter}/jobs/{job_id}/bundle")
            assert restored_packet.status_code == 200, restored_packet.text
            with zipfile.ZipFile(io.BytesIO(restored_packet.content)) as zf:
                assert json.loads(zf.read("manifest.json")) == original_manifest
                assert "certificate.html" in zf.namelist()

            restored_refused_cert = client.get(
                f"/v1/matters/{matter}/jobs/{refused_job_id}/certificate"
            )
            assert restored_refused_cert.status_code == 200
            assert "refused" in restored_refused_cert.text.lower()

            restored_audit = client.get(f"/v1/matters/{matter}/audit")
            restored_audit.raise_for_status()
            assert restored_audit.json()["chain_ok"] is True

            assert client.get("/v1/matters").status_code == 401
            client.post("/v1/auth/logout").raise_for_status()

        _teardown(restored_files)
    finally:
        _teardown(files)
