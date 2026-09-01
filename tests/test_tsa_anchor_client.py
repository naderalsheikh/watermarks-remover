"""service/app/tsa.py -- the RFC 3161 TSA anchor client (spec:
docs/rfc3161-anchor-implementation-proposal.md §2-§4).

These tests run the client against a local mock TSA (an in-thread HTTP
server) that can be told to time out, return garbage, return a TSA
refusal, or return a real captured DigiCert token -- proving the
client degrades to an unanchored result cleanly in every failure mode
(§4.5: "this must never block a release") before any happy path.

Test-only dependencies (the differential oracle) are imported inside
the oracle tests only; the client itself is stdlib urllib.
"""

from __future__ import annotations

import hashlib
import socket
import sys
import threading
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[1] / "service" / "app"
if str(APP_DIR.parent) not in sys.path:
    sys.path.insert(0, str(APP_DIR.parent))

from app import tsa

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_TOKEN_A = (FIXTURES / "rfc3161_token_a.der").read_bytes()
REAL_SIG_A = (FIXTURES / "rfc3161_sig_a.bin").read_bytes()
REAL_SIG_B = (FIXTURES / "rfc3161_sig_b.bin").read_bytes()


class MockTSA:
    """Minimal test-only HTTP handler speaking RFC 3161's HTTP binding:
    accept any body, respond with a configured status/content-type/body
    or a deliberate stall. Real token bytes come from the captured
    DigiCert fixtures, so the happy path exercises real parsing."""

    def __init__(self, behavior: dict):
        self.behavior = behavior
        self.requests: list[bytes] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/"
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(10)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    if b"\r\n\r\n" not in data:
                        continue
                    head, body = data.split(b"\r\n\r\n", 1)
                    headers = head.decode("latin-1").split("\r\n")
                    length = 0
                    for h in headers:
                        if h.lower().startswith("content-length:"):
                            length = int(h.split(":", 1)[1].strip())
                    while len(body) < length:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        body += chunk
                    self.requests.append(body)
                    b = self.behavior
                    if b.get("stall_s"):
                        import time

                        time.sleep(b["stall_s"])
                        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                        continue
                    status = b.get("status", 200)
                    ctype = b.get("content_type", "application/timestamp-reply")
                    payload = b.get("body", b"")
                    reason = {200: "OK", 400: "Bad Request", 500: "Server Error"}[status]
                    conn.sendall(
                        f"HTTP/1.0 {status} {reason}\r\nContent-Type: {ctype}\r\n"
                        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                        + payload
                    )
                except (OSError, TimeoutError):
                    continue

    def close(self):
        self.sock.close()


@pytest.fixture()
def mock_tsa():
    servers: list[MockTSA] = []

    def _make(behavior: dict) -> MockTSA:
        srv = MockTSA(behavior)
        servers.append(srv)
        return srv

    yield _make
    for s in servers:
        s.close()


# --- §4.5 degradation: every failure mode returns an UNANCHORED result ---

def test_timeout_degrades_to_unanchored(mock_tsa):
    """A TSA that stalls past the client timeout must produce the exact
    today-shaped unanchored result, never an exception into the release
    path (the single most important client property per §4.5)."""
    srv = mock_tsa({"stall_s": 5})
    result = tsa.request_anchor(signature_bytes=REAL_SIG_A, tsa_url=srv.url, timeout_s=0.2)
    assert result == {"type": "ed25519-operator", "digest": None, "reference": None}


def test_garbage_response_degrades_to_unanchored(mock_tsa):
    """A non-DER body must degrade, not raise: 'network error, TSA
    downtime, rate limit' are all the same case to the release path."""
    srv = mock_tsa({"status": 200, "body": b"not a timestamp reply at all"})
    result = tsa.request_anchor(signature_bytes=REAL_SIG_A, tsa_url=srv.url, timeout_s=2)
    assert result == {"type": "ed25519-operator", "digest": None, "reference": None}


def test_http_error_degrades_to_unanchored(mock_tsa):
    srv = mock_tsa({"status": 500, "body": b"boom"})
    result = tsa.request_anchor(signature_bytes=REAL_SIG_A, tsa_url=srv.url, timeout_s=2)
    assert result == {"type": "ed25519-operator", "digest": None, "reference": None}


def test_tsa_refusal_status_degrades_to_unanchored(mock_tsa):
    """status != granted (rejection, or a token-less response) is a
    failure to anchor, not an error to propagate."""
    # full TimeStampResp: SEQUENCE { status SEQUENCE { INTEGER 2 } }
    resp = bytes.fromhex("3005") + bytes.fromhex("3003020102") + bytes.fromhex("3000")
    srv = mock_tsa({"body": resp})
    result = tsa.request_anchor(signature_bytes=REAL_SIG_A, tsa_url=srv.url, timeout_s=2)
    assert result == {"type": "ed25519-operator", "digest": None, "reference": None}


def test_one_retry_then_fall_through(mock_tsa):
    """§4.5: exactly one retry on failure, then fall through -- the TSA
    sees two requests, the caller gets an unanchored result."""
    srv = mock_tsa({"status": 500, "body": b"boom"})
    tsa.request_anchor(signature_bytes=REAL_SIG_A, tsa_url=srv.url, timeout_s=2)
    assert len(srv.requests) == 2
    # and both carried the same query body (same nonce-less request)
    assert srv.requests[0] == srv.requests[1]


def test_unreachable_host_degrades_to_unanchored():
    """Connection refused (no server listening) -- the classic TSA-down
    case -- degrades in bounded time with zero retries hitting the wire."""
    result = tsa.request_anchor(
        signature_bytes=REAL_SIG_A, tsa_url="http://127.0.0.1:1/", timeout_s=1
    )
    assert result == {"type": "ed25519-operator", "digest": None, "reference": None}


# --- §4 happy path: a granted token becomes the anchor dict ---

def test_granted_token_produces_rfc3161_anchor(mock_tsa):
    """The end-to-end happy path against the REAL captured DigiCert
    token: the anchor dict carries the type, the recomputable digest,
    and the base64 token; the digest is sha256 of the submitted
    signature, exactly what the verifier will recompute independently."""
    import base64

    srv = mock_tsa({"body": (FIXTURES / "rfc3161_reply_full_a.der").read_bytes()})
    result = tsa.request_anchor(signature_bytes=REAL_SIG_A, tsa_url=srv.url, timeout_s=5)
    assert result["type"] == "rfc3161-tsa"
    assert result["digest"] == hashlib.sha256(REAL_SIG_A).hexdigest()
    token = base64.b64decode(result["reference"])
    assert token == REAL_TOKEN_A


def test_query_is_well_formed_der_with_certreq(mock_tsa):
    """The client's TimeStampReq must be parseable DER, v1, SHA-256
    messageImprint over the submitted signature, certReq=true -- the
    shape the real DigiCert TSA accepted when the fixture was captured."""
    from asn1crypto import tsp

    srv = mock_tsa({"body": b""})
    tsa.request_anchor(signature_bytes=REAL_SIG_A, tsa_url=srv.url, timeout_s=5)
    req = tsp.TimeStampReq.load(srv.requests[0])
    assert req["version"].native == "v1"
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    assert req["message_imprint"]["hashed_message"].native == hashlib.sha256(REAL_SIG_A).digest()
    assert req["cert_req"].native is True
