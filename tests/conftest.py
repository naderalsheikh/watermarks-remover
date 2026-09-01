"""Suite-wide fixture: no release test may ever reach a live timestamp
authority.

The RFC 3161 TSA client (service/app/tsa.py) is wired into the release
path; without this pin, every job_bundle test that runs without
explicitly setting COUNSELCLEAR_TSA_URL would POST a real query to the
default public TSA -- a flaky network dependency, and a security smell
in a test suite (docs/rfc3161-anchor-implementation-proposal.md §7
forbids live third-party calls in tests). The pin points at a closed
local port: refused instantly, so the client's one retry also fails
instantly and the release path falls through to the operator anchor
exactly as it would in a real outage. Tests that exercise the TSA path
set their own URL (or monkeypatch request_anchor) and override this.
"""

import pytest


@pytest.fixture(autouse=True)
def _no_live_tsa(monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_TSA_URL", "http://127.0.0.1:9")
