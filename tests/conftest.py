"""Suite-wide fixture: no release test may ever reach a live timestamp
authority.

The RFC 3161 TSA client (service/app/tsa.py) is wired into the release
path; without this pin, every job_bundle test that runs without
explicitly setting COUNSELCLEAR_TSA_URL would POST a real query to the
default public TSA -- a flaky network dependency, and a security smell
in a test suite (docs/rfc3161-anchor-implementation-proposal.md §7
forbids live third-party calls in tests). The pin names a sentinel URL
whose transport raises connection refused deterministically. A real
closed loopback port can take seconds to refuse on Windows; repeating
that connection twice per bundle made unrelated tests needlessly slow.
The real client still builds its query, retries once, and falls through
to the operator anchor. Other URLs and test-supplied transport mocks
remain untouched, including the explicit network/TSA tests.
"""

import urllib.error
import urllib.request

import pytest

_TSA_SENTINEL = "http://127.0.0.1:9"


@pytest.fixture(autouse=True)
def _no_live_tsa(monkeypatch):
    monkeypatch.setenv("COUNSELCLEAR_TSA_URL", _TSA_SENTINEL)
    original_urlopen = urllib.request.urlopen

    def sentinel_urlopen(url, *args, **kwargs):
        if getattr(url, "full_url", url) == _TSA_SENTINEL:
            raise urllib.error.URLError(ConnectionRefusedError("test TSA is unavailable"))
        return original_urlopen(url, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", sentinel_urlopen)
