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

import os
import sys
import urllib.error
import urllib.request
import uuid

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


@pytest.fixture(
    params=["sqlite"] + (["postgres"] if os.getenv("COUNSELCLEAR_TEST_POSTGRES_URL") else [])
)
def queue_backend(request, monkeypatch):
    """Each PostgreSQL case owns a new database on an explicitly supplied test server."""
    if request.param == "sqlite":
        monkeypatch.delenv("COUNSELCLEAR_DATABASE_URL", raising=False)
        yield "sqlite"
        return
    import psycopg
    from psycopg import sql
    from sqlalchemy.engine import make_url

    admin = make_url(os.environ["COUNSELCLEAR_TEST_POSTGRES_URL"])
    database_name = "cc_queue_test_" + uuid.uuid4().hex
    connection = psycopg.connect(
        admin.set(drivername="postgresql").render_as_string(hide_password=False), autocommit=True
    )
    try:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
        monkeypatch.setenv(
            "COUNSELCLEAR_DATABASE_URL",
            admin.set(database=database_name).render_as_string(hide_password=False),
        )
        yield "postgres"
    finally:
        connection.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database_name))
        )
        connection.close()


@pytest.fixture(autouse=True)
def _stop_test_dispatchers(monkeypatch):
    # Many legacy TestClient fixtures do not enter lifespan. Jobs now start
    # background dispatch on demand; close those pools at each test boundary.
    module = sys.modules.get("app.dispatcher")
    started = set()
    if module is not None:
        original_start = module.BatchDispatcher.start

        def start(dispatcher):
            started.add(dispatcher)
            return original_start(dispatcher)

        monkeypatch.setattr(module.BatchDispatcher, "start", start)
    yield
    for dispatcher in started:
        dispatcher.stop()
        dispatcher._executor.shutdown(wait=True, cancel_futures=True)
