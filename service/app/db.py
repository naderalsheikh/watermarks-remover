"""Engine/session for the configured backend (SQLite or Postgres)."""

from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import Config


class Base(DeclarativeBase):
    pass


def make_engine(cfg: Config):
    url = cfg.db_url()

    # Postgres (COUNSELCLEAR_DATABASE_URL): a real server handles
    # concurrency — MVCC snapshots plus row locks serialize the audit
    # chain's read-then-insert across processes, and none of SQLite's
    # file-level knobs below exist. pool_pre_ping drops connections the
    # server (or an intermediate firewall) has reaped instead of failing
    # a request on first use after idle.
    if not url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True)

    cfg.data_root.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args={"check_same_thread": False})

    # Every write transaction acquires SQLite's write lock immediately
    # instead of deferring it until the first write statement. Without this,
    # audit.append_event's read-then-insert (max(seq), then INSERT seq+1)
    # relied entirely on a Python threading.Lock to stay atomic — which only
    # serializes writers *inside one process*. Two uvicorn worker processes
    # (a normal production topology, not a hypothetical one) sharing this
    # SQLite file could both read the same max(seq) before either commits
    # and insert two rows claiming the same seq, forking the audit chain
    # the design doc calls "tamper-evident" — silently, since SQLite's
    # default deferred-lock mode lets both transactions proceed right up to
    # the point of conflict instead of one blocking for the other's turn.
    # BEGIN IMMEDIATE is the standard SQLAlchemy/pysqlite pattern for this
    # exact scenario (concurrent writers to one SQLite file): it makes the
    # second writer *block* until the first commits, rather than racing.
    # The unique (matter_id, seq) constraint (see the migration alongside
    # this change) is the backstop if that ever somehow isn't enough.
    @event.listens_for(engine, "connect")
    def _sqlite_manual_begin(dbapi_connection, _connection_record):
        # Disable pysqlite's own implicit BEGIN so our "begin" listener
        # below controls exactly when and how each transaction starts.
        dbapi_connection.isolation_level = None
        # WAL lets readers proceed while a writer holds the write lock —
        # without it every BEGIN IMMEDIATE below blocks reads too, so one
        # long job-status commit stalls every concurrent request.
        dbapi_connection.execute("PRAGMA journal_mode=WAL")
        # Block up to 5 s instead of failing instantly with "database is
        # locked" when another process is mid-commit. BEGIN IMMEDIATE makes
        # writers serialize; this keeps them serializing *patiently*.
        dbapi_connection.execute("PRAGMA busy_timeout=5000")
        # Enforce the declared ForeignKeys (matters -> documents -> jobs) —
        # SQLite leaves them off by default, silently accepting orphans.
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    @event.listens_for(engine, "begin")
    def _sqlite_begin_immediate(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def make_session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
