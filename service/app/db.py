"""SQLite engine/session (single-tenant profile)."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import Config


class Base(DeclarativeBase):
    pass


def make_engine(cfg: Config):
    cfg.data_root.mkdir(parents=True, exist_ok=True)
    return create_engine(
        f"sqlite:///{Path(cfg.db_path)}", connect_args={"check_same_thread": False}
    )


def make_session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
