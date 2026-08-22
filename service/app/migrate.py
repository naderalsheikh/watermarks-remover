"""Schema bring-up for the single-tenant profile.

Honest deviation from the design doc: alembic is deferred until the
production profile; this profile creates the current schema directly and
assumes a fresh data root. upgrade_head() exists so the call site reads
the same when alembic lands.
"""

from __future__ import annotations

from sqlalchemy import create_engine

from . import models  # noqa: F401  (registers tables on Base.metadata)
from .db import Base


def upgrade_head(db_url: str) -> None:
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
