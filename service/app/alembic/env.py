from __future__ import annotations

import logging
import sys
from pathlib import Path

_SERVICE = Path(__file__).resolve().parents[2]
if str(_SERVICE) not in sys.path:
    sys.path.insert(0, str(_SERVICE))

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.db import Base
from app import models  # noqa: F401  — register tables

# Deliberately NO fileConfig() here. This env.py runs inside the API process
# (migrate.upgrade_head on every boot), and fileConfig would rip out the
# host application's root-logging handlers and install alembic.ini's own —
# silently breaking pytest's caplog, uvicorn's handlers, and any structured
# logging the app configures. Alembic's "alembic.runtime" records propagate
# to the root logger like everyone else's; only their level is set here.
logging.getLogger("alembic").setLevel(logging.INFO)

config = context.config

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
