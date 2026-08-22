"""Schema bring-up: drives real Alembic migrations, not create_all().

create_all() can only add tables that don't exist yet — it silently cannot
apply an ALTER to a table that's already there, so a schema change shipped
as a new migration would never actually reach an existing data root. This
runs the real migration chain (service/app/alembic/) every time the app
starts, same as any other deployment profile; on a fresh data root that
just means running from revision None to head.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig

_ALEMBIC_DIR = Path(__file__).resolve().parent / "alembic"
_ALEMBIC_INI = _ALEMBIC_DIR.parent / "alembic.ini"


def upgrade_head(db_url: str) -> None:
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_DIR))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")
