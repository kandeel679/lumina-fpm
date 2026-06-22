"""Alembic environment for LuminaFPM.

Loads the full model metadata (core Schema v4 + the still-wired LTI tables) and
the database URL from ``core.config`` so migrations and the app share one source
of configuration. Autogenerate works against ``Base.metadata`` for future revisions.
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the backend package importable when alembic runs from backend/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.models import Base  # noqa: E402  (registers all Schema v4 tables)

# Best-effort: include the still-wired LTI threat-intel tables in the metadata so
# the baseline migration creates them too. These are slated for demotion (ADR
# LFPM-IMPL-005); importing is guarded so a missing optional dependency never
# breaks migrations.
try:  # pragma: no cover
    from services.lumina_threat_intel import db_models as _lti_models  # noqa: F401,E402
except Exception:  # noqa: BLE001
    pass

try:
    from core.config import settings  # noqa: E402

    _DB_URL = settings.database_url
except Exception:  # pragma: no cover - fallback if config import fails
    _DB_URL = os.getenv("DATABASE_URL", "postgresql://lumina:lumina@db:5432/lumina_fpm")

config = context.config
config.set_main_option("sqlalchemy.url", _DB_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=_DB_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _DB_URL
    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
