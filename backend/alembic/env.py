from logging.config import fileConfig
from pathlib import Path
import os
import sys

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from dotenv import load_dotenv

from alembic import context


# Project paths
BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


# Load environment variables
load_dotenv()


# Import the application's database metadata and models.
from app.database import Base
from app import models  # noqa: F401


config = context.config


# Configure logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# Use the application's SQLAlchemy metadata for autogeneration.
target_metadata = Base.metadata


# Allow DATABASE_URL from .env, falling back to the current SQLite DB.
database_url = os.getenv(
    "DATABASE_URL",
    "sqlite:///./securesphere.db"
)

config.set_main_option(
    "sqlalchemy.url",
    database_url
)


def run_migrations_offline() -> None:
    """Run migrations without creating an Engine."""

    url = config.get_main_option(
        "sqlalchemy.url"
    )

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={
            "paramstyle": "named"
        },
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using a live database connection."""

    connectable = engine_from_config(
        config.get_section(
            config.config_ini_section,
            {}
        ),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()