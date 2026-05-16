from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import text as sa_text
from sqlmodel import SQLModel, Session, create_engine

DB_PATH = os.getenv("DB_PATH", "/app/data/wss.db")

# Garantizar que el directorio exista (útil en desarrollo local)
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

_engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    echo=False,
)


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(_engine)
    # Migración ligera: añadir columnas nuevas que no existían en versiones anteriores
    _migrate_add_columns()
    _seed_platform_settings()


def _migrate_add_columns() -> None:
    """Añade columnas nuevas a tablas existentes si aún no existen (SQLite no hace ALTER automático)."""
    migrations = [
        ("scan_history", "list_id", "INTEGER REFERENCES domain_lists(id)"),
        ("users", "avatar", "TEXT"),
    ]
    with _engine.connect() as conn:
        for table, column, col_def in migrations:
            # Verificar si la columna ya existe
            existing = [row[1] for row in conn.execute(sa_text(f"PRAGMA table_info({table})"))]
            if column not in existing:
                conn.execute(sa_text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
                conn.commit()


_SETTING_DEFAULTS: list[tuple[str, str]] = [
    ("app_title",      "Web Security Suite"),
    ("logo_base64",    ""),
    ("color_pass",     "#3fb950"),
    ("color_fail",     "#f85149"),
    ("color_warn",     "#d29922"),
    ("color_skip",     "#bc8cff"),
    ("favicon_base64", ""),
]


def _seed_platform_settings() -> None:
    """Inserta los valores por defecto de configuración de plataforma si no existen."""
    from models import PlatformSetting  # import local para evitar ciclo circular
    with Session(_engine) as session:
        for key, default_value in _SETTING_DEFAULTS:
            if not session.get(PlatformSetting, key):
                session.add(PlatformSetting(key=key, value=default_value))
        session.commit()


def get_session():
    with Session(_engine) as session:
        yield session
