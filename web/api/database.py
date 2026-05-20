from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import text as sa_text
from sqlmodel import SQLModel, Session, create_engine, select

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
    sync_test_catalog()


def _migrate_add_columns() -> None:
    """Añade columnas nuevas a tablas existentes si aún no existen (SQLite no hace ALTER automático)."""
    with _engine.connect() as conn:
        catalog_info = list(conn.execute(sa_text("PRAGMA table_info(test_catalog)")))
        if catalog_info:
            columns = {row[1]: row for row in catalog_info}
            id_type = str(columns.get("id", ["", "", ""])[2]).upper()
            if "code" not in columns or "INT" not in id_type:
                conn.execute(sa_text("DROP TABLE test_catalog"))
                conn.commit()
                SQLModel.metadata.create_all(_engine)

    migrations = [
        ("scan_history",  "list_id",           "INTEGER REFERENCES domain_lists(id)"),
        ("users",         "avatar",             "TEXT"),
        ("test_catalog",  "is_active",          "INTEGER NOT NULL DEFAULT 1"),
        ("test_catalog",  "description_custom", "INTEGER NOT NULL DEFAULT 0"),
        ("test_catalog",  "display_order",      "INTEGER NOT NULL DEFAULT 0"),
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


def sync_test_catalog() -> None:
    """Sincroniza TEST_REGISTRY → tabla test_catalog (upsert).

    Reglas de sync:
    - Campos siempre actualizados desde código: name, block, block_name, severity, cwe,
      references, package, synced_at.
    - ``description`` solo se actualiza si ``description_custom == False``.
    - ``is_active`` nunca se toca (campo puramente administrativo).
    """
    import json
    from datetime import datetime, timezone

    from wss.core.scanner import _ensure_tests_loaded
    from wss.core.registry import TEST_REGISTRY
    from wss.descriptions import DESCRIPTIONS as _SEED

    _ensure_tests_loaded()

    from models import TestCatalog  # import local para evitar ciclo circular
    now = datetime.now(timezone.utc)

    with Session(_engine) as session:
        for meta in TEST_REGISTRY:
            row = session.exec(select(TestCatalog).where(TestCatalog.code == meta.code)).first()
            is_new = row is None
            if is_new:
                row = TestCatalog(code=meta.code)
                session.add(row)
            # Campos siempre actualizados desde código
            row.code = meta.code
            row.name = meta.name
            row.block = meta.block
            row.display_order = meta.order
            row.block_name = meta.block_name
            row.severity = meta.severity.value if hasattr(meta.severity, "value") else str(meta.severity)
            row.cwe = meta.cwe
            row.references = json.dumps(meta.references, ensure_ascii=False)
            row.package = meta.package
            row.synced_at = now
            # description: rellenar desde wss/descriptions.py solo cuando la DB
            # no tiene descripción propia (vacía y no editada manualmente).
            # Las descripciones con description_custom=True nunca se tocan.
            if not row.description_custom:
                seed = _SEED.get(meta.code, meta.description or "")
                if is_new or not row.description:
                    row.description = seed
            # is_active: nunca tocar en rows existentes
        session.commit()
