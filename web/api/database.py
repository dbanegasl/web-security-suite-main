from __future__ import annotations

import os
from pathlib import Path

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


def get_session():
    with Session(_engine) as session:
        yield session
