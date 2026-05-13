from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, max_length=64)
    password_hash: str
    role: str = Field(default="analyst")   # "admin" | "analyst"
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = Field(default=None)


class ScanHistory(SQLModel, table=True):
    __tablename__ = "scan_history"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    domain: str = Field(index=True)
    scanned_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    pass_count: int = Field(default=0)
    fail_count: int = Field(default=0)
    warn_count: int = Field(default=0)
    skip_count: int = Field(default=0)
    scan_mode: str = Field(default="individual")   # "individual" | "batch"
    results_json: str = Field(default="{}")
    triggered_by: Optional[int] = Field(default=None, foreign_key="users.id")
