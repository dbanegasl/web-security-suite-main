from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, max_length=64)
    password_hash: str
    role: str = Field(default="analyst")   # "admin" | "analyst"
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = Field(default=None)


class DomainList(SQLModel, table=True):
    __tablename__ = "domain_lists"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, max_length=128)
    description: str = Field(default="", max_length=512)
    created_by: Optional[int] = Field(default=None, foreign_key="users.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ListDomain(SQLModel, table=True):
    __tablename__ = "list_domains"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    list_id: int = Field(foreign_key="domain_lists.id", index=True)
    domain: str = Field(max_length=253)
    session_cookie: str = Field(default="", max_length=128)
    ip: str = Field(default="", max_length=45)
    notes: str = Field(default="", max_length=512)
    is_active: bool = Field(default=True)
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanHistory(SQLModel, table=True):
    __tablename__ = "scan_history"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    domain: str = Field(index=True)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    pass_count: int = Field(default=0)
    fail_count: int = Field(default=0)
    warn_count: int = Field(default=0)
    skip_count: int = Field(default=0)
    scan_mode: str = Field(default="individual")   # "individual" | "batch" | "list"
    results_json: str = Field(default="{}")
    triggered_by: Optional[int] = Field(default=None, foreign_key="users.id")
    list_id: Optional[int] = Field(default=None, foreign_key="domain_lists.id")
