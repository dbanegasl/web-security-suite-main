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
    avatar: Optional[str] = Field(default=None)   # base64 data URL


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


class PlatformSetting(SQLModel, table=True):
    __tablename__ = "platform_settings"  # type: ignore[assignment]

    key: str = Field(primary_key=True, max_length=64)
    value: str = Field(default="")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_by: Optional[int] = Field(default=None, foreign_key="users.id")


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


class ScheduledScan(SQLModel, table=True):
    """Configuración de un escaneo periódico programado."""

    __tablename__ = "scheduled_scans"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=128)                         # nombre descriptivo
    domain: str = Field(index=True, max_length=253)
    session_cookie: str = Field(default="", max_length=128)
    ip: str = Field(default="", max_length=45)                # IP forzada opcional
    cron_expression: str = Field(max_length=64)               # e.g. "0 8 * * 1"
    is_active: bool = Field(default=True)
    webhook_url: str = Field(default="", max_length=512)      # Slack / Teams / genérico
    min_severity: str = Field(default="HIGH", max_length=16)  # LOW|MEDIUM|HIGH|CRITICAL
    notify_on_new_fail: bool = Field(default=True)            # notificar solo nuevos FAILs
    last_run: Optional[datetime] = Field(default=None)
    last_scan_id: Optional[int] = Field(default=None, foreign_key="scan_history.id")
    created_by: Optional[int] = Field(default=None, foreign_key="users.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScheduledScanRun(SQLModel, table=True):
    """Log de cada ejecución de un escaneo programado."""

    __tablename__ = "scheduled_scan_runs"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    schedule_id: int = Field(index=True, foreign_key="scheduled_scans.id")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    finished_at: Optional[datetime] = Field(default=None)
    duration_ms: Optional[int] = Field(default=None)
    status: str = Field(default="ok", max_length=8)           # "ok" | "error"
    error_msg: Optional[str] = Field(default=None, max_length=512)
    pass_count: int = Field(default=0)
    fail_count: int = Field(default=0)
    warn_count: int = Field(default=0)
    skip_count: int = Field(default=0)
    scan_id: Optional[int] = Field(default=None, foreign_key="scan_history.id")


class TestCatalog(SQLModel, table=True):
    """Catálogo de tests sincronizado desde TEST_REGISTRY en cada arranque."""

    __tablename__ = "test_catalog"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    code: str = Field(index=True, unique=True, max_length=96)
    name: str = Field(max_length=128)
    block: int = Field(index=True)
    display_order: int = Field(default=0, index=True)
    block_name: str = Field(default="", max_length=64)
    severity: str = Field(default="MEDIUM", max_length=16)   # LOW|MEDIUM|HIGH|CRITICAL
    cwe: Optional[str] = Field(default=None, max_length=32)
    description: str = Field(default="")
    references: str = Field(default="[]")                    # JSON array de URLs
    package: str = Field(default="", max_length=128)         # módulo Python de origen
    synced_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # ── Campos administrados manualmente (el sync NO los sobreescribe) ──────
    is_active: bool = Field(default=True)                    # activar/desactivar test
    description_custom: bool = Field(default=False)          # True = desc editada vía CRUD
