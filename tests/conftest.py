"""Fixtures y helpers compartidos para los tests de pytest."""
from __future__ import annotations

import sys
import dataclasses
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import MagicMock

# ── Mock de dependencias de la API web (no instaladas en el entorno local) ────
# scheduler.py importa APScheduler, sqlmodel y módulos propios de la API al
# nivel de módulo. Para que test_scheduler.py pueda importar las funciones
# puras (_severity_gte, _send_webhook) sin necesitar esas dependencias
# instaladas, inyectamos mocks antes de que pytest coleccione los tests.

# 1) APScheduler — mock completo (las funciones puras no lo usan)
for _mod in (
    "apscheduler",
    "apscheduler.schedulers",
    "apscheduler.schedulers.asyncio",
    "apscheduler.triggers",
    "apscheduler.triggers.cron",
    "sqlmodel",
    "database",
):
    sys.modules.setdefault(_mod, MagicMock())

# 2) models — mock con ScheduledScan como dataclass real para que
#    _make_schedule() en test_scheduler.py pueda acceder a .domain, .min_severity, etc.
@dataclasses.dataclass
class _ScheduledScanMock:
    id: Optional[int] = None
    name: str = ""
    domain: str = ""
    cron_expression: str = ""
    session_cookie: str = ""
    ip: str = ""
    webhook_url: str = ""
    min_severity: str = "HIGH"
    notify_on_new_fail: bool = True
    is_active: bool = True
    last_run: Optional[datetime] = None
    last_scan_id: Optional[int] = None
    created_by: Optional[int] = None
    created_at: datetime = dataclasses.field(default_factory=lambda: datetime.now(timezone.utc))


_models_mock = MagicMock()
_models_mock.ScheduledScan = _ScheduledScanMock
_models_mock.ScanHistory = MagicMock()
sys.modules["models"] = _models_mock

import pytest
import httpx

from wss.core.context import ScanContext


def make_ctx(
    set_cookies: list[str] | None = None,
    session_cookie: str = "",
    domain: str = "example.com",
    ip: str = "",
) -> ScanContext:
    """Crea un ScanContext con la caché de Set-Cookie pre-poblada.

    No realiza ninguna petición HTTP real — es suficiente para tests
    del bloque 1 (cookies), que solo leen la respuesta inicial.
    """
    ctx = ScanContext(
        domain=domain,
        host=domain,
        base_url=f"https://{domain}/",
        session_cookie=session_cookie,
        ip=ip,
    )
    # Pre-poblar caché para evitar peticiones HTTP en los tests unitarios
    ctx._set_cookies_cache = set_cookies or []
    return ctx
