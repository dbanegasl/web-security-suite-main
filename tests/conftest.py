"""Fixtures y helpers compartidos para los tests de pytest."""
from __future__ import annotations

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
