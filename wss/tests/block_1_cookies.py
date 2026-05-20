"""Bloque 1 — Cookies (COOKIE-SECURE a COOKIE-PATH)

Verifica que las cookies establecidas por el servidor tengan los atributos
de seguridad correctos. Paridad exacta con la lógica bash de scan-cli.sh.

Metodología:
    Se reutiliza la respuesta HEAD inicial cacheada en ScanContext.
    No se realizan peticiones adicionales.
"""
from __future__ import annotations

import re

from wss.core.registry import test
from wss.core.context import ScanContext
from wss.core.result import Result

# ── Helpers de parsing ──────────────────────────────────────────────────────


def _cookie_name(raw: str) -> str:
    """Extrae el nombre de una cookie de un header Set-Cookie raw."""
    return raw.split(";")[0].split("=")[0].strip()


# ── Tests ───────────────────────────────────────────────────────────────────


@test(
    "COOKIE-SECURE",
    block=1,
    block_name="Cookies",
    name="Cookie attribute: Secure",
    severity="HIGH",
    cwe="CWE-614",
)
async def test_secure(ctx: ScanContext) -> Result:
    """Todas las cookies deben tener el atributo Secure.

    Paridad bash: grep -qi "; secure"
    Cualquier cookie sin "; secure" (case-insensitive) → FAIL.
    """
    cookies = await ctx.set_cookies()
    if not cookies:
        return Result.pass_("no se encontraron cookies")

    failing = [_cookie_name(c) for c in cookies if "; secure" not in c.lower()]
    if failing:
        return Result.fail(f"sin Secure: {', '.join(failing)}")
    return Result.pass_()


@test(
    "COOKIE-HTTPONLY",
    block=1,
    block_name="Cookies",
    name="Cookie attribute: HttpOnly",
    severity="HIGH",
    cwe="CWE-1004",
)
async def test_httponly(ctx: ScanContext) -> Result:
    """La cookie de sesión principal debe tener el atributo HttpOnly.

    Paridad bash:
    - Sin SESSION_COOKIE_NAME → SKIP
    - Cookie no encontrada en raíz → SKIP
    - XSRF-TOKEN queda excluido (debe ser legible por JS)
    - Verifica "httponly" case-insensitive
    """
    if not ctx.session_cookie:
        return Result.skip("sin cookie de sesión identificada")

    # XSRF-TOKEN debe ser legible por JS — HttpOnly no aplica
    if ctx.session_cookie.upper() == "XSRF-TOKEN":
        return Result.skip("XSRF-TOKEN debe ser legible por JS — HttpOnly no aplica")

    cookies = await ctx.set_cookies()
    session_lines = [c for c in cookies if ctx.session_cookie.lower() in c.lower()]

    if not session_lines:
        return Result.skip(f"cookie '{ctx.session_cookie}' no hallada en raíz")

    if "httponly" in session_lines[0].lower():
        return Result.pass_()
    return Result.fail(f"cookie '{ctx.session_cookie}' sin HttpOnly")


@test(
    "COOKIE-SAMESITE",
    block=1,
    block_name="Cookies",
    name="Cookie attribute: SameSite=Lax|Strict",
    severity="MEDIUM",
    cwe="CWE-352",
)
async def test_samesite(ctx: ScanContext) -> Result:
    """Todas las cookies deben tener SameSite=Lax o SameSite=Strict.

    Paridad bash: grep -qiP "samesite=(lax|strict)"
    SameSite=None o ausente → FAIL.
    """
    cookies = await ctx.set_cookies()
    if not cookies:
        return Result.pass_("no se encontraron cookies")

    failing = [
        _cookie_name(c)
        for c in cookies
        if not re.search(r"samesite=(lax|strict)", c, re.IGNORECASE)
    ]
    if failing:
        return Result.fail(f"sin SameSite=Lax/Strict: {', '.join(failing)}")
    return Result.pass_()


@test(
    "COOKIE-PATH",
    block=1,
    block_name="Cookies",
    name="Cookie attribute: Path definido",
    severity="LOW",
    cwe=None,
)
async def test_path(ctx: ScanContext) -> Result:
    """Todas las cookies deberían tener el atributo Path definido.

    Paridad bash: grep -qi "path="
    Ausencia de Path → WARN (no FAIL), scope de cookie sin restringir.
    """
    cookies = await ctx.set_cookies()
    if not cookies:
        return Result.pass_("no se encontraron cookies")

    failing = [_cookie_name(c) for c in cookies if "path=" not in c.lower()]
    if failing:
        return Result.warn(f"sin Path: {', '.join(failing)} — scope sin restringir")
    return Result.pass_()
