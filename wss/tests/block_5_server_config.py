"""Bloque 5 — Configuración del servidor (TEST-18 a TEST-20)."""
from __future__ import annotations

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result


@test(
    "18",
    block=5,
    block_name="Configuración del servidor",
    name="CORS sin wildcard Access-Control-Allow-Origin",
    severity="HIGH",
    cwe="CWE-942",
)
async def test_cors(ctx: ScanContext) -> Result:
    """CORS no debe permitir cualquier origen con wildcard '*'."""
    val = await ctx.get_header("access-control-allow-origin")
    if not val:
        return Result.pass_("CORS no expuesto en raíz")
    if val.strip() == "*":
        return Result.fail("wildcard '*' — cualquier origen permitido")
    return Result.pass_(val)


@test(
    "19",
    block=5,
    block_name="Configuración del servidor",
    name="HTTP TRACE deshabilitado",
    severity="MEDIUM",
    cwe="CWE-16",
)
async def test_http_trace(ctx: ScanContext) -> Result:
    """El método HTTP TRACE debe estar deshabilitado (Cross-Site Tracing)."""
    try:
        resp = await ctx.client.request("TRACE", ctx.base_url)
        code = resp.status_code
        if code == 200:
            return Result.fail(f"responde {code} — método TRACE activo")
        if code in (403, 404, 405):
            return Result.pass_(f"responde {code}")
        return Result.warn(f"respuesta inesperada: {code}")
    except Exception as exc:
        return Result.warn(f"no se pudo verificar: {exc!s:.80}")


@test(
    "20",
    block=5,
    block_name="Configuración del servidor",
    name="Cache-Control seguro",
    severity="MEDIUM",
    cwe="CWE-524",
)
async def test_cache_control(ctx: ScanContext) -> Result:
    """Cache-Control debe incluir no-store, no-cache o private para rutas sensibles."""
    val = await ctx.get_header("cache-control")
    if not val:
        return Result.warn("ausente — navegador puede cachear contenido sensible")

    val_lower = val.lower()
    if any(d in val_lower for d in ("no-store", "no-cache", "private")):
        return Result.pass_(val)

    return Result.warn(f"{val} — revisar si aplica a rutas autenticadas")
