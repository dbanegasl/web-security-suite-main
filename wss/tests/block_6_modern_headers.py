"""Bloque 6 — Headers modernos y deprecados (TEST-21 a TEST-25)."""
from __future__ import annotations

import re

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result


@test(
    "21",
    block=6,
    block_name="Headers modernos y deprecados",
    name="Headers deprecados ausentes",
    severity="LOW",
    cwe=None,
)
async def test_deprecated_headers(ctx: ScanContext) -> Result:
    """X-XSS-Protection, Expect-CT y Pragma no deben estar presentes (obsoletos)."""
    deprecated = ["x-xss-protection", "expect-ct", "pragma"]
    found = []
    for h in deprecated:
        if await ctx.get_header(h):
            found.append(h)
    if found:
        return Result.warn(f"presentes: {', '.join(found)} — retirados de estándares modernos")
    return Result.pass_()


@test(
    "22",
    block=6,
    block_name="Headers modernos y deprecados",
    name="Cross-Origin-Opener-Policy (COOP)",
    severity="MEDIUM",
    cwe="CWE-346",
)
async def test_coop(ctx: ScanContext) -> Result:
    """COOP debe estar presente para aislar el contexto de ventana."""
    val = await ctx.get_header("cross-origin-opener-policy")
    if val:
        return Result.pass_(val)
    return Result.warn("ausente — riesgo de cross-origin window attacks")


@test(
    "23",
    block=6,
    block_name="Headers modernos y deprecados",
    name="Cross-Origin-Embedder-Policy (COEP)",
    severity="MEDIUM",
    cwe="CWE-346",
)
async def test_coep(ctx: ScanContext) -> Result:
    """COEP debe estar presente para habilitar aislamiento cross-origin."""
    val = await ctx.get_header("cross-origin-embedder-policy")
    if val:
        return Result.pass_(val)
    return Result.warn("ausente — habilitar junto con COOP para aislamiento")


@test(
    "24",
    block=6,
    block_name="Headers modernos y deprecados",
    name="Cross-Origin-Resource-Policy (CORP)",
    severity="MEDIUM",
    cwe="CWE-346",
)
async def test_corp(ctx: ScanContext) -> Result:
    """CORP debe estar presente para restringir qué orígenes pueden cargar los recursos."""
    val = await ctx.get_header("cross-origin-resource-policy")
    if val:
        return Result.pass_(val)
    return Result.warn("ausente — recursos accesibles desde cualquier origen")


@test(
    "25",
    block=6,
    block_name="Headers modernos y deprecados",
    name="X-Permitted-Cross-Domain-Policies",
    severity="LOW",
    cwe="CWE-942",
)
async def test_x_permitted_cross_domain(ctx: ScanContext) -> Result:
    """X-Permitted-Cross-Domain-Policies no debe ser 'all' (Adobe Flash/PDF)."""
    val = await ctx.get_header("x-permitted-cross-domain-policies")
    if not val:
        return Result.warn("ausente — controla acceso de Adobe Flash/PDF a recursos del dominio")
    # Valor 'all' es demasiado permisivo (word boundary)
    if re.search(r"\ball\b", val, re.IGNORECASE):
        return Result.warn(f"valor 'all' — demasiado permisivo: {val}")
    return Result.pass_(val)
