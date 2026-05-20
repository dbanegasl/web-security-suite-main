"""Bloque 4 — Fuga de información (INFOLEAK-SERVER-HEADER a INFOLEAK-ASP-NET-VERSION)."""
from __future__ import annotations

import re

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result


@test(
    "INFOLEAK-SERVER-HEADER",
    block=4,
    block_name="Fuga de información",
    name="Server header oculto",
    severity="MEDIUM",
    cwe="CWE-200",
)
async def test_server_header(ctx: ScanContext) -> Result:
    """El header Server no debe revelar versión del software."""
    val = await ctx.get_header("server")
    if not val:
        return Result.pass_()

    # Versión detectada: al menos 3 dígitos/puntos (ej: Apache/2.4.51, nginx/1.25)
    if re.search(r"\d{1,3}[.\d]{2,}", val):
        return Result.fail(f"{val} — revela versión")

    return Result.pass_(val)


@test(
    "INFOLEAK-X-POWERED-BY",
    block=4,
    block_name="Fuga de información",
    name="X-Powered-By ausente",
    severity="MEDIUM",
    cwe="CWE-200",
)
async def test_x_powered_by(ctx: ScanContext) -> Result:
    """X-Powered-By no debe estar presente (revela stack tecnológico)."""
    val = await ctx.get_header("x-powered-by")
    if val:
        return Result.fail(val)
    return Result.pass_()


@test(
    "INFOLEAK-ASP-NET-VERSION",
    block=4,
    block_name="Fuga de información",
    name="X-AspNet-Version ausente",
    severity="MEDIUM",
    cwe="CWE-200",
)
async def test_aspnet_version(ctx: ScanContext) -> Result:
    """X-AspNet-Version y X-AspNetMvc-Version no deben estar presentes."""
    aspnet = await ctx.get_header("x-aspnet-version")
    aspnetmvc = await ctx.get_header("x-aspnetmvc-version")
    val = aspnet or aspnetmvc
    if val:
        return Result.fail(val)
    return Result.pass_()
