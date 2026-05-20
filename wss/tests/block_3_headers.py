"""Bloque 3 — Cabeceras HTTP de seguridad (HEADER-X-FRAME-OPTIONS a HEADER-PERMISSIONS-POLICY)."""
from __future__ import annotations

import re

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result


@test(
    "HEADER-X-FRAME-OPTIONS",
    block=3,
    block_name="Cabeceras HTTP",
    name="X-Frame-Options (anti-clickjacking)",
    severity="HIGH",
    cwe="CWE-1021",
)
async def test_xframe_options(ctx: ScanContext) -> Result:
    """X-Frame-Options debe estar presente para prevenir clickjacking."""
    val = await ctx.get_header("x-frame-options")
    if val:
        return Result.pass_(val)
    return Result.fail("header ausente")


@test(
    "HEADER-X-CONTENT-TYPE-OPTIONS",
    block=3,
    block_name="Cabeceras HTTP",
    name="X-Content-Type-Options: nosniff",
    severity="MEDIUM",
    cwe="CWE-430",
)
async def test_xcontent_type_options(ctx: ScanContext) -> Result:
    """X-Content-Type-Options: nosniff debe estar presente para prevenir MIME sniffing."""
    val = await ctx.get_header("x-content-type-options")
    if val:
        return Result.pass_(val)
    return Result.fail("header ausente")


@test(
    "HEADER-CSP",
    block=3,
    block_name="Cabeceras HTTP",
    name="Content-Security-Policy",
    severity="HIGH",
    cwe="CWE-693",
)
async def test_csp(ctx: ScanContext) -> Result:
    """CSP debe estar presente y no debe contener directivas inseguras."""
    csp = await ctx.get_header("content-security-policy")
    if not csp:
        return Result.fail("header ausente")

    csp_lower = csp.lower()

    if "unsafe-eval" in csp_lower:
        return Result.warn("contiene 'unsafe-eval' — permite ejecución JS dinámica")

    # Comodín de origen: " *;" o " *:" o ": *" o " https: "
    if re.search(r"([\s;:'])\*[\s;']|[\s;]https?:[\s;]", csp):
        return Result.warn("fuente comodín en CSP — cualquier origen puede cargar recursos")

    if "unsafe-inline" in csp_lower:
        return Result.warn("contiene 'unsafe-inline' — permite JS/CSS inline (vector XSS)")

    if "base-uri" not in csp_lower:
        return Result.warn("sin 'base-uri' — vulnerable a inyección de <base> tag")

    if "form-action" not in csp_lower:
        return Result.warn("sin 'form-action' — formularios pueden enviarse a cualquier origen")

    return Result.pass_()


@test(
    "HEADER-REFERRER-POLICY",
    block=3,
    block_name="Cabeceras HTTP",
    name="Referrer-Policy",
    severity="LOW",
    cwe="CWE-200",
)
async def test_referrer_policy(ctx: ScanContext) -> Result:
    """Referrer-Policy debe estar presente para evitar fuga de URLs."""
    val = await ctx.get_header("referrer-policy")
    if val:
        return Result.pass_(val)
    return Result.warn("header ausente — recomendado")


@test(
    "HEADER-PERMISSIONS-POLICY",
    block=3,
    block_name="Cabeceras HTTP",
    name="Permissions-Policy",
    severity="LOW",
    cwe="CWE-284",
)
async def test_permissions_policy(ctx: ScanContext) -> Result:
    """Permissions-Policy debe estar presente para limitar el acceso a APIs del navegador."""
    val = await ctx.get_header("permissions-policy")
    if val:
        return Result.pass_()
    return Result.warn("header ausente — recomendado")
