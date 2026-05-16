"""Bloque 2 — Transporte y TLS (TEST-05 a TEST-09)."""
from __future__ import annotations

import asyncio
import re
import ssl
import time

import httpx

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result


def _http_url(ctx: ScanContext) -> str:
    """URL HTTP (puerto 80) equivalente a la base_url HTTPS del contexto."""
    # base_url es "https://host/path" — sustituimos el esquema
    return ctx.base_url.replace("https://", "http://", 1)


async def _tls_version_accepted(
    host: str, ip: str, tls_version: "ssl.TLSVersion"
) -> bool | None:
    """Intenta conectar al servidor forzando una versión de TLS concreta.

    Returns:
        True  → el servidor acepta esa versión (FAIL del test).
        False → conexión rechazada o error (PASS del test).
        None  → el cliente local no soporta esa versión (SKIP del test).
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    except (AttributeError, ssl.SSLError, OSError):
        return None  # OpenSSL local no soporta la versión

    target = ip or host
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, 443, ssl=ctx, server_hostname=host),
            timeout=6.0,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _cert_days_left(host: str, ip: str) -> int | None:
    """Devuelve días hasta la expiración del certificado SSL o None si no se pudo leer."""
    target = ip or host

    # Primer intento: con verificación (obtiene decoded cert)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, 443, ssl=ctx, server_hostname=host),
            timeout=6.0,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                expiry = ssl.cert_time_to_seconds(not_after)
                return int((expiry - time.time()) / 86400)
    except ssl.SSLCertVerificationError:
        # Certificado inválido/self-signed — intentar sin verificación solo para leer la fecha
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            reader2, writer2 = await asyncio.wait_for(
                asyncio.open_connection(target, 443, ssl=ctx2, server_hostname=host),
                timeout=6.0,
            )
            ssl_obj2 = writer2.get_extra_info("ssl_object")
            # Con CERT_NONE, getpeercert() puede devolver None — no se puede decodificar
            writer2.close()
            try:
                await writer2.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
    except Exception:
        pass
    return None


# ── TEST-05 ───────────────────────────────────────────────────────────────────


@test(
    "05",
    block=2,
    block_name="Transporte y TLS",
    name="HTTP → HTTPS redirect 301/302",
    severity="MEDIUM",
    cwe="CWE-319",
)
async def test_http_redirect(ctx: ScanContext) -> Result:
    """El servidor debe redirigir HTTP a HTTPS con código 301 o 302."""
    http_url = _http_url(ctx)

    from wss.core.http_client import ForcedIPTransport

    transport = (
        ForcedIPTransport(ctx.host, ctx.ip, verify=False)
        if ctx.ip
        else httpx.AsyncHTTPTransport(verify=False)
    )

    try:
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=httpx.Timeout(8.0, connect=4.0),
        ) as client:
            resp = await client.head(http_url)
            location = resp.headers.get("location", "")
            is_redirect = resp.status_code in (301, 302)
            is_https = location.lower().startswith("https://")
            if is_redirect and is_https:
                return Result.pass_()
            return Result.fail(
                f"HTTP {resp.status_code}"
                + (f" → {location}" if location else " — sin redirección a HTTPS")
            )
    except Exception as exc:
        return Result.fail(f"no se pudo conectar por HTTP: {exc!s:.80}")


# ── TEST-06 ───────────────────────────────────────────────────────────────────


@test(
    "06",
    block=2,
    block_name="Transporte y TLS",
    name="HSTS Strict-Transport-Security",
    severity="HIGH",
    cwe="CWE-523",
)
async def test_hsts(ctx: ScanContext) -> Result:
    """HSTS debe estar presente con max-age >= 31536000 (1 año)."""
    hsts = await ctx.get_header("strict-transport-security")
    if not hsts:
        return Result.fail("header ausente")

    m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    max_age = int(m.group(1)) if m else 0

    if max_age < 31_536_000:
        return Result.warn(f"max-age={max_age} < 31536000 (1 año)")
    return Result.pass_()


# ── TEST-07 ───────────────────────────────────────────────────────────────────


@test(
    "07",
    block=2,
    block_name="Transporte y TLS",
    name="TLS 1.0 deshabilitado",
    severity="HIGH",
    cwe="CWE-326",
)
async def test_tls10_disabled(ctx: ScanContext) -> Result:
    """El servidor no debe aceptar conexiones TLS 1.0 (POODLE)."""
    tls10 = getattr(ssl.TLSVersion, "TLSv1", None)
    if tls10 is None:
        return Result.skip("ssl.TLSVersion.TLSv1 no disponible en este entorno")

    accepted = await _tls_version_accepted(ctx.host, ctx.ip, tls10)
    if accepted is None:
        return Result.skip("OpenSSL local no soporta TLS 1.0 — no se puede determinar")
    if accepted:
        return Result.fail("servidor acepta TLS 1.0 (inseguro — POODLE)")
    return Result.pass_()


# ── TEST-08 ───────────────────────────────────────────────────────────────────


@test(
    "08",
    block=2,
    block_name="Transporte y TLS",
    name="TLS 1.1 deshabilitado",
    severity="MEDIUM",
    cwe="CWE-326",
)
async def test_tls11_disabled(ctx: ScanContext) -> Result:
    """El servidor no debe aceptar conexiones TLS 1.1 (obsoleto)."""
    tls11 = getattr(ssl.TLSVersion, "TLSv1_1", None)
    if tls11 is None:
        return Result.skip("ssl.TLSVersion.TLSv1_1 no disponible en este entorno")

    accepted = await _tls_version_accepted(ctx.host, ctx.ip, tls11)
    if accepted is None:
        return Result.skip("OpenSSL local no soporta TLS 1.1 — no se puede determinar")
    if accepted:
        return Result.fail("servidor acepta TLS 1.1 (obsoleto)")
    return Result.pass_()


# ── TEST-09 ───────────────────────────────────────────────────────────────────


@test(
    "09",
    block=2,
    block_name="Transporte y TLS",
    name="Certificado SSL vigente",
    severity="CRITICAL",
    cwe="CWE-298",
)
async def test_cert_valid(ctx: ScanContext) -> Result:
    """El certificado SSL no debe estar próximo a expirar (< 30 días → WARN, < 7 → FAIL)."""
    days = await _cert_days_left(ctx.host, ctx.ip)
    if days is None:
        return Result.skip("no se pudo leer el certificado")
    if days <= 7:
        return Result.fail(f"expira en {days} días — CRÍTICO")
    if days <= 30:
        return Result.warn(f"expira en {days} días — renovar pronto")
    return Result.pass_(f"expira en {days} días")
