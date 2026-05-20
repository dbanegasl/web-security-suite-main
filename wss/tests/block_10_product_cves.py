"""Bloque 10 — Vulnerabilidades de producto (CVE-NGINX-VERSION a WEBSHELL-DETECTED)."""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result

_BLOCK = 10
_BLOCK_NAME = "Vulnerabilidades de producto"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get(ctx: ScanContext, path: str, timeout: float = 5.0) -> Optional[object]:
    """GET https://host/path. Devuelve Response o None si falla."""
    try:
        url = f"https://{ctx.host}{path}"
        return await ctx.client.get(url, follow_redirects=False, timeout=timeout)
    except Exception:
        return None


async def _head(ctx: ScanContext, path: str, timeout: float = 5.0) -> Optional[object]:
    """HEAD https://host/path. Devuelve Response o None si falla."""
    try:
        url = f"https://{ctx.host}{path}"
        return await ctx.client.head(url, follow_redirects=False, timeout=timeout)
    except Exception:
        return None


def _parse_nginx_version(server: str) -> Optional[tuple[int, ...]]:
    """Extrae la tupla de versión de una cabecera Server del tipo 'nginx/X.Y.Z'."""
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", server or "", re.IGNORECASE)
    return tuple(int(x) for x in m.groups()) if m else None


def _nginx_vulnerable_42945(v: tuple[int, ...]) -> bool:
    """Rango vulnerable CVE-2025-42945 / memoria: 0.6.27 – 1.30.0 inclusive."""
    return (0, 6, 27) <= v <= (1, 30, 0)


def _nginx_vulnerable_42926(v: tuple[int, ...]) -> bool:
    """Rango vulnerable CVE-2025-42926 / HTTP2: 1.29.4 – 1.30.0 inclusive."""
    return (1, 29, 4) <= v <= (1, 30, 0)


# Patrones que indican respuesta de webshell real (no página de error 200)
_WEBSHELL_PATTERNS = [
    re.compile(r"(?i)(uname\s*-a|/etc/passwd|eval\s*\(base64_decode|system\s*\(|shell_exec\s*\(|passthru\s*\()"),
    re.compile(r"(?i)(c99shell|r57shell|b374k|p0wny|neoregeorg|FilesMan)"),
    re.compile(r"(?i)(cmd=|command=|exec=|execute=).*shell"),
    re.compile(r"(?i)<title>\s*(c99|r57|webshell|shell)\s*</title>"),
    re.compile(r"(?i)(<?php.*system|<?php.*exec|<?php.*passthru)"),
]


def _webshell_score(body: str) -> int:
    """Cuenta cuántos patrones de webshell distintos coinciden en el body."""
    return sum(1 for p in _WEBSHELL_PATTERNS if p.search(body))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@test(
    "CVE-NGINX-VERSION",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="nginx versión vulnerable (CVE-2025-42945)",
    severity="HIGH",
    cwe="CWE-122",
    description=(
        "Detecta si el servidor expone una versión de nginx dentro del rango "
        "0.6.27 – 1.30.0, afectado por el desbordamiento de búfer basado en heap "
        "CVE-2025-42945 en el módulo mp4 (CVSS 9.1)."
    ),
    references=["https://nvd.nist.gov/vuln/detail/CVE-2025-42945"],
    order=1,
)
async def test_cve_nginx_version(ctx: ScanContext) -> Result:
    server = (await ctx.get_header("server")) or ""
    version = _parse_nginx_version(server)
    if version is None:
        return Result.skip("Cabecera Server no expone versión de nginx")
    if _nginx_vulnerable_42945(version):
        ver_str = ".".join(str(x) for x in version)
        return Result.fail(
            f"nginx/{ver_str} en rango vulnerable CVE-2025-42945 (0.6.27 – 1.30.0). "
            f"Actualizar a ≥ 1.30.1 (stable) o ≥ 1.31.x (mainline)."
        )
    ver_str = ".".join(str(x) for x in version)
    return Result.pass_(f"nginx/{ver_str} no está en el rango vulnerable de CVE-2025-42945")


@test(
    "CVE-NGINX-HTTP2",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="nginx HTTP/2 vulnerable (CVE-2025-42926)",
    severity="MEDIUM",
    cwe="CWE-693",
    description=(
        "Detecta si el servidor expone una versión de nginx en el rango 1.29.4 – 1.30.0, "
        "afectado por CVE-2025-42926 (protección insuficiente contra RST-based DoS vía HTTP/2)."
    ),
    references=["https://nvd.nist.gov/vuln/detail/CVE-2025-42926"],
    order=2,
)
async def test_cve_nginx_http2(ctx: ScanContext) -> Result:
    server = (await ctx.get_header("server")) or ""
    version = _parse_nginx_version(server)
    if version is None:
        return Result.skip("Cabecera Server no expone versión de nginx")
    if _nginx_vulnerable_42926(version):
        ver_str = ".".join(str(x) for x in version)
        return Result.warn(
            f"nginx/{ver_str} en rango vulnerable CVE-2025-42926 HTTP/2 (1.29.4 – 1.30.0). "
            f"Actualizar a ≥ 1.30.1 o deshabilitar HTTP/2 si no es necesario."
        )
    ver_str = ".".join(str(x) for x in version)
    return Result.pass_(f"nginx/{ver_str} no está en el rango vulnerable de CVE-2025-42926")


@test(
    "NGINX-STATUS-EXPOSED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Endpoint de estado nginx expuesto",
    severity="HIGH",
    cwe="CWE-200",
    description=(
        "Comprueba si el endpoint de métricas de nginx (stub_status) es accesible "
        "públicamente. Expone número de conexiones activas, peticiones totales y "
        "workers, información útil para fingerprinting y planificación de ataques DoS."
    ),
    references=["https://nginx.org/en/docs/http/ngx_http_stub_status_module.html"],
    order=3,
)
async def test_nginx_status_exposed(ctx: ScanContext) -> Result:
    paths = ["/nginx_status", "/stub_status", "/status", "/basic_status"]
    _NGINX_STATUS_PATTERNS = [
        re.compile(r"Active connections:\s*\d+"),
        re.compile(r"server accepts handled requests"),
        re.compile(r"Reading:\s*\d+\s+Writing:\s*\d+"),
        re.compile(r"requests:\s*\d+"),
    ]

    async def _check(path: str) -> Optional[str]:
        r = await _get(ctx, path, timeout=5.0)
        if r is None or r.status_code != 200:
            return None
        body = r.text[:1000]
        if any(p.search(body) for p in _NGINX_STATUS_PATTERNS):
            return path
        return None

    found = [p for p in await asyncio.gather(*(_check(p) for p in paths)) if p]
    if found:
        return Result.fail(
            f"Endpoint(s) de estado nginx accesibles: {', '.join(found)}. "
            "Restringir con allow/deny en la directiva location o eliminar el módulo stub_status."
        )
    return Result.pass_("Endpoints de estado nginx no expuestos")


@test(
    "WEBSHELL-DETECTED",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Webshell PHP detectada",
    severity="CRITICAL",
    cwe="CWE-434",
    description=(
        "Busca webshells PHP comunes (c99, r57, w.php, cmd.php, shell.php) en rutas "
        "frecuentes. Una respuesta con patrones de webshell confirma compromiso activo."
    ),
    references=["https://owasp.org/www-community/attacks/Web_Shell_Usage"],
    order=4,
)
async def test_webshell_detected(ctx: ScanContext) -> Result:
    _SHELL_PATHS = [
        "/shell.php", "/cmd.php", "/c99.php", "/r57.php", "/w.php",
        "/uploads/shell.php", "/images/shell.php", "/tmp/shell.php",
        "/wp-content/uploads/shell.php", "/media/shell.php",
    ]

    async def _check_path(path: str) -> Optional[tuple[str, int]]:
        # HEAD primero para no descargar bodies grandes innecesariamente
        hr = await _head(ctx, path, timeout=5.0)
        if hr is None or hr.status_code not in (200, 403):
            return None
        # GET para inspeccionar el body
        r = await _get(ctx, path, timeout=5.0)
        if r is None or r.status_code != 200:
            return None
        score = _webshell_score(r.text[:10000])
        if score > 0:
            return (path, score)
        return None

    hits = [h for h in await asyncio.gather(*(_check_path(p) for p in _SHELL_PATHS)) if h]
    if not hits:
        return Result.pass_("No se detectaron webshells PHP en rutas comunes")

    critical_hits = [(p, s) for p, s in hits if s >= 2]
    if critical_hits:
        paths_str = ", ".join(p for p, _ in critical_hits)
        return Result.fail(
            f"¡Webshell(s) PHP activa(s) detectada(s): {paths_str}! "
            "El servidor puede estar comprometido. Eliminar inmediatamente y auditlar logs."
        )
    # Score == 1: sospechoso pero no confirmado
    paths_str = ", ".join(p for p, _ in hits)
    return Result.warn(
        f"Patrón sospechoso de webshell en: {paths_str}. Verificar manualmente."
    )
