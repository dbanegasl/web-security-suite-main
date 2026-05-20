"""Bloque 11 — Amenazas activas: SHADOW-AETHER (SA040-WEBSHELL-NEOREGEORG a SA040-STRUTS2-FINGERPRINT)."""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result

_BLOCK = 11
_BLOCK_NAME = "Amenazas activas — SHADOW-AETHER"


# ── Helpers ────────────────────────────────────────────────────────────────────


async def _get(
    ctx: ScanContext, path: str, *, timeout: float = 5.0
) -> Optional[httpx.Response]:
    """GET a https://{host}{path}. Devuelve Response o None en caso de error de red."""
    try:
        return await ctx.client.get(
            f"https://{ctx.host}{path}",
            follow_redirects=False,
            timeout=timeout,
        )
    except Exception:
        return None


async def _head(
    ctx: ScanContext, path: str, *, timeout: float = 3.0
) -> Optional[httpx.Response]:
    """HEAD a https://{host}{path}. Devuelve Response o None en caso de error de red."""
    try:
        return await ctx.client.head(
            f"https://{ctx.host}{path}",
            follow_redirects=False,
            timeout=timeout,
        )
    except Exception:
        return None


def _found_patterns(text: str, patterns: list[str]) -> list[str]:
    """Devuelve los patrones encontrados en text (comparación case-insensitive)."""
    text_lower = text.lower()
    return [p for p in patterns if p.lower() in text_lower]


# ── SA040-WEBSHELL-NEOREGEORG ──────────────────────────────────────────────────

_NEOREGEORG_PATHS = [
    "/tunnel.php",
    "/neoreg.php",
    "/tunnel.jsp",
    "/tunnel.jspx",
    "/tunnel.aspx",
    "/tunnel.ashx",
]

_NEOREGEORG_SIGNATURES = [
    "NeoGeorg says",
    "all seems fine",
]


@test(
    "SA040-WEBSHELL-NEOREGEORG",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Neo-reGeorg tunnel webshell no detectado",
    severity="CRITICAL",
    cwe="CWE-506",
)
async def test_webshell_neoregeorg(ctx: ScanContext) -> Result:
    """Detecta el webshell Neo-reGeorg por firma directa y heurística de respuesta anómala."""
    responses = await asyncio.gather(*[_get(ctx, p) for p in _NEOREGEORG_PATHS])

    found_direct: list[str] = []
    found_heuristic: list[str] = []

    for path, resp in zip(_NEOREGEORG_PATHS, responses):
        if resp is None or resp.status_code != 200:
            continue

        body = resp.text

        # Firma directa
        if _found_patterns(body, _NEOREGEORG_SIGNATURES):
            found_direct.append(path)
            continue

        # Heurística: body corto + sin estructura HTML + sin Set-Cookie
        has_html = any(tag in body.lower() for tag in ("<!doctype", "<html", "<body"))
        has_cookie = "set-cookie" in {k.lower() for k in resp.headers.keys()}
        if len(body) < 200 and not has_html and not has_cookie:
            found_heuristic.append(path)

    if found_direct:
        return Result.fail(
            f"Neo-reGeorg detectado (firma directa): {', '.join(found_direct)}"
        )
    if found_heuristic:
        return Result.warn(
            f"Respuesta anómala compatible con Neo-reGeorg: {', '.join(found_heuristic)}"
        )

    return Result.pass_("Ningún path de Neo-reGeorg accesible con firma sospechosa")


# ── SA040-WEBSHELL-POW ─────────────────────────────────────────────────────────

_POW_PATHS = [
    "/pow.jsp",
    "/shell/pow.jsp",
    "/upload/pow.jsp",
    "/images/pow.jsp",
    "/pow/index.jsp",
]

_POW_PATTERNS = [
    '<input name="cmd"',
    '<input name="command"',
    "Runtime.exec(",
    "ProcessBuilder",
    "/bin/sh",
    "cmd.exe",
    "execute command",
    "JSP Shell",
]


@test(
    "SA040-WEBSHELL-POW",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="POW webshell (JSP) no detectado",
    severity="CRITICAL",
    cwe="CWE-506",
)
async def test_webshell_pow(ctx: ScanContext) -> Result:
    """Detecta el webshell POW (JSP) mediante firma HTML y patrones de ejecución de comandos."""
    for path in _POW_PATHS:
        head = await _head(ctx, path)
        if head is None or head.status_code != 200:
            continue

        resp = await _get(ctx, path)
        if resp is None:
            continue

        found = _found_patterns(resp.text, _POW_PATTERNS)
        if len(found) >= 2:
            return Result.fail(
                f"Webshell POW detectado en {path} — patrones: {', '.join(found[:3])}"
            )
        if found:
            return Result.warn(
                f"Path sospechoso {path} con patrón de webshell: {found[0]}"
            )

    return Result.pass_("Ningún path POW webshell accesible con firma")


# ── SA040-ADMIN-JBOSS ─────────────────────────────────────────────────────────

_JBOSS_PATHS = [
    "/jmx-console/",
    "/jmx-console/HtmlAdaptor",
    "/web-console/",
    "/admin-console/",
]

_JBOSS_SIGNATURES = [
    "JBoss JMX Management Console",
    "MBean View",
    "jboss.system",
    "java.lang:type=Memory",
]


@test(
    "SA040-ADMIN-JBOSS",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="JBoss JMX Console no expuesto",
    severity="CRITICAL",
    cwe="CWE-306",
)
async def test_admin_jboss(ctx: ScanContext) -> Result:
    """Detecta la consola JMX de JBoss expuesta sin autenticación."""
    responses = await asyncio.gather(*[_get(ctx, p) for p in _JBOSS_PATHS])

    for path, resp in zip(_JBOSS_PATHS, responses):
        if resp is None:
            continue

        if resp.status_code == 200:
            found = _found_patterns(resp.text, _JBOSS_SIGNATURES)
            if found:
                return Result.fail(
                    f"JBoss JMX Console accesible sin autenticación en {path}"
                )
            # 200 sin firma confirmada en paths críticos → advertencia
            if path in ("/jmx-console/", "/admin-console/"):
                return Result.warn(
                    f"Path {path} responde HTTP 200 sin firma JBoss confirmada"
                )

        elif resp.status_code == 401:
            return Result.warn(
                f"JBoss JMX Console expuesto en {path} — protegido con Basic Auth "
                f"(riesgo de fuerza bruta)"
            )

    return Result.pass_("JBoss JMX Console no accesible")


# ── SA040-ADMIN-TOMCAT ────────────────────────────────────────────────────────

_TOMCAT_PATHS = [
    "/manager/html",
    "/manager/status",
    "/host-manager/html",
]

_TOMCAT_SIGNATURES = [
    "Tomcat Web Application Manager",
    "Apache Tomcat",
    "tomcat-users.xml",
]

_TOMCAT_REALM_KEYWORD = "Tomcat Manager"


@test(
    "SA040-ADMIN-TOMCAT",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Tomcat Manager no expuesto",
    severity="HIGH",
    cwe="CWE-306",
)
async def test_admin_tomcat(ctx: ScanContext) -> Result:
    """Detecta Tomcat Manager expuesto o protegido con Basic Auth (vector de deploy WAR)."""
    for path in _TOMCAT_PATHS:
        resp = await _get(ctx, path)
        if resp is None:
            continue

        if resp.status_code == 200:
            found = _found_patterns(resp.text, _TOMCAT_SIGNATURES)
            if found:
                return Result.fail(
                    f"Tomcat Manager accesible sin autenticación en {path}"
                )
        elif resp.status_code == 401:
            www_auth = resp.headers.get("www-authenticate", "")
            if _TOMCAT_REALM_KEYWORD.lower() in www_auth.lower():
                return Result.warn(
                    f"Tomcat Manager expuesto en {path} — Basic Auth con realm Tomcat "
                    f"(riesgo de fuerza bruta)"
                )

    return Result.pass_("Tomcat Manager no accesible públicamente")


# ── SA040-ADMIN-ZIMBRA ────────────────────────────────────────────────────────

_ZIMBRA_PATHS = [
    "/zimbraAdmin/",
    "/zimbraAdmin",
    "/service/admin/soap/",
]

_ZIMBRA_SIGNATURES = [
    "Zimbra Administration Console",
    "zimbraAdmin",
    "com.zimbra",
    "ZmMsg",
]


@test(
    "SA040-ADMIN-ZIMBRA",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Zimbra admin no expuesto",
    severity="HIGH",
    cwe="CWE-306",
)
async def test_admin_zimbra(ctx: ScanContext) -> Result:
    """Detecta la consola de administración de Zimbra expuesta o versión revelada por header."""
    # Verificar X-Zimbra-Version en la respuesta inicial del servidor
    zimbra_version = await ctx.get_header("x-zimbra-version")
    if zimbra_version:
        return Result.warn(
            f"Header X-Zimbra-Version expuesto en respuesta inicial: {zimbra_version}"
        )

    responses = await asyncio.gather(*[_get(ctx, p) for p in _ZIMBRA_PATHS])

    for path, resp in zip(_ZIMBRA_PATHS, responses):
        if resp is None:
            continue

        # Header de versión en respuesta específica del path
        zv = resp.headers.get("x-zimbra-version", "")
        if zv:
            return Result.warn(f"Header X-Zimbra-Version en {path}: {zv}")

        if resp.status_code == 200:
            found = _found_patterns(resp.text, _ZIMBRA_SIGNATURES)
            if found:
                return Result.fail(
                    f"Zimbra Administration Console accesible en {path}"
                )
        elif resp.status_code in (301, 302):
            location = resp.headers.get("location", "")
            if "zimbra" in location.lower():
                return Result.warn(
                    f"Redirección Zimbra detectada en {path} → {location[:80]}"
                )

    return Result.pass_("Panel Zimbra Admin no accesible por HTTP(S) estándar")


# ── SA040-STRUTS2-FINGERPRINT ─────────────────────────────────────────────────

_STRUTS2_WEBCONSOLE_PATH = "/struts/webconsole.html"
_STRUTS2_ACTION_PATH = "/index.action"

_STRUTS2_DEV_SIGNATURES = [
    "OGNL",
    "Webconsole",
    "Struts2 Webconsole",
]

_STRUTS2_STACKTRACE_SIGNATURES = [
    "org.apache.struts2",
    "com.opensymphony.xwork2",
    "OGNL expression",
]


@test(
    "SA040-STRUTS2-FINGERPRINT",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Struts2 sin fingerprint expuesto",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_struts2_fingerprint(ctx: ScanContext) -> Result:
    """Fingerprinting pasivo de Struts2: header X-Powered-By, dev console y stack traces."""
    # 1) Header X-Powered-By con Struts en la respuesta inicial
    xpb = await ctx.get_header("x-powered-by")
    if xpb and "struts" in xpb.lower():
        return Result.warn(f"Header X-Powered-By revela Struts: {xpb}")

    # 2) Webconsole de desarrollo activa (modo devMode)
    webconsole_resp, action_resp = await asyncio.gather(
        _get(ctx, _STRUTS2_WEBCONSOLE_PATH),
        _get(ctx, _STRUTS2_ACTION_PATH),
    )

    if webconsole_resp is not None and webconsole_resp.status_code == 200:
        found = _found_patterns(webconsole_resp.text, _STRUTS2_DEV_SIGNATURES)
        if found:
            return Result.fail(
                f"Struts2 webconsole activa en {_STRUTS2_WEBCONSOLE_PATH} — modo desarrollo expuesto"
            )

    # 3) Stack trace con clases de Struts2
    if action_resp is not None and action_resp.status_code in (200, 400, 500):
        found = _found_patterns(action_resp.text, _STRUTS2_STACKTRACE_SIGNATURES)
        if found:
            return Result.warn(
                f"Stack trace de Struts2 visible en {_STRUTS2_ACTION_PATH}: {found[0]}"
            )

    return Result.pass_("No se detectaron indicadores de Struts2 expuesto")
