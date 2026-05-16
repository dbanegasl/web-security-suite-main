"""Bloque 9 — Fingerprinting y Content Analysis (TEST-48 a TEST-55)."""
from __future__ import annotations

import re
from typing import Optional

import httpx

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result

_BLOCK = 9
_BLOCK_NAME = "Fingerprinting y Contenido"


async def _fetch_body(ctx: ScanContext, url: Optional[str] = None) -> Optional[str]:
    """GET al URL (o base_url si no se especifica). Devuelve body[:30000] o None."""
    try:
        target = url or ctx.base_url
        r = await ctx.client.get(target, follow_redirects=True)
        return r.text[:30000]
    except Exception:
        return None


def _parse_html(body: str) -> "Any":
    """Devuelve un objeto BeautifulSoup o None si bs4 no está disponible."""
    try:
        from bs4 import BeautifulSoup  # type: ignore
        return BeautifulSoup(body, "lxml")
    except ImportError:
        try:
            from bs4 import BeautifulSoup  # type: ignore
            return BeautifulSoup(body, "html.parser")
        except ImportError:
            return None


from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# TEST-48  Página de debug Django expuesta
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "48",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Django DEBUG=True no expuesto",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_django_debug(ctx: ScanContext) -> Result:
    """La página de debug de Django (DEBUG=True) no debe estar activa en producción."""
    body = await _fetch_body(ctx)
    if body is None:
        return Result.skip("no se pudo obtener el cuerpo de la respuesta")

    patterns = [
        "You're seeing this error because you have",
        "Django Version",
        "Traceback (most recent call last)",
        "Request Method:",
        "Request URL:",
        "Django settings",
    ]
    hits = [p for p in patterns if p in body]
    if len(hits) >= 2:
        return Result.fail(f"página debug Django activa — {len(hits)} indicadores detectados")
    return Result.pass_("página debug Django no detectada")


# ─────────────────────────────────────────────────────────────────────────────
# TEST-49  Página de debug Laravel expuesta
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "49",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Laravel debug page no expuesta",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_laravel_debug(ctx: ScanContext) -> Result:
    """La página Whoops! de Laravel no debe estar activa en producción."""
    body = await _fetch_body(ctx)
    if body is None:
        return Result.skip("no se pudo obtener el cuerpo de la respuesta")

    patterns = [
        "Whoops!",
        "Whoops, looks like something went wrong",
        "vendor/laravel",
        "laravel/framework",
        "Illuminate\\",
    ]
    hits = [p for p in patterns if p in body]
    if hits:
        return Result.fail(f"página debug Laravel activa — detectado: {hits[0]}")
    return Result.pass_("página debug Laravel no detectada")


# ─────────────────────────────────────────────────────────────────────────────
# TEST-50  Spring Boot Actuator expuesto
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "50",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Spring Boot Actuator no expuesto",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_spring_actuator(ctx: ScanContext) -> Result:
    """El endpoint /actuator no debe exponer información sensible."""
    try:
        url = f"https://{ctx.host}/actuator"
        r = await ctx.client.get(url)
        if r.status_code == 200:
            body = r.text[:2000]
            body_lower = body.lower()
            if '"_links"' in body_lower or '"href"' in body_lower:
                return Result.warn("/actuator accesible — Spring Boot Actuator expuesto")
    except Exception:
        return Result.skip("no se pudo verificar /actuator")
    return Result.pass_("Spring Boot Actuator no accesible")


# ─────────────────────────────────────────────────────────────────────────────
# TEST-51  Versión CMS en meta generator
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "51",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Meta generator sin versión de CMS",
    severity="MEDIUM",
    cwe="CWE-200",
)
async def test_cms_version(ctx: ScanContext) -> Result:
    """El tag meta generator no debe revelar versión específica del CMS."""
    body = await _fetch_body(ctx)
    if body is None:
        return Result.skip("no se pudo obtener el cuerpo de la respuesta")

    soup = _parse_html(body)
    if soup is None:
        # Fallback: regex
        match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE,
        )
        if match:
            content = match.group(1)
            if re.search(r"\d+\.\d+", content):
                return Result.warn(f"meta generator revela versión: {content}")
        return Result.pass_("meta generator sin versión o ausente")

    meta = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if meta:
        content = meta.get("content", "")
        if re.search(r"\d+\.\d+", content):
            return Result.warn(f"meta generator revela versión: {content}")
        if content:
            return Result.pass_(f"meta generator sin versión: {content}")

    return Result.pass_("meta generator ausente")


# ─────────────────────────────────────────────────────────────────────────────
# TEST-52  Comentarios HTML con datos sensibles
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_COMMENT_PATTERNS = re.compile(
    r"\b(password|passwd|secret|token|api[_\s-]?key|debug|todo|fixme|hack|credentials?|"
    r"username|user_?name|auth[_\s]?key|private[_\s]?key|access[_\s]?key)\b",
    re.IGNORECASE,
)


@test(
    "52",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Comentarios HTML sin datos sensibles",
    severity="MEDIUM",
    cwe="CWE-615",
)
async def test_html_comments(ctx: ScanContext) -> Result:
    """Los comentarios HTML no deben contener información sensible."""
    body = await _fetch_body(ctx)
    if body is None:
        return Result.skip("no se pudo obtener el cuerpo de la respuesta")

    comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
    findings: list[str] = []
    for comment in comments:
        match = _SENSITIVE_COMMENT_PATTERNS.search(comment)
        if match:
            snippet = comment.strip()[:80].replace("\n", " ")
            findings.append(f"'{match.group(0)}' en: {snippet!r}")

    if findings:
        summary = "; ".join(findings[:3])
        return Result.warn(f"{len(findings)} comentario(s) con datos sensibles: {summary}")
    return Result.pass_("comentarios HTML sin datos sensibles detectados")


# ─────────────────────────────────────────────────────────────────────────────
# TEST-53  Contenido mixto (mixed content)
# ─────────────────────────────────────────────────────────────────────────────

_MIXED_CONTENT_RE = re.compile(
    r'(?:src|href|action|data-src)\s*=\s*["\']http://[^"\']+["\']',
    re.IGNORECASE,
)


@test(
    "53",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Sin contenido mixto (HTTP en HTTPS)",
    severity="MEDIUM",
    cwe="CWE-311",
)
async def test_mixed_content(ctx: ScanContext) -> Result:
    """Una página HTTPS no debe cargar recursos activos vía HTTP."""
    body = await _fetch_body(ctx)
    if body is None:
        return Result.skip("no se pudo obtener el cuerpo de la respuesta")

    matches = _MIXED_CONTENT_RE.findall(body)
    if matches:
        samples = matches[:3]
        return Result.warn(
            f"{len(matches)} referencia(s) HTTP en página HTTPS: {'; '.join(s[:80] for s in samples)}"
        )
    return Result.pass_("sin contenido mixto detectado")


# ─────────────────────────────────────────────────────────────────────────────
# TEST-54  Formularios con acción HTTP
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "54",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Formularios con action HTTPS o relativo",
    severity="HIGH",
    cwe="CWE-319",
)
async def test_form_http_action(ctx: ScanContext) -> Result:
    """Los formularios no deben enviar datos a URLs HTTP (sin cifrar)."""
    body = await _fetch_body(ctx)
    if body is None:
        return Result.skip("no se pudo obtener el cuerpo de la respuesta")

    forms_with_http = re.findall(
        r'<form[^>]+action\s*=\s*["\']http://[^"\']+["\'][^>]*>',
        body,
        re.IGNORECASE,
    )
    if forms_with_http:
        snippet = forms_with_http[0][:120]
        return Result.fail(
            f"{len(forms_with_http)} formulario(s) con action HTTP: {snippet}"
        )
    return Result.pass_("formularios sin action HTTP inseguro")


# ─────────────────────────────────────────────────────────────────────────────
# TEST-55  Campos de contraseña servidos por HTTP
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "55",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Campos de contraseña no servidos por HTTP",
    severity="CRITICAL",
    cwe="CWE-319",
)
async def test_password_over_http(ctx: ScanContext) -> Result:
    """Los formularios de contraseña no deben servirse sobre HTTP."""
    http_url = f"http://{ctx.host}/"

    body: Optional[str] = None
    try:
        # Construir cliente HTTP temporal para este test
        transport = httpx.AsyncHTTPTransport(verify=False)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(8.0, connect=4.0),
            follow_redirects=True,
            headers={"User-Agent": "wss/4.0 security-scanner"},
        ) as client:
            r = await client.get(http_url)
            # Si redirige a HTTPS = correcto
            for redirect in r.history:
                if redirect.headers.get("location", "").startswith("https://"):
                    return Result.pass_("HTTP redirige a HTTPS — campos de contraseña protegidos")
            body = r.text[:30000]
    except Exception:
        return Result.skip("no se pudo conectar por HTTP")

    if body is None:
        return Result.skip("sin respuesta HTTP")

    # Buscar campos de contraseña en el cuerpo HTTP
    password_inputs = re.findall(
        r'<input[^>]+type\s*=\s*["\']password["\'][^>]*>',
        body,
        re.IGNORECASE,
    )
    if password_inputs:
        return Result.fail(
            f"{len(password_inputs)} campo(s) de contraseña servidos por HTTP sin cifrado"
        )
    return Result.pass_("sin campos de contraseña detectados en HTTP")
