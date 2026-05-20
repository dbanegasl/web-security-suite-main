"""Bloque 7 — Archivos y rutas expuestas (EXPOSED-ENV a EXPOSED-DS-STORE)."""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result

_BLOCK = 7
_BLOCK_NAME = "Archivos y rutas expuestas"


async def _probe(ctx: ScanContext, path: str) -> Optional[tuple[int, str]]:
    """GET a https://host/path. Devuelve (status_code, body[:2000]) o None."""
    try:
        url = f"https://{ctx.host}{path}"
        r = await ctx.client.get(url)
        return r.status_code, r.text[:2000]
    except Exception:
        return None


def _is_html_error(body: str) -> bool:
    """Detecta páginas de error HTML que devuelven 200 (CMS 404 = 200)."""
    lower = body.lower()
    return any(
        kw in lower
        for kw in [
            "<!doctype html",
            "<html",
            "not found",
            "page not found",
            "404 error",
            "no encontrado",
        ]
    )


async def _probe_many(
    ctx: ScanContext, paths: list[str]
) -> list[tuple[str, int, str]]:
    """Prueba varias rutas en paralelo. Devuelve [(path, code, body), ...]."""
    results = await asyncio.gather(*(_probe(ctx, p) for p in paths))
    out = []
    for path, res in zip(paths, results):
        if res is not None:
            out.append((path, res[0], res[1]))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-ENV  Archivos .env expuestos
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-ENV",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Archivos .env no expuestos",
    severity="CRITICAL",
    cwe="CWE-200",
)
async def test_env_exposed(ctx: ScanContext) -> Result:
    """/.env, /.env.local y /.env.production no deben ser accesibles."""
    paths = ["/.env", "/.env.local", "/.env.production"]
    probed = await _probe_many(ctx, paths)

    for path, code, body in probed:
        if code == 200 and "=" in body and not _is_html_error(body):
            return Result.fail(f"{path} accesible — contiene variables de entorno")
    return Result.pass_("archivos .env no expuestos")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-GIT  Repositorio Git expuesto
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-GIT",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Repositorio .git no expuesto",
    severity="CRITICAL",
    cwe="CWE-200",
)
async def test_git_exposed(ctx: ScanContext) -> Result:
    """/.git/HEAD y /.git/config no deben ser accesibles."""
    probed = await _probe_many(ctx, ["/.git/HEAD", "/.git/config"])
    for path, code, body in probed:
        if code == 200:
            if path.endswith("HEAD") and body.startswith("ref:"):
                return Result.fail(f"{path} accesible — repositorio Git expuesto")
            if path.endswith("config") and "[core]" in body:
                return Result.fail(f"{path} accesible — configuración Git expuesta")
    return Result.pass_("repositorio .git no expuesto")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-SVN-HG  Repositorios SVN/HG expuestos
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-SVN-HG",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Repositorios SVN/HG no expuestos",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_svn_hg_exposed(ctx: ScanContext) -> Result:
    """/.svn/entries y /.hg/hgrc no deben ser accesibles."""
    probed = await _probe_many(ctx, ["/.svn/entries", "/.hg/hgrc"])
    for path, code, body in probed:
        if code == 200 and not _is_html_error(body):
            return Result.fail(f"{path} accesible — repositorio de control de versiones expuesto")
    return Result.pass_("repositorios SVN/HG no expuestos")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-SQL-DUMPS  Volcados de base de datos expuestos
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-SQL-DUMPS",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Volcados SQL no expuestos",
    severity="CRITICAL",
    cwe="CWE-530",
)
async def test_sql_dumps_exposed(ctx: ScanContext) -> Result:
    """Archivos .sql no deben ser accesibles."""
    paths = ["/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/mysql.sql"]
    probed = await _probe_many(ctx, paths)
    for path, code, body in probed:
        if code == 200:
            body_lower = body.lower()
            if any(kw in body_lower for kw in ["create table", "insert into", "drop table", "--"]):
                return Result.fail(f"{path} accesible — volcado SQL expuesto")
    return Result.pass_("volcados SQL no expuestos")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-BACKUP-FILES  Archivos de copia de seguridad expuestos
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-BACKUP-FILES",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Archivos de backup no expuestos",
    severity="HIGH",
    cwe="CWE-530",
)
async def test_backup_files_exposed(ctx: ScanContext) -> Result:
    """Archivos .bak, .old, .orig, .swp, .tmp no deben ser accesibles."""
    paths = [
        "/index.bak", "/index.php.bak", "/config.bak",
        "/index.old", "/index.php.old",
        "/index.orig", "/.htaccess.bak", "/web.config.bak",
        "/config.php.swp", "/index.php.tmp",
    ]
    probed = await _probe_many(ctx, paths)
    found = []
    for path, code, body in probed:
        if code == 200 and len(body) > 20 and not _is_html_error(body):
            found.append(path)
    if found:
        return Result.warn(f"posibles backups accesibles: {', '.join(found)}")
    return Result.pass_("archivos de backup no expuestos")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-PHPINFO  Páginas phpinfo expuestas
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-PHPINFO",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Página phpinfo no expuesta",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_phpinfo_exposed(ctx: ScanContext) -> Result:
    """phpinfo.php, info.php y test.php no deben exponer información PHP."""
    paths = ["/phpinfo.php", "/info.php", "/test.php", "/php_info.php"]
    probed = await _probe_many(ctx, paths)
    for path, code, body in probed:
        if code == 200 and "PHP Version" in body:
            return Result.fail(f"{path} accesible — phpinfo() activo")
    return Result.pass_("páginas phpinfo no expuestas")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-SECURITY-TXT  Archivo security.txt presente
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-SECURITY-TXT",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="security.txt presente (RFC 9116)",
    severity="LOW",
    cwe=None,
)
async def test_security_txt(ctx: ScanContext) -> Result:
    """/.well-known/security.txt debe estar presente (RFC 9116)."""
    paths = ["/.well-known/security.txt", "/security.txt"]
    probed = await _probe_many(ctx, paths)
    for path, code, body in probed:
        if code == 200 and "contact:" in body.lower():
            return Result.pass_(f"security.txt encontrado en {path}")
    return Result.warn("security.txt ausente — recomendado por RFC 9116")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-SERVER-STATUS  Páginas de estado del servidor expuestas
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-SERVER-STATUS",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Páginas de estado del servidor no expuestas",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_server_status_exposed(ctx: ScanContext) -> Result:
    """/server-status y /server-info de Apache no deben ser accesibles."""
    probed = await _probe_many(ctx, ["/server-status", "/server-info"])
    for path, code, body in probed:
        if code == 200:
            body_lower = body.lower()
            if any(kw in body_lower for kw in ["apache", "server version", "requests currently being processed"]):
                return Result.fail(f"{path} accesible — información de servidor expuesta")
    return Result.pass_("páginas de estado no expuestas")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-ADMIN-PANELS  Paneles de administración sin protección
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-ADMIN-PANELS",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Paneles de administración protegidos",
    severity="HIGH",
    cwe="CWE-284",
)
async def test_admin_panels(ctx: ScanContext) -> Result:
    """wp-admin, phpmyadmin y paneles similares deben requerir autenticación."""
    paths = ["/wp-admin/", "/wp-login.php", "/administrator/", "/phpmyadmin/", "/pma/"]
    probed = await _probe_many(ctx, paths)
    found = []
    for path, code, body in probed:
        # 200 = panel accesible (login page o interfaz abierta) — siempre sospechoso
        if code == 200:
            found.append(f"{path} ({code})")
        # 301/302 sin pasar por auth = redirección interna sospechosa
        elif code in (301, 302):
            found.append(f"{path} ({code} redirect)")
    if found:
        return Result.warn(f"paneles accesibles sin verificar auth: {', '.join(found)}")
    return Result.pass_("paneles de administración protegidos o inexistentes")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-CONFIG-FILES  Archivos de configuración del servidor expuestos
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-CONFIG-FILES",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Archivos de configuración no expuestos",
    severity="CRITICAL",
    cwe="CWE-200",
)
async def test_config_files_exposed(ctx: ScanContext) -> Result:
    """.htaccess, .htpasswd y web.config no deben ser accesibles."""
    probed = await _probe_many(ctx, ["/.htaccess", "/.htpasswd", "/web.config"])
    for path, code, body in probed:
        if code == 200 and not _is_html_error(body):
            if path.endswith(".htaccess") and any(
                kw in body.lower() for kw in ["rewriteengine", "options", "authtype", "deny from", "allow from"]
            ):
                return Result.fail(f"{path} accesible — configuración Apache expuesta")
            if path.endswith(".htpasswd") and re.search(r"\w+:\$", body):
                return Result.fail(f"{path} accesible — credenciales hash expuestas")
            if path.endswith("web.config") and "<configuration" in body.lower():
                return Result.fail(f"{path} accesible — configuración IIS expuesta")
    return Result.pass_("archivos de configuración no expuestos")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-DEPENDENCY-MANIFESTS  Manifiestos de dependencias expuestos
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-DEPENDENCY-MANIFESTS",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Manifiestos de dependencias no expuestos",
    severity="MEDIUM",
    cwe="CWE-200",
)
async def test_dependency_manifests(ctx: ScanContext) -> Result:
    """composer.json, package.json, Gemfile.lock y requirements.txt no deben ser accesibles."""
    paths = ["/composer.json", "/package.json", "/Gemfile.lock", "/requirements.txt"]
    probed = await _probe_many(ctx, paths)
    found = []
    for path, code, body in probed:
        if code == 200 and not _is_html_error(body):
            # Verificar que contiene versiones/dependencias (no solo una página de error)
            if path.endswith(".json"):
                if '"require"' in body or '"dependencies"' in body or '"version"' in body:
                    found.append(path)
            elif path.endswith(".lock") and "GEM" in body:
                found.append(path)
            elif path.endswith(".txt") and re.search(r"\w+[>=<~!]+\d", body):
                found.append(path)
    if found:
        return Result.warn(f"manifiestos de dependencias accesibles: {', '.join(found)}")
    return Result.pass_("manifiestos de dependencias no expuestos")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-CROSSDOMAIN-WILDCARD  Políticas de acceso entre dominios inseguras
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-CROSSDOMAIN-WILDCARD",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="crossdomain.xml sin wildcard",
    severity="HIGH",
    cwe="CWE-942",
)
async def test_crossdomain_wildcard(ctx: ScanContext) -> Result:
    """crossdomain.xml y clientaccesspolicy.xml no deben permitir acceso universal."""
    paths = ["/crossdomain.xml", "/clientaccesspolicy.xml"]
    probed = await _probe_many(ctx, paths)
    for path, code, body in probed:
        if code == 200:
            if 'domain="*"' in body or "allow-access-from-identity" in body:
                return Result.fail(f"{path} con wildcard '*' — permite acceso universal")
    return Result.pass_("crossdomain.xml sin wildcard o no presente")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-API-DOCS  Documentación de API expuesta
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-API-DOCS",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Documentación de API no expuesta públicamente",
    severity="MEDIUM",
    cwe="CWE-284",
)
async def test_api_docs_exposed(ctx: ScanContext) -> Result:
    """/swagger.json, /openapi.json, /api-docs y /graphql no deben ser accesibles sin autenticación."""
    paths = ["/swagger.json", "/openapi.json", "/api-docs", "/api-docs/", "/graphql"]
    probed = await _probe_many(ctx, paths)
    found = []
    for path, code, body in probed:
        if code == 200 and not _is_html_error(body):
            body_lower = body.lower()
            if any(kw in body_lower for kw in ["swagger", "openapi", "paths", "graphql", "query"]):
                found.append(path)
    if found:
        return Result.warn(f"documentación de API accesible: {', '.join(found)}")
    return Result.pass_("documentación de API no expuesta o protegida")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-SPRING-ACTUATOR  Endpoints de Spring Actuator expuestos
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-SPRING-ACTUATOR",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Spring Actuator no expuesto",
    severity="HIGH",
    cwe="CWE-200",
)
async def test_actuator_exposed(ctx: ScanContext) -> Result:
    """/actuator/env, /actuator/health e /actuator/info no deben exponer datos sensibles."""
    paths = ["/actuator/env", "/actuator/health", "/actuator/info", "/actuator"]
    probed = await _probe_many(ctx, paths)
    for path, code, body in probed:
        if code == 200 and not _is_html_error(body):
            body_lower = body.lower()
            if path.endswith("/env") and any(
                kw in body_lower for kw in ["datasource", "password", "secret", "token"]
            ):
                return Result.fail(f"{path} expone variables de entorno sensibles")
            if any(kw in body_lower for kw in ["_links", "status", "components"]):
                return Result.warn(f"{path} accesible — endpoint Actuator expuesto")
    return Result.pass_("endpoints Spring Actuator no expuestos")


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSED-DS-STORE  Archivo .DS_Store expuesto
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "EXPOSED-DS-STORE",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Archivo .DS_Store no expuesto",
    severity="MEDIUM",
    cwe="CWE-200",
)
async def test_ds_store_exposed(ctx: ScanContext) -> Result:
    """/.DS_Store no debe ser accesible (revela estructura de directorios macOS)."""
    res = await _probe(ctx, "/.DS_Store")
    if res is None:
        return Result.skip("no se pudo conectar")
    code, body = res
    if code == 200 and not _is_html_error(body) and (
        body.startswith("\x00\x00\x00") or "Bud1" in body[:20] or len(body) > 100
    ):
        return Result.fail("/.DS_Store accesible — revela estructura de directorios")
    return Result.pass_(".DS_Store no expuesto")
