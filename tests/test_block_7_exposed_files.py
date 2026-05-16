"""Tests unitarios — Bloque 7: Archivos y rutas expuestas (TEST-26 a TEST-40)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from wss.core.result import Status
from wss.tests.block_7_exposed_files import (
    test_env_exposed as _run_env_exposed,
    test_git_exposed as _run_git_exposed,
    test_svn_hg_exposed as _run_svn_hg_exposed,
    test_sql_dumps_exposed as _run_sql_dumps_exposed,
    test_backup_files_exposed as _run_backup_files_exposed,
    test_phpinfo_exposed as _run_phpinfo_exposed,
    test_security_txt as _run_security_txt,
    test_server_status_exposed as _run_server_status_exposed,
    test_admin_panels as _run_admin_panels,
    test_config_files_exposed as _run_config_files_exposed,
    test_dependency_manifests as _run_dependency_manifests,
    test_crossdomain_wildcard as _run_crossdomain_wildcard,
    test_api_docs_exposed as _run_api_docs_exposed,
    test_actuator_exposed as _run_actuator_exposed,
    test_ds_store_exposed as _run_ds_store_exposed,
)
from tests.conftest import make_ctx


def _ctx_with_url_map(url_map: dict[str, tuple[int, str]]):
    """Contexto con cliente mock que devuelve respuestas según el path de la URL."""
    ctx = make_ctx()

    async def mock_get(url, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        for pattern, (code, body) in url_map.items():
            if str(url).endswith(pattern) or pattern in str(url):
                resp.status_code = code
                resp.text = body
                resp.history = []
                return resp
        resp.status_code = 404
        resp.text = ""
        resp.history = []
        return resp

    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx._client = mock_client
    return ctx


def _ctx_404():
    """Contexto donde todas las rutas devuelven 404."""
    return _ctx_with_url_map({})


# ── TEST-26: .env expuesto ────────────────────────────────────────────────────


async def test_26_fail_env_exposed():
    ctx = _ctx_with_url_map({"/.env": (200, "APP_KEY=base64:xxx\nDB_PASSWORD=secret")})
    r = await _run_env_exposed(ctx)
    assert r.status == Status.FAIL
    assert ".env" in r.detail


async def test_26_pass_all_404():
    ctx = _ctx_404()
    r = await _run_env_exposed(ctx)
    assert r.status == Status.PASS


async def test_26_pass_html_200_on_404():
    """CMS que devuelven 200 con HTML no deben generar FAIL."""
    ctx = _ctx_with_url_map({
        "/.env": (200, "<!DOCTYPE html><html><body>Not Found</body></html>"),
    })
    r = await _run_env_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-27: .git expuesto ────────────────────────────────────────────────────


async def test_27_fail_git_head():
    ctx = _ctx_with_url_map({"/.git/HEAD": (200, "ref: refs/heads/main\n")})
    r = await _run_git_exposed(ctx)
    assert r.status == Status.FAIL
    assert "Git" in r.detail


async def test_27_fail_git_config():
    ctx = _ctx_with_url_map({"/.git/config": (200, "[core]\n\trepositoryformatversion = 0\n")})
    r = await _run_git_exposed(ctx)
    assert r.status == Status.FAIL


async def test_27_pass():
    ctx = _ctx_404()
    r = await _run_git_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-28: SVN/HG expuestos ─────────────────────────────────────────────────


async def test_28_fail_svn():
    ctx = _ctx_with_url_map({"/.svn/entries": (200, "10\n\ndir\n")})
    r = await _run_svn_hg_exposed(ctx)
    assert r.status == Status.FAIL


async def test_28_pass():
    ctx = _ctx_404()
    r = await _run_svn_hg_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-29: Volcados SQL ─────────────────────────────────────────────────────


async def test_29_fail_sql_dump():
    ctx = _ctx_with_url_map({
        "/backup.sql": (200, "-- MySQL dump\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);"),
    })
    r = await _run_sql_dumps_exposed(ctx)
    assert r.status == Status.FAIL
    assert "SQL" in r.detail


async def test_29_pass():
    ctx = _ctx_404()
    r = await _run_sql_dumps_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-30: Archivos de backup ───────────────────────────────────────────────


async def test_30_warn_backup():
    ctx = _ctx_with_url_map({"/index.bak": (200, "<?php // backup content with lots of stuff here")})
    r = await _run_backup_files_exposed(ctx)
    assert r.status == Status.WARN


async def test_30_pass():
    ctx = _ctx_404()
    r = await _run_backup_files_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-31: phpinfo ──────────────────────────────────────────────────────────


async def test_31_fail_phpinfo():
    ctx = _ctx_with_url_map({"/phpinfo.php": (200, "<html>PHP Version 8.2.0 — phpinfo()</html>")})
    r = await _run_phpinfo_exposed(ctx)
    assert r.status == Status.FAIL
    assert "phpinfo" in r.detail.lower()


async def test_31_pass():
    ctx = _ctx_404()
    r = await _run_phpinfo_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-32: security.txt ─────────────────────────────────────────────────────


async def test_32_pass_present():
    ctx = _ctx_with_url_map({
        "/.well-known/security.txt": (200, "Contact: mailto:security@example.com\nExpires: 2026-01-01T00:00:00Z"),
    })
    r = await _run_security_txt(ctx)
    assert r.status == Status.PASS


async def test_32_warn_absent():
    ctx = _ctx_404()
    r = await _run_security_txt(ctx)
    assert r.status == Status.WARN


# ── TEST-33: server-status ────────────────────────────────────────────────────


async def test_33_fail_server_status():
    ctx = _ctx_with_url_map({
        "/server-status": (200, "Apache Server Status for example.com — requests currently being processed: 5"),
    })
    r = await _run_server_status_exposed(ctx)
    assert r.status == Status.FAIL


async def test_33_pass_403():
    ctx = _ctx_with_url_map({"/server-status": (403, ""), "/server-info": (403, "")})
    r = await _run_server_status_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-34: Admin panels ─────────────────────────────────────────────────────


async def test_34_warn_wp_admin_200():
    ctx = _ctx_with_url_map({"/wp-admin/": (200, "<html><title>Dashboard — WordPress</title></html>")})
    r = await _run_admin_panels(ctx)
    assert r.status == Status.WARN


async def test_34_pass_all_401():
    ctx = _ctx_with_url_map({
        "/wp-admin/": (401, ""), "/wp-login.php": (200, ""),
        "/administrator/": (401, ""), "/phpmyadmin/": (401, ""), "/pma/": (404, ""),
    })
    # wp-login.php devuelve 200 normalmente (login page)
    r = await _run_admin_panels(ctx)
    assert r.status in (Status.PASS, Status.WARN)


# ── TEST-35: Archivos de configuración ───────────────────────────────────────


async def test_35_fail_htaccess():
    ctx = _ctx_with_url_map({
        "/.htaccess": (200, "RewriteEngine On\nOptions -Indexes\nAuthType Basic"),
    })
    r = await _run_config_files_exposed(ctx)
    assert r.status == Status.FAIL
    assert ".htaccess" in r.detail


async def test_35_fail_htpasswd():
    ctx = _ctx_with_url_map({"/.htpasswd": (200, "admin:$apr1$xyz$hashedpassword")})
    r = await _run_config_files_exposed(ctx)
    assert r.status == Status.FAIL


async def test_35_fail_webconfig():
    ctx = _ctx_with_url_map({
        "/web.config": (200, '<?xml version="1.0"?><configuration><system.webServer/></configuration>'),
    })
    r = await _run_config_files_exposed(ctx)
    assert r.status == Status.FAIL


async def test_35_pass_403():
    ctx = _ctx_with_url_map({"/.htaccess": (403, ""), "/.htpasswd": (403, ""), "/web.config": (403, "")})
    r = await _run_config_files_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-36: Manifiestos de dependencias ─────────────────────────────────────


async def test_36_warn_composer():
    ctx = _ctx_with_url_map({
        "/composer.json": (200, '{"require": {"php": "^8.1", "laravel/framework": "^10.0"}}'),
    })
    r = await _run_dependency_manifests(ctx)
    assert r.status == Status.WARN
    assert "composer.json" in r.detail


async def test_36_warn_package_json():
    ctx = _ctx_with_url_map({
        "/package.json": (200, '{"name": "myapp", "version": "1.0.0", "dependencies": {"express": "^4.18"}}'),
    })
    r = await _run_dependency_manifests(ctx)
    assert r.status == Status.WARN


async def test_36_pass():
    ctx = _ctx_404()
    r = await _run_dependency_manifests(ctx)
    assert r.status == Status.PASS


# ── TEST-37: crossdomain.xml wildcard ────────────────────────────────────────


async def test_37_fail_wildcard():
    ctx = _ctx_with_url_map({
        "/crossdomain.xml": (200, '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>'),
    })
    r = await _run_crossdomain_wildcard(ctx)
    assert r.status == Status.FAIL


async def test_37_pass_absent():
    ctx = _ctx_404()
    r = await _run_crossdomain_wildcard(ctx)
    assert r.status == Status.PASS


async def test_37_pass_restricted():
    ctx = _ctx_with_url_map({
        "/crossdomain.xml": (200, '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="api.example.com"/></cross-domain-policy>'),
    })
    r = await _run_crossdomain_wildcard(ctx)
    assert r.status == Status.PASS


# ── TEST-38: API docs expuestos ───────────────────────────────────────────────


async def test_38_warn_swagger():
    ctx = _ctx_with_url_map({
        "/swagger.json": (200, '{"swagger":"2.0","info":{"title":"My API"},"paths":{}}'),
    })
    r = await _run_api_docs_exposed(ctx)
    assert r.status == Status.WARN


async def test_38_pass():
    ctx = _ctx_404()
    r = await _run_api_docs_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-39: Spring Actuator ──────────────────────────────────────────────────


async def test_39_fail_actuator_env():
    ctx = _ctx_with_url_map({
        "/actuator/env": (200, '{"activeProfiles":[],"propertySources":[{"name":"systemEnvironment","properties":{"datasource.password":{"value":"secret"}}}]}'),
    })
    r = await _run_actuator_exposed(ctx)
    assert r.status == Status.FAIL
    assert "actuator" in r.detail.lower()


async def test_39_warn_actuator_health():
    ctx = _ctx_with_url_map({
        "/actuator/health": (200, '{"status":"UP","components":{"db":{"status":"UP"}}}'),
    })
    r = await _run_actuator_exposed(ctx)
    assert r.status == Status.WARN


async def test_39_pass():
    ctx = _ctx_404()
    r = await _run_actuator_exposed(ctx)
    assert r.status == Status.PASS


# ── TEST-40: .DS_Store ────────────────────────────────────────────────────────


async def test_40_fail_ds_store():
    ctx = _ctx_with_url_map({
        "/.DS_Store": (200, "Bud1" + "x" * 200),
    })
    r = await _run_ds_store_exposed(ctx)
    assert r.status == Status.FAIL


async def test_40_pass_404():
    ctx = _ctx_404()
    r = await _run_ds_store_exposed(ctx)
    assert r.status == Status.PASS
