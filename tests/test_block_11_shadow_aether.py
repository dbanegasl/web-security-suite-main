"""Tests unitarios — Bloque 11: Amenazas activas SHADOW-AETHER."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from wss.core.result import Status
from wss.tests.block_11_shadow_aether import (
    test_webshell_neoregeorg as _run_neoregeorg,
    test_webshell_pow as _run_pow,
    test_admin_jboss as _run_jboss,
    test_admin_tomcat as _run_tomcat,
    test_admin_zimbra as _run_zimbra,
    test_struts2_fingerprint as _run_struts2,
)
from tests.conftest import make_ctx


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_response(status_code: int, body: str = "", headers: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = body
    resp.headers = httpx.Headers(headers or {})
    return resp


def _ctx_with_mock(
    get_map: dict[str, tuple[int, str]] | None = None,
    head_map: dict[str, tuple[int, str]] | None = None,
    get_headers_map: dict[str, tuple[int, str, dict]] | None = None,
    initial_headers: dict | None = None,
):
    """Contexto con cliente mock configurable para GET y HEAD."""
    ctx = make_ctx()

    async def mock_get(url, **kwargs):
        url_str = str(url)
        if get_headers_map:
            for pattern, (code, body, hdrs) in get_headers_map.items():
                if pattern in url_str:
                    return _make_response(code, body, hdrs)
        if get_map:
            for pattern, (code, body) in get_map.items():
                if pattern in url_str:
                    return _make_response(code, body)
        return _make_response(404)

    async def mock_head(url, **kwargs):
        url_str = str(url)
        if head_map:
            for pattern, (code, body) in head_map.items():
                if pattern in url_str:
                    return _make_response(code, body)
        return _make_response(404)

    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=mock_get)
    mock_client.head = AsyncMock(side_effect=mock_head)
    ctx._client = mock_client

    if initial_headers is not None:
        # Poblar la respuesta inicial cacheada para ctx.get_header()
        mock_initial = MagicMock(spec=httpx.Response)
        mock_initial.headers = httpx.Headers(initial_headers)
        ctx._initial_response = mock_initial

    return ctx


def _ctx_all_404():
    """Todos los paths devuelven 404."""
    return _ctx_with_mock()


# ── SA040-WEBSHELL-NEOREGEORG ──────────────────────────────────────────────────


async def test_neoregeorg_pass_all_404():
    ctx = _ctx_all_404()
    r = await _run_neoregeorg(ctx)
    assert r.status == Status.PASS


async def test_neoregeorg_fail_direct_signature():
    ctx = _ctx_with_mock(
        get_map={"/tunnel.php": (200, "NeoGeorg says: 'all seems fine'")}
    )
    r = await _run_neoregeorg(ctx)
    assert r.status == Status.FAIL
    assert "tunnel.php" in r.detail


async def test_neoregeorg_fail_neoreg_path():
    ctx = _ctx_with_mock(
        get_map={"/neoreg.php": (200, "all seems fine")}
    )
    r = await _run_neoregeorg(ctx)
    assert r.status == Status.FAIL


async def test_neoregeorg_warn_heuristic_short_body():
    """Body corto sin HTML ni Set-Cookie debe disparar WARN heurístico."""
    ctx = _ctx_with_mock(
        get_map={"/tunnel.jsp": (200, "OK")}
    )
    r = await _run_neoregeorg(ctx)
    assert r.status == Status.WARN
    assert "tunnel.jsp" in r.detail


async def test_neoregeorg_pass_html_200():
    """Página HTML normal en tunnel.php no debe generar alerta."""
    ctx = _ctx_with_mock(
        get_map={
            "/tunnel.php": (200, "<!DOCTYPE html><html><body>Not Found</body></html>")
        }
    )
    r = await _run_neoregeorg(ctx)
    assert r.status == Status.PASS


async def test_neoregeorg_pass_200_with_cookie():
    """Body corto con Set-Cookie no debe generar WARN heurístico."""
    ctx = _ctx_with_mock(
        get_headers_map={
            "/tunnel.php": (200, "OK", {"set-cookie": "session=abc"})
        }
    )
    r = await _run_neoregeorg(ctx)
    assert r.status == Status.PASS


# ── SA040-WEBSHELL-POW ─────────────────────────────────────────────────────────


async def test_pow_pass_all_404():
    ctx = _ctx_all_404()
    r = await _run_pow(ctx)
    assert r.status == Status.PASS


async def test_pow_fail_two_patterns():
    ctx = _ctx_with_mock(
        head_map={"/pow.jsp": (200, "")},
        get_map={"/pow.jsp": (200, '<input name="cmd"> Runtime.exec( /bin/sh')}
    )
    r = await _run_pow(ctx)
    assert r.status == Status.FAIL
    assert "pow.jsp" in r.detail


async def test_pow_warn_one_pattern():
    ctx = _ctx_with_mock(
        head_map={"/shell/pow.jsp": (200, "")},
        get_map={"/shell/pow.jsp": (200, '<input name="cmd"> some other content')}
    )
    r = await _run_pow(ctx)
    assert r.status == Status.WARN


async def test_pow_pass_head_404():
    """HEAD 404 → no debe hacer GET ni reportar alerta."""
    ctx = _ctx_with_mock(
        head_map={},
        get_map={"/pow.jsp": (200, "Runtime.exec( ProcessBuilder cmd.exe")}
    )
    r = await _run_pow(ctx)
    assert r.status == Status.PASS


# ── SA040-ADMIN-JBOSS ─────────────────────────────────────────────────────────


async def test_jboss_pass_all_404():
    ctx = _ctx_all_404()
    r = await _run_jboss(ctx)
    assert r.status == Status.PASS


async def test_jboss_fail_jmx_console_exposed():
    ctx = _ctx_with_mock(
        get_map={
            "/jmx-console/": (200, "JBoss JMX Management Console — MBean View")
        }
    )
    r = await _run_jboss(ctx)
    assert r.status == Status.FAIL
    assert "jmx-console" in r.detail


async def test_jboss_fail_html_adaptor():
    ctx = _ctx_with_mock(
        get_map={
            "/jmx-console/HtmlAdaptor": (200, "jboss.system:type=ServerInfo")
        }
    )
    r = await _run_jboss(ctx)
    assert r.status == Status.FAIL


async def test_jboss_warn_401():
    ctx = _ctx_with_mock(
        get_map={"/jmx-console/": (401, "")}
    )
    r = await _run_jboss(ctx)
    assert r.status == Status.WARN


async def test_jboss_warn_200_no_signature_critical_path():
    ctx = _ctx_with_mock(
        get_map={"/jmx-console/": (200, "<html><body>Some page</body></html>")}
    )
    r = await _run_jboss(ctx)
    assert r.status == Status.WARN


# ── SA040-ADMIN-TOMCAT ────────────────────────────────────────────────────────


async def test_tomcat_pass_all_404():
    ctx = _ctx_all_404()
    r = await _run_tomcat(ctx)
    assert r.status == Status.PASS


async def test_tomcat_fail_manager_exposed():
    ctx = _ctx_with_mock(
        get_map={
            "/manager/html": (200, "Tomcat Web Application Manager — Deploy")
        }
    )
    r = await _run_tomcat(ctx)
    assert r.status == Status.FAIL
    assert "manager" in r.detail.lower()


async def test_tomcat_warn_401_tomcat_realm():
    ctx = _ctx_with_mock(
        get_headers_map={
            "/manager/html": (
                401,
                "",
                {"www-authenticate": 'Basic realm="Tomcat Manager Application"'},
            )
        }
    )
    r = await _run_tomcat(ctx)
    assert r.status == Status.WARN


async def test_tomcat_pass_401_no_tomcat_realm():
    ctx = _ctx_with_mock(
        get_headers_map={
            "/manager/html": (
                401,
                "",
                {"www-authenticate": 'Basic realm="Restricted"'},
            )
        }
    )
    r = await _run_tomcat(ctx)
    assert r.status == Status.PASS


# ── SA040-ADMIN-ZIMBRA ────────────────────────────────────────────────────────


async def test_zimbra_pass_all_404():
    ctx = _ctx_with_mock(initial_headers={})
    r = await _run_zimbra(ctx)
    assert r.status == Status.PASS


async def test_zimbra_warn_initial_header():
    ctx = _ctx_with_mock(
        initial_headers={"x-zimbra-version": "8.8.15"}
    )
    r = await _run_zimbra(ctx)
    assert r.status == Status.WARN
    assert "8.8.15" in r.detail


async def test_zimbra_fail_admin_console_exposed():
    ctx = _ctx_with_mock(
        initial_headers={},
        get_map={"/zimbraAdmin/": (200, "Zimbra Administration Console — Login")},
    )
    r = await _run_zimbra(ctx)
    assert r.status == Status.FAIL
    assert "zimbraAdmin" in r.detail


async def test_zimbra_warn_path_header():
    ctx = _ctx_with_mock(
        initial_headers={},
        get_headers_map={
            "/service/admin/soap/": (200, "", {"x-zimbra-version": "9.0.0"})
        },
    )
    r = await _run_zimbra(ctx)
    assert r.status == Status.WARN


async def test_zimbra_warn_redirect_to_zimbra():
    ctx = _ctx_with_mock(
        initial_headers={},
        get_headers_map={
            "/zimbraAdmin/": (302, "", {"location": "https://mail.example.com/zimbraAdmin/login"})
        },
    )
    r = await _run_zimbra(ctx)
    assert r.status == Status.WARN


# ── SA040-STRUTS2-FINGERPRINT ─────────────────────────────────────────────────


async def test_struts2_pass_nothing():
    ctx = _ctx_with_mock(initial_headers={})
    r = await _run_struts2(ctx)
    assert r.status == Status.PASS


async def test_struts2_warn_xpoweredby():
    ctx = _ctx_with_mock(
        initial_headers={"x-powered-by": "Struts2/2.5.26"}
    )
    r = await _run_struts2(ctx)
    assert r.status == Status.WARN
    assert "Struts" in r.detail


async def test_struts2_fail_webconsole():
    ctx = _ctx_with_mock(
        initial_headers={},
        get_map={
            "/struts/webconsole.html": (200, "OGNL expression console — Struts2 Webconsole")
        },
    )
    r = await _run_struts2(ctx)
    assert r.status == Status.FAIL
    assert "webconsole" in r.detail.lower()


async def test_struts2_warn_stacktrace():
    ctx = _ctx_with_mock(
        initial_headers={},
        get_map={
            "/struts/webconsole.html": (404, ""),
            "/index.action": (
                500,
                "org.apache.struts2.dispatcher.Dispatcher — Stack trace",
            ),
        },
    )
    r = await _run_struts2(ctx)
    assert r.status == Status.WARN
    assert "struts2" in r.detail.lower()


async def test_struts2_pass_action_200_no_signature():
    ctx = _ctx_with_mock(
        initial_headers={},
        get_map={
            "/struts/webconsole.html": (404, ""),
            "/index.action": (200, "<html><body>Welcome</body></html>"),
        },
    )
    r = await _run_struts2(ctx)
    assert r.status == Status.PASS
