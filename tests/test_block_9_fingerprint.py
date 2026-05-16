"""Tests unitarios — Bloque 9: Fingerprinting y Content Analysis (TEST-48 a TEST-55)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from wss.core.result import Status
from wss.tests.block_9_fingerprint import (
    test_django_debug as _run_django_debug,
    test_laravel_debug as _run_laravel_debug,
    test_spring_actuator as _run_spring_actuator,
    test_cms_version as _run_cms_version,
    test_html_comments as _run_html_comments,
    test_mixed_content as _run_mixed_content,
    test_form_http_action as _run_form_http_action,
    test_password_over_http as _run_password_over_http,
)
from tests.conftest import make_ctx


def _ctx_with_body(body: str):
    """Contexto cuyo cliente mock devuelve el body indicado para cualquier GET."""
    ctx = make_ctx()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = body
    mock_resp.history = []
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    ctx._client = mock_client
    return ctx


def _ctx_with_url_responses(url_map: dict[str, tuple[int, str]]):
    """Contexto cuyo cliente devuelve respuestas diferentes según la URL."""
    ctx = make_ctx()

    async def mock_get(url, **kwargs):
        url_str = str(url)
        for pattern, (code, body) in url_map.items():
            if pattern in url_str:
                mock_resp = MagicMock(spec=httpx.Response)
                mock_resp.status_code = code
                mock_resp.text = body
                mock_resp.history = []
                return mock_resp
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 404
        mock_resp.text = ""
        mock_resp.history = []
        return mock_resp

    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx._client = mock_client
    return ctx


# ── TEST-48: Django debug ─────────────────────────────────────────────────────


DJANGO_DEBUG_PAGE = """
<html><head><title>RuntimeError at /</title></head><body>
<h1>RuntimeError at /</h1>
<p>You're seeing this error because you have <code>DEBUG = True</code></p>
<p>Django Version: 4.2.7</p>
<p>Request Method: GET</p>
<p>Request URL: http://example.com/</p>
<p>Django settings: myproject.settings</p>
</body></html>
"""


async def test_48_fail_django_debug():
    ctx = _ctx_with_body(DJANGO_DEBUG_PAGE)
    r = await _run_django_debug(ctx)
    assert r.status == Status.FAIL
    assert "Django" in r.detail


async def test_48_pass_normal_page():
    ctx = _ctx_with_body("<html><body><h1>Welcome to my site</h1></body></html>")
    r = await _run_django_debug(ctx)
    assert r.status == Status.PASS


async def test_48_skip_no_response():
    ctx = make_ctx()
    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
    ctx._client = mock_client
    r = await _run_django_debug(ctx)
    assert r.status == Status.SKIP


# ── TEST-49: Laravel debug ────────────────────────────────────────────────────


LARAVEL_DEBUG_PAGE = """
<!DOCTYPE html>
<html><body>
<div class="container">
    <h1>Whoops, looks like something went wrong.</h1>
    <div>vendor/laravel/framework/src/Illuminate/Routing/Router.php</div>
</div>
</body></html>
"""


async def test_49_fail_laravel_debug():
    ctx = _ctx_with_body(LARAVEL_DEBUG_PAGE)
    r = await _run_laravel_debug(ctx)
    assert r.status == Status.FAIL
    assert "Laravel" in r.detail or "Whoops" in r.detail


async def test_49_pass_normal_page():
    ctx = _ctx_with_body("<html><body><p>Welcome!</p></body></html>")
    r = await _run_laravel_debug(ctx)
    assert r.status == Status.PASS


# ── TEST-50: Spring Actuator ──────────────────────────────────────────────────


ACTUATOR_RESPONSE = '{"_links":{"self":{"href":"http://example.com/actuator","templated":false},"health":{"href":"http://example.com/actuator/health","templated":false}}}'


async def test_50_warn_actuator_exposed():
    ctx = _ctx_with_url_responses({"/actuator": (200, ACTUATOR_RESPONSE)})
    r = await _run_spring_actuator(ctx)
    assert r.status == Status.WARN
    assert "Actuator" in r.detail


async def test_50_pass_actuator_404():
    ctx = _ctx_with_url_responses({"/actuator": (404, "")})
    r = await _run_spring_actuator(ctx)
    assert r.status == Status.PASS


# ── TEST-51: CMS version en meta generator ───────────────────────────────────


async def test_51_warn_wordpress_version():
    body = '<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_cms_version(ctx)
    assert r.status == Status.WARN
    assert "6.4.2" in r.detail or "WordPress" in r.detail


async def test_51_warn_joomla_version():
    body = '<html><head><meta name="generator" content="Joomla! 4.3" /></head><body></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_cms_version(ctx)
    assert r.status == Status.WARN


async def test_51_pass_no_version():
    body = '<html><head><meta name="generator" content="My Custom Site" /></head><body></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_cms_version(ctx)
    assert r.status == Status.PASS


async def test_51_pass_no_generator():
    body = "<html><head><title>Test</title></head><body></body></html>"
    ctx = _ctx_with_body(body)
    r = await _run_cms_version(ctx)
    assert r.status == Status.PASS


# ── TEST-52: Comentarios HTML sensibles ──────────────────────────────────────


async def test_52_warn_password_in_comment():
    body = "<!-- password: admin123 --><html><body>Hello</body></html>"
    ctx = _ctx_with_body(body)
    r = await _run_html_comments(ctx)
    assert r.status == Status.WARN
    assert "password" in r.detail.lower()


async def test_52_warn_todo_in_comment():
    body = "<!-- TODO: remove this debug code --><html><body></body></html>"
    ctx = _ctx_with_body(body)
    r = await _run_html_comments(ctx)
    assert r.status == Status.WARN


async def test_52_pass_safe_comment():
    body = "<!-- Main navigation --><html><body><nav>Menu</nav></body></html>"
    ctx = _ctx_with_body(body)
    r = await _run_html_comments(ctx)
    assert r.status == Status.PASS


async def test_52_pass_no_comments():
    body = "<html><body><p>Clean page</p></body></html>"
    ctx = _ctx_with_body(body)
    r = await _run_html_comments(ctx)
    assert r.status == Status.PASS


# ── TEST-53: Mixed content ────────────────────────────────────────────────────


async def test_53_warn_http_img_src():
    body = '<html><body><img src="http://cdn.example.com/img.png"></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_mixed_content(ctx)
    assert r.status == Status.WARN
    assert "http://" in r.detail


async def test_53_warn_http_script_src():
    body = '<html><head><script src="http://example.com/app.js"></script></head></html>'
    ctx = _ctx_with_body(body)
    r = await _run_mixed_content(ctx)
    assert r.status == Status.WARN


async def test_53_pass_all_https():
    body = '<html><body><img src="https://cdn.example.com/img.png"><script src="https://example.com/app.js"></script></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_mixed_content(ctx)
    assert r.status == Status.PASS


# ── TEST-54: Formularios con action HTTP ─────────────────────────────────────


async def test_54_fail_form_http_action():
    body = '<html><body><form action="http://example.com/login" method="post"><input name="user"><input type="submit"></form></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_form_http_action(ctx)
    assert r.status == Status.FAIL
    assert "http://" in r.detail


async def test_54_pass_form_https_action():
    body = '<html><body><form action="https://example.com/login" method="post"></form></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_form_http_action(ctx)
    assert r.status == Status.PASS


async def test_54_pass_form_relative_action():
    body = '<html><body><form action="/login" method="post"></form></body></html>'
    ctx = _ctx_with_body(body)
    r = await _run_form_http_action(ctx)
    assert r.status == Status.PASS


# ── TEST-55: Contraseñas sobre HTTP ──────────────────────────────────────────


async def test_55_fail_password_over_http():
    """Página HTTP con campo de contraseña debe devolver FAIL."""
    body = '<html><body><form><input type="password" name="pwd"></form></body></html>'

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = body
    mock_resp.history = []

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("wss.tests.block_9_fingerprint.httpx.AsyncClient", return_value=mock_client):
        ctx = make_ctx()
        r = await _run_password_over_http(ctx)
    assert r.status == Status.FAIL
    assert "contraseña" in r.detail or "password" in r.detail.lower()


async def test_55_pass_http_redirects_to_https():
    """HTTP que redirige a HTTPS debe devolver PASS."""
    redirect_resp = MagicMock(spec=httpx.Response)
    redirect_resp.status_code = 301
    redirect_resp.headers = {"location": "https://example.com/"}
    redirect_resp.history = []

    final_resp = MagicMock(spec=httpx.Response)
    final_resp.status_code = 200
    final_resp.text = "<html><body>Secure page</body></html>"
    final_resp.history = [redirect_resp]

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=final_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("wss.tests.block_9_fingerprint.httpx.AsyncClient", return_value=mock_client):
        ctx = make_ctx()
        r = await _run_password_over_http(ctx)
    assert r.status == Status.PASS


async def test_55_skip_no_http_response():
    """Excepción al conectar por HTTP debe devolver SKIP."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("wss.tests.block_9_fingerprint.httpx.AsyncClient", return_value=mock_client):
        ctx = make_ctx()
        r = await _run_password_over_http(ctx)
    assert r.status == Status.SKIP
