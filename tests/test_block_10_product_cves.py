"""Tests unitarios — Bloque 10: Vulnerabilidades de producto."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from wss.core.result import Status
from wss.tests.block_10_product_cves import (
    test_cve_nginx_version as _run_cve_version,
    test_cve_nginx_http2 as _run_cve_http2,
    test_nginx_status_exposed as _run_nginx_status,
    test_webshell_detected as _run_webshell,
    _parse_nginx_version,
    _nginx_vulnerable_42945,
    _nginx_vulnerable_42926,
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
    initial_headers: dict | None = None,
) -> "ScanContext":
    """Contexto con cliente mock configurable para GET y HEAD."""
    ctx = make_ctx()

    async def mock_get(url, **kwargs):
        url_str = str(url)
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
        mock_initial = MagicMock(spec=httpx.Response)
        mock_initial.headers = httpx.Headers(initial_headers)
        ctx._initial_response = mock_initial

    return ctx


def _ctx_all_404(initial_headers: dict | None = None):
    """Todos los paths devuelven 404."""
    return _ctx_with_mock(initial_headers=initial_headers)


# ── Helpers internos ──────────────────────────────────────────────────────────


class TestParseNginxVersion:
    def test_standard_version(self):
        assert _parse_nginx_version("nginx/1.24.0") == (1, 24, 0)

    def test_with_extra_info(self):
        assert _parse_nginx_version("nginx/1.30.0 (Ubuntu)") == (1, 30, 0)

    def test_old_version(self):
        assert _parse_nginx_version("nginx/0.6.27") == (0, 6, 27)

    def test_no_nginx(self):
        assert _parse_nginx_version("Apache/2.4.51") is None

    def test_empty_string(self):
        assert _parse_nginx_version("") is None

    def test_none_input(self):
        assert _parse_nginx_version(None) is None

    def test_partial_version(self):
        # Sin parche — no debe coincidir (requiere X.Y.Z)
        assert _parse_nginx_version("nginx/1.24") is None


class TestNginxVulnerable42945:
    def test_lower_bound_inclusive(self):
        assert _nginx_vulnerable_42945((0, 6, 27)) is True

    def test_upper_bound_inclusive(self):
        assert _nginx_vulnerable_42945((1, 30, 0)) is True

    def test_below_lower_bound(self):
        assert _nginx_vulnerable_42945((0, 6, 26)) is False

    def test_above_upper_bound(self):
        assert _nginx_vulnerable_42945((1, 30, 1)) is False

    def test_latest_stable_safe(self):
        assert _nginx_vulnerable_42945((1, 31, 0)) is False

    def test_mid_range(self):
        assert _nginx_vulnerable_42945((1, 24, 0)) is True


class TestNginxVulnerable42926:
    def test_lower_bound_inclusive(self):
        assert _nginx_vulnerable_42926((1, 29, 4)) is True

    def test_upper_bound_inclusive(self):
        assert _nginx_vulnerable_42926((1, 30, 0)) is True

    def test_below_lower_bound(self):
        assert _nginx_vulnerable_42926((1, 29, 3)) is False

    def test_above_upper_bound(self):
        assert _nginx_vulnerable_42926((1, 30, 1)) is False

    def test_old_version_not_affected(self):
        assert _nginx_vulnerable_42926((1, 24, 0)) is False


# ── CVE-NGINX-VERSION ─────────────────────────────────────────────────────────


class TestCveNginxVersion:
    async def test_vulnerable_version_fails(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.24.0"})
        r = await _run_cve_version(ctx)
        assert r.status == Status.FAIL
        assert "1.24.0" in r.detail

    async def test_safe_version_passes(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.30.1"})
        r = await _run_cve_version(ctx)
        assert r.status == Status.PASS
        assert "1.30.1" in r.detail

    async def test_upper_bound_vulnerable(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.30.0"})
        r = await _run_cve_version(ctx)
        assert r.status == Status.FAIL
        assert "1.30.0" in r.detail

    async def test_no_nginx_header_skips(self):
        ctx = _ctx_all_404(initial_headers={"server": "Apache/2.4.51"})
        r = await _run_cve_version(ctx)
        assert r.status == Status.SKIP

    async def test_missing_server_header_skips(self):
        ctx = _ctx_all_404(initial_headers={})
        r = await _run_cve_version(ctx)
        assert r.status == Status.SKIP

    async def test_old_version_vulnerable(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/0.6.27"})
        r = await _run_cve_version(ctx)
        assert r.status == Status.FAIL

    async def test_very_old_version_not_vulnerable(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/0.6.26"})
        r = await _run_cve_version(ctx)
        assert r.status == Status.PASS

    async def test_mainline_safe(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.31.0"})
        r = await _run_cve_version(ctx)
        assert r.status == Status.PASS


# ── CVE-NGINX-HTTP2 ──────────────────────────────────────────────────────────


class TestCveNginxHttp2:
    async def test_vulnerable_version_warns(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.29.4"})
        r = await _run_cve_http2(ctx)
        assert r.status == Status.WARN
        assert "1.29.4" in r.detail

    async def test_upper_bound_warns(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.30.0"})
        r = await _run_cve_http2(ctx)
        assert r.status == Status.WARN

    async def test_safe_version_passes(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.30.1"})
        r = await _run_cve_http2(ctx)
        assert r.status == Status.PASS

    async def test_old_version_not_affected(self):
        # 1.24.0 no está en rango 1.29.4 – 1.30.0 → PASS
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.24.0"})
        r = await _run_cve_http2(ctx)
        assert r.status == Status.PASS

    async def test_no_nginx_skips(self):
        ctx = _ctx_all_404(initial_headers={"server": "Caddy"})
        r = await _run_cve_http2(ctx)
        assert r.status == Status.SKIP

    async def test_missing_server_header_skips(self):
        ctx = _ctx_all_404(initial_headers={})
        r = await _run_cve_http2(ctx)
        assert r.status == Status.SKIP

    async def test_below_lower_bound_passes(self):
        ctx = _ctx_all_404(initial_headers={"server": "nginx/1.29.3"})
        r = await _run_cve_http2(ctx)
        assert r.status == Status.PASS


# ── NGINX-STATUS-EXPOSED ──────────────────────────────────────────────────────


_NGINX_STATUS_BODY = (
    "Active connections: 42 \n"
    "server accepts handled requests\n"
    " 100 100 200 \n"
    "Reading: 1 Writing: 2 Waiting: 10 \n"
)

_STUB_STATUS_BODY = (
    "Active connections: 5\n"
    "server accepts handled requests\n"
    " 50 50 150 \n"
    "Reading: 0 Writing: 1 Waiting: 4\n"
)


class TestNginxStatusExposed:
    async def test_nginx_status_exposed_fails(self):
        ctx = _ctx_with_mock(
            get_map={"/nginx_status": (200, _NGINX_STATUS_BODY)},
        )
        r = await _run_nginx_status(ctx)
        assert r.status == Status.FAIL
        assert "/nginx_status" in r.detail

    async def test_stub_status_exposed_fails(self):
        ctx = _ctx_with_mock(
            get_map={"/stub_status": (200, _STUB_STATUS_BODY)},
        )
        r = await _run_nginx_status(ctx)
        assert r.status == Status.FAIL
        assert "/stub_status" in r.detail

    async def test_status_path_exposed_fails(self):
        ctx = _ctx_with_mock(
            get_map={"/status": (200, _NGINX_STATUS_BODY)},
        )
        r = await _run_nginx_status(ctx)
        assert r.status == Status.FAIL

    async def test_none_exposed_passes(self):
        ctx = _ctx_all_404()
        r = await _run_nginx_status(ctx)
        assert r.status == Status.PASS

    async def test_200_but_html_body_passes(self):
        # 200 pero sin patrones nginx_status → no se detecta
        ctx = _ctx_with_mock(
            get_map={"/nginx_status": (200, "<html><body>Not found</body></html>")},
        )
        r = await _run_nginx_status(ctx)
        assert r.status == Status.PASS

    async def test_403_not_detected(self):
        ctx = _ctx_with_mock(
            get_map={"/nginx_status": (403, "Forbidden")},
        )
        r = await _run_nginx_status(ctx)
        assert r.status == Status.PASS

    async def test_requests_pattern_detected(self):
        # El body tiene "requests: 200" que debe ser detectado
        ctx = _ctx_with_mock(
            get_map={"/basic_status": (200, "requests: 200\nActive connections: 3\n")},
        )
        r = await _run_nginx_status(ctx)
        assert r.status == Status.FAIL
        assert "/basic_status" in r.detail


# ── WEBSHELL-DETECTED ─────────────────────────────────────────────────────────


_WEBSHELL_BODY_STRONG = (
    "<?php system($_GET['cmd']); ?>\n"
    "<title>c99shell</title>\n"
    "eval(base64_decode('aGVsbG8='));"
)

_WEBSHELL_BODY_WEAK = (
    "<?php passthru($_REQUEST['x']); ?>"
)

_PHP_ERROR_BODY = (
    "<?php\n// safe PHP script\necho 'Hello World';\n"
)


class TestWebshellDetected:
    async def test_strong_match_fails(self):
        ctx = _ctx_with_mock(
            head_map={"/shell.php": (200, "")},
            get_map={"/shell.php": (200, _WEBSHELL_BODY_STRONG)},
        )
        r = await _run_webshell(ctx)
        assert r.status == Status.FAIL
        assert "/shell.php" in r.detail

    async def test_weak_match_warns(self):
        # Cuerpo con score=1 exacto: sólo /etc/passwd dispara el patrón 1
        body_score1 = "cat /etc/passwd output:\nroot:x:0:0:root"
        ctx = _ctx_with_mock(
            head_map={"/cmd.php": (200, "")},
            get_map={"/cmd.php": (200, body_score1)},
        )
        r = await _run_webshell(ctx)
        assert r.status == Status.WARN

    async def test_no_shells_passes(self):
        ctx = _ctx_all_404()
        r = await _run_webshell(ctx)
        assert r.status == Status.PASS

    async def test_404_head_skipped(self):
        # HEAD retorna 404 (no en 200/403) → no se hace GET → pass
        ctx = _ctx_with_mock(
            head_map={"/shell.php": (404, "")},
            get_map={"/shell.php": (200, _WEBSHELL_BODY_STRONG)},
        )
        r = await _run_webshell(ctx)
        assert r.status == Status.PASS

    async def test_200_head_but_no_pattern_passes(self):
        ctx = _ctx_with_mock(
            head_map={"/shell.php": (200, "")},
            get_map={"/shell.php": (200, _PHP_ERROR_BODY)},
        )
        r = await _run_webshell(ctx)
        assert r.status == Status.PASS

    async def test_c99_body_fails(self):
        body = "<html><title>c99shell</title><body>FilesMan eval(base64_decode('x'));</body></html>"
        ctx = _ctx_with_mock(
            head_map={"/c99.php": (200, "")},
            get_map={"/c99.php": (200, body)},
        )
        r = await _run_webshell(ctx)
        assert r.status == Status.FAIL
        assert "/c99.php" in r.detail

    async def test_r57_body_warns(self):
        # score=1: solo uname -a → WARN
        body = "uname -a output: Linux server 5.15.0"
        ctx = _ctx_with_mock(
            head_map={"/r57.php": (200, "")},
            get_map={"/r57.php": (200, body)},
        )
        r = await _run_webshell(ctx)
        assert r.status == Status.WARN

    async def test_multiple_shells_fails(self):
        body = _WEBSHELL_BODY_STRONG
        ctx = _ctx_with_mock(
            head_map={
                "/shell.php": (200, ""),
                "/cmd.php": (200, ""),
            },
            get_map={
                "/shell.php": (200, body),
                "/cmd.php": (200, body),
            },
        )
        r = await _run_webshell(ctx)
        assert r.status == Status.FAIL

    async def test_network_error_head_skipped(self):
        # HEAD lanza excepción → mock no retorna 200 → se salta
        ctx = _ctx_all_404()
        r = await _run_webshell(ctx)
        assert r.status == Status.PASS
