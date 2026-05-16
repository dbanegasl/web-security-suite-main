"""Tests unitarios — Bloque 5: Configuración del servidor (TEST-18 a TEST-20)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from wss.core.result import Status
from wss.tests.block_5_server_config import (
    test_cors as _run_cors,
    test_http_trace as _run_trace,
    test_cache_control as _run_cache,
)
from tests.conftest import make_ctx


def _ctx_with_headers(headers: dict[str, str]):
    ctx = make_ctx()
    async def get_header(name):
        return headers.get(name.lower(), "")
    ctx.get_header = get_header
    return ctx


def _ctx_with_trace_response(status_code: int):
    """Contexto con mock de ctx.client para el test TRACE."""
    ctx = make_ctx()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_client = MagicMock()
    mock_client.request = AsyncMock(return_value=mock_resp)
    ctx._client = mock_client  # lazy-init ya devuelve _client si no es None
    return ctx


# ── TEST-18: CORS ──────────────────────────────────────────────────────────────


async def test_18_pass_absent():
    ctx = _ctx_with_headers({})
    r = await _run_cors(ctx)
    assert r.status == Status.PASS


async def test_18_fail_wildcard():
    ctx = _ctx_with_headers({"access-control-allow-origin": "*"})
    r = await _run_cors(ctx)
    assert r.status == Status.FAIL
    assert "wildcard" in r.detail


async def test_18_pass_specific_origin():
    ctx = _ctx_with_headers({"access-control-allow-origin": "https://app.example.com"})
    r = await _run_cors(ctx)
    assert r.status == Status.PASS


# ── TEST-19: HTTP TRACE ────────────────────────────────────────────────────────


async def test_19_fail_trace_200():
    ctx = _ctx_with_trace_response(200)
    r = await _run_trace(ctx)
    assert r.status == Status.FAIL
    assert "TRACE activo" in r.detail


async def test_19_pass_trace_405():
    ctx = _ctx_with_trace_response(405)
    r = await _run_trace(ctx)
    assert r.status == Status.PASS


async def test_19_pass_trace_403():
    ctx = _ctx_with_trace_response(403)
    r = await _run_trace(ctx)
    assert r.status == Status.PASS


async def test_19_warn_trace_unexpected():
    ctx = _ctx_with_trace_response(501)
    r = await _run_trace(ctx)
    assert r.status == Status.WARN


# ── TEST-20: Cache-Control ─────────────────────────────────────────────────────


async def test_20_warn_absent():
    ctx = _ctx_with_headers({})
    r = await _run_cache(ctx)
    assert r.status == Status.WARN


async def test_20_pass_no_store():
    ctx = _ctx_with_headers({"cache-control": "no-store, no-cache"})
    r = await _run_cache(ctx)
    assert r.status == Status.PASS


async def test_20_pass_private():
    ctx = _ctx_with_headers({"cache-control": "private, max-age=0"})
    r = await _run_cache(ctx)
    assert r.status == Status.PASS


async def test_20_warn_public():
    ctx = _ctx_with_headers({"cache-control": "public, max-age=3600"})
    r = await _run_cache(ctx)
    assert r.status == Status.WARN
