"""Tests unitarios — Bloque 4: Fuga de información (INFOLEAK-SERVER-HEADER a INFOLEAK-ASP-NET-VERSION)."""
from __future__ import annotations

from wss.core.result import Status
from wss.tests.block_4_info_leak import (
    test_server_header as _run_server,
    test_x_powered_by as _run_xpb,
    test_aspnet_version as _run_aspnet,
)
from tests.conftest import make_ctx


def _ctx_with_headers(headers: dict[str, str]):
    ctx = make_ctx()
    async def get_header(name):
        return headers.get(name.lower(), "")
    ctx.get_header = get_header
    return ctx


# ── INFOLEAK-SERVER-HEADER: Server header ────────────────────────────────────────────────────


async def test_15_pass_absent():
    ctx = _ctx_with_headers({})
    r = await _run_server(ctx)
    assert r.status == Status.PASS


async def test_15_pass_no_version():
    ctx = _ctx_with_headers({"server": "nginx"})
    r = await _run_server(ctx)
    assert r.status == Status.PASS


async def test_15_fail_with_version():
    ctx = _ctx_with_headers({"server": "nginx/1.25.0"})
    r = await _run_server(ctx)
    assert r.status == Status.FAIL
    assert "revela versión" in r.detail


async def test_15_fail_apache_version():
    ctx = _ctx_with_headers({"server": "Apache/2.4.51 (Ubuntu)"})
    r = await _run_server(ctx)
    assert r.status == Status.FAIL


# ── INFOLEAK-X-POWERED-BY: X-Powered-By ─────────────────────────────────────────────────────


async def test_16_pass_absent():
    ctx = _ctx_with_headers({})
    r = await _run_xpb(ctx)
    assert r.status == Status.PASS


async def test_16_fail_present():
    ctx = _ctx_with_headers({"x-powered-by": "PHP/8.2.0"})
    r = await _run_xpb(ctx)
    assert r.status == Status.FAIL
    assert "PHP" in r.detail


# ── INFOLEAK-ASP-NET-VERSION: X-AspNet-Version ─────────────────────────────────────────────────


async def test_17_pass_absent():
    ctx = _ctx_with_headers({})
    r = await _run_aspnet(ctx)
    assert r.status == Status.PASS


async def test_17_fail_aspnet():
    ctx = _ctx_with_headers({"x-aspnet-version": "4.0.30319"})
    r = await _run_aspnet(ctx)
    assert r.status == Status.FAIL


async def test_17_fail_aspnetmvc():
    ctx = _ctx_with_headers({"x-aspnetmvc-version": "5.0"})
    r = await _run_aspnet(ctx)
    assert r.status == Status.FAIL
