"""Tests unitarios — Bloque 6: Headers modernos y deprecados (MODERNHDR-DEPRECATED a MODERNHDR-X-PERMITTED-CROSS-DOMAIN)."""
from __future__ import annotations

from wss.core.result import Status
from wss.tests.block_6_modern_headers import (
    test_deprecated_headers as _run_depr,
    test_coop as _run_coop,
    test_coep as _run_coep,
    test_corp as _run_corp,
    test_x_permitted_cross_domain as _run_xpcd,
)
from tests.conftest import make_ctx


def _ctx_with_headers(headers: dict[str, str]):
    ctx = make_ctx()
    async def get_header(name):
        return headers.get(name.lower(), "")
    ctx.get_header = get_header
    return ctx


# ── MODERNHDR-DEPRECATED: Deprecated headers ───────────────────────────────────────────────


async def test_21_pass_none_present():
    ctx = _ctx_with_headers({})
    r = await _run_depr(ctx)
    assert r.status == Status.PASS


async def test_21_warn_xxss_protection():
    ctx = _ctx_with_headers({"x-xss-protection": "1; mode=block"})
    r = await _run_depr(ctx)
    assert r.status == Status.WARN
    assert "x-xss-protection" in r.detail


async def test_21_warn_multiple():
    ctx = _ctx_with_headers({
        "x-xss-protection": "1",
        "pragma": "no-cache",
    })
    r = await _run_depr(ctx)
    assert r.status == Status.WARN
    assert "x-xss-protection" in r.detail
    assert "pragma" in r.detail


# ── MODERNHDR-COOP: COOP ──────────────────────────────────────────────────────────────


async def test_22_pass():
    ctx = _ctx_with_headers({"cross-origin-opener-policy": "same-origin"})
    r = await _run_coop(ctx)
    assert r.status == Status.PASS


async def test_22_warn_absent():
    ctx = _ctx_with_headers({})
    r = await _run_coop(ctx)
    assert r.status == Status.WARN


# ── MODERNHDR-COEP: COEP ──────────────────────────────────────────────────────────────


async def test_23_pass():
    ctx = _ctx_with_headers({"cross-origin-embedder-policy": "require-corp"})
    r = await _run_coep(ctx)
    assert r.status == Status.PASS


async def test_23_warn_absent():
    ctx = _ctx_with_headers({})
    r = await _run_coep(ctx)
    assert r.status == Status.WARN


# ── MODERNHDR-CORP: CORP ──────────────────────────────────────────────────────────────


async def test_24_pass():
    ctx = _ctx_with_headers({"cross-origin-resource-policy": "same-origin"})
    r = await _run_corp(ctx)
    assert r.status == Status.PASS


async def test_24_warn_absent():
    ctx = _ctx_with_headers({})
    r = await _run_corp(ctx)
    assert r.status == Status.WARN


# ── MODERNHDR-X-PERMITTED-CROSS-DOMAIN: X-Permitted-Cross-Domain-Policies ────────────────────────────────


async def test_25_warn_absent():
    ctx = _ctx_with_headers({})
    r = await _run_xpcd(ctx)
    assert r.status == Status.WARN


async def test_25_warn_all():
    ctx = _ctx_with_headers({"x-permitted-cross-domain-policies": "all"})
    r = await _run_xpcd(ctx)
    assert r.status == Status.WARN
    assert "all" in r.detail


async def test_25_pass_none():
    ctx = _ctx_with_headers({"x-permitted-cross-domain-policies": "none"})
    r = await _run_xpcd(ctx)
    assert r.status == Status.PASS


async def test_25_pass_master_only():
    ctx = _ctx_with_headers({"x-permitted-cross-domain-policies": "master-only"})
    r = await _run_xpcd(ctx)
    assert r.status == Status.PASS
