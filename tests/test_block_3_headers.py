"""Tests unitarios — Bloque 3: Cabeceras HTTP (HEADER-X-FRAME-OPTIONS a HEADER-PERMISSIONS-POLICY)."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from wss.core.result import Status
from wss.tests.block_3_headers import (
    test_xframe_options as _run_xfo,
    test_xcontent_type_options as _run_xcto,
    test_csp as _run_csp,
    test_referrer_policy as _run_rp,
    test_permissions_policy as _run_pp,
)
from tests.conftest import make_ctx


def _ctx_with_headers(headers: dict[str, str]):
    ctx = make_ctx()
    # Patch get_header para leer del dict
    async def get_header(name):
        return headers.get(name.lower(), "")
    ctx.get_header = get_header
    return ctx


# ── HEADER-X-FRAME-OPTIONS: X-Frame-Options ──────────────────────────────────────────────────


async def test_10_pass():
    ctx = _ctx_with_headers({"x-frame-options": "SAMEORIGIN"})
    r = await _run_xfo(ctx)
    assert r.status == Status.PASS


async def test_10_fail():
    ctx = _ctx_with_headers({})
    r = await _run_xfo(ctx)
    assert r.status == Status.FAIL


# ── HEADER-X-CONTENT-TYPE-OPTIONS: X-Content-Type-Options ──────────────────────────────────────────


async def test_11_pass():
    ctx = _ctx_with_headers({"x-content-type-options": "nosniff"})
    r = await _run_xcto(ctx)
    assert r.status == Status.PASS


async def test_11_fail():
    ctx = _ctx_with_headers({})
    r = await _run_xcto(ctx)
    assert r.status == Status.FAIL


# ── HEADER-CSP: CSP ──────────────────────────────────────────────────────────────


async def test_12_fail_absent():
    ctx = _ctx_with_headers({})
    r = await _run_csp(ctx)
    assert r.status == Status.FAIL


async def test_12_warn_unsafe_eval():
    ctx = _ctx_with_headers({"content-security-policy": "default-src 'self' 'unsafe-eval'"})
    r = await _run_csp(ctx)
    assert r.status == Status.WARN
    assert "unsafe-eval" in r.detail


async def test_12_warn_unsafe_inline():
    ctx = _ctx_with_headers({"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    r = await _run_csp(ctx)
    assert r.status == Status.WARN
    assert "unsafe-inline" in r.detail


async def test_12_warn_no_base_uri():
    ctx = _ctx_with_headers({"content-security-policy": "default-src 'self'; form-action 'self'"})
    r = await _run_csp(ctx)
    assert r.status == Status.WARN
    assert "base-uri" in r.detail


async def test_12_warn_no_form_action():
    ctx = _ctx_with_headers({"content-security-policy": "default-src 'self'; base-uri 'self'"})
    r = await _run_csp(ctx)
    assert r.status == Status.WARN
    assert "form-action" in r.detail


async def test_12_pass_complete():
    ctx = _ctx_with_headers({
        "content-security-policy": "default-src 'self'; base-uri 'self'; form-action 'self'"
    })
    r = await _run_csp(ctx)
    assert r.status == Status.PASS


# ── HEADER-REFERRER-POLICY: Referrer-Policy ──────────────────────────────────────────────────


async def test_13_pass():
    ctx = _ctx_with_headers({"referrer-policy": "strict-origin-when-cross-origin"})
    r = await _run_rp(ctx)
    assert r.status == Status.PASS


async def test_13_warn_absent():
    ctx = _ctx_with_headers({})
    r = await _run_rp(ctx)
    assert r.status == Status.WARN


# ── HEADER-PERMISSIONS-POLICY: Permissions-Policy ───────────────────────────────────────────────


async def test_14_pass():
    ctx = _ctx_with_headers({"permissions-policy": "camera=(), microphone=()"})
    r = await _run_pp(ctx)
    assert r.status == Status.PASS


async def test_14_warn_absent():
    ctx = _ctx_with_headers({})
    r = await _run_pp(ctx)
    assert r.status == Status.WARN
