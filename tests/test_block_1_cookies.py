"""Tests unitarios — Bloque 1: Cookies (TEST-01 a TEST-04)

Cada test cubre los casos del bash original:
    - Camino feliz (PASS)
    - Camino de fallo (FAIL / WARN)
    - Camino de skip (SKIP)
    - Sin cookies (PASS vacío)

Los tests usan contextos pre-poblados (sin peticiones HTTP reales).
"""
from __future__ import annotations

import pytest

from wss.core.result import Status
from wss.tests.block_1_cookies import (
    test_secure as _run_secure,
    test_httponly as _run_httponly,
    test_samesite as _run_samesite,
    test_path as _run_path,
)
from tests.conftest import make_ctx


# ── TEST-01: Secure ─────────────────────────────────────────────────────────


async def test_01_pass_all_secure():
    ctx = make_ctx([
        "session=abc; Secure; HttpOnly; SameSite=Lax; Path=/",
        "csrf=xyz; Secure; SameSite=Strict; Path=/",
    ])
    result = await _run_secure(ctx)
    assert result.status == Status.PASS


async def test_01_fail_missing_secure():
    ctx = make_ctx([
        "session=abc; HttpOnly; SameSite=Lax; Path=/",  # sin Secure
        "csrf=xyz; Secure; SameSite=Strict; Path=/",
    ])
    result = await _run_secure(ctx)
    assert result.status == Status.FAIL
    assert "session" in result.detail


async def test_01_fail_all_missing_secure():
    ctx = make_ctx([
        "session=abc; HttpOnly; SameSite=Lax; Path=/",
        "csrf=xyz; SameSite=Strict; Path=/",
    ])
    result = await _run_secure(ctx)
    assert result.status == Status.FAIL


async def test_01_pass_no_cookies():
    ctx = make_ctx([])
    result = await _run_secure(ctx)
    assert result.status == Status.PASS


async def test_01_case_insensitive():
    """Verifica que '; SECURE' (mayúsculas) sea aceptado — paridad bash grep -i."""
    ctx = make_ctx(["session=abc; SECURE; HttpOnly; SameSite=Lax; Path=/"])
    result = await _run_secure(ctx)
    assert result.status == Status.PASS


# ── TEST-02: HttpOnly ────────────────────────────────────────────────────────


async def test_02_skip_no_session_cookie_defined():
    ctx = make_ctx(
        ["session=abc; Secure; HttpOnly; SameSite=Lax; Path=/"],
        session_cookie="",
    )
    result = await _run_httponly(ctx)
    assert result.status == Status.SKIP


async def test_02_skip_cookie_not_in_response():
    ctx = make_ctx(
        ["csrf=xyz; Secure; SameSite=Strict; Path=/"],
        session_cookie="sessionid",
    )
    result = await _run_httponly(ctx)
    assert result.status == Status.SKIP
    assert "sessionid" in result.detail


async def test_02_pass_httponly_present():
    ctx = make_ctx(
        ["sessionid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"],
        session_cookie="sessionid",
    )
    result = await _run_httponly(ctx)
    assert result.status == Status.PASS


async def test_02_fail_httponly_missing():
    ctx = make_ctx(
        ["sessionid=abc; Secure; SameSite=Lax; Path=/"],  # sin HttpOnly
        session_cookie="sessionid",
    )
    result = await _run_httponly(ctx)
    assert result.status == Status.FAIL
    assert "sessionid" in result.detail


async def test_02_skip_xsrf_token():
    """XSRF-TOKEN debe ser legible por JS — HttpOnly no aplica."""
    ctx = make_ctx(
        ["XSRF-TOKEN=abc; Secure; SameSite=Strict; Path=/"],
        session_cookie="XSRF-TOKEN",
    )
    result = await _run_httponly(ctx)
    assert result.status == Status.SKIP


async def test_02_case_insensitive_httponly():
    """Verifica que 'HTTPONLY' en mayúsculas sea aceptado."""
    ctx = make_ctx(
        ["sessionid=abc; Secure; HTTPONLY; SameSite=Lax; Path=/"],
        session_cookie="sessionid",
    )
    result = await _run_httponly(ctx)
    assert result.status == Status.PASS


# ── TEST-03: SameSite ────────────────────────────────────────────────────────


async def test_03_pass_samesite_lax():
    ctx = make_ctx([
        "session=abc; Secure; HttpOnly; SameSite=Lax; Path=/",
    ])
    result = await _run_samesite(ctx)
    assert result.status == Status.PASS


async def test_03_pass_samesite_strict():
    ctx = make_ctx([
        "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
    ])
    result = await _run_samesite(ctx)
    assert result.status == Status.PASS


async def test_03_fail_samesite_none():
    ctx = make_ctx([
        "session=abc; Secure; HttpOnly; SameSite=None; Path=/",
    ])
    result = await _run_samesite(ctx)
    assert result.status == Status.FAIL


async def test_03_fail_samesite_absent():
    ctx = make_ctx([
        "session=abc; Secure; HttpOnly; Path=/",  # sin SameSite
    ])
    result = await _run_samesite(ctx)
    assert result.status == Status.FAIL
    assert "session" in result.detail


async def test_03_pass_no_cookies():
    ctx = make_ctx([])
    result = await _run_samesite(ctx)
    assert result.status == Status.PASS


async def test_03_mixed_fail_only_reports_failing():
    """Si una cookie tiene SameSite y otra no, solo aparece la que falla."""
    ctx = make_ctx([
        "good=a; Secure; HttpOnly; SameSite=Lax; Path=/",
        "bad=b; Secure; HttpOnly; Path=/",  # sin SameSite
    ])
    result = await _run_samesite(ctx)
    assert result.status == Status.FAIL
    assert "bad" in result.detail
    assert "good" not in result.detail


# ── TEST-04: Path ────────────────────────────────────────────────────────────


async def test_04_pass_all_have_path():
    ctx = make_ctx([
        "session=abc; Secure; HttpOnly; SameSite=Lax; Path=/",
        "csrf=xyz; Secure; SameSite=Strict; Path=/api",
    ])
    result = await _run_path(ctx)
    assert result.status == Status.PASS


async def test_04_warn_missing_path():
    ctx = make_ctx([
        "session=abc; Secure; HttpOnly; SameSite=Lax",  # sin Path
    ])
    result = await _run_path(ctx)
    # Path ausente es WARN (no FAIL) — paridad con el bash
    assert result.status == Status.WARN
    assert "session" in result.detail


async def test_04_pass_no_cookies():
    ctx = make_ctx([])
    result = await _run_path(ctx)
    assert result.status == Status.PASS


async def test_04_warn_partial_missing_path():
    """Solo la cookie sin Path aparece en el detalle."""
    ctx = make_ctx([
        "good=a; Secure; HttpOnly; SameSite=Lax; Path=/",
        "bad=b; Secure; HttpOnly; SameSite=Strict",  # sin Path
    ])
    result = await _run_path(ctx)
    assert result.status == Status.WARN
    assert "bad" in result.detail
    assert "good" not in result.detail
