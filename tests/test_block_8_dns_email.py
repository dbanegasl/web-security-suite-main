"""Tests unitarios — Bloque 8: DNS, Email y Dominio (TEST-41 a TEST-47)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wss.core.result import Status
from wss.tests.block_8_dns_email import (
    test_spf as _run_spf,
    test_dmarc as _run_dmarc,
    test_dkim as _run_dkim,
    test_caa as _run_caa,
    test_dnssec as _run_dnssec,
    test_subdomain_takeover as _run_subdomain_takeover,
    test_sensitive_ports as _run_sensitive_ports,
    _port_open,
)
from tests.conftest import make_ctx


# ─── Helper: simular respuestas DNS ──────────────────────────────────────────


def _make_txt_answer(txt_values: list[str]):
    """Crea un Answer mock de dnspython con registros TXT."""
    rdatas = []
    for val in txt_values:
        rdata = MagicMock()
        rdata.strings = [val.encode()]
        rdatas.append(rdata)

    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter(rdatas))
    return answer


def _make_rdata_answer(rdata_list: list):
    """Crea un Answer genérico con la lista de rdatas dada."""
    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter(rdata_list))
    return answer


# ── TEST-41: SPF ──────────────────────────────────────────────────────────────


async def test_41_fail_no_spf():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=None):
        r = await _run_spf(ctx)
    assert r.status == Status.SKIP


async def test_41_fail_spf_missing():
    """TXT present pero sin v=spf1."""
    ctx = make_ctx()
    answer = _make_txt_answer(["v=DMARC1; p=reject"])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_spf(ctx)
    assert r.status == Status.FAIL
    assert "SPF" in r.detail


async def test_41_fail_spf_plus_all():
    ctx = make_ctx()
    answer = _make_txt_answer(["v=spf1 include:_spf.google.com +all"])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_spf(ctx)
    assert r.status == Status.FAIL
    assert "+all" in r.detail


async def test_41_warn_spf_soft_fail():
    ctx = make_ctx()
    answer = _make_txt_answer(["v=spf1 include:_spf.google.com ~all"])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_spf(ctx)
    assert r.status == Status.WARN


async def test_41_pass_spf_strict():
    ctx = make_ctx()
    answer = _make_txt_answer(["v=spf1 include:_spf.google.com -all"])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_spf(ctx)
    assert r.status == Status.PASS


# ── TEST-42: DMARC ────────────────────────────────────────────────────────────


async def test_42_fail_no_dmarc():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=None):
        r = await _run_dmarc(ctx)
    assert r.status == Status.FAIL


async def test_42_warn_dmarc_none_policy():
    ctx = make_ctx()
    answer = _make_txt_answer(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_dmarc(ctx)
    assert r.status == Status.WARN
    assert "none" in r.detail


async def test_42_warn_dmarc_no_rua():
    ctx = make_ctx()
    answer = _make_txt_answer(["v=DMARC1; p=reject"])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_dmarc(ctx)
    assert r.status == Status.WARN
    assert "rua" in r.detail


async def test_42_pass_dmarc_full():
    ctx = make_ctx()
    answer = _make_txt_answer(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_dmarc(ctx)
    assert r.status == Status.PASS


# ── TEST-43: DKIM ─────────────────────────────────────────────────────────────


async def test_43_warn_no_dkim():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=None):
        r = await _run_dkim(ctx)
    assert r.status == Status.WARN


async def test_43_pass_dkim_found():
    ctx = make_ctx()
    hit = _make_txt_answer(["v=DKIM1; k=rsa; p=MIGfMA0GCSq..."])

    async def mock_dns(qname, rdtype):
        if "default._domainkey" in qname:
            return hit
        return None

    with patch("wss.tests.block_8_dns_email._dns_query", side_effect=mock_dns):
        r = await _run_dkim(ctx)
    assert r.status == Status.PASS
    assert "default" in r.detail


# ── TEST-44: CAA ──────────────────────────────────────────────────────────────


async def test_44_warn_no_caa():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=None):
        r = await _run_caa(ctx)
    assert r.status == Status.WARN


async def test_44_pass_caa_present():
    ctx = make_ctx()
    rdata = MagicMock()
    rdata.__str__ = MagicMock(return_value='0 issue "letsencrypt.org"')
    answer = _make_rdata_answer([rdata])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_caa(ctx)
    assert r.status == Status.PASS


# ── TEST-45: DNSSEC ───────────────────────────────────────────────────────────


async def test_45_warn_no_dnssec():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=None):
        r = await _run_dnssec(ctx)
    assert r.status == Status.WARN


async def test_45_pass_dnskey_present():
    ctx = make_ctx()
    rdata = MagicMock()
    answer = _make_rdata_answer([rdata, rdata])
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=answer):
        r = await _run_dnssec(ctx)
    assert r.status == Status.PASS
    assert "2" in r.detail


# ── TEST-46: Subdomain takeover ───────────────────────────────────────────────


async def test_46_pass_no_cname():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._dns_query", return_value=None):
        r = await _run_subdomain_takeover(ctx)
    assert r.status == Status.PASS


async def test_46_fail_takeover_detected():
    ctx = make_ctx()
    # CNAME a github.io
    rdata = MagicMock()
    rdata.__str__ = MagicMock(return_value="myorg.github.io.")
    cname_answer = _make_rdata_answer([rdata])

    # Respuesta HTTP con firma de takeover
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "There isn't a GitHub Pages site here."
    mock_resp.history = []

    async def mock_dns(qname, rdtype):
        if rdtype == "CNAME":
            return cname_answer
        return None

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    ctx._client = mock_client

    with patch("wss.tests.block_8_dns_email._dns_query", side_effect=mock_dns):
        r = await _run_subdomain_takeover(ctx)
    assert r.status == Status.FAIL
    assert "takeover" in r.detail.lower()


# ── TEST-47: Puertos sensibles ────────────────────────────────────────────────


async def test_47_fail_port_open():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._port_open", return_value=True):
        r = await _run_sensitive_ports(ctx)
    assert r.status == Status.FAIL
    assert "3306" in r.detail or "MySQL" in r.detail


async def test_47_pass_all_closed():
    ctx = make_ctx()
    with patch("wss.tests.block_8_dns_email._port_open", return_value=False):
        r = await _run_sensitive_ports(ctx)
    assert r.status == Status.PASS


async def test_port_open_false_on_exception():
    """_port_open devuelve False si la conexión falla."""
    result = await _port_open("127.0.0.1", 19999, timeout=0.1)
    assert result is False
