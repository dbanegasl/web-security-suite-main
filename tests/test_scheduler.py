"""Tests unitarios para el módulo scheduler de la API.

Cubre:
  - _severity_gte(): comparación de severidades
  - _send_webhook(): formato Slack, Teams, genérico + error silencioso
  - Lógica de filtrado de nuevos FAILs en _run_scheduled_scan (mock)
"""
from __future__ import annotations

import json
import pytest
import respx
import httpx


# ── Helpers importados directamente (no requieren BD ni APScheduler) ──────────

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web", "api"))

from scheduler import _severity_gte, _send_webhook
from models import ScheduledScan
from datetime import datetime, timezone


# ── _severity_gte ─────────────────────────────────────────────────────────────

class TestSeverityGte:
    def test_same_level(self):
        assert _severity_gte("HIGH", "HIGH") is True

    def test_above_threshold(self):
        assert _severity_gte("CRITICAL", "HIGH") is True

    def test_below_threshold(self):
        assert _severity_gte("LOW", "MEDIUM") is False

    def test_case_insensitive(self):
        assert _severity_gte("critical", "high") is True
        assert _severity_gte("low", "MEDIUM") is False

    def test_unknown_treated_as_info(self):
        # Valor desconocido → índice 0 (INFO)
        assert _severity_gte("UNKNOWN", "LOW") is False
        assert _severity_gte("HIGH", "UNKNOWN") is True

    def test_all_levels_order(self):
        levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for i, level in enumerate(levels):
            for j, threshold in enumerate(levels):
                expected = i >= j
                assert _severity_gte(level, threshold) is expected, (
                    f"_severity_gte({level!r}, {threshold!r}) should be {expected}"
                )


# ── _send_webhook ─────────────────────────────────────────────────────────────

def _make_schedule(webhook_url: str, min_severity: str = "HIGH") -> ScheduledScan:
    return ScheduledScan(
        id=1,
        name="test schedule",
        domain="example.com",
        cron_expression="0 8 * * 1",
        webhook_url=webhook_url,
        min_severity=min_severity,
        created_at=datetime.now(timezone.utc),
    )


NEW_FAILS = [
    {"id": "01", "name": "Secure Cookie", "result": "FAIL", "severity": "HIGH", "detail": "Missing Secure flag"},
    {"id": "02", "name": "HSTS", "result": "FAIL", "severity": "CRITICAL", "detail": "No HSTS header"},
]


@pytest.mark.anyio
async def test_send_webhook_slack():
    """Verifica que el payload Slack se envía correctamente."""
    url = "https://hooks.slack.com/services/T000/B000/xxxx"
    schedule = _make_schedule(url)

    with respx.mock:
        route = respx.post(url).mock(return_value=httpx.Response(200, text="ok"))
        await _send_webhook(url, schedule, NEW_FAILS)
        assert route.called
        sent = json.loads(route.calls[0].request.content)
        assert "text" in sent
        assert "example.com" in sent["text"]
        assert "2 FAIL(s)" in sent["text"]


@pytest.mark.anyio
async def test_send_webhook_teams():
    """Verifica que el payload Teams (MessageCard) se envía correctamente."""
    url = "https://myorg.webhook.office.com/webhookb2/xxx"
    schedule = _make_schedule(url)

    with respx.mock:
        route = respx.post(url).mock(return_value=httpx.Response(200, text="ok"))
        await _send_webhook(url, schedule, NEW_FAILS)
        assert route.called
        sent = json.loads(route.calls[0].request.content)
        assert sent["@type"] == "MessageCard"
        assert "example.com" in sent["summary"]


@pytest.mark.anyio
async def test_send_webhook_generic():
    """Verifica que el payload genérico incluye 'source' y 'results'."""
    url = "https://my-custom-webhook.example.com/notify"
    schedule = _make_schedule(url)

    with respx.mock:
        route = respx.post(url).mock(return_value=httpx.Response(200, text="ok"))
        await _send_webhook(url, schedule, NEW_FAILS)
        assert route.called
        sent = json.loads(route.calls[0].request.content)
        assert sent["source"] == "web-security-suite"
        assert sent["domain"] == "example.com"
        assert sent["new_fails"] == 2
        assert len(sent["results"]) == 2


@pytest.mark.anyio
async def test_send_webhook_empty_url():
    """Si webhook_url está vacío, no se realiza ninguna petición."""
    schedule = _make_schedule("")

    with respx.mock:
        # No se debe llamar a ninguna URL
        await _send_webhook("", schedule, NEW_FAILS)
        assert not respx.calls


@pytest.mark.anyio
async def test_send_webhook_error_silenced():
    """Un error HTTP no debe propagar excepción (solo log.warning)."""
    url = "https://hooks.slack.com/services/bad"
    schedule = _make_schedule(url)

    with respx.mock:
        respx.post(url).mock(return_value=httpx.Response(500, text="error"))
        # No debe lanzar excepción
        await _send_webhook(url, schedule, NEW_FAILS)


@pytest.mark.anyio
async def test_send_webhook_network_error_silenced():
    """Un error de conexión no debe propagar excepción."""
    url = "https://hooks.slack.com/services/down"
    schedule = _make_schedule(url)

    with respx.mock:
        respx.post(url).mock(side_effect=httpx.ConnectError("connection refused"))
        await _send_webhook(url, schedule, NEW_FAILS)


# ── Filtrado de nuevos FAILs ──────────────────────────────────────────────────

class TestNewFailFiltering:
    """Verifica la lógica de filtrado de FAILs nuevos vs existentes."""

    def _apply_filter(self, all_results, prev_fail_ids, min_severity, notify_on_new_fail):
        """Replica la lógica de _run_scheduled_scan para pruebas aisladas."""
        from scheduler import _severity_gte
        if notify_on_new_fail:
            return [
                t for t in all_results
                if t.get("result") == "FAIL"
                and _severity_gte(t.get("severity", "MEDIUM"), min_severity)
                and t.get("id") not in prev_fail_ids
            ]
        else:
            return [
                t for t in all_results
                if t.get("result") == "FAIL"
                and _severity_gte(t.get("severity", "MEDIUM"), min_severity)
            ]

    def test_new_fail_detected(self):
        """Un FAIL nuevo (no en el anterior) debe aparecer en la notificación."""
        results = [{"id": "03", "result": "FAIL", "severity": "HIGH", "name": "New test"}]
        prev_ids = set()
        filtered = self._apply_filter(results, prev_ids, "HIGH", True)
        assert len(filtered) == 1

    def test_existing_fail_ignored(self):
        """Un FAIL que ya existía en el anterior no debe notificarse."""
        results = [{"id": "01", "result": "FAIL", "severity": "HIGH", "name": "Old fail"}]
        prev_ids = {"01"}
        filtered = self._apply_filter(results, prev_ids, "HIGH", True)
        assert len(filtered) == 0

    def test_below_severity_ignored(self):
        """Un FAIL por debajo del umbral no debe notificarse."""
        results = [{"id": "04", "result": "FAIL", "severity": "LOW", "name": "Low severity"}]
        prev_ids = set()
        filtered = self._apply_filter(results, prev_ids, "HIGH", True)
        assert len(filtered) == 0

    def test_pass_not_included(self):
        """Resultados PASS nunca deben incluirse en la notificación."""
        results = [{"id": "05", "result": "PASS", "severity": "HIGH", "name": "Passing test"}]
        prev_ids = set()
        filtered = self._apply_filter(results, prev_ids, "HIGH", True)
        assert len(filtered) == 0

    def test_notify_all_mode(self):
        """Cuando notify_on_new_fail=False, todos los FAILs (incl. los conocidos) deben notificarse."""
        results = [
            {"id": "01", "result": "FAIL", "severity": "HIGH", "name": "Old fail"},
            {"id": "06", "result": "FAIL", "severity": "HIGH", "name": "New fail"},
        ]
        prev_ids = {"01"}
        filtered = self._apply_filter(results, prev_ids, "HIGH", False)
        assert len(filtered) == 2
