"""Tests unitarios para wss/reporters/sarif_reporter.py."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from wss.core.result import Result, Severity, Status
from wss.core.registry import TestMeta, TEST_REGISTRY
from wss.reporters.sarif_reporter import generate, generate_from_dicts, _build_rules, _build_results


# ── Fixtures ────────────────────────────────────────────────────────────────

def _make_result(
    code: str = "COOKIE-SECURE",
    name: str = "Test dummy",
    status: Status = Status.FAIL,
    detail: str = "Detalle del fallo",
    severity: Severity = Severity.HIGH,
    cwe: str | None = "CWE-200",
    block: int = 1,
    duration_ms: float = 12.5,
) -> Result:
    return Result(
        code=code,
        name=name,
        status=status,
        detail=detail,
        severity=severity,
        cwe=cwe,
        block=block,
        duration_ms=duration_ms,
    )


def _make_meta(
    code: str = "COOKIE-SECURE",
    name: str = "Test dummy",
    block: int = 1,
    severity: str = "HIGH",
    cwe: str | None = "CWE-200",
    description: str = "Descripción del test",
) -> TestMeta:
    return TestMeta(
        code=code,
        name=name,
        block=block,
        block_name="Cookies",
        severity=Severity(severity),
        cwe=cwe,
        fn=lambda ctx: None,
        description=description,
    )


# ── Tests de estructura SARIF top-level ─────────────────────────────────────

def test_sarif_version():
    """El documento generado debe declarar SARIF 2.1.0."""
    results = [_make_result()]
    doc = json.loads(generate(results, domain="example.com"))
    assert doc["version"] == "2.1.0"


def test_sarif_schema():
    """El campo $schema debe apuntar al JSON Schema de SARIF 2.1.0."""
    results = [_make_result()]
    doc = json.loads(generate(results, domain="example.com"))
    assert "sarif-schema-2.1.0" in doc["$schema"]


def test_runs_is_list_with_one_element():
    """El array runs[] debe tener exactamente un elemento."""
    results = [_make_result()]
    doc = json.loads(generate(results, domain="example.com"))
    assert isinstance(doc["runs"], list)
    assert len(doc["runs"]) == 1


def test_tool_driver_name():
    """El driver.name debe ser 'wss'."""
    results = [_make_result()]
    doc = json.loads(generate(results, domain="example.com"))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "wss"


def test_tool_driver_version_present():
    """El driver.version debe estar presente (puede ser 'dev' en entorno de dev)."""
    results = [_make_result()]
    doc = json.loads(generate(results, domain="example.com"))
    driver = doc["runs"][0]["tool"]["driver"]
    assert "version" in driver
    assert isinstance(driver["version"], str)
    assert len(driver["version"]) > 0


# ── Tests de rules[] ────────────────────────────────────────────────────────

def test_build_rules_id_format():
    """Las rules deben tener id con prefijo WSS-."""
    metas = [_make_meta("COOKIE-SECURE"), _make_meta("EXPOSED-ENV", block=7)]
    rules = _build_rules(metas)
    ids = [r["id"] for r in rules]
    assert "WSS-COOKIE-SECURE" in ids
    assert "WSS-EXPOSED-ENV" in ids


def test_build_rules_severity_critical_maps_to_error():
    """Severidad CRITICAL → level='error'."""
    metas = [_make_meta("COOKIE-SECURE", severity="CRITICAL")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "error"


def test_build_rules_severity_high_maps_to_error():
    """Severidad HIGH → level='error'."""
    metas = [_make_meta("COOKIE-SECURE", severity="HIGH")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "error"


def test_build_rules_severity_medium_maps_to_warning():
    """Severidad MEDIUM → level='warning'."""
    metas = [_make_meta("COOKIE-SECURE", severity="MEDIUM")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "warning"


def test_build_rules_severity_low_maps_to_note():
    """Severidad LOW → level='note'."""
    metas = [_make_meta("COOKIE-SECURE", severity="LOW")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "note"


def test_build_rules_cwe_in_tags():
    """El CWE del test debe aparecer en properties.tags."""
    metas = [_make_meta("COOKIE-SECURE", cwe="CWE-614")]
    rules = _build_rules(metas)
    assert "CWE-614" in rules[0]["properties"]["tags"]


def test_build_rules_no_cwe_empty_tags():
    """Un test sin CWE debe tener tags vacío."""
    metas = [_make_meta("COOKIE-SECURE", cwe=None)]
    rules = _build_rules(metas)
    assert rules[0]["properties"]["tags"] == []


def test_build_rules_short_description():
    """shortDescription.text debe coincidir con el nombre del test."""
    metas = [_make_meta("COOKIE-SECURE", name="Cookie Secure attribute")]
    rules = _build_rules(metas)
    assert rules[0]["shortDescription"]["text"] == "Cookie Secure attribute"


def test_build_rules_sorted_by_block_order_code():
    """Las rules deben estar ordenadas por bloque, orden visual y código."""
    metas = [_make_meta("EXPOSED-ENV", block=7), _make_meta("COOKIE-SECURE"), _make_meta("HEADER-X-FRAME-OPTIONS", block=3)]
    rules = _build_rules(metas)
    ids = [r["id"] for r in rules]
    assert ids == [
        "WSS-COOKIE-SECURE",
        "WSS-HEADER-X-FRAME-OPTIONS",
        "WSS-EXPOSED-ENV",
    ]


# ── Tests de results[] — solo FAIL y WARN ───────────────────────────────────

def test_fail_results_appear_in_sarif():
    """Los resultados FAIL deben aparecer en runs[0].results."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.FAIL)]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 1
    assert sarif_results[0]["level"] == "error"


def test_warn_results_appear_in_sarif():
    """Los resultados WARN deben aparecer en runs[0].results con level='warning'."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.WARN)]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 1
    assert sarif_results[0]["level"] == "warning"


def test_pass_results_not_in_sarif():
    """Los resultados PASS no deben aparecer en runs[0].results."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.PASS, detail="Todo correcto")]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 0


def test_skip_results_not_in_sarif():
    """Los resultados SKIP no deben aparecer en runs[0].results."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.SKIP, detail="Test omitido")]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 0


def test_mixed_results_only_fail_and_warn():
    """Con PASS, FAIL, WARN, SKIP — solo FAIL y WARN aparecen en results."""
    results = [
        _make_result("COOKIE-SECURE", status=Status.PASS),
        _make_result("TLS-HSTS", status=Status.FAIL),
        _make_result("HEADER-CSP", status=Status.WARN),
        _make_result("EXPOSED-ENV", status=Status.SKIP),
    ]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 2
    levels = {r["level"] for r in sarif_results}
    assert levels == {"error", "warning"}


def test_result_rule_id_format():
    """El ruleId de cada result debe tener prefijo WSS-."""
    results = [_make_result(code="EXPOSED-ENV", status=Status.FAIL)]
    sarif_results = _build_results(results, domain="example.com")
    assert sarif_results[0]["ruleId"] == "WSS-EXPOSED-ENV"


def test_result_message_uses_detail():
    """message.text debe contener el detalle del resultado."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.FAIL, detail="Cookie sin Secure")]
    sarif_results = _build_results(results, domain="example.com")
    assert sarif_results[0]["message"]["text"] == "Cookie sin Secure"


def test_result_location_uri_uses_domain():
    """La uri de location debe usar la ruta virtual del dominio escaneado."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.FAIL)]
    sarif_results = _build_results(results, domain="app.ejemplo.com")
    uri = sarif_results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "scanned/app.ejemplo.com/index"


def test_result_cwe_in_properties():
    """Si el resultado tiene CWE, debe aparecer en properties.cwe."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.FAIL, cwe="CWE-614")]
    sarif_results = _build_results(results, domain="example.com")
    assert sarif_results[0]["properties"]["cwe"] == "CWE-614"


def test_result_no_cwe_not_in_properties():
    """Si el resultado no tiene CWE, properties.cwe no debe existir."""
    results = [_make_result(code="COOKIE-SECURE", status=Status.FAIL, cwe=None)]
    sarif_results = _build_results(results, domain="example.com")
    assert "cwe" not in sarif_results[0]["properties"]


# ── Tests de generate() — integración end-to-end ────────────────────────────

def test_generate_empty_results_valid_sarif():
    """Con resultados vacíos, generate() debe devolver SARIF válido con results=[]."""
    doc = json.loads(generate([], domain="example.com"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_generate_only_pass_results():
    """Si todos los resultados son PASS, results[] debe ser vacío."""
    results = [
        _make_result("COOKIE-SECURE", status=Status.PASS),
        _make_result("TLS-HSTS", status=Status.PASS),
    ]
    doc = json.loads(generate(results, domain="example.com"))
    assert doc["runs"][0]["results"] == []


def test_generate_invocations_domain():
    """Las invocations deben registrar el dominio escaneado."""
    results = [_make_result()]
    doc = json.loads(generate(results, domain="my.domain.com"))
    invocation = doc["runs"][0]["invocations"][0]
    assert invocation["properties"]["domain"] == "my.domain.com"
    assert invocation["executionSuccessful"] is True


def test_generate_artifacts_uri():
    """El array artifacts debe contener la URI del dominio."""
    results = [_make_result()]
    doc = json.loads(generate(results, domain="test.com"))
    artifact_uri = doc["runs"][0]["artifacts"][0]["location"]["uri"]
    assert artifact_uri == "https://test.com/"


def test_generate_output_is_valid_json():
    """generate() debe devolver un JSON válido (no lanzar excepciones)."""
    results = [
        _make_result("COOKIE-SECURE", status=Status.FAIL),
        _make_result("TLS-HSTS", status=Status.WARN),
        _make_result("HEADER-CSP", status=Status.PASS),
    ]
    output = generate(results, domain="example.com")
    # No debe lanzar excepciones
    parsed = json.loads(output)
    assert parsed is not None


# ── Tests de _to_utc_str / timestamp ────────────────────────────────────────

def test_generate_timestamp_naive_ends_with_Z():
    """generate() con scanned_at naive debe producir timestamp terminado en Z."""
    results = [_make_result()]
    naive = datetime(2026, 5, 16, 12, 0, 0)
    doc = json.loads(generate(results, domain="example.com", scanned_at=naive))
    ts = doc["runs"][0]["invocations"][0]["startTimeUtc"]
    assert ts.endswith("Z")
    assert "+00:00" not in ts


def test_generate_timestamp_aware_ends_with_Z_no_offset():
    """generate() con scanned_at timezone-aware no debe producir '+00:00Z'."""
    results = [_make_result()]
    aware = datetime(2026, 5, 16, 12, 0, 0, tzinfo=timezone.utc)
    doc = json.loads(generate(results, domain="example.com", scanned_at=aware))
    ts = doc["runs"][0]["invocations"][0]["startTimeUtc"]
    assert ts.endswith("Z")
    assert "+00:00" not in ts
    assert ts == "2026-05-16T12:00:00Z"


# ── Tests de generate_from_dicts() ──────────────────────────────────────────

def _make_dict(
    code: str = "COOKIE-SECURE",
    name: str = "Test dummy",
    result: str = "FAIL",
    detail: str = "Detalle",
    severity: str = "HIGH",
    cwe: str | None = "CWE-200",
    block: int = 1,
    duration_ms: float = 10.0,
) -> dict:
    """Construye un dict equivalente al que almacena Result.to_dict()."""
    return {
        "code": code,
        "name": name,
        "result": result,  # clave 'result', no 'status'
        "detail": detail,
        "severity": severity,
        "cwe": cwe,
        "block": block,
        "duration_ms": duration_ms,
    }


def test_generate_from_dicts_valid_sarif():
    """generate_from_dicts() debe devolver SARIF 2.1.0 válido."""
    dicts = [_make_dict()]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    assert doc["version"] == "2.1.0"
    assert "sarif-schema-2.1.0" in doc["$schema"]
    assert len(doc["runs"]) == 1


def test_generate_from_dicts_fail_appears():
    """Los dicts con result='FAIL' deben aparecer en runs[0].results."""
    dicts = [_make_dict(code="COOKIE-SECURE", result="FAIL")]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"
    assert results[0]["ruleId"] == "WSS-COOKIE-SECURE"


def test_generate_from_dicts_warn_appears():
    """Los dicts con result='WARN' deben aparecer con level='warning'."""
    dicts = [_make_dict(code="TLS-HSTS", result="WARN")]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "warning"


def test_generate_from_dicts_pass_not_in_results():
    """Los dicts con result='PASS' no deben aparecer en runs[0].results."""
    dicts = [_make_dict(code="COOKIE-SECURE", result="PASS")]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    assert doc["runs"][0]["results"] == []


def test_generate_from_dicts_skip_not_in_results():
    """Los dicts con result='SKIP' no deben aparecer en runs[0].results."""
    dicts = [_make_dict(code="COOKIE-SECURE", result="SKIP")]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    assert doc["runs"][0]["results"] == []


def test_generate_from_dicts_mixed_filters_correctly():
    """Con FAIL, WARN, PASS, SKIP — solo FAIL y WARN en results."""
    dicts = [
        _make_dict("COOKIE-SECURE", result="FAIL"),
        _make_dict("TLS-HSTS", result="WARN"),
        _make_dict("HEADER-CSP", result="PASS"),
        _make_dict("EXPOSED-ENV", result="SKIP"),
    ]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    levels = {r["level"] for r in results}
    assert levels == {"error", "warning"}


def test_generate_from_dicts_message_uses_detail():
    """message.text debe ser el campo 'detail' del dict."""
    dicts = [_make_dict(code="COOKIE-SECURE", result="FAIL", detail="Archivo .env expuesto")]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    assert doc["runs"][0]["results"][0]["message"]["text"] == "Archivo .env expuesto"


def test_generate_from_dicts_location_uses_domain():
    """La uri de location debe ser https://domain/."""
    dicts = [_make_dict(code="COOKIE-SECURE", result="FAIL")]
    doc = json.loads(generate_from_dicts(dicts, domain="target.com"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://target.com/"


def test_generate_from_dicts_cwe_in_properties():
    """Si el dict tiene cwe, debe aparecer en properties.cwe."""
    dicts = [_make_dict(code="COOKIE-SECURE", result="FAIL", cwe="CWE-530")]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    assert doc["runs"][0]["results"][0]["properties"]["cwe"] == "CWE-530"


def test_generate_from_dicts_no_cwe_not_in_properties():
    """Si el dict no tiene cwe, properties.cwe no debe existir."""
    dicts = [_make_dict(code="COOKIE-SECURE", result="FAIL", cwe=None)]
    doc = json.loads(generate_from_dicts(dicts, domain="example.com"))
    assert "cwe" not in doc["runs"][0]["results"][0]["properties"]


def test_generate_from_dicts_timestamp_aware_no_double_tz():
    """Con scanned_at timezone-aware el timestamp resultante no debe contener '+00:00Z'."""
    dicts = [_make_dict()]
    aware = datetime(2026, 5, 16, 8, 30, 0, tzinfo=timezone.utc)
    doc = json.loads(generate_from_dicts(dicts, domain="example.com", scanned_at=aware))
    ts = doc["runs"][0]["invocations"][0]["startTimeUtc"]
    assert ts.endswith("Z")
    assert "+00:00" not in ts
    assert ts == "2026-05-16T08:30:00Z"


def test_generate_from_dicts_empty_list():
    """Con lista vacía debe devolver SARIF válido con results=[]."""
    doc = json.loads(generate_from_dicts([], domain="example.com"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
