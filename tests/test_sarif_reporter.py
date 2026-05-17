"""Tests unitarios para wss/reporters/sarif_reporter.py."""
from __future__ import annotations

import json

import pytest

from wss.core.result import Result, Severity, Status
from wss.core.registry import TestMeta, TEST_REGISTRY
from wss.reporters.sarif_reporter import generate, _build_rules, _build_results


# ── Fixtures ────────────────────────────────────────────────────────────────

def _make_result(
    id: str = "01",
    name: str = "Test dummy",
    status: Status = Status.FAIL,
    detail: str = "Detalle del fallo",
    severity: Severity = Severity.HIGH,
    cwe: str | None = "CWE-200",
    block: int = 1,
    duration_ms: float = 12.5,
) -> Result:
    return Result(
        id=id,
        name=name,
        status=status,
        detail=detail,
        severity=severity,
        cwe=cwe,
        block=block,
        duration_ms=duration_ms,
    )


def _make_meta(
    id: str = "01",
    name: str = "Test dummy",
    block: int = 1,
    severity: str = "HIGH",
    cwe: str | None = "CWE-200",
    description: str = "Descripción del test",
) -> TestMeta:
    return TestMeta(
        id=id,
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
    metas = [_make_meta("01"), _make_meta("26", block=7)]
    rules = _build_rules(metas)
    ids = [r["id"] for r in rules]
    assert "WSS-01" in ids
    assert "WSS-26" in ids


def test_build_rules_severity_critical_maps_to_error():
    """Severidad CRITICAL → level='error'."""
    metas = [_make_meta("01", severity="CRITICAL")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "error"


def test_build_rules_severity_high_maps_to_error():
    """Severidad HIGH → level='error'."""
    metas = [_make_meta("01", severity="HIGH")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "error"


def test_build_rules_severity_medium_maps_to_warning():
    """Severidad MEDIUM → level='warning'."""
    metas = [_make_meta("01", severity="MEDIUM")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "warning"


def test_build_rules_severity_low_maps_to_note():
    """Severidad LOW → level='note'."""
    metas = [_make_meta("01", severity="LOW")]
    rules = _build_rules(metas)
    assert rules[0]["defaultConfiguration"]["level"] == "note"


def test_build_rules_cwe_in_tags():
    """El CWE del test debe aparecer en properties.tags."""
    metas = [_make_meta("01", cwe="CWE-614")]
    rules = _build_rules(metas)
    assert "CWE-614" in rules[0]["properties"]["tags"]


def test_build_rules_no_cwe_empty_tags():
    """Un test sin CWE debe tener tags vacío."""
    metas = [_make_meta("01", cwe=None)]
    rules = _build_rules(metas)
    assert rules[0]["properties"]["tags"] == []


def test_build_rules_short_description():
    """shortDescription.text debe coincidir con el nombre del test."""
    metas = [_make_meta("01", name="Cookie Secure attribute")]
    rules = _build_rules(metas)
    assert rules[0]["shortDescription"]["text"] == "Cookie Secure attribute"


def test_build_rules_sorted_by_id():
    """Las rules deben estar ordenadas por id."""
    metas = [_make_meta("26", block=7), _make_meta("01"), _make_meta("10", block=3)]
    rules = _build_rules(metas)
    ids = [r["id"] for r in rules]
    assert ids == sorted(ids)


# ── Tests de results[] — solo FAIL y WARN ───────────────────────────────────

def test_fail_results_appear_in_sarif():
    """Los resultados FAIL deben aparecer en runs[0].results."""
    results = [_make_result(id="01", status=Status.FAIL)]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 1
    assert sarif_results[0]["level"] == "error"


def test_warn_results_appear_in_sarif():
    """Los resultados WARN deben aparecer en runs[0].results con level='warning'."""
    results = [_make_result(id="01", status=Status.WARN)]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 1
    assert sarif_results[0]["level"] == "warning"


def test_pass_results_not_in_sarif():
    """Los resultados PASS no deben aparecer en runs[0].results."""
    results = [_make_result(id="01", status=Status.PASS, detail="Todo correcto")]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 0


def test_skip_results_not_in_sarif():
    """Los resultados SKIP no deben aparecer en runs[0].results."""
    results = [_make_result(id="01", status=Status.SKIP, detail="Test omitido")]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 0


def test_mixed_results_only_fail_and_warn():
    """Con PASS, FAIL, WARN, SKIP — solo FAIL y WARN aparecen en results."""
    results = [
        _make_result("01", status=Status.PASS),
        _make_result("02", status=Status.FAIL),
        _make_result("03", status=Status.WARN),
        _make_result("04", status=Status.SKIP),
    ]
    sarif_results = _build_results(results, domain="example.com")
    assert len(sarif_results) == 2
    levels = {r["level"] for r in sarif_results}
    assert levels == {"error", "warning"}


def test_result_rule_id_format():
    """El ruleId de cada result debe tener prefijo WSS-."""
    results = [_make_result(id="26", status=Status.FAIL)]
    sarif_results = _build_results(results, domain="example.com")
    assert sarif_results[0]["ruleId"] == "WSS-26"


def test_result_message_uses_detail():
    """message.text debe contener el detalle del resultado."""
    results = [_make_result(id="01", status=Status.FAIL, detail="Cookie sin Secure")]
    sarif_results = _build_results(results, domain="example.com")
    assert sarif_results[0]["message"]["text"] == "Cookie sin Secure"


def test_result_location_uri_uses_domain():
    """La uri de location debe ser https://domain/."""
    results = [_make_result(id="01", status=Status.FAIL)]
    sarif_results = _build_results(results, domain="app.ejemplo.com")
    uri = sarif_results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://app.ejemplo.com/"


def test_result_cwe_in_properties():
    """Si el resultado tiene CWE, debe aparecer en properties.cwe."""
    results = [_make_result(id="01", status=Status.FAIL, cwe="CWE-614")]
    sarif_results = _build_results(results, domain="example.com")
    assert sarif_results[0]["properties"]["cwe"] == "CWE-614"


def test_result_no_cwe_not_in_properties():
    """Si el resultado no tiene CWE, properties.cwe no debe existir."""
    results = [_make_result(id="01", status=Status.FAIL, cwe=None)]
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
        _make_result("01", status=Status.PASS),
        _make_result("02", status=Status.PASS),
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
        _make_result("01", status=Status.FAIL),
        _make_result("02", status=Status.WARN),
        _make_result("03", status=Status.PASS),
    ]
    output = generate(results, domain="example.com")
    # No debe lanzar excepciones
    parsed = json.loads(output)
    assert parsed is not None
