"""Reporter SARIF 2.1.0 — integración con GitHub Code Scanning, Azure Defender y SonarQube.

Especificación: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
Schema:         https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json

Solo se incluyen resultados FAIL y WARN (PASS/SKIP no se reportan por convención SARIF).
Los resultados FAIL se mapean a level="error", WARN a level="warning".
"""
from __future__ import annotations

import importlib.metadata
import json
from datetime import datetime, timezone
from typing import Optional

from wss.core.registry import TEST_REGISTRY, TestMeta
from wss.core.result import Result, Status

# Mapping de severidad WSS → SARIF level (para las rules)
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Mapping de status de resultado → SARIF level (para los results individuales)
_STATUS_TO_LEVEL: dict[str, str] = {
    "FAIL": "error",
    "WARN": "warning",
}


def _to_utc_str(dt: datetime) -> str:
    """Convierte datetime (naive o aware) a string UTC ISO 8601 terminado en Z."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="seconds") + "Z"


def _tool_version() -> str:
    try:
        return importlib.metadata.version("wss")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


def _build_rules(registry: list[TestMeta]) -> list[dict]:
    """Genera el array rules[] del driver a partir del TEST_REGISTRY."""
    rules = []
    for meta in sorted(registry, key=lambda m: m.id):
        rule: dict = {
            "id": f"WSS-{meta.id}",
            "name": meta.name.replace(" ", "").replace("-", "").replace(":", ""),
            "shortDescription": {"text": meta.name},
            "fullDescription": {
                "text": meta.description or meta.name,
            },
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL.get(meta.severity.value, "warning"),
            },
            "properties": {
                "tags": [],
                "block": meta.block,
                "blockName": meta.block_name,
                "severity": meta.severity.value,
            },
        }
        if meta.cwe:
            rule["properties"]["tags"].append(meta.cwe)
        if meta.references:
            rule["helpUri"] = meta.references[0]
            rule["help"] = {
                "text": " ".join(meta.references),
                "markdown": "\n".join(f"- {r}" for r in meta.references),
            }
        rules.append(rule)
    return rules


def _build_results(results: list[Result], domain: str) -> list[dict]:
    """Genera el array results[] con solo FAIL y WARN."""
    sarif_results = []
    artifact_uri = f"https://{domain}/"

    for r in results:
        if r.status not in (Status.FAIL, Status.WARN):
            continue

        level = _STATUS_TO_LEVEL[r.status.value]

        sarif_result: dict = {
            "ruleId": f"WSS-{r.id}",
            "level": level,
            "message": {"text": r.detail or r.name},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "severity": r.severity.value,
                "block": r.block,
                "duration_ms": r.duration_ms,
            },
        }
        if r.cwe:
            sarif_result["properties"]["cwe"] = r.cwe

        sarif_results.append(sarif_result)

    return sarif_results


def _build_results_from_dicts(results_dicts: list[dict], domain: str) -> list[dict]:
    """Como _build_results() pero acepta dicts (de results_json en BD)."""
    sarif_results = []
    artifact_uri = f"https://{domain}/"

    for r in results_dicts:
        status_val = r.get("result", "")
        if status_val not in ("FAIL", "WARN"):
            continue

        level = _STATUS_TO_LEVEL[status_val]

        sarif_result: dict = {
            "ruleId": f"WSS-{r['id']}",
            "level": level,
            "message": {"text": r.get("detail") or r.get("name", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "severity": r.get("severity", ""),
                "block": r.get("block"),
                "duration_ms": r.get("duration_ms"),
            },
        }
        if r.get("cwe"):
            sarif_result["properties"]["cwe"] = r["cwe"]

        sarif_results.append(sarif_result)

    return sarif_results


def generate_from_dicts(
    results_dicts: list[dict],
    domain: str,
    scanned_at: Optional[datetime] = None,
) -> str:
    """Genera SARIF 2.1.0 a partir de dicts (resultados almacenados en BD).

    Equivalente a generate() pero acepta la lista de dicts que se almacena en
    ScanHistory.results_json, donde cada dict tiene las claves:
    id, name, result (no status), detail, severity, cwe, block, duration_ms.

    Args:
        results_dicts: Lista de dicts de resultados (de results_json).
        domain:        Dominio escaneado (sin protocolo).
        scanned_at:    Timestamp del escaneo (default: ahora).

    Returns:
        JSON string con formato SARIF 2.1.0 válido.
    """
    if scanned_at is None:
        scanned_at = datetime.now()

    rules = _build_rules(TEST_REGISTRY)
    sarif_results = _build_results_from_dicts(results_dicts, domain)

    sarif_doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wss",
                        "version": _tool_version(),
                        "informationUri": "https://github.com/dbanegasl/web-security-suite-main",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": _to_utc_str(scanned_at),
                        "properties": {"domain": domain},
                    }
                ],
                "results": sarif_results,
                "artifacts": [
                    {
                        "location": {"uri": f"https://{domain}/"},
                        "description": {"text": f"Target web application: {domain}"},
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif_doc, ensure_ascii=False, indent=2)


def generate(
    results: list[Result],
    domain: str,
    scanned_at: Optional[datetime] = None,
) -> str:
    """Genera el reporte como string SARIF 2.1.0.

    Args:
        results:    Lista de resultados del scan.
        domain:     Dominio escaneado (sin protocolo).
        scanned_at: Timestamp del escaneo (default: ahora).

    Returns:
        JSON string con formato SARIF 2.1.0 válido.
    """
    if scanned_at is None:
        scanned_at = datetime.now()

    # Importar el registry poblado (los módulos de tests deben estar ya importados
    # por el scanner antes de llamar a generate())
    rules = _build_rules(TEST_REGISTRY)
    sarif_results = _build_results(results, domain)

    sarif_doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wss",
                        "version": _tool_version(),
                        "informationUri": "https://github.com/dbanegasl/web-security-suite-main",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": _to_utc_str(scanned_at),
                        "properties": {"domain": domain},
                    }
                ],
                "results": sarif_results,
                "artifacts": [
                    {
                        "location": {"uri": f"https://{domain}/"},
                        "description": {"text": f"Target web application: {domain}"},
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif_doc, ensure_ascii=False, indent=2)
