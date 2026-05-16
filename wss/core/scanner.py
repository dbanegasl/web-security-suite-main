"""Scanner — orquestador async que ejecuta todos los tests registrados."""
from __future__ import annotations

import importlib
import time
from typing import Optional

from wss.core.registry import TEST_REGISTRY
from wss.core.context import ScanContext
from wss.core.result import Result, Status

# Módulos de tests — importarlos activa sus decoradores @test y puebla TEST_REGISTRY.
# Añadir aquí cada nuevo bloque conforme se migre.
_TEST_MODULES = [
    "wss.tests.block_1_cookies",
    "wss.tests.block_2_transport",
    "wss.tests.block_3_headers",
    "wss.tests.block_4_info_leak",
    "wss.tests.block_5_server_config",
    "wss.tests.block_6_modern_headers",
    "wss.tests.block_7_exposed_files",
    "wss.tests.block_8_dns_email",
    "wss.tests.block_9_fingerprint",
]


def _ensure_tests_loaded() -> None:
    """Importa todos los módulos de tests para registrar sus decoradores."""
    for module in _TEST_MODULES:
        importlib.import_module(module)


async def scan(
    ctx: ScanContext,
    test_ids: Optional[list[str]] = None,
) -> list[Result]:
    """Ejecuta todos los tests registrados contra ctx.

    Args:
        ctx:       Contexto del escaneo (dominio, cookie, IP, cliente HTTP).
        test_ids:  Si se especifica, solo ejecuta los tests con esos IDs.

    Returns:
        Lista de Result ordenada por ID de test.
    """
    _ensure_tests_loaded()

    # Pre-fetch de la respuesta inicial (cacheada en ctx para todos los tests del bloque 1-6)
    try:
        await ctx.fetch_initial()
    except Exception:
        # Si falla la conexión, los tests individuales manejarán el error
        pass

    results: list[Result] = []
    registry = sorted(TEST_REGISTRY, key=lambda m: m.id)

    for meta in registry:
        if test_ids and meta.id not in test_ids:
            continue

        t0 = time.monotonic()
        try:
            result: Result = await meta.fn(ctx)
        except Exception as exc:
            result = Result.skip(detail=f"error inesperado: {exc}")

        # Rellenar metadatos desde el decorador
        result.id = meta.id
        result.name = meta.name
        result.block = meta.block
        result.severity = meta.severity
        result.cwe = meta.cwe
        result.duration_ms = (time.monotonic() - t0) * 1000

        results.append(result)

    return results


def summary(results: list[Result]) -> dict[str, int]:
    """Devuelve contadores PASS/FAIL/WARN/SKIP y total."""
    return {
        "PASS": sum(1 for r in results if r.status == Status.PASS),
        "FAIL": sum(1 for r in results if r.status == Status.FAIL),
        "WARN": sum(1 for r in results if r.status == Status.WARN),
        "SKIP": sum(1 for r in results if r.status == Status.SKIP),
        "total": len(results),
    }


def overall_status(results: list[Result]) -> str:
    """Devuelve el estado general del escaneo como string."""
    s = summary(results)
    if s["FAIL"] == 0 and s["WARN"] == 0:
        return "EXCELLENT"
    elif s["FAIL"] == 0:
        return "ACCEPTABLE"
    elif s["FAIL"] <= 2:
        return "IMPROVABLE"
    else:
        return "CRITICAL"
