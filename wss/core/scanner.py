"""Scanner — orquestador async que ejecuta todos los tests registrados."""
from __future__ import annotations

import importlib
import pkgutil
import time
from typing import Optional

from wss.core.registry import TEST_REGISTRY
from wss.core.context import ScanContext
from wss.core.result import Result, Status

# ── Auto-discovery ──────────────────────────────────────────────────────────
# Se descubren automáticamente todos los módulos bajo wss.tests que empiecen
# por "block_". Esto permite añadir wss/tests/block_N_*.py sin tocar este
# archivo.  Los módulos externos que usen el entry-point "wss.tests" se
# añadirán aquí en una fase futura.

def _discover_test_modules() -> list[str]:
    """Devuelve la lista de módulos wss.tests.block_* disponibles, ordenados."""
    import wss.tests as _tests_pkg
    modules = []
    for info in pkgutil.iter_modules(_tests_pkg.__path__, prefix="wss.tests."):
        if info.name.split(".")[-1].startswith("block_"):
            modules.append(info.name)
    return sorted(modules)


_loaded = False


def _ensure_tests_loaded() -> None:
    """Importa todos los módulos de tests descubiertos para registrar sus decoradores.

    Idempotente: solo importa una vez por proceso.
    """
    global _loaded
    if _loaded:
        return
    for module in _discover_test_modules():
        importlib.import_module(module)
    _loaded = True


async def scan(
    ctx: ScanContext,
    test_codes: Optional[list[str]] = None,
) -> list[Result]:
    """Ejecuta todos los tests registrados contra ctx.

    Args:
        ctx:       Contexto del escaneo (dominio, cookie, IP, cliente HTTP).
        test_codes: Si se especifica, solo ejecuta los tests con esos códigos.

    Returns:
        Lista de Result ordenada por bloque/orden/código.
    """
    _ensure_tests_loaded()

    # Pre-fetch de la respuesta inicial (cacheada en ctx para todos los tests del bloque 1-6)
    try:
        await ctx.fetch_initial()
    except Exception:
        # Si falla la conexión, los tests individuales manejarán el error
        pass

    results: list[Result] = []
    registry = sorted(TEST_REGISTRY, key=lambda m: (m.block, m.order, m.code))

    for meta in registry:
        if test_codes and meta.code not in test_codes:
            continue

        t0 = time.monotonic()
        try:
            result: Result = await meta.fn(ctx)
        except Exception as exc:
            result = Result.skip(detail=f"error inesperado: {exc}")

        # Rellenar metadatos desde el decorador
        result.code = meta.code
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
