"""Test registry — decorador @test y lista global TEST_REGISTRY."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from wss.core.result import Severity


@dataclass
class TestMeta:
    """Metadatos de un test registrado."""

    id: str
    name: str
    block: int
    block_name: str
    severity: Severity
    cwe: Optional[str]
    fn: Callable


# Lista global ordenada — se puebla al importar los módulos de tests
TEST_REGISTRY: list[TestMeta] = []


def test(
    id: str,
    *,
    block: int,
    name: str,
    block_name: str = "",
    severity: str = "MEDIUM",
    cwe: Optional[str] = None,
) -> Callable:
    """Decorador que registra una función de test en TEST_REGISTRY.

    Uso:
        @test("01", block=1, block_name="Cookies", name="Cookie: Secure",
              severity="HIGH", cwe="CWE-614")
        async def test_secure(ctx: ScanContext) -> Result:
            ...
    """

    def decorator(fn: Callable) -> Callable:
        TEST_REGISTRY.append(
            TestMeta(
                id=id,
                name=name,
                block=block,
                block_name=block_name,
                severity=Severity(severity),
                cwe=cwe,
                fn=fn,
            )
        )
        return fn

    return decorator
