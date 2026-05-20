"""Result types for WSS tests."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Result:
    """Resultado de un test individual.

    Los campos code, name, block, severity y cwe son rellenados por el scanner
    tras la ejecución del test, a partir de los metadatos del decorador @test.
    Las funciones de test solo devuelven status y detail.
    """

    # Rellenados por el scanner desde los metadatos del decorador
    code: str = ""
    name: str = ""
    block: int = 0
    severity: Severity = Severity.MEDIUM
    cwe: Optional[str] = None

    # Devueltos por la función de test
    status: Status = Status.SKIP
    detail: str = ""

    # Medición de rendimiento — rellenada por el scanner
    duration_ms: float = 0.0

    # ── Constructores de conveniencia (usados dentro de los tests) ─────────

    @classmethod
    def pass_(cls, detail: str = "") -> "Result":
        return cls(status=Status.PASS, detail=detail)

    @classmethod
    def fail(cls, detail: str = "") -> "Result":
        return cls(status=Status.FAIL, detail=detail)

    @classmethod
    def warn(cls, detail: str = "") -> "Result":
        return cls(status=Status.WARN, detail=detail)

    @classmethod
    def skip(cls, detail: str = "") -> "Result":
        return cls(status=Status.SKIP, detail=detail)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "name": self.name,
            "result": self.status.value,
            "detail": self.detail,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "block": self.block,
            "duration_ms": round(self.duration_ms, 2),
        }
