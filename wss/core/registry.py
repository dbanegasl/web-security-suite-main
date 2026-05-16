"""Test registry — decorador @test, lista global TEST_REGISTRY y metadatos de bloques."""
from __future__ import annotations

from dataclasses import dataclass, field
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
    description: str = ""
    references: list[str] = field(default_factory=list)
    package: str = ""   # módulo Python de origen, ej. "wss.tests.block_1_cookies"


# ── Metadatos de bloques — fuente de verdad para el home y la wiki ──────────

@dataclass
class BlockMeta:
    block: int
    name: str
    icon: str        # clase FontAwesome, ej. "fa-cookie-bite"
    color: str       # clase CSS del home, ej. "hb-orange"
    description: str = ""


BLOCK_META: dict[int, BlockMeta] = {
    1: BlockMeta(1, "Cookies",                     "fa-cookie-bite",          "hb-orange",
                 "Atributos de seguridad en cookies de sesión (Secure, HttpOnly, SameSite, Path)."),
    2: BlockMeta(2, "Transporte y TLS",             "fa-lock",                 "hb-green",
                 "Redirección HTTPS, HSTS, versiones TLS obsoletas y validez del certificado."),
    3: BlockMeta(3, "Cabeceras HTTP",               "fa-shield-halved",        "hb-blue",
                 "Cabeceras de seguridad esenciales: X-Frame-Options, CSP, Referrer-Policy, etc."),
    4: BlockMeta(4, "Fuga de información",          "fa-eye-slash",            "hb-magenta",
                 "Cabeceras que revelan tecnología del servidor: Server, X-Powered-By, etc."),
    5: BlockMeta(5, "Configuración del servidor",   "fa-server",               "hb-yellow",
                 "CORS, HTTP TRACE y directivas de caché que pueden exponer datos."),
    6: BlockMeta(6, "Headers modernos",             "fa-wand-magic-sparkles",  "hb-teal",
                 "Cabeceras de aislamiento modernas (COOP, COEP, CORP) y deprecación de legados."),
    7: BlockMeta(7, "Archivos expuestos",           "fa-folder-open",          "hb-red",
                 "Rutas y archivos sensibles accesibles públicamente: .env, .git, dumps SQL, etc."),
    8: BlockMeta(8, "DNS y Email",                  "fa-at",                   "hb-purple",
                 "SPF, DMARC, DKIM, CAA, DNSSEC, subdomain takeover y puertos DB expuestos."),
    9: BlockMeta(9, "Fingerprinting",               "fa-fingerprint",          "hb-indigo",
                 "Páginas de debug activas, versión de CMS expuesta, mixed content y formularios inseguros."),
}


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
    description: str = "",
    references: Optional[list[str]] = None,
) -> Callable:
    """Decorador que registra una función de test en TEST_REGISTRY.

    Uso:
        @test(
            "01",
            block=1,
            block_name="Cookies",
            name="Cookie attribute: Secure",
            severity="HIGH",
            cwe="CWE-614",
            description="Verifica que todas las cookies tengan el atributo Secure.",
            references=["https://owasp.org/www-community/controls/SecureFlag"],
        )
        async def test_secure(ctx: ScanContext) -> Result:
            ...
    """

    def decorator(fn: Callable) -> Callable:
        TEST_REGISTRY.append(
            TestMeta(
                id=id,
                name=name,
                block=block,
                block_name=block_name or (BLOCK_META[block].name if block in BLOCK_META else ""),
                severity=Severity(severity),
                cwe=cwe,
                fn=fn,
                description=description,
                references=references or [],
                package=fn.__module__,
            )
        )
        return fn

    return decorator
