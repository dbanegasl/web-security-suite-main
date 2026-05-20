"""Bloque 8 — DNS, Email y Dominio (DNS-SPF a DNS-SENSITIVE-PORTS)."""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from wss.core.context import ScanContext
from wss.core.registry import test
from wss.core.result import Result

_BLOCK = 8
_BLOCK_NAME = "DNS, Email y Dominio"


async def _dns_query(qname: str, rdtype: str) -> Optional[Any]:
    """Ejecuta una consulta DNS en un executor (dnspython es síncrono).

    Devuelve el objeto Answer o None en caso de error (NXDOMAIN, timeout, etc.).
    """
    import dns.resolver  # type: ignore
    import dns.exception  # type: ignore

    loop = asyncio.get_event_loop()

    def _resolve() -> Any:
        return dns.resolver.resolve(qname, rdtype, lifetime=5.0)

    try:
        return await loop.run_in_executor(None, _resolve)
    except Exception:
        return None


def _get_txt_strings(answer: Any) -> list[str]:
    """Extrae todas las cadenas TXT de un Answer de dnspython."""
    texts: list[str] = []
    for rdata in answer:
        for s in rdata.strings:
            texts.append(s.decode("utf-8", errors="ignore"))
    return texts


# ─────────────────────────────────────────────────────────────────────────────
# DNS-SPF  Registro SPF
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "DNS-SPF",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Registro SPF configurado correctamente",
    severity="HIGH",
    cwe=None,
)
async def test_spf(ctx: ScanContext) -> Result:
    """El registro SPF debe existir y terminar en -all (RFC 7208)."""
    answer = await _dns_query(ctx.host, "TXT")
    if answer is None:
        return Result.skip("no se pudo consultar registros TXT")

    spf = None
    for txt in _get_txt_strings(answer):
        if txt.startswith("v=spf1"):
            spf = txt
            break

    if spf is None:
        return Result.fail("registro SPF ausente — dominio vulnerable a suplantación de correo")

    if "+all" in spf:
        return Result.fail(f"SPF con '+all' — cualquier servidor puede enviar correo: {spf[:120]}")

    if "-all" not in spf and "~all" not in spf:
        return Result.warn(f"SPF sin '-all' ni '~all' — política permisiva: {spf[:120]}")

    if "~all" in spf and "-all" not in spf:
        return Result.warn(f"SPF con '~all' (softfail) — se recomienda '-all': {spf[:120]}")

    return Result.pass_(f"SPF presente con política estricta: {spf[:120]}")


# ─────────────────────────────────────────────────────────────────────────────
# DNS-DMARC  Registro DMARC
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "DNS-DMARC",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Registro DMARC configurado correctamente",
    severity="HIGH",
    cwe=None,
)
async def test_dmarc(ctx: ScanContext) -> Result:
    """El registro DMARC debe existir y tener política quarantine o reject (RFC 7489)."""
    qname = f"_dmarc.{ctx.host}"
    answer = await _dns_query(qname, "TXT")
    if answer is None:
        return Result.fail(f"registro DMARC ausente en {qname}")

    dmarc = None
    for txt in _get_txt_strings(answer):
        if txt.startswith("v=DMARC1"):
            dmarc = txt
            break

    if dmarc is None:
        return Result.fail(f"registro DMARC ausente en {qname}")

    issues: list[str] = []
    if "p=none" in dmarc:
        issues.append("política 'none' (sin acción sobre fallos)")
    if "rua=" not in dmarc:
        issues.append("sin dirección rua (sin informes de agregado)")

    if issues:
        return Result.warn(f"DMARC presente pero incompleto: {'; '.join(issues)}")
    return Result.pass_(f"DMARC correctamente configurado: {dmarc[:120]}")


# ─────────────────────────────────────────────────────────────────────────────
# DNS-DKIM  Selectores DKIM
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "DNS-DKIM",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="DKIM con al menos un selector activo",
    severity="MEDIUM",
    cwe=None,
)
async def test_dkim(ctx: ScanContext) -> Result:
    """Al menos un selector DKIM debe existir (RFC 6376)."""
    selectors = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2", "s1", "s2"]
    tasks = [_dns_query(f"{sel}._domainkey.{ctx.host}", "TXT") for sel in selectors]
    results = await asyncio.gather(*tasks)

    found = []
    for sel, answer in zip(selectors, results):
        if answer is not None:
            txts = _get_txt_strings(answer)
            if any("v=DKIM1" in t for t in txts):
                found.append(sel)

    if not found:
        return Result.warn(f"ningún selector DKIM encontrado para {ctx.host}")
    return Result.pass_(f"selectores DKIM encontrados: {', '.join(found)}")


# ─────────────────────────────────────────────────────────────────────────────
# DNS-CAA  Registro CAA
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "DNS-CAA",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Registro CAA presente",
    severity="LOW",
    cwe=None,
)
async def test_caa(ctx: ScanContext) -> Result:
    """El registro CAA debe estar presente para restringir emisión de certificados (RFC 8659)."""
    answer = await _dns_query(ctx.host, "CAA")
    if answer is None:
        return Result.warn(f"registro CAA ausente — cualquier CA puede emitir certificados para {ctx.host}")
    entries = []
    for rdata in answer:
        entries.append(str(rdata))
    return Result.pass_(f"CAA presente: {'; '.join(entries[:3])}")


# ─────────────────────────────────────────────────────────────────────────────
# DNS-DNSSEC  DNSSEC
# ─────────────────────────────────────────────────────────────────────────────

@test(
    "DNS-DNSSEC",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="DNSSEC habilitado",
    severity="LOW",
    cwe=None,
)
async def test_dnssec(ctx: ScanContext) -> Result:
    """DNSSEC debe estar habilitado (DNSKEY presente) para proteger la integridad DNS (RFC 4033)."""
    answer = await _dns_query(ctx.host, "DNSKEY")
    if answer is None:
        return Result.warn(f"DNSKEY no encontrado — DNSSEC probablemente no habilitado para {ctx.host}")
    keys = sum(1 for _ in answer)
    return Result.pass_(f"DNSSEC habilitado — {keys} DNSKEY registrado(s)")


# ─────────────────────────────────────────────────────────────────────────────
# DNS-SUBDOMAIN-TAKEOVER  Subdomain takeover
# ─────────────────────────────────────────────────────────────────────────────

# Servicios comunes que devuelven respuestas reconocibles cuando el recurso
# apuntado por CNAME no existe / no está reclamado.
_TAKEOVER_SIGNATURES: dict[str, list[str]] = {
    "github.io": ["There isn't a GitHub Pages site here", "404 - File not found"],
    "amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "azurewebsites.net": ["404 Web Site not found"],
    "heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "cargo.site": ["If you're the owner of this website"],
    "surge.sh": ["project not found"],
    "netlify": ["Not found - Request ID"],
    "fastly": ["Fastly error: unknown domain"],
}


@test(
    "DNS-SUBDOMAIN-TAKEOVER",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Sin riesgo de subdomain takeover",
    severity="HIGH",
    cwe="CWE-284",
)
async def test_subdomain_takeover(ctx: ScanContext) -> Result:
    """El CNAME del dominio no debe apuntar a un servicio no reclamado."""
    answer = await _dns_query(ctx.host, "CNAME")
    if answer is None:
        return Result.pass_("sin CNAME apuntando a servicios externos o no aplicable")

    cname_target = str(list(answer)[0]).rstrip(".")

    # Comprobar si el CNAME apunta a un servicio conocido
    matched_service = None
    for service in _TAKEOVER_SIGNATURES:
        if service in cname_target.lower():
            matched_service = service
            break

    if matched_service is None:
        return Result.pass_(f"CNAME a {cname_target} — servicio no en lista de riesgo")

    # Intentar acceder al dominio y detectar firma de takeover
    try:
        url = f"https://{ctx.host}/"
        r = await ctx.client.get(url, follow_redirects=True)
        body = r.text[:2000]
        for sig in _TAKEOVER_SIGNATURES[matched_service]:
            if sig.lower() in body.lower():
                return Result.fail(
                    f"posible subdomain takeover — CNAME a {cname_target} con firma detectada"
                )
        return Result.warn(f"CNAME a {cname_target} ({matched_service}) — verificar manualmente")
    except Exception:
        return Result.warn(f"CNAME a {cname_target} — no se pudo verificar disponibilidad")


# ─────────────────────────────────────────────────────────────────────────────
# DNS-SENSITIVE-PORTS  Puertos sensibles expuestos
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    9300: "Elasticsearch (cluster)",
    5984: "CouchDB",
    7474: "Neo4j",
    8086: "InfluxDB",
}


async def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Devuelve True si el puerto TCP está abierto."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


@test(
    "DNS-SENSITIVE-PORTS",
    block=_BLOCK,
    block_name=_BLOCK_NAME,
    name="Puertos de bases de datos no expuestos",
    severity="CRITICAL",
    cwe="CWE-284",
)
async def test_sensitive_ports(ctx: ScanContext) -> Result:
    """Puertos de BD (MySQL, PostgreSQL, Redis, MongoDB, etc.) no deben estar accesibles."""
    # Usar ctx.ip si está disponible, de lo contrario ctx.host
    target = ctx.ip if ctx.ip else ctx.host

    ports = list(_SENSITIVE_PORTS.keys())
    results = await asyncio.gather(*(_port_open(target, p) for p in ports))

    open_ports = [
        f"{port}/{_SENSITIVE_PORTS[port]}"
        for port, is_open in zip(ports, results)
        if is_open
    ]

    if open_ports:
        return Result.fail(f"puertos sensibles abiertos: {', '.join(open_ports)}")
    return Result.pass_("puertos de bases de datos no expuestos")
