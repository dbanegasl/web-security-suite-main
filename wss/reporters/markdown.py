"""Reporter Markdown — replica el formato de generate_report_individual() del bash."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from wss.core.result import Result, Status
from wss.core.scanner import summary, overall_status

_ICONS = {
    Status.PASS: "✅ PASS",
    Status.FAIL: "❌ FAIL",
    Status.WARN: "⚠️  WARN",
    Status.SKIP: "⏭  SKIP",
}

_OVERALL_LABELS = {
    "EXCELLENT": "🟢 EXCELENTE — sin fallos ni advertencias",
    "ACCEPTABLE": "🟡 ACEPTABLE — sin fallos críticos, {warn} advertencia(s)",
    "IMPROVABLE": "🟠 MEJORABLE — {fail} fallo(s) a corregir",
    "CRITICAL": "🔴 CRÍTICO — {fail} fallos detectados",
}

# Tabla de referencia estática (misma que en generate_report_individual del bash)
_REFERENCE_ROWS = [
    ("01", "Cookie flag: **Secure**", "Cookies", "Medio — cookie enviada por HTTP"),
    ("02", "Cookie flag: **HttpOnly**", "Cookies", "**Alto** — robo de sesión via XSS"),
    ("03", "Cookie flag: **SameSite**", "Cookies", "Medio — CSRF cross-site"),
    ("04", "Cookie attribute: **Path**", "Cookies", "Bajo — scope de cookie sin restringir"),
    ("05", "**HTTP → HTTPS** redirect 301/302", "Transporte", "Medio — tráfico en claro posible"),
    ("06", "**HSTS** Strict-Transport-Security", "Transporte", "**Alto** — SSL stripping attack"),
    ("07", "**TLS 1.0** deshabilitado", "Transporte", "**Alto** — protocolo roto (POODLE)"),
    ("08", "**TLS 1.1** deshabilitado", "Transporte", "Medio — protocolo obsoleto"),
    ("09", "Certificado SSL **vigente**", "Transporte", "Crítico — conexión insegura si expira"),
    ("10", "**X-Frame-Options** (anti-clickjacking)", "Cabeceras", "**Alto** — iframes maliciosos"),
    ("11", "**X-Content-Type-Options**: nosniff", "Cabeceras", "Medio — MIME confusion attack"),
    ("12", "**Content-Security-Policy** (CSP)", "Cabeceras", "**Alto** — XSS sin restricción de scripts"),
    ("13", "**Referrer-Policy**", "Cabeceras", "Bajo — fuga de URLs a terceros"),
    ("14", "**Permissions-Policy**", "Cabeceras", "Bajo — acceso a APIs del navegador"),
    ("15", "**Server** header oculto", "Fuga de info", "Medio — revela versión del servidor"),
    ("16", "**X-Powered-By** ausente", "Fuga de info", "Medio — revela stack (PHP, etc.)"),
    ("17", "**X-AspNet-Version** ausente", "Fuga de info", "Medio — revela versión de .NET"),
    ("18", "**CORS** sin wildcard", "Config. servidor", "**Alto** — acceso cross-origin irrestricto"),
    ("19", "**HTTP TRACE** deshabilitado", "Config. servidor", "Medio — XST (Cross-Site Tracing)"),
    ("20", "**Cache-Control** adecuado", "Config. servidor", "Medio — datos sensibles en caché"),
    ("21", "**Headers deprecados** ausentes", "Modernización", "Bajo — X-XSS-Protection, Expect-CT y Pragma obsoletos"),
    ("22", "**Cross-Origin-Opener-Policy** (COOP)", "Aislamiento", "Medio — ataques de ventana cross-origin"),
    ("23", "**Cross-Origin-Embedder-Policy** (COEP)", "Aislamiento", "Medio — necesario para SharedArrayBuffer"),
    ("24", "**Cross-Origin-Resource-Policy** (CORP)", "Aislamiento", "Medio — recursos cargables desde orígenes externos"),
    ("25", "**X-Permitted-Cross-Domain-Policies**", "Aislamiento", "Bajo — acceso de Adobe Flash/PDF a recursos"),
]


def generate_individual(
    results: list[Result],
    domain: str,
    base_url: str,
    ip: Optional[str] = None,
    scanned_at: Optional[datetime] = None,
) -> str:
    """Genera el reporte Markdown individual (misma estructura que el bash).

    Args:
        results:    Lista de Result del escaneo.
        domain:     Dominio escaneado.
        base_url:   URL base utilizada.
        ip:         IP forzada (opcional).
        scanned_at: Fecha/hora del escaneo (por defecto: now).

    Returns:
        String con el contenido Markdown listo para escribir a archivo.
    """
    if scanned_at is None:
        scanned_at = datetime.now()

    s = summary(results)
    total = s["total"]
    status = overall_status(results)
    date_str = scanned_at.strftime("%Y-%m-%d %H:%M:%S")

    lines: list[str] = []

    # Cabecera
    lines += [
        f"# Reporte de Seguridad Web — {domain}",
        "",
        "| Campo | Valor |",
        "|-------|-------|",
        f"| **Fecha** | {date_str} |",
        f"| **URL base** | {base_url} |",
    ]
    if ip:
        lines.append(f"| **IP forzada** | {ip} |")
    lines += ["", "---", ""]

    # Resumen
    overall_label = _OVERALL_LABELS[status].format(
        warn=s["WARN"], fail=s["FAIL"]
    )
    lines += [
        "## Resumen",
        "",
        "| Resultado | Cantidad |",
        "|-----------|:--------:|",
        f"| ✅ PASS   | {s['PASS']} |",
        f"| ❌ FAIL   | {s['FAIL']} |",
        f"| ⚠️  WARN  | {s['WARN']} |",
        f"| ⏭  SKIP  | {s['SKIP']} |",
        f"| **Total** | **{total}** |",
        "",
        f"**Estado general:** {overall_label}",
        "",
        "---",
        "",
    ]

    # Detalle de tests
    lines += [
        "## Detalle de tests",
        "",
        "| Test | Descripción | Resultado | Detalle |",
        "|:----:|-------------|:---------:|---------|",
    ]
    for r in results:
        icon = _ICONS.get(r.status, "?")
        detail = r.detail if r.detail else "-"
        lines.append(f"| {r.id} | {r.name} | {icon} | {detail} |")

    lines += ["", "---", ""]

    # Hallazgos críticos
    fails = [r for r in results if r.status == Status.FAIL]
    if fails:
        lines += ["## ❌ Hallazgos críticos (FAIL)", ""]
        for r in fails:
            suffix = f": {r.detail}" if r.detail else ""
            lines.append(f"- **TEST-{r.id} — {r.name}**{suffix}")
        lines.append("")

    # Advertencias
    warns = [r for r in results if r.status == Status.WARN]
    if warns:
        lines += ["## ⚠️  Advertencias (WARN)", ""]
        for r in warns:
            suffix = f": {r.detail}" if r.detail else ""
            lines.append(f"- **TEST-{r.id} — {r.name}**{suffix}")
        lines.append("")

    # Referencia de tests
    lines += [
        "---",
        "",
        "## Referencia de tests",
        "",
        "| ID | Nombre | Bloque | Riesgo si falla |",
        "|----|--------|--------|-----------------|",
    ]
    for row in _REFERENCE_ROWS:
        lines.append(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |")

    lines += [
        "",
        "---",
        "",
        f"_Generado con Web Security Scanner v4.0 — {date_str}_",
    ]

    return "\n".join(lines) + "\n"
