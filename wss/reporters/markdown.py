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

def _reference_rows() -> list[tuple[str, str, str, str]]:
    """Construye la referencia desde el registro real para evitar IDs hardcodeados."""
    from wss.core.registry import TEST_REGISTRY
    from wss.core.scanner import _ensure_tests_loaded

    _ensure_tests_loaded()
    rows = []
    for meta in sorted(TEST_REGISTRY, key=lambda m: (m.block, m.order, m.code)):
        rows.append(
            (
                meta.code,
                meta.name,
                meta.block_name,
                meta.description or meta.severity.value,
            )
        )
    return rows


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
        lines.append(f"| {r.code} | {r.name} | {icon} | {detail} |")

    lines += ["", "---", ""]

    # Hallazgos críticos
    fails = [r for r in results if r.status == Status.FAIL]
    if fails:
        lines += ["## ❌ Hallazgos críticos (FAIL)", ""]
        for r in fails:
            suffix = f": {r.detail}" if r.detail else ""
            lines.append(f"- **{r.code} — {r.name}**{suffix}")
        lines.append("")

    # Advertencias
    warns = [r for r in results if r.status == Status.WARN]
    if warns:
        lines += ["## ⚠️  Advertencias (WARN)", ""]
        for r in warns:
            suffix = f": {r.detail}" if r.detail else ""
            lines.append(f"- **{r.code} — {r.name}**{suffix}")
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
    for row in _reference_rows():
        lines.append(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |")

    lines += [
        "",
        "---",
        "",
        f"_Generado con Web Security Scanner v4.0 — {date_str}_",
    ]

    return "\n".join(lines) + "\n"
