"""Reporter Table — salida coloreada en terminal usando Rich."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

from wss.core.result import Result, Status
from wss.core.scanner import summary

_STATUS_STYLE = {
    Status.PASS: ("✅ PASS", "green"),
    Status.FAIL: ("❌ FAIL", "red"),
    Status.WARN: ("⚠️  WARN", "yellow"),
    Status.SKIP: ("⏭  SKIP", "magenta"),
}


def print_results(
    results: list[Result],
    domain: str,
    ip: Optional[str] = None,
    scanned_at: Optional[datetime] = None,
    console: Optional[Console] = None,
) -> None:
    """Imprime los resultados en terminal con colores usando Rich.

    Replica la salida visual del script bash (sección por bloque,
    línea por test, resumen final).
    """
    if console is None:
        console = Console()
    if scanned_at is None:
        scanned_at = datetime.now()

    # Cabecera
    console.print()
    console.print(
        f"  [bold cyan]{'━' * 51}[/]\n"
        f"  [bold]  Dominio  : [/]{domain}\n"
        + (f"  [bold]  IP forzada: [/]{ip}\n" if ip else "")
        + f"  [bold]  Fecha    : [/]{scanned_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  [bold cyan]{'━' * 51}[/]"
    )
    console.print()

    # Tests agrupados por bloque
    current_block = -1
    for r in results:
        if r.block != current_block:
            current_block = r.block
            # Obtener block_name desde el registry
            from wss.core.registry import TEST_REGISTRY
            meta = next((m for m in TEST_REGISTRY if m.id == r.id), None)
            block_name = meta.block_name if meta else f"BLOQUE {r.block}"
            console.print(f"\n  [bold cyan]▸ {block_name}[/]")

        icon, style = _STATUS_STYLE.get(r.status, ("?", "white"))
        suffix = f"  → {r.detail}" if r.detail else ""
        console.print(
            f"  [[bold {style}]{icon}[/]] TEST-{r.id} — {r.name}[dim]{suffix}[/]"
        )

    # Resumen final
    s = summary(results)
    console.print()
    console.print(f"  [bold]{'━' * 51}[/]")
    console.print(
        f"  [bold]RESUMEN:[/] "
        f"[green]{s['PASS']} PASS[/]  "
        f"[red]{s['FAIL']} FAIL[/]  "
        f"[yellow]{s['WARN']} WARN[/]  "
        f"[magenta]{s['SKIP']} SKIP[/]  "
        f"/  {s['total']} tests"
    )
    console.print()

    if s["FAIL"] == 0 and s["WARN"] == 0:
        console.print(f"  [green]✅ SECURITY SCAN: TODOS LOS TESTS PASARON — {domain}[/]")
    elif s["FAIL"] == 0:
        console.print(
            f"  [yellow]⚠️  SECURITY SCAN: SIN FALLOS CRÍTICOS, "
            f"{s['WARN']} advertencia(s) — {domain}[/]"
        )
    else:
        console.print(
            f"  [red]❌ SECURITY SCAN: {s['FAIL']} FALLO(S) CRÍTICO(S) — {domain}[/]"
        )

    console.print(f"  [bold]{'━' * 51}[/]")
    console.print()
