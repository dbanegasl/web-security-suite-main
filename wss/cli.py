"""CLI — interfaz de línea de comandos con Typer.

Reemplaza scan-cli.sh en modo no interactivo.
Mantiene compatibilidad con las variables de entorno existentes:
    DOMAIN, SESSION_COOKIE_NAME, IP, OUTPUT_FORMAT
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="wss",
    help="Web Security Suite — passive HTTP security scanner",
    add_completion=False,
)

console = Console()


def _build_context(domain: str, session_cookie: str, ip: str):
    """Construye un ScanContext a partir de los parámetros del CLI."""
    from wss.core.context import ScanContext

    # Separar host y path (ej: app.ejemplo.com/portal → host=app.ejemplo.com, path=/portal)
    if "/" in domain:
        host, _, path_rest = domain.partition("/")
        base_path = f"/{path_rest}" if path_rest else "/"
    else:
        host = domain
        base_path = "/"

    base_url = f"https://{host}{base_path}"

    return ScanContext(
        domain=domain,
        host=host,
        base_url=base_url,
        session_cookie=session_cookie,
        ip=ip,
    )


async def _run_scan(
    domain: str,
    session_cookie: str,
    ip: str,
    fmt: str,
    output: Optional[Path],
) -> int:
    """Ejecuta el escaneo y devuelve el exit code (0=sin FAILs, 1=hay FAILs)."""
    from wss.core.scanner import scan, summary
    from wss.reporters.table import print_results
    from wss.reporters.markdown import generate_individual
    from wss.reporters.json_reporter import generate as json_generate
    from wss.reporters.sarif_reporter import generate as sarif_generate

    ctx = _build_context(domain, session_cookie, ip)
    scanned_at = datetime.now()

    console.print(f"\n  [bold cyan]Escaneando {domain}...[/]")

    results = await scan(ctx)

    if fmt == "table":
        print_results(results, domain=domain, ip=ip or None, scanned_at=scanned_at)

    elif fmt == "json":
        content = json_generate(
            results, domain=domain, base_url=ctx.base_url,
            ip=ip or None, scanned_at=scanned_at,
        )
        if output:
            output.write_text(content, encoding="utf-8")
        else:
            print(content)

    elif fmt == "markdown":
        content = generate_individual(
            results, domain=domain, base_url=ctx.base_url,
            ip=ip or None, scanned_at=scanned_at,
        )
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"  [green]Reporte guardado en {output}[/]")
        else:
            print(content)

    elif fmt == "sarif":
        content = sarif_generate(results, domain=domain, scanned_at=scanned_at)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"  [green]Reporte SARIF guardado en {output}[/]")
        else:
            print(content)

    s = summary(results)
    return 0 if s["FAIL"] == 0 else 1


@app.command()
def scan(
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d",
        envvar="DOMAIN",
        help="Dominio a escanear (sin https://). Ej: app.ejemplo.com",
    ),
    session_cookie: str = typer.Option(
        "",
        "--session-cookie", "-c",
        envvar="SESSION_COOKIE_NAME",
        help="Nombre de la cookie de sesión principal (para COOKIE-HTTPONLY).",
    ),
    ip: str = typer.Option(
        "",
        "--ip", "-i",
        envvar="IP",
        help="IP del servidor para forzar resolución DNS (equivalente a curl --resolve).",
    ),
    fmt: str = typer.Option(
        "table",
        "--format", "-f",
        envvar="OUTPUT_FORMAT",
        help="Formato de salida: table | json | markdown | sarif",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Archivo de salida (solo para json y markdown).",
    ),
) -> None:
    """Ejecuta el security scan pasivo contra un dominio web."""
    if not domain:
        console.print(
            "[red]Error:[/] especifica el dominio con --domain o la variable DOMAIN."
        )
        raise typer.Exit(code=2)

    exit_code = asyncio.run(_run_scan(domain, session_cookie, ip, fmt, output))
    raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
