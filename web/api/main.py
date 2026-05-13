"""
Web Security Suite — API Backend (Opción B: wrapper de scan.sh)
Fase 2: API FastAPI que ejecuta scan.sh con OUTPUT_FORMAT=json

Uso:
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ── Configuración ──────────────────────────────────────────────────────────────
SCAN_SCRIPT = Path(os.environ.get("SCAN_SCRIPT_PATH", str(Path(__file__).parent / "scan.sh")))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SECONDS", "120"))
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:8080")

# ── Rate limiting ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Web Security Suite API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS — solo permitir el origen del frontend ────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ── Patrones de validación ─────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(/.*)?$"
)
_COOKIE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")
_IP_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# ── Modelos ────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    domain: str
    session_cookie: str = ""
    ip: str = ""

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip()
        # Eliminar esquema si lo incluyen
        v = re.sub(r"^https?://", "", v)
        host = v.split("/")[0]
        if not _DOMAIN_RE.match(v) or len(host) > 253:
            raise ValueError("Dominio no válido")
        return v

    @field_validator("session_cookie")
    @classmethod
    def validate_cookie(cls, v: str) -> str:
        v = v.strip()
        if v and not _COOKIE_RE.match(v):
            raise ValueError("Nombre de cookie no válido (solo alfanumérico, _, -, .)")
        return v

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        if v and not _IP_RE.match(v):
            raise ValueError("IP no válida (se espera IPv4)")
        return v


class BatchRequest(BaseModel):
    """CSV en texto plano: dominio,cookie_sesion,ip_forzada (columnas 2 y 3 opcionales)."""
    csv_content: str


# ── Helpers ────────────────────────────────────────────────────────────────────
def _build_env(domain: str, cookie: str, ip: str) -> dict[str, str]:
    """Construye el entorno seguro para ejecutar scan.sh."""
    return {
        "OUTPUT_FORMAT": "json",
        "DOMAIN": domain,
        "SESSION_COOKIE_NAME": cookie,
        "IP": ip,
        # Variables de sistema mínimas necesarias para curl/openssl/dig
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


async def _run_scan(domain: str, cookie: str, ip: str) -> dict[str, Any]:
    """Ejecuta scan.sh y devuelve el resultado JSON parseado."""
    env = _build_env(domain, cookie, ip)

    loop = asyncio.get_event_loop()
    try:
        result: subprocess.CompletedProcess = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: subprocess.run(  # noqa: S603 — args como lista, sin shell
                    ["bash", str(SCAN_SCRIPT)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=SCAN_TIMEOUT,
                ),
            ),
            timeout=SCAN_TIMEOUT + 10,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Timeout: el scan tardó demasiado")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="scan.sh no encontrado")

    stdout = result.stdout.strip()
    if not stdout:
        raise HTTPException(
            status_code=500,
            detail="El script no produjo salida. stderr: " + result.stderr[:200],
        )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error al parsear JSON del script: {exc}. stdout: {stdout[:200]}",
        )

    # Adjuntar código de retorno para que el frontend sepa si hay FAILs
    data["exitCode"] = result.returncode
    return data


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "scriptExists": SCAN_SCRIPT.exists()}


@app.post("/api/scan")
@limiter.limit("10/minute")
async def scan(request: Request, body: ScanRequest):
    """Ejecuta el scan sobre un único dominio y devuelve JSON estructurado."""
    return await _run_scan(body.domain, body.session_cookie, body.ip)


@app.post("/api/batch")
@limiter.limit("3/minute")
async def batch(request: Request, body: BatchRequest):
    """
    Ejecuta el scan en paralelo para múltiples dominios enviados como CSV.
    Formato CSV: dominio,cookie_sesion,ip_forzada  (columnas 2 y 3 opcionales)
    """
    results = []
    tasks = []

    for line in body.csv_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        domain = parts[0] if len(parts) > 0 else ""
        cookie = parts[1] if len(parts) > 1 else ""
        ip = parts[2] if len(parts) > 2 else ""

        # Validar cada dominio antes de ejecutar
        try:
            validated = ScanRequest(domain=domain, session_cookie=cookie, ip=ip)
        except Exception as exc:
            results.append({"domain": domain, "error": str(exc)})
            continue

        tasks.append(_run_scan(validated.domain, validated.session_cookie, validated.ip))

    # Ejecutar en paralelo (limitado por los timeouts de cada scan)
    scan_results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in scan_results:
        if isinstance(r, Exception):
            results.append({"error": str(r)})
        else:
            results.append(r)

    return {"total": len(results), "results": results}
