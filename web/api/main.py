"""
Web Security Suite — API Backend
Fase A: Autenticación JWT + historial persistente SQLite
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlmodel import Session, col, func, select

import auth
import database
from models import DomainList, ListDomain, ScanHistory, User

# ── Configuración ──────────────────────────────────────────────────────────────
SCAN_SCRIPT = Path(os.environ.get("SCAN_SCRIPT_PATH", str(Path(__file__).parent / "scan.sh")))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SECONDS", "120"))
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:8080")
FIRST_ADMIN_USER = os.getenv("APP_FIRST_ADMIN_USER", "admin")
FIRST_ADMIN_PASS = os.getenv("APP_FIRST_ADMIN_PASSWORD", "")

# ── Rate limiting ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Web Security Suite API", version="2.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS — origen del frontend + cabecera Authorization ───────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# ── Startup: DB + admin inicial ────────────────────────────────────────────────
@app.on_event("startup")
def on_startup() -> None:
    database.create_db_and_tables()
    with Session(database._engine) as session:
        if not session.exec(select(User)).first():
            if not FIRST_ADMIN_PASS:
                print("WARNING: APP_FIRST_ADMIN_PASSWORD no definida — admin no creado")
                return
            session.add(User(
                username=FIRST_ADMIN_USER,
                password_hash=auth.hash_password(FIRST_ADMIN_PASS),
                role="admin",
            ))
            session.commit()
            print(f"INFO: Usuario admin '{FIRST_ADMIN_USER}' creado")

# ── Patrones de validación ─────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(/.*)?$"
)
_COOKIE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")
_IP_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# ── Modelos de request ─────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


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

    data["exitCode"] = result.returncode
    return data


def _save_scan(
    session: Session,
    data: dict[str, Any],
    mode: str,
    user_id: Optional[int],
    list_id: Optional[int] = None,
) -> ScanHistory:
    """Persiste el resultado de un scan en la base de datos."""
    s = data.get("summary", {})
    record = ScanHistory(
        domain=data.get("domain", ""),
        pass_count=s.get("pass", 0),
        fail_count=s.get("fail", 0),
        warn_count=s.get("warn", 0),
        skip_count=s.get("skip", 0),
        scan_mode=mode,
        results_json=json.dumps(data),
        triggered_by=user_id,
        list_id=list_id,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


# ── Endpoints: salud (público) ────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "scriptExists": SCAN_SCRIPT.exists()}


# ── Endpoints: autenticación ──────────────────────────────────────────────────
@app.post("/api/auth/login")
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: LoginRequest,
    session: Session = Depends(database.get_session),
):
    user = session.exec(select(User).where(User.username == body.username)).first()
    if not user or not user.is_active or not auth.verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
        )
    user.last_login = datetime.utcnow()
    session.add(user)
    session.commit()
    token = auth.create_access_token(user.id, user.username, user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
    }


@app.get("/api/auth/me")
async def me(current_user: User = Depends(auth.get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
    }


# ── Endpoints: scans ──────────────────────────────────────────────────────────
@app.post("/api/scan")
@limiter.limit("10/minute")
async def scan(
    request: Request,
    body: ScanRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    """Ejecuta el scan sobre un único dominio y devuelve JSON estructurado."""
    data = await _run_scan(body.domain, body.session_cookie, body.ip)
    _save_scan(session, data, "individual", current_user.id)
    return data


@app.post("/api/batch")
@limiter.limit("3/minute")
async def batch(
    request: Request,
    body: BatchRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
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

        try:
            validated = ScanRequest(domain=domain, session_cookie=cookie, ip=ip)
        except Exception as exc:
            results.append({"domain": domain, "error": str(exc)})
            continue

        tasks.append(_run_scan(validated.domain, validated.session_cookie, validated.ip))

    scan_results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in scan_results:
        if isinstance(r, Exception):
            results.append({"error": str(r)})
        else:
            _save_scan(session, r, "batch", current_user.id)
            results.append(r)

    return {"total": len(results), "results": results}


# ── Endpoints: historial ──────────────────────────────────────────────────────
# IMPORTANTE: /api/history/compare debe estar declarado ANTES de /api/history/{scan_id}
@app.get("/api/history/compare")
async def history_compare(
    a: int = Query(..., description="ID del primer scan"),
    b: int = Query(..., description="ID del segundo scan"),
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    rec_a = session.get(ScanHistory, a)
    rec_b = session.get(ScanHistory, b)
    if not rec_a or not rec_b:
        raise HTTPException(status_code=404, detail="Scan no encontrado")

    data_a = json.loads(rec_a.results_json)
    data_b = json.loads(rec_b.results_json)
    map_a = {t["id"]: t for t in data_a.get("tests", [])}
    map_b = {t["id"]: t for t in data_b.get("tests", [])}

    diff = []
    for tid in sorted(set(map_a) | set(map_b)):
        ta = map_a.get(tid, {})
        tb = map_b.get(tid, {})
        ra = ta.get("result", "?")
        rb = tb.get("result", "?")
        diff.append({
            "id": tid,
            "name": ta.get("name") or tb.get("name", ""),
            "result_a": ra,
            "result_b": rb,
            "changed": ra != rb,
        })

    return {
        "scan_a": {
            "id": rec_a.id,
            "domain": rec_a.domain,
            "scanned_at": rec_a.scanned_at.isoformat(),
        },
        "scan_b": {
            "id": rec_b.id,
            "domain": rec_b.domain,
            "scanned_at": rec_b.scanned_at.isoformat(),
        },
        "diff": diff,
    }


@app.get("/api/history/{scan_id}")
async def history_detail(
    scan_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    record = session.get(ScanHistory, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return {
        "id": record.id,
        "domain": record.domain,
        "scanned_at": record.scanned_at.isoformat(),
        "pass_count": record.pass_count,
        "fail_count": record.fail_count,
        "warn_count": record.warn_count,
        "skip_count": record.skip_count,
        "scan_mode": record.scan_mode,
        "results": json.loads(record.results_json),
    }


@app.get("/api/history")
async def history_list(
    domain: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    base = select(ScanHistory)
    if domain:
        base = base.where(col(ScanHistory.domain).contains(domain))

    total = session.exec(
        select(func.count()).select_from(base.subquery())
    ).one()

    records = session.exec(
        base.order_by(col(ScanHistory.scanned_at).desc()).offset(offset).limit(limit)
    ).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": r.id,
                "domain": r.domain,
                "scanned_at": r.scanned_at.isoformat(),
                "pass_count": r.pass_count,
                "fail_count": r.fail_count,
                "warn_count": r.warn_count,
                "skip_count": r.skip_count,
                "scan_mode": r.scan_mode,
                "list_id": r.list_id,
            }
            for r in records
        ],
    }


# ── Endpoints: listas de dominios (Fase B) ────────────────────────────────────

class ListCreateRequest(BaseModel):
    name: str
    description: str = ""

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("El nombre es obligatorio y debe tener menos de 128 caracteres")
        return v


class DomainEntryRequest(BaseModel):
    domain: str
    session_cookie: str = ""
    ip: str = ""
    notes: str = ""
    is_active: bool = True

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip()
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
            raise ValueError("Nombre de cookie no válido")
        return v

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        if v and not _IP_RE.match(v):
            raise ValueError("IP no válida")
        return v


def _list_or_404(list_id: int, session: Session) -> DomainList:
    dl = session.get(DomainList, list_id)
    if not dl:
        raise HTTPException(status_code=404, detail="Lista no encontrada")
    return dl


@app.get("/api/lists")
async def lists_index(
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    rows = session.exec(select(DomainList).order_by(col(DomainList.created_at).desc())).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "created_at": r.created_at.isoformat(),
            "domain_count": session.exec(
                select(func.count()).where(ListDomain.list_id == r.id)
            ).one(),
        }
        for r in rows
    ]


@app.post("/api/lists", status_code=201)
async def lists_create(
    body: ListCreateRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    dl = DomainList(name=body.name, description=body.description, created_by=current_user.id)
    session.add(dl)
    session.commit()
    session.refresh(dl)
    return {"id": dl.id, "name": dl.name, "description": dl.description, "created_at": dl.created_at.isoformat()}


@app.get("/api/lists/{list_id}")
async def lists_get(
    list_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    dl = _list_or_404(list_id, session)
    domains = session.exec(select(ListDomain).where(ListDomain.list_id == list_id)).all()
    return {
        "id": dl.id,
        "name": dl.name,
        "description": dl.description,
        "created_at": dl.created_at.isoformat(),
        "domains": [
            {
                "id": d.id,
                "domain": d.domain,
                "session_cookie": d.session_cookie,
                "ip": d.ip,
                "notes": d.notes,
                "is_active": d.is_active,
                "added_at": d.added_at.isoformat(),
            }
            for d in domains
        ],
    }


@app.put("/api/lists/{list_id}")
async def lists_update(
    list_id: int,
    body: ListCreateRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    dl = _list_or_404(list_id, session)
    dl.name = body.name
    dl.description = body.description
    session.add(dl)
    session.commit()
    session.refresh(dl)
    return {"id": dl.id, "name": dl.name, "description": dl.description}


@app.delete("/api/lists/{list_id}", status_code=204)
async def lists_delete(
    list_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    dl = _list_or_404(list_id, session)
    # Eliminar dominios asociados primero
    for d in session.exec(select(ListDomain).where(ListDomain.list_id == list_id)).all():
        session.delete(d)
    session.delete(dl)
    session.commit()


@app.post("/api/lists/{list_id}/domains", status_code=201)
async def lists_add_domain(
    list_id: int,
    body: DomainEntryRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    _list_or_404(list_id, session)
    d = ListDomain(
        list_id=list_id,
        domain=body.domain,
        session_cookie=body.session_cookie,
        ip=body.ip,
        notes=body.notes,
        is_active=body.is_active,
    )
    session.add(d)
    session.commit()
    session.refresh(d)
    return {"id": d.id, "domain": d.domain, "session_cookie": d.session_cookie, "ip": d.ip, "notes": d.notes, "is_active": d.is_active}


@app.put("/api/lists/{list_id}/domains/{domain_id}")
async def lists_update_domain(
    list_id: int,
    domain_id: int,
    body: DomainEntryRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    _list_or_404(list_id, session)
    d = session.get(ListDomain, domain_id)
    if not d or d.list_id != list_id:
        raise HTTPException(status_code=404, detail="Dominio no encontrado en la lista")
    d.domain = body.domain
    d.session_cookie = body.session_cookie
    d.ip = body.ip
    d.notes = body.notes
    d.is_active = body.is_active
    session.add(d)
    session.commit()
    session.refresh(d)
    return {"id": d.id, "domain": d.domain, "session_cookie": d.session_cookie, "ip": d.ip, "notes": d.notes, "is_active": d.is_active}


@app.delete("/api/lists/{list_id}/domains/{domain_id}", status_code=204)
async def lists_delete_domain(
    list_id: int,
    domain_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    _list_or_404(list_id, session)
    d = session.get(ListDomain, domain_id)
    if not d or d.list_id != list_id:
        raise HTTPException(status_code=404, detail="Dominio no encontrado en la lista")
    session.delete(d)
    session.commit()


@app.post("/api/lists/{list_id}/import-csv")
async def lists_import_csv(
    list_id: int,
    body: BatchRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    _list_or_404(list_id, session)
    added = 0
    errors = []
    for line in body.csv_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        domain_raw = parts[0] if parts else ""
        cookie = parts[1] if len(parts) > 1 else ""
        ip = parts[2] if len(parts) > 2 else ""
        try:
            validated = DomainEntryRequest(domain=domain_raw, session_cookie=cookie, ip=ip)
        except Exception as exc:
            errors.append({"line": line, "error": str(exc)})
            continue
        session.add(ListDomain(
            list_id=list_id,
            domain=validated.domain,
            session_cookie=validated.session_cookie,
            ip=validated.ip,
        ))
        added += 1
    session.commit()
    return {"added": added, "errors": errors}


@app.get("/api/lists/{list_id}/export-csv")
async def lists_export_csv(
    list_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    dl = _list_or_404(list_id, session)
    domains = session.exec(
        select(ListDomain).where(ListDomain.list_id == list_id).where(ListDomain.is_active == True)  # noqa: E712
    ).all()
    lines = ["# dominio,cookie_sesion,ip_forzada"]
    for d in domains:
        lines.append(f"{d.domain},{d.session_cookie},{d.ip}")
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{dl.name}.csv"'},
    )


@app.post("/api/lists/{list_id}/scan")
@limiter.limit("3/minute")
async def lists_scan(
    request: Request,
    list_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    _list_or_404(list_id, session)
    domains = session.exec(
        select(ListDomain).where(ListDomain.list_id == list_id).where(ListDomain.is_active == True)  # noqa: E712
    ).all()
    if not domains:
        raise HTTPException(status_code=400, detail="La lista no tiene dominios activos")

    tasks = [_run_scan(d.domain, d.session_cookie, d.ip) for d in domains]
    scan_results = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for r in scan_results:
        if isinstance(r, Exception):
            results.append({"error": str(r)})
        else:
            _save_scan(session, r, "list", current_user.id, list_id=list_id)
            results.append(r)

    return {"list_id": list_id, "total": len(results), "results": results}
