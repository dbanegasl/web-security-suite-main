"""
Web Security Suite — API Backend
Fase A: Autenticación JWT + historial persistente SQLite
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlmodel import Session, col, delete as sql_delete, func, select

import auth
import database
from models import DomainList, ListDomain, PlatformSetting, ScanHistory, TestCatalog, User

# wss Python core (evita subprocess)
from wss.core.context import ScanContext
from wss.core.scanner import scan as _wss_scan
from wss.reporters.json_reporter import generate as _json_generate

# ── Configuración ──────────────────────────────────────────────────────────────
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
    if auth.JWT_SECRET == "insecure-default-change-before-production":
        print(
            "WARNING: JWT_SECRET no configurado. "
            "El servidor usa una clave pública conocida. "
            "Configura JWT_SECRET en producción antes de exponer esta aplicación."
        )
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
def _build_scan_context(domain: str, cookie: str, ip: str) -> ScanContext:
    """Construye un ScanContext a partir de los parámetros de la petición."""
    clean = re.sub(r"^https?://", "", domain)
    if "/" in clean:
        host, _, path_rest = clean.partition("/")
        base_path = f"/{path_rest}" if path_rest else "/"
    else:
        host = clean
        base_path = "/"
    return ScanContext(
        domain=domain,
        host=host,
        base_url=f"https://{host}{base_path}",
        session_cookie=cookie,
        ip=ip,
    )


# Semáforo global: máximo 3 scans simultáneos para evitar saturación de red/CPU
_SCAN_SEM = asyncio.Semaphore(3)


async def _run_scan(domain: str, cookie: str, ip: str) -> dict[str, Any]:
    """Ejecuta el scan con wss Python core y devuelve el resultado JSON."""
    async with _SCAN_SEM:
        return await _run_scan_inner(domain, cookie, ip)


async def _run_scan_inner(domain: str, cookie: str, ip: str) -> dict[str, Any]:
    """Lógica interna del scan usando wss core directamente (sin subprocess)."""
    ctx = _build_scan_context(domain, cookie, ip)
    try:
        results = await asyncio.wait_for(_wss_scan(ctx), timeout=SCAN_TIMEOUT)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Timeout: el scan tardó demasiado")
    finally:
        # Cerrar el cliente httpx si fue creado
        if ctx._client is not None:
            await ctx._client.aclose()

    data: dict[str, Any] = json.loads(
        _json_generate(results, domain=domain, base_url=ctx.base_url,
                       ip=ip or None, scanned_at=datetime.now())
    )
    data["exitCode"] = 0 if not any(r.status.value == "FAIL" for r in results) else 1
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
    return {"status": "ok"}


# ── Endpoints: catálogo de tests ─────────────────────────────────────────────
@app.get("/api/tests")
async def get_tests(
    block: Optional[int] = Query(default=None, description="Filtrar por bloque"),
    severity: Optional[str] = Query(default=None, description="Filtrar por severidad (LOW|MEDIUM|HIGH|CRITICAL)"),
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    """Devuelve el catálogo completo de tests con metadatos de bloques.

    Respuesta:
        {
            total: int,
            blocks: [{block, name, icon, color, description, count}],
            tests:  [{id, name, block, block_name, severity, cwe, description, references, package}]
        }
    """
    from wss.core.registry import BLOCK_META
    import json

    stmt = select(TestCatalog).order_by(TestCatalog.id)
    if block is not None:
        stmt = stmt.where(TestCatalog.block == block)
    if severity is not None:
        stmt = stmt.where(TestCatalog.severity == severity.upper())

    rows = session.exec(stmt).all()

    tests_out = [
        {
            "id": r.id,
            "name": r.name,
            "block": r.block,
            "block_name": r.block_name,
            "severity": r.severity,
            "cwe": r.cwe,
            "description": r.description,
            "references": json.loads(r.references or "[]"),
            "package": r.package,
        }
        for r in rows
    ]

    # Agrupar contadores por bloque desde los resultados filtrados
    block_counts: dict[int, int] = {}
    for r in rows:
        block_counts[r.block] = block_counts.get(r.block, 0) + 1

    # Si no hay filtro de bloque devolvemos todos los bloques conocidos
    if block is None:
        all_blocks = sorted(BLOCK_META.keys())
    else:
        all_blocks = [block]

    blocks_out = [
        {
            "block": b,
            "name": BLOCK_META[b].name if b in BLOCK_META else f"Bloque {b}",
            "icon": BLOCK_META[b].icon if b in BLOCK_META else "fa-circle",
            "color": BLOCK_META[b].color if b in BLOCK_META else "hb-blue",
            "description": BLOCK_META[b].description if b in BLOCK_META else "",
            "count": block_counts.get(b, 0),
        }
        for b in all_blocks
    ]

    return {"total": len(tests_out), "blocks": blocks_out, "tests": tests_out}


# ── Endpoints: descubrimiento de cookies ─────────────────────────────────────
@app.get("/api/discover-cookies")
@limiter.limit("20/minute")
async def discover_cookies(
    request: Request,
    domain: str = Query(..., min_length=1, max_length=253),
    ip: str = Query("", max_length=15),
    current_user: User = Depends(auth.get_current_user),
):
    """Hace HEAD a https://{domain}/ y devuelve los nombres de cookies Set-Cookie."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Dominio no válido")
    if ip and not _IP_RE.match(ip):
        raise HTTPException(status_code=400, detail="IP no válida")

    from wss.core.http_client import ForcedIPTransport

    transport = (
        ForcedIPTransport(domain, ip, verify=False)
        if ip
        else httpx.AsyncHTTPTransport(verify=False)
    )

    try:
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=True,
            timeout=httpx.Timeout(8.0, connect=4.0),
        ) as client:
            resp = await asyncio.wait_for(
                client.head(f"https://{domain}/"),
                timeout=12.0,
            )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Timeout al contactar el servidor")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Error al contactar el servidor: {exc!s:.120}")

    names = []
    for k, v in resp.headers.multi_items():
        if k.lower() == "set-cookie":
            m = re.match(r"([^=;,\s]+)", v.strip())
            if m:
                names.append(m.group(1))
    return {"cookies": names}


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
    user.last_login = datetime.now(timezone.utc)
    session.add(user)
    session.commit()
    token = auth.create_access_token(user.id, user.username, user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "avatar": user.avatar,
    }


@app.get("/api/auth/me")
async def me(
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    # Refrescar para incluir el avatar actualizado
    user = session.get(User, current_user.id) or current_user
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "avatar": user.avatar,
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
    if current_user.role != "admin":
        if rec_a.triggered_by != current_user.id or rec_b.triggered_by != current_user.id:
            raise HTTPException(status_code=403, detail="No tienes permiso para comparar estos scans")

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
    if current_user.role != "admin" and record.triggered_by != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para ver este scan")
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
    if current_user.role != "admin":
        base = base.where(ScanHistory.triggered_by == current_user.id)
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


def _list_or_404(list_id: int, session: Session, current_user: Optional[User] = None) -> DomainList:
    dl = session.get(DomainList, list_id)
    if not dl:
        raise HTTPException(status_code=404, detail="Lista no encontrada")
    if current_user is not None and current_user.role != "admin" and dl.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="No tienes permiso para acceder a esta lista")
    return dl


@app.get("/api/lists")
async def lists_index(
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    stmt = (
        select(DomainList, func.count(ListDomain.id).label("domain_count"))
        .outerjoin(ListDomain, ListDomain.list_id == DomainList.id)
        .group_by(DomainList.id)
        .order_by(col(DomainList.created_at).desc())
    )
    if current_user.role != "admin":
        stmt = stmt.where(DomainList.created_by == current_user.id)
    rows = session.exec(stmt).all()
    return [
        {
            "id": r.DomainList.id,
            "name": r.DomainList.name,
            "description": r.DomainList.description,
            "created_at": r.DomainList.created_at.isoformat(),
            "domain_count": r.domain_count,
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
    dl = _list_or_404(list_id, session, current_user)
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
    dl = _list_or_404(list_id, session, current_user)
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
    dl = _list_or_404(list_id, session, current_user)
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
    _list_or_404(list_id, session, current_user)
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
    _list_or_404(list_id, session, current_user)
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
    _list_or_404(list_id, session, current_user)
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
    _list_or_404(list_id, session, current_user)

    # Cargar dominios existentes para deduplicación
    # Clave: (domain_lower, cookie_norm, ip_norm)
    existing = session.exec(
        select(ListDomain).where(ListDomain.list_id == list_id)
    ).all()

    def _norm(val: str) -> str:
        """Normaliza un campo: strip y lowercase; None o vacío → ''"""
        return (val or "").strip().lower()

    existing_keys: set[tuple[str, str, str]] = {
        (_norm(d.domain), _norm(d.session_cookie), _norm(d.ip))
        for d in existing
    }

    added = 0
    skipped = 0
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
        key = (_norm(validated.domain), _norm(validated.session_cookie), _norm(validated.ip))
        if key in existing_keys:
            skipped += 1
            continue
        existing_keys.add(key)  # evitar duplicados dentro del mismo CSV
        session.add(ListDomain(
            list_id=list_id,
            domain=validated.domain,
            session_cookie=validated.session_cookie,
            ip=validated.ip,
        ))
        added += 1
    session.commit()
    return {"added": added, "skipped": skipped, "errors": errors}


@app.get("/api/lists/{list_id}/export-csv")
async def lists_export_csv(
    list_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    dl = _list_or_404(list_id, session, current_user)
    domains = session.exec(
        select(ListDomain).where(ListDomain.list_id == list_id).where(ListDomain.is_active == True)  # noqa: E712
    ).all()
    lines = ["# dominio,cookie_sesion,ip_forzada"]
    for d in domains:
        lines.append(f"{d.domain},{d.session_cookie},{d.ip}")
    safe_name = dl.name.replace('"', "'").replace('\r', '').replace('\n', '')
    return PlainTextResponse(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.csv"'},
    )


@app.get("/api/lists/{list_id}/scan-stream")
@limiter.limit("3/minute")
async def lists_scan_stream(
    request: Request,
    list_id: int,
    token: str = Query(..., description="JWT token"),
    session: Session = Depends(database.get_session),
):
    """
    Ejecuta el scan de una lista y devuelve resultados via SSE (Server-Sent Events).
    Cada dominio completado emite un evento JSON inmediatamente.
    El cliente no necesita esperar a que terminen todos los dominios.
    """
    # Autenticar via query param (EventSource no soporta Authorization header)
    try:
        current_user = auth.get_current_user_from_token(token, session)
    except Exception:
        async def _auth_err():
            yield "event: error\ndata: {\"detail\": \"No autorizado\"}\n\n"
        return StreamingResponse(_auth_err(), media_type="text/event-stream")

    dl = session.get(DomainList, list_id)
    if not dl:
        async def _notfound():
            yield "event: error\ndata: {\"detail\": \"Lista no encontrada\"}\n\n"
        return StreamingResponse(_notfound(), media_type="text/event-stream")
    if current_user.role != "admin" and dl.created_by != current_user.id:
        async def _forbidden():
            yield "event: error\ndata: {\"detail\": \"No tienes permiso para acceder a esta lista\"}\n\n"
        return StreamingResponse(_forbidden(), media_type="text/event-stream")

    domains = session.exec(
        select(ListDomain)
        .where(ListDomain.list_id == list_id)
        .where(ListDomain.is_active == True)  # noqa: E712
    ).all()

    if not domains:
        async def _empty():
            yield "event: error\ndata: {\"detail\": \"La lista no tiene dominios activos\"}\n\n"
        return StreamingResponse(_empty(), media_type="text/event-stream")

    total = len(domains)
    user_id = current_user.id

    async def _stream():
        completed = 0
        yield f"event: start\ndata: {json.dumps({'total': total})}\n\n"

        async def _scan_one(d: ListDomain) -> dict:
            try:
                return await _run_scan(d.domain, d.session_cookie, d.ip)
            except Exception as exc:
                return {"domain": d.domain, "error": str(exc)}

        import database as _db
        from sqlmodel import Session as DBSession

        # Crear Tasks cancelables (el semáforo controla la concurrencia real)
        pending: set[asyncio.Task] = {
            asyncio.create_task(_scan_one(d)) for d in domains
        }

        while pending:
            # Verificar si el cliente se desconectó — cancelar todo y salir
            if await request.is_disconnected():
                for t in pending:
                    t.cancel()
                return

            # Esperar la próxima tarea que termine (timeout 1s para re-chequear desconexión)
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED, timeout=1.0
            )

            for task in done:
                if task.cancelled():
                    continue
                exc = task.exception()
                result = {"error": str(exc)} if exc else task.result()
                completed += 1

                if "error" not in result:
                    with DBSession(_db._engine) as db_sess:
                        _save_scan(db_sess, result, "list", user_id, list_id=list_id)

                payload = json.dumps({"index": completed, "total": total, "result": result})
                yield f"event: result\ndata: {payload}\n\n"

        yield f"event: done\ndata: {json.dumps({'total': total, 'completed': completed})}\n\n"

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # deshabilitar buffering en nginx
        },
    )


@app.post("/api/lists/{list_id}/scan")
@limiter.limit("3/minute")
async def lists_scan(
    request: Request,
    list_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    """Endpoint legacy — redirige a scan-stream internamente para compatibilidad."""
    _list_or_404(list_id, session, current_user)
    domains = session.exec(
        select(ListDomain).where(ListDomain.list_id == list_id).where(ListDomain.is_active == True)  # noqa: E712
    ).all()
    if not domains:
        raise HTTPException(status_code=400, detail="La lista no tiene dominios activos")

    async def _scan_one(d: ListDomain) -> dict:
        try:
            return await _run_scan(d.domain, d.session_cookie, d.ip)
        except Exception as exc:
            return {"domain": d.domain, "error": str(exc)}

    tasks = [asyncio.create_task(_scan_one(d)) for d in domains]
    scan_results = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for r in scan_results:
        if isinstance(r, Exception):
            results.append({"error": str(r)})
        else:
            _save_scan(session, r, "list", current_user.id, list_id=list_id)
            results.append(r)

    return {"list_id": list_id, "total": len(results), "results": results}


# ── Endpoints: Fase C — Evolución temporal ────────────────────────────────────

@app.get("/api/history/evolution/{domain}")
async def history_evolution(
    domain: str,
    days: int = Query(90, ge=7, le=365),
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = (
        select(ScanHistory)
        .where(ScanHistory.domain == domain)
        .where(ScanHistory.scanned_at >= since)
    )
    if current_user.role != "admin":
        stmt = stmt.where(ScanHistory.triggered_by == current_user.id)
    records = session.exec(stmt.order_by(col(ScanHistory.scanned_at).asc())).all()

    tests_ts: dict[str, dict] = {}
    for rec in records:
        data = json.loads(rec.results_json)
        for test in data.get("tests", []):
            tid = test["id"]
            if tid not in tests_ts:
                tests_ts[tid] = {"id": tid, "name": test.get("name", ""), "series": []}
            tests_ts[tid]["series"].append({
                "date": rec.scanned_at.isoformat(),
                "result": test.get("result", "?"),
                "scan_id": rec.id,
            })

    return {
        "domain": domain,
        "days": days,
        "total_scans": len(records),
        "tests": sorted(tests_ts.values(), key=lambda x: x["id"]),
    }


@app.get("/api/lists/{list_id}/summary")
async def lists_summary(
    list_id: int,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    dl = _list_or_404(list_id, session, current_user)
    domains = session.exec(
        select(ListDomain)
        .where(ListDomain.list_id == list_id)
        .where(ListDomain.is_active == True)  # noqa: E712
    ).all()

    result = []
    for d in domains:
        scans = session.exec(
            select(ScanHistory)
            .where(ScanHistory.domain == d.domain)
            .where(ScanHistory.list_id == list_id)
            .order_by(col(ScanHistory.scanned_at).desc())
            .limit(2)
        ).all()
        last = scans[0] if scans else None
        prev = scans[1] if len(scans) > 1 else None

        trend = "stable"
        if last and prev:
            if last.fail_count < prev.fail_count:
                trend = "improving"
            elif last.fail_count > prev.fail_count:
                trend = "worsening"

        last_tests: dict[str, str] = {}
        if last:
            data = json.loads(last.results_json)
            for t in data.get("tests", []):
                last_tests[t["id"]] = t.get("result", "?")

        result.append({
            "domain": d.domain,
            "last_scan_id": last.id if last else None,
            "last_scanned_at": last.scanned_at.isoformat() if last else None,
            "fail_count": last.fail_count if last else None,
            "warn_count": last.warn_count if last else None,
            "pass_count": last.pass_count if last else None,
            "trend": trend,
            "tests": last_tests,
        })

    return {
        "list_id": list_id,
        "list_name": dl.name,
        "domains": result,
    }


# ── Endpoints: Fase C — Admin: gestión de usuarios ───────────────────────────

def _require_admin(current_user: User = Depends(auth.get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Acceso restringido a administradores")
    return current_user


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("El nombre de usuario es obligatorio (máx. 64 caracteres)")
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError("Solo letras, números, _, -, .")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("admin", "analyst"):
            raise ValueError("Rol no válido (admin | analyst)")
        return v


class UserUpdateRequest(BaseModel):
    role: str
    is_active: bool

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("admin", "analyst"):
            raise ValueError("Rol no válido")
        return v


class PasswordResetRequest(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres")
        return v


@app.get("/api/admin/users")
async def admin_users_list(
    admin: User = Depends(_require_admin),
    session: Session = Depends(database.get_session),
):
    users = session.exec(select(User).order_by(col(User.username))).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat(),
            "last_login": u.last_login.isoformat() if u.last_login else None,
        }
        for u in users
    ]


@app.post("/api/admin/users", status_code=201)
async def admin_users_create(
    body: UserCreateRequest,
    admin: User = Depends(_require_admin),
    session: Session = Depends(database.get_session),
):
    if session.exec(select(User).where(User.username == body.username)).first():
        raise HTTPException(status_code=409, detail="El usuario ya existe")
    u = User(
        username=body.username,
        password_hash=auth.hash_password(body.password),
        role=body.role,
    )
    session.add(u)
    session.commit()
    session.refresh(u)
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat(),
    }


@app.put("/api/admin/users/{user_id}")
async def admin_users_update(
    user_id: int,
    body: UserUpdateRequest,
    admin: User = Depends(_require_admin),
    session: Session = Depends(database.get_session),
):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if u.id == admin.id:
        raise HTTPException(status_code=400, detail="No puedes modificar tu propia cuenta desde aquí")
    u.role = body.role
    u.is_active = body.is_active
    session.add(u)
    session.commit()
    session.refresh(u)
    return {"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active}


@app.delete("/api/admin/users/{user_id}", status_code=204)
async def admin_users_delete(
    user_id: int,
    admin: User = Depends(_require_admin),
    session: Session = Depends(database.get_session),
):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if u.id == admin.id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propia cuenta")
    session.delete(u)
    session.commit()


class PurgeHistoryRequest(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v:
            raise ValueError("La contraseña es obligatoria")
        return v


@app.delete("/api/admin/history", status_code=200)
async def admin_purge_history(
    body: PurgeHistoryRequest,
    admin: User = Depends(_require_admin),
    session: Session = Depends(database.get_session),
):
    """Elimina todo el historial de escaneos. Requiere verificación de contraseña."""
    if not auth.verify_password(body.password, admin.password_hash):
        raise HTTPException(status_code=403, detail="Contraseña incorrecta")
    count = session.exec(select(func.count()).select_from(ScanHistory)).one()
    session.exec(sql_delete(ScanHistory))
    session.commit()
    return {"deleted": count}


@app.put("/api/admin/users/{user_id}/reset-password")
async def admin_users_reset_password(
    user_id: int,
    body: PasswordResetRequest,
    admin: User = Depends(_require_admin),
    session: Session = Depends(database.get_session),
):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    u.password_hash = auth.hash_password(body.password)
    session.add(u)
    session.commit()
    return {"ok": True}


# ── Endpoints: configuración de plataforma ────────────────────────────────────

_SETTINGS_WHITELIST = {
    "app_title", "logo_base64", "color_pass", "color_fail",
    "color_warn", "color_skip", "favicon_base64",
}

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_B64_DATA_RE  = re.compile(r"^data:image/(png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$")


@app.get("/api/settings")
async def settings_get(session: Session = Depends(database.get_session)):
    """Devuelve la configuración de plataforma. Público — no requiere auth."""
    rows = session.exec(select(PlatformSetting)).all()
    return {r.key: r.value for r in rows}


class SettingUpdateRequest(BaseModel):
    key: str
    value: str

    @field_validator("key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        if v not in _SETTINGS_WHITELIST:
            raise ValueError(f"Clave no permitida. Valores válidos: {sorted(_SETTINGS_WHITELIST)}")
        return v

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        # Límite de tamaño: 300 KB (logos base64 en pantalla completa)
        if len(v.encode()) > 300 * 1024:
            raise ValueError("El valor supera el tamaño máximo de 300 KB")
        return v


@app.put("/api/admin/settings")
async def settings_update(
    body: SettingUpdateRequest,
    admin: User = Depends(_require_admin),
    session: Session = Depends(database.get_session),
):
    """Actualiza un parámetro de configuración de plataforma. Solo admins."""
    # Validaciones específicas por tipo de clave
    if body.key.startswith("color_"):
        if body.value and not _HEX_COLOR_RE.match(body.value):
            raise HTTPException(status_code=422, detail="El color debe ser un valor hexadecimal (#rrggbb)")
    if body.key.endswith("_base64") and body.value:
        if not _B64_DATA_RE.match(body.value):
            raise HTTPException(status_code=422, detail="El valor base64 debe ser un data URL de imagen válido")
    if body.key == "app_title" and not body.value.strip():
        raise HTTPException(status_code=422, detail="El título no puede estar vacío")

    row = session.get(PlatformSetting, body.key)
    if row:
        row.value = body.value
        row.updated_at = datetime.now(timezone.utc)
        row.updated_by = admin.id
        session.add(row)
    else:
        session.add(PlatformSetting(
            key=body.key,
            value=body.value,
            updated_by=admin.id,
        ))
    session.commit()
    return {"key": body.key, "ok": True}


# ── Endpoints: perfil de usuario (avatar y contraseña) ───────────────────────

_AVATAR_SIZE_LIMIT = 200 * 1024  # 200 KB en bytes


class AvatarUpdateRequest(BaseModel):
    avatar_base64: str

    @field_validator("avatar_base64")
    @classmethod
    def validate_avatar(cls, v: str) -> str:
        if not _B64_DATA_RE.match(v):
            raise ValueError("El avatar debe ser un data URL de imagen válido (png, jpeg, gif, webp)")
        if len(v.encode()) > _AVATAR_SIZE_LIMIT:
            raise ValueError("El avatar supera el tamaño máximo de 200 KB")
        return v


@app.post("/api/users/me/avatar")
async def users_me_avatar_set(
    body: AvatarUpdateRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    u = session.get(User, current_user.id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    u.avatar = body.avatar_base64
    session.add(u)
    session.commit()
    return {"ok": True}


@app.delete("/api/users/me/avatar", status_code=200)
async def users_me_avatar_delete(
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    u = session.get(User, current_user.id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    u.avatar = None
    session.add(u)
    session.commit()
    return {"ok": True}


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres")
        return v


@app.put("/api/users/me/password")
async def users_me_password_change(
    body: PasswordChangeRequest,
    current_user: User = Depends(auth.get_current_user),
    session: Session = Depends(database.get_session),
):
    u = session.get(User, current_user.id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not auth.verify_password(body.current_password, u.password_hash):
        raise HTTPException(status_code=403, detail="La contraseña actual es incorrecta")
    u.password_hash = auth.hash_password(body.new_password)
    session.add(u)
    session.commit()
    return {"ok": True}
