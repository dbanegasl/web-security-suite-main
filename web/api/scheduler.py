"""
Web Security Suite — Scheduler de escaneos periódicos
======================================================

Gestiona APScheduler (AsyncIOScheduler) para ejecutar escaneos programados
y enviar notificaciones vía webhook (Slack / Teams / genérico) cuando aparecen
nuevos FAILs cuya severidad supera el umbral configurado.

Uso desde main.py:
    from scheduler import start_scheduler, stop_scheduler, reload_job

API pública:
    start_scheduler()          — arranca APScheduler en el loop de asyncio
    stop_scheduler()           — para el scheduler limpiamente
    reload_job(schedule_id)    — añade / actualiza / elimina un job concreto
    reload_all_jobs()          — recarga todos los jobs activos desde la BD
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlmodel import Session, select

import database
from models import ScheduledScan, ScanHistory

log = logging.getLogger("wss.scheduler")

_scheduler: AsyncIOScheduler = AsyncIOScheduler(timezone="UTC")

# ── Severidades (mayor índice = más grave) ─────────────────────────────────────
_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_gte(sev: str, threshold: str) -> bool:
    return _SEVERITY_ORDER.get(sev.upper(), 0) >= _SEVERITY_ORDER.get(threshold.upper(), 0)


# ── Webhook ────────────────────────────────────────────────────────────────────

async def _send_webhook(url: str, schedule: ScheduledScan, new_fails: list[dict]) -> None:
    """Envía notificación vía POST JSON al webhook_url configurado.

    Detecta automáticamente si es Slack, Teams o un webhook genérico según la URL.
    """
    if not url:
        return

    domain = schedule.domain
    fail_lines = "\n".join(
        f"• [{r.get('severity','?')}] TEST-{r.get('id','?')} {r.get('name','?')}: {r.get('detail','')}"
        for r in new_fails[:10]  # máx 10 en la notificación
    )
    total_msg = f"{len(new_fails)} FAIL(s) nuevo(s)" if len(new_fails) <= 10 else f"{len(new_fails)} FAIL(s) nuevos (mostrando 10)"

    if "hooks.slack.com" in url:
        payload = {
            "text": f":warning: *Web Security Suite* — {total_msg} en `{domain}`\n{fail_lines}"
        }
    elif "office.com" in url or "webhook.office.com" in url or "teams" in url.lower():
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "F85149",
            "summary": f"WSS: {total_msg} en {domain}",
            "sections": [{
                "activityTitle": f"🔴 {total_msg} en `{domain}`",
                "activitySubtitle": "Web Security Suite — escaneo automático",
                "text": fail_lines.replace("\n", "<br>"),
            }]
        }
    else:
        # Webhook genérico — JSON completo
        payload = {
            "source": "web-security-suite",
            "domain": domain,
            "new_fails": len(new_fails),
            "threshold_severity": schedule.min_severity,
            "results": new_fails[:20],
        }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        log.info("Webhook enviado a %s para dominio %s (%d FAILs)", url[:40], domain, len(new_fails))
    except Exception as exc:
        log.warning("Error enviando webhook a %s: %s", url[:40], exc)


# ── Lógica del escaneo programado ─────────────────────────────────────────────

async def _run_scheduled_scan(schedule_id: int) -> None:
    """Callback que ejecuta el escaneo y guarda el resultado en la BD."""
    from wss.core.context import ScanContext
    from wss.core.scanner import scan as _wss_scan
    from wss.reporters.json_reporter import generate as _json_generate

    with Session(database._engine) as session:
        schedule = session.get(ScheduledScan, schedule_id)
        if not schedule or not schedule.is_active:
            return

    log.info("Ejecutando escaneo programado id=%d dominio=%s", schedule_id, schedule.domain)

    # Buscar último resultado para comparar (diff)
    prev_fails: set[str] = set()
    if schedule.last_scan_id:
        with Session(database._engine) as session:
            prev = session.get(ScanHistory, schedule.last_scan_id)
            if prev:
                try:
                    prev_results = json.loads(prev.results_json).get("tests", [])
                    prev_fails = {
                        r["id"] for r in prev_results
                        if r.get("result") in ("FAIL",)
                    }
                except Exception:
                    pass

    # Ejecutar scan
    try:
        import re as _re
        _clean = _re.sub(r"^https?://", "", schedule.domain)
        if "/" in _clean:
            _host, _, _path_rest = _clean.partition("/")
            _base_path = f"/{_path_rest}" if _path_rest else "/"
        else:
            _host = _clean
            _base_path = "/"
        ctx = ScanContext(
            domain=schedule.domain,
            host=_host,
            base_url=f"https://{_host}{_base_path}",
            session_cookie=schedule.session_cookie or "",
            ip=schedule.ip or "",
        )
        results = await _wss_scan(ctx)
        output = _json_generate(results, schedule.domain, f"https://{_host}{_base_path}")
        data = json.loads(output)
    except Exception as exc:
        log.error("Error en escaneo programado id=%d: %s", schedule_id, exc)
        return

    tests = data.get("tests", [])
    pass_count  = sum(1 for t in tests if t.get("result") == "PASS")
    fail_count  = sum(1 for t in tests if t.get("result") == "FAIL")
    warn_count  = sum(1 for t in tests if t.get("result") == "WARN")
    skip_count  = sum(1 for t in tests if t.get("result") == "SKIP")

    # Guardar en historial
    scan_entry = ScanHistory(
        domain=schedule.domain,
        scanned_at=datetime.now(timezone.utc),
        pass_count=pass_count,
        fail_count=fail_count,
        warn_count=warn_count,
        skip_count=skip_count,
        scan_mode="scheduled",
        results_json=output,
    )
    with Session(database._engine) as session:
        session.add(scan_entry)
        session.commit()
        session.refresh(scan_entry)
        new_scan_id = scan_entry.id

    # Actualizar schedule
    with Session(database._engine) as session:
        sched = session.get(ScheduledScan, schedule_id)
        if sched:
            sched.last_run = datetime.now(timezone.utc)
            sched.last_scan_id = new_scan_id
            session.add(sched)
            session.commit()

    # Webhook: nuevos FAILs que superan el umbral
    if schedule.webhook_url and schedule.notify_on_new_fail:
        current_fails = [
            t for t in tests
            if t.get("result") == "FAIL"
            and _severity_gte(t.get("severity", "MEDIUM"), schedule.min_severity)
            and (not schedule.last_scan_id or t.get("id") not in prev_fails)
        ]
        if current_fails:
            await _send_webhook(schedule.webhook_url, schedule, current_fails)
    elif schedule.webhook_url and not schedule.notify_on_new_fail:
        # Siempre notificar si hay algún FAIL (no solo nuevos)
        current_fails = [
            t for t in tests
            if t.get("result") == "FAIL"
            and _severity_gte(t.get("severity", "MEDIUM"), schedule.min_severity)
        ]
        if current_fails:
            await _send_webhook(schedule.webhook_url, schedule, current_fails)

    log.info(
        "Escaneo programado id=%d completado: %d PASS / %d FAIL / %d WARN",
        schedule_id, pass_count, fail_count, warn_count,
    )


# ── Gestión de jobs ───────────────────────────────────────────────────────────

def _job_id(schedule_id: int) -> str:
    return f"wss_schedule_{schedule_id}"


def reload_job(schedule_id: int) -> None:
    """Añade o actualiza el job para un schedule específico. Si está inactivo, lo elimina."""
    with Session(database._engine) as session:
        schedule = session.get(ScheduledScan, schedule_id)

    if not schedule or not schedule.is_active:
        jid = _job_id(schedule_id)
        if _scheduler.get_job(jid):
            _scheduler.remove_job(jid)
            log.info("Job eliminado: %s", jid)
        return

    try:
        trigger = CronTrigger.from_crontab(schedule.cron_expression, timezone="UTC")
    except Exception as exc:
        log.warning("Cron inválido en schedule id=%d (%s): %s", schedule_id, schedule.cron_expression, exc)
        return

    jid = _job_id(schedule_id)
    if _scheduler.get_job(jid):
        _scheduler.reschedule_job(jid, trigger=trigger)
        log.info("Job actualizado: %s — cron: %s", jid, schedule.cron_expression)
    else:
        _scheduler.add_job(
            _run_scheduled_scan,
            trigger=trigger,
            id=jid,
            name=f"WSS schedule {schedule_id}: {schedule.domain}",
            args=[schedule_id],
            replace_existing=True,
            misfire_grace_time=300,
        )
        log.info("Job creado: %s — cron: %s dominio: %s", jid, schedule.cron_expression, schedule.domain)


def reload_all_jobs() -> None:
    """Carga todos los schedules activos desde la BD y registra sus jobs."""
    with Session(database._engine) as session:
        schedules = session.exec(
            select(ScheduledScan).where(ScheduledScan.is_active == True)  # noqa: E712
        ).all()

    count = 0
    for sched in schedules:
        try:
            reload_job(sched.id)
            count += 1
        except Exception as exc:
            log.warning("Error cargando job para schedule %d: %s", sched.id, exc)

    log.info("Scheduler: %d job(s) cargados desde BD", count)


def start_scheduler() -> None:
    if not _scheduler.running:
        _scheduler.start()
        reload_all_jobs()
        log.info("APScheduler iniciado")


def stop_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("APScheduler detenido")


def next_run_utc(schedule_id: int) -> Optional[str]:
    """Retorna la próxima ejecución del job en ISO 8601 UTC, o None si no existe."""
    job = _scheduler.get_job(_job_id(schedule_id))
    if not job or not job.next_run_time:
        return None
    nrt = job.next_run_time
    if nrt.tzinfo is None:
        nrt = nrt.replace(tzinfo=timezone.utc)
    return nrt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
