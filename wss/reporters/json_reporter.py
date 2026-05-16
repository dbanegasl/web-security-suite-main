"""Reporter JSON — salida estructurada para consumo programático y API."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from wss.core.result import Result
from wss.core.scanner import summary, overall_status


def generate(
    results: list[Result],
    domain: str,
    base_url: str,
    ip: Optional[str] = None,
    scanned_at: Optional[datetime] = None,
) -> str:
    """Genera el reporte como JSON string.

    El schema es compatible con el output actual de scan.sh (extensión, no ruptura):
    se añaden los campos severity, cwe, block y duration_ms.
    """
    if scanned_at is None:
        scanned_at = datetime.now()

    s = summary(results)

    payload = {
        "domain": domain,
        "base_url": base_url,
        "ip": ip or "",
        "scanned_at": scanned_at.isoformat(),
        "summary": {
            "pass": s["PASS"],
            "fail": s["FAIL"],
            "warn": s["WARN"],
            "skip": s["SKIP"],
            "total": s["total"],
            "overall": overall_status(results),
        },
        "tests": [r.to_dict() for r in results],
    }

    return json.dumps(payload, ensure_ascii=False, indent=2)
