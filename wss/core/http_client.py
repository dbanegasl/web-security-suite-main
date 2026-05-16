"""HTTP client — wrapper de httpx con soporte de IP forzada (curl --resolve)."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from wss.core.context import ScanContext


class ForcedIPTransport(httpx.AsyncHTTPTransport):
    """Enruta peticiones para un hostname específico a una IP fija.

    Equivale a curl --resolve HOST:PORT:IP.

    Al reescribir la URL con la IP, el transporte se conecta a esa IP,
    pero el header Host conserva el hostname original para que el servidor
    pueda identificar el vhost correcto (requiere verify=False porque el
    certificado TLS está emitido para el hostname, no para la IP).
    """

    def __init__(self, hostname: str, ip: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._hostname = hostname
        self._ip = ip

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == self._hostname:
            new_url = request.url.copy_with(host=self._ip)
            headers = dict(request.headers)
            headers["host"] = self._hostname
            request = httpx.Request(
                method=request.method,
                url=new_url,
                headers=headers,
            )
        return await super().handle_async_request(request)


def build_client(ctx: "ScanContext") -> httpx.AsyncClient:
    """Construye un httpx.AsyncClient configurado para scanning pasivo.

    Espeja el comportamiento de curl -sk (TLS sin verificación, sin redireccionamiento),
    con timeouts ajustados y soporte opcional de IP forzada.
    """
    transport_kwargs: dict[str, Any] = {"verify": False}

    if ctx.ip:
        transport: httpx.AsyncBaseTransport = ForcedIPTransport(
            hostname=ctx.host,
            ip=ctx.ip,
            **transport_kwargs,
        )
    else:
        transport = httpx.AsyncHTTPTransport(**transport_kwargs)

    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(8.0, connect=4.0),
        follow_redirects=False,
        headers={"User-Agent": "wss/4.0 security-scanner"},
    )
