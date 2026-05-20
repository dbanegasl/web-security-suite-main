"""ScanContext — estado de un escaneo individual."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

import httpx

if TYPE_CHECKING:
    pass


@dataclass
class ScanContext:
    """Contiene todo el estado necesario para ejecutar los tests de un dominio.

    Campos públicos (se pasan al constructor):
        domain          Dominio completo tal como lo ingresó el usuario
                        (puede incluir path, ej: app.ejemplo.com/portal)
        host            Solo el hostname, sin path ni protocolo
        base_url        URL base para peticiones HTTP: https://host/path/
        session_cookie  Nombre de la cookie de sesión principal (para COOKIE-HTTPONLY)
        ip              IP para forzar resolución DNS (equivalente a curl --resolve)

    Campos internos (gestionados por el contexto):
        _client               httpx.AsyncClient configurado para el dominio
        _initial_response     Respuesta HEAD cacheada de base_url (se obtiene una vez)
        _set_cookies_cache    Lista de valores raw de headers Set-Cookie
    """

    domain: str
    host: str
    base_url: str
    session_cookie: str = ""
    ip: str = ""

    # Estado interno — no forman parte del __init__ público
    _client: Optional[httpx.AsyncClient] = field(
        default=None, repr=False, compare=False, init=False
    )
    _initial_response: Optional[httpx.Response] = field(
        default=None, repr=False, compare=False, init=False
    )
    _set_cookies_cache: Optional[list[str]] = field(
        default=None, repr=False, compare=False, init=False
    )

    @property
    def client(self) -> httpx.AsyncClient:
        """httpx.AsyncClient configurado (creado con lazy init)."""
        if self._client is None:
            from wss.core.http_client import build_client

            self._client = build_client(self)
        return self._client

    async def fetch_initial(self) -> httpx.Response:
        """Devuelve la respuesta HEAD de base_url (cacheada, se ejecuta una sola vez)."""
        if self._initial_response is None:
            self._initial_response = await self.client.head(self.base_url)
        return self._initial_response

    async def set_cookies(self) -> list[str]:
        """Devuelve la lista de valores raw de los headers Set-Cookie de la respuesta inicial."""
        if self._set_cookies_cache is None:
            resp = await self.fetch_initial()
            self._set_cookies_cache = [
                v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"
            ]
        return self._set_cookies_cache

    async def get_header(self, name: str) -> str:
        """Devuelve el valor del primer header con ese nombre en la respuesta inicial (o '')."""
        resp = await self.fetch_initial()
        return resp.headers.get(name, "")

    async def get_headers(self, name: str) -> list[str]:
        """Devuelve todos los valores del header con ese nombre en la respuesta inicial."""
        resp = await self.fetch_initial()
        return [v for k, v in resp.headers.multi_items() if k.lower() == name.lower()]
