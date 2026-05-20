# web-security-suite — Agent Instructions

Suite de auditoría de seguridad HTTP para dominios web. Motor Python (`wss`) con **55 tests organizados en 9 bloques**. Interfaz web completa: SPA Bootstrap 5.3, FastAPI, SQLite, autenticación JWT, SSE en tiempo real.

## Estructura

```
wss/                   # Motor Python de scanning
  core/
    scanner.py         # scan(), auto-discovery de bloques por pkgutil
    registry.py        # Decorador @test, TEST_REGISTRY
    context.py         # ScanContext (domain, ip, cookies, http_client, …)
    result.py          # Result (pass/fail/warn/skip)
    http_client.py     # httpx + ForcedIPTransport (replica curl --resolve)
  tests/
    block_1_cookies.py
    block_2_transport.py
    … (9 bloques, 55 tests)
scan-cli.sh            # Script CLI legacy (Bash)
domains.csv            # Dominios batch (gitignored; usar domains.csv.example como base)
reports/               # Reportes Markdown (contenido gitignored, carpeta trackeada)
docs/
  tests-reference.md   # Especificación técnica bloques 1-6
  usage-guide.md       # Guía operativa completa
  creating-tests.md    # Cómo añadir un test Python
  security-tests-wiki.html
web/                   # Interfaz web Docker
  docker-compose.yml
  api/                 # FastAPI — main.py, auth.py, database.py, models.py
  frontend/            # SPA nginx — index.html, app.js, custom.css, version.json
.github/
  instructions/        # Reglas Copilot por patrón de archivo
  prompts/             # Prompts reutilizables: añadir-test, analizar-reporte, release
  skills/              # Skills Copilot
```

## Bloques de tests (fuente de verdad)

> **Antes de citar cualquier número, consulta esta tabla.** Los tests ya no usan
> numeración global secuencial como identidad funcional. Cada test tiene un
> `code` estable y expresivo; el orden visible se controla con `block` + `order`.

| Bloque | Nombre | Tests |
|---|---|---:|
| 1 | Cookies | 4 |
| 2 | Transporte y TLS | 5 |
| 3 | Cabeceras HTTP | 5 |
| 4 | Fuga de información | 3 |
| 5 | Configuración del servidor | 3 |
| 6 | Headers modernos y deprecados | 5 |
| 7 | Archivos y rutas expuestas | 15 |
| 8 | DNS, Email y Dominio | 7 |
| 9 | Fingerprinting y Contenido | 8 |
| **Total** | | **55** |

## Motor de scanning (`wss/`)

Paquete Python con auto-discovery de bloques. Los tests se registran con el decorador `@test`; `scan()` en `wss/core/scanner.py` los descubre automáticamente via `pkgutil`.

```python
from wss.core.registry import test
from wss.core.context import ScanContext
from wss.core.result import Result

@test(
    "EXPOSED-ENV",
    block=7,
    name="Archivo .env expuesto",
)
async def test_env_exposed(ctx: ScanContext) -> Result:
    resp = await ctx.http_client.get(f"https://{ctx.domain}/.env")
    if resp.status_code == 200:
        return Result.fail("Archivo .env accesible públicamente")
    return Result.pass_()
```

Ver [docs/creating-tests.md](docs/creating-tests.md) para la guía completa.

## CLI legacy

```bash
# Scan individual (Bash legacy)
DOMAIN=dominio.ejemplo.ec SESSION_COOKIE_NAME=sessionid bash scan-cli.sh

# Con IP forzada
DOMAIN=dominio.ejemplo.ec SESSION_COOKIE_NAME=sessionid IP=192.168.x.x bash scan-cli.sh
```

## Stack web (`web/`)

Interfaz web completa. Solo tocar si la tarea involucra la UI o la API.

- **API** (`web/api/main.py`): FastAPI 40+ endpoints. Usa el paquete Python `wss` para ejecutar tests (`wss.core.scanner.scan()`) de forma asíncrona. JWT auth, SQLite vía SQLModel, SSE sin buffering para batch y listas.
- **SSE**: `POST /api/batch-stream` y `GET /api/lists/{id}/scan-stream` usan `StreamingResponse` + `asyncio.Queue`. Concurrencia: `asyncio.Semaphore(5)`. Timeout: `SCAN_TIMEOUT_SECONDS` (default 180s).
- **ForcedIPTransport**: `web/api/http_client.py` reploca `curl --resolve HOST:PORT:IP`. Si la IP no responde al probe TCP (`IP_PROBE_TIMEOUT=3.0s`), hace fallback a DNS automáticamente.
- **SQLite**: bind mount `data/` — historial, listas, catálogo tests (`sync_test_catalog()` al arrancar), usuarios. Tras `docker compose down` + borrar `data/wss.db`, el catálogo y las descripciones se regeneran automáticamente al siguiente arranque.
- **Frontend** (`web/frontend/`): SPA vanilla JS + Bootstrap 5.3 Bootswatch Vapor (dark). Navegación por `data-nav` → `navigateTo()` en `app.js`.
- **Red Docker**: ambos servicios en red bridge `internal`. El nginx del frontend hace `proxy_pass http://api:8001` por DNS interno. El contenedor API alcanza IPs privadas de la subred del host vía NAT bridge — suficiente para escanear servidores internos en la misma red local.
- **Proxy externo**: el nginx del host enruta a `host:FRONTEND_PORT` (default 8080). Usa `sub_filter 'const API_BASE = ""' 'const API_BASE = "/ruta"'` para desplegar en un subpath sin tocar el código fuente.
- **CSS variables clave**: `--wss-pass` (verde `#3fb950`), `--wss-fail` (rojo `#f85149`), `--wss-warn` (amarillo `#d29922`), `--wss-skip` (magenta `#bc8cff`). Estilos custom en `custom.css` (no tocar `styles.css`).
- **Versión**: `web/frontend/version.json` — seguir las reglas de `.github/instructions/version-bump.instructions.md` al modificarlo.
- **Levantar**: `cd web && docker compose up --build`

## Regla: al añadir o modificar un test

Actualizar **todos** estos archivos en la misma operación:
1. `wss/tests/block_N_nombre.py` — implementar con `@test` y `ScanContext`
2. `docs/tests-reference.md` — especificación técnica
3. `docs/security-tests-wiki.html` — wiki (contadores en hero y footer)
4. `README.md` — tabla de bloques y contadores
5. `docs/usage-guide.md` — ejemplos de resumen
6. `AGENTS.md` (esta tabla de bloques) — si cambia el rango o el total
7. `web/frontend/app.js` — array `TESTS` y `TESTS_META` (longitud y meta de cada test)
8. `web/frontend/index.html` — hero stats y coverage grid del home
9. Opcionalmente: `web/api/database.py` → `sync_test_catalog()` para descripción inicial en SQLite

## Convenciones del motor Python (`wss/`)

### Añadir un test

Registrar con el decorador `@test` — ver guía completa en [docs/creating-tests.md](docs/creating-tests.md):

```python
@test("MI-CATEGORIA-CODIGO", block=N, name="Descripción corta")
async def test_nombre(ctx: ScanContext) -> Result:
    # ctx.domain, ctx.ip, ctx.cookies, ctx.http_client
    ...
    return Result.pass_()       # PASS
    return Result.fail("msg")  # FAIL
    return Result.warn("msg")  # WARN
    return Result.skip("msg")  # SKIP
```

- Usar `code` funcional, estable y expresivo, por ejemplo `COOKIE-SECURE`,
  `EXPOSED-ENV` o `CVE-NGINX-2026-42945-VERSION`. No usar numeración global
  secuencial como identidad del test.
- Si hace falta controlar posición visual dentro del bloque, usar `order=`.
- `ScanContext.http_client` es un cliente `httpx.AsyncClient` con `ForcedIPTransport` si se indica IP.
- Usar `Result.skip()` cuando falta contexto (ej.: cookie no definida) o herramienta no disponible.

### ScanContext — atributos clave

| Atributo | Tipo | Descripción |
|---|---|---|
| `ctx.domain` | `str` | Host sin protocolo ni path |
| `ctx.ip` | `str \| None` | IP para ForcedIPTransport (opcional) |
| `ctx.cookies` | `dict` | Cookies descubiertas |
| `ctx.session_cookie` | `str \| None` | Nombre de la cookie de sesión principal |
| `ctx.http_client` | `httpx.AsyncClient` | Cliente listo con IP forzada si corresponde |

### Reportes Markdown

Generados desde la SPA (botón "Descargar reporte"). El contenido de `reports/` está en `.gitignore`.

## Documentación

- Especificación de tests (criterios, snippets bash): [docs/tests-reference.md](docs/tests-reference.md)
- Guía de uso y modos de ejecución: [docs/usage-guide.md](docs/usage-guide.md)
- Despliegue detrás de un proxy nginx (subpath, sub_filter): [docs/deploy-nginx-proxy.md](docs/deploy-nginx-proxy.md)
- **Cómo crear un test nuevo** (decorador @test, auto-discovery, tests unitarios): [docs/creating-tests.md](docs/creating-tests.md)
- Formato CSV para batch: ver [domains.csv.example](domains.csv.example) (`dominio,cookie_sesion,ip_forzada`)

## Pitfalls frecuentes

- **ForcedIPTransport**: si la IP forzada no responde al probe TCP, el cliente hace fallback silencioso a DNS. No confundir con un error de la app.
- **Cookie XSRF-TOKEN**: excluir de `COOKIE-HTTPONLY` — debe ser legible por JS.
- **SSE en nginx**: las rutas `*-stream` tienen `proxy_buffering off` y `X-Accel-Buffering no` en `nginx.conf`. No eliminar esas directivas.
- **sync_test_catalog()**: se ejecuta al arrancar la API. Si el test no aparece en la wiki, verificar que el ID exista en `TEST_REGISTRY`.
- **Borrar `data/wss.db`**: elimina historial, listas y catálogo. Al reiniciar, `sync_test_catalog()` recrea el catálogo con descripciones desde `wss/descriptions.py`; el usuario admin se recrea si `APP_FIRST_ADMIN_PASSWORD` está configurado.
