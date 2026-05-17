# web-security-suite — Agent Instructions

Suite de auditoría de seguridad HTTP para dominios web. Motor Python (`wss`) con **55 tests organizados en 9 bloques**. Interfaz web completa: SPA Bootstrap 5.3, FastAPI, SQLite, autenticación JWT, SSE en tiempo real.

## Estructura

```
wss/                   # Motor Python de scanning
  core/
    scanner.py         # _wss_scan(), auto-discovery de bloques por pkgutil
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

> **Antes de citar cualquier número, consulta esta tabla.**

| Bloque | Rango | Nombre | Tests |
|---|---|---|---|
| 1 | TEST-01 a TEST-04 | Cookies | 4 |
| 2 | TEST-05 a TEST-09 | Transporte y TLS | 5 |
| 3 | TEST-10 a TEST-14 | Cabeceras HTTP | 5 |
| 4 | TEST-15 a TEST-17 | Fuga de información | 3 |
| 5 | TEST-18 a TEST-20 | Configuración del servidor | 3 |
| 6 | TEST-21 a TEST-25 | Headers modernos y deprecados | 5 |
| 7 | TEST-26 a TEST-40 | Archivos y rutas expuestas | 15 |
| 8 | TEST-41 a TEST-47 | DNS, Email y Dominio | 7 |
| 9 | TEST-48 a TEST-55 | Fingerprinting y Contenido | 8 |
| **Total** | **TEST-01 a TEST-55** | | **55** |

## Motor de scanning (`wss/`)

Paquete Python con auto-discovery de bloques. Los tests se registran con el decorador `@test`; `_wss_scan()` los descubre automáticamente via `pkgutil`.

```python
from wss.core.registry import test
from wss.core.context import ScanContext
from wss.core.result import Result

@test("26", "Archivo .env expuesto", block=7)
async def test_env_exposed(ctx: ScanContext) -> Result:
    resp = await ctx.http_client.get(f"https://{ctx.domain}/.env")
    if resp.status_code == 200:
        return Result.fail("Archivo .env accesible públicamente")
    return Result.ok()
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

- **API** (`web/api/main.py`): FastAPI 40+ endpoints. Usa el paquete Python `wss` para ejecutar tests (`_wss_scan()`) de forma asíncrona. JWT auth, SQLite vía SQLModel, SSE sin buffering para batch y listas.
- **SSE**: `POST /api/batch-stream` y `GET /api/lists/{id}/scan-stream` usan `StreamingResponse` + `asyncio.Queue`. Concurrencia: `asyncio.Semaphore(5)`. Timeout: `SCAN_TIMEOUT_SECONDS` (default 180s).
- **ForcedIPTransport**: `web/api/http_client.py` reploca `curl --resolve HOST:PORT:IP`. Si la IP no responde al probe TCP (`IP_PROBE_TIMEOUT=3.0s`), hace fallback a DNS automáticamente.
- **SQLite**: volumen Docker — historial, listas, catálogo tests (`sync_test_catalog()` al arrancar), usuarios. Si `docker compose down -v`, re-seed con `python3 temp/seed_descriptions.py`.
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
@test("ID", "Descripción corta", block=N)
async def test_nombre(ctx: ScanContext) -> Result:
    # ctx.domain, ctx.ip, ctx.cookies, ctx.http_client
    ...
    return Result.ok()         # PASS
    return Result.fail("msg")  # FAIL
    return Result.warn("msg")  # WARN
    return Result.skip("msg")  # SKIP
```

- IDs con cero padding: `"01"`–`"55"` (actualmente). Los nuevos tests continúan la numeración.
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
- **Cookie XSRF-TOKEN**: excluir de TEST-02 (HttpOnly) — debe ser legible por JS.
- **SSE en nginx**: las rutas `*-stream` tienen `proxy_buffering off` y `X-Accel-Buffering no` en `nginx.conf`. No eliminar esas directivas.
- **sync_test_catalog()**: se ejecuta al arrancar la API. Si el test no aparece en la wiki, verificar que el ID exista en `TEST_REGISTRY`.
- **`docker compose down -v`**: borra el volumen SQLite — re-seed necesario con `python3 temp/seed_descriptions.py`.
