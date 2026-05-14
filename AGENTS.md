# web-security-suite — Agent Instructions

Suite de auditoría de seguridad HTTP para dominios web. Un solo script Bash (`web-security-scan.sh`) con **25 tests organizados en 6 bloques**. Complementado por una interfaz web Docker (FastAPI + SPA nginx).

## Estructura

```
web-security-scan.sh   # Script principal — único archivo ejecutable
domains.csv            # Dominios para análisis batch (gitignored; usar domains.csv.example como base)
reports/               # Reportes Markdown generados (contenido gitignored, carpeta trackeada)
docs/
  tests-reference.md   # Especificación técnica de cada test (snippets bash independientes)
  usage-guide.md       # Guía operativa completa
  security-tests-wiki.html
web/                   # Interfaz web Docker (ver sección "Stack web" más abajo)
  docker-compose.yml
  api/                 # FastAPI — endpoints /api/scan, /api/batch, /api/history
  frontend/            # SPA nginx — index.html, app.js, custom.css, version.json
.github/
  instructions/        # Reglas Copilot por patrón de archivo (version-bump.instructions.md)
  prompts/             # Prompts reutilizables: añadir-test, analizar-reporte, release
  skills/              # Skills Copilot: exportar-csv
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
| **Total** | **TEST-01 a TEST-25** | | **25** |

## Ejecución

Sin dependencias externas — solo `curl`, `openssl`, `dig`/`getent` (Bash ≥ 4.0).

```bash
# Modo interactivo
bash web-security-scan.sh

# Modo no interactivo (CI/CD, cron)
DOMAIN=dominio.ejemplo.ec SESSION_COOKIE_NAME=sessionid bash web-security-scan.sh

# Con IP forzada (servidores internos/staging)
DOMAIN=dominio.ejemplo.ec SESSION_COOKIE_NAME=sessionid IP=192.168.x.x bash web-security-scan.sh
```

## Stack web (`web/`)

Interfaz opcional que expone el script vía HTTP. Solo tocar si la tarea involucra la UI o la API.

- **API** (`web/api/main.py`): FastAPI, endpoints `/api/scan`, `/api/batch`, `/api/history`. Llama al script Bash en subprocess.
- **Frontend** (`web/frontend/`): SPA vanilla JS + Bootstrap 5.3 Bootswatch Vapor (dark). Navegación por `data-nav` → `navigateTo()` en `app.js`.
- **CSS variables clave**: `--wss-pass` (verde `#3fb950`), `--wss-fail` (rojo `#f85149`), `--wss-warn` (amarillo `#d29922`), `--wss-skip` (magenta `#bc8cff`). Estilos custom en `custom.css` (no tocar `styles.css`).
- **Versión**: `web/frontend/version.json` — seguir las reglas de `.github/instructions/version-bump.instructions.md` al modificarlo.
- **Levantar**: `cd web && docker compose up --build`

## Regla: al añadir o modificar un test

Actualizar **todos** estos archivos en la misma operación:
1. `web-security-scan.sh` — el test en sí
2. `docs/tests-reference.md` — especificación técnica
3. `docs/security-tests-wiki.html` — wiki (contadores en hero y footer)
4. `README.md` — tabla de bloques y contadores
5. `docs/usage-guide.md` — ejemplos de resumen
6. `AGENTS.md` (esta tabla de bloques) — si cambia el rango o el total
7. `web/frontend/index.html` — hero stats y coverage grid del home

## Convenciones del script

### Añadir un test

Usa siempre `run_test` — nunca hagas `echo` de resultados directamente:

```bash
run_test "ID_2DIGITOS" "Descripción corta" "PASS|FAIL|WARN|SKIP" "detalle opcional"
```

- IDs con cero padding: `01`–`25` (actualmente). Los nuevos tests continúan la numeración.
- `run_test` actualiza `BATCH_RESULTS`, `SCAN_DATA`/`SCAN_ORDER`, y los contadores `PASS/FAIL/WARN/SKIP` automáticamente.
- Resultados válidos: `PASS` / `FAIL` / `WARN` / `SKIP` (en mayúsculas).
- Usar `SKIP` cuando falta contexto (ej.: cookie no definida) o herramienta no disponible.

### Variables globales clave

| Variable | Descripción |
|---|---|
| `DOMAIN` | Host sin protocolo ni path |
| `HOST` | Igual que `DOMAIN` tras separación host/path |
| `BASE_URL` | `https://${DOMAIN}${BASE_PATH}` |
| `SESSION_COOKIE_NAME` | Cookie de sesión para TEST-02 |
| `IP` | IP para `--resolve` de curl (opcional) |
| `RESOLVE_443` / `RESOLVE_80` | Flags `--resolve` construidos a partir de `IP` |
| `RESPONSE` / `COOKIES` | Cabeceras HTTP cacheadas por `run_tests()` |
| `BATCH_SILENT` | `1` durante batch — suprime salida por pantalla |
| `BATCH_CURRENT_DOMAIN` | Dominio activo en modo batch (vacío en modo individual) |

### Modo batch

- `BATCH_SILENT=1` durante el análisis de cada dominio. No añadas `echo` extra que dependan de esta variable — usa siempre `run_test`.
- `BATCH_RESULTS["${BATCH_CURRENT_DOMAIN}:${ID}"]` almacena resultados por dominio.
- `batch_print_table` genera la tabla comparativa al final.

### Secciones de tests

Agrupa tests con `section "Nombre"` antes del bloque. La función respeta `BATCH_SILENT`.

### Reportes Markdown

Generados por `generate_report_individual()` y `generate_report_batch()`. Se guardan en `reports/` con nombre `YYYYMMDD-HHMMSS-<dominio>.md`. El contenido de `reports/` está en `.gitignore`.

## Documentación

- Especificación de tests (criterios, snippets bash): [docs/tests-reference.md](docs/tests-reference.md)
- Guía de uso y modos de ejecución: [docs/usage-guide.md](docs/usage-guide.md)
- Formato CSV para batch: ver [domains.csv.example](domains.csv.example) (`dominio,cookie_sesion,ip_forzada`)

## Pitfalls frecuentes

- **No separar HOST de BASE_URL**: los tests TLS/DNS van contra `HOST`; los tests HTTP contra `BASE_URL`.
- **Cookie XSRF-TOKEN**: excluir de TEST-02 (HttpOnly) — debe ser legible por JS.
- **`--resolve` con espacios**: `RESOLVE_443` puede estar vacío; no entrecomillar la variable al usarla en `curl`.
