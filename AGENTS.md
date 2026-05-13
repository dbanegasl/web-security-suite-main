# web-security-suite — Agent Instructions

Suite de auditoría de seguridad HTTP para dominios web. Un solo script Bash (`web-security-scan.sh`) con 20 tests organizados en 5 bloques.

## Estructura

```
web-security-scan.sh   # Script principal — único archivo ejecutable
domains.csv            # Dominios para análisis batch (gitignored; usar domains.csv.example como base)
reports/               # Reportes Markdown generados (contenido gitignored, carpeta trackeada)
docs/
  tests-reference.md   # Especificación técnica de cada test (snippets bash independientes)
  usage-guide.md       # Guía operativa completa
  security-tests-wiki.html
```

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

## Convenciones del script

### Añadir un test

Usa siempre `run_test` — nunca hagas `echo` de resultados directamente:

```bash
run_test "ID_2DIGITOS" "Descripción corta" "PASS|FAIL|WARN|SKIP" "detalle opcional"
```

- IDs con cero padding: `01`–`20` (actualmente). Los nuevos tests continúan la numeración.
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
