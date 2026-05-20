# web-security-suite

Suite de pruebas de seguridad HTTP para auditoría de dominios web. Ejecuta **55 tests** organizados en 9 bloques, detectando las vulnerabilidades más comunes (OWASP Top 10 basics, Security Headers, exposición de archivos, DNS/email y fingerprinting).

**Versión:** 7.0 · **Autor:** Daniel Banegas · **Organización:** DUOTICS

---

## Características

- Motor 100 % Python (`wss`) — `httpx` + `asyncio`; sin dependencias externas de shell
- **55 tests** en 9 bloques de seguridad con auto-discovery por `pkgutil`
- **Interfaz web Docker** completa: SPA Bootstrap 5.3, FastAPI, SQLite, autenticación JWT
- **Análisis individual** desde formulario web o API REST
- **Análisis batch con SSE**: resultados en tiempo real, dominio a dominio conforme terminan
- **Listas de dominios** persistentes en SQLite: CRUD, importación/exportación CSV, escaneo SSE
- **Historial persistente** con comparación de scans y evolución temporal por dominio
- **Panel de administración**: gestión de usuarios, edición de wiki de tests, ajustes globales
- **Wiki de tests integrada**: modal con descripción, severidad, CWE y referencias para cada test
- **IP forzada con probe TCP**: si la IP no es alcanzable, fallback a DNS automáticamente
- Concurrencia controlada (semáforo 5 scans paralelos) y timeout configurable por dominio
- Reportes descargables en Markdown

---

## Requisitos

- Docker ≥ 24 con plugin Compose
- Acceso de red al dominio a auditar desde el host donde corre Docker

---

## Inicio rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/dbanegasl/web-security-suite-main.git
cd web-security-suite-main

# 2. Levantar (git pull + docker compose up --build)
bash deploy.sh
# → http://localhost:8778
```

### Variables de entorno (`web/.env`)

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `FRONTEND_PORT` | Puerto del host para la interfaz | `8778` |
| `FRONTEND_ORIGIN` | Origen CORS permitido por la API | `http://localhost:8778` |
| `SCAN_TIMEOUT_SECONDS` | Timeout máximo por dominio (segundos) | `180` |
| `IP_PROBE_TIMEOUT` | Timeout TCP probe para IP forzada (segundos) | `3.0` |

---

## Arquitectura

```
navegador → nginx :FRONTEND_PORT ─┬─ /api/                    → FastAPI :8001 (red interna Docker)
                                   ├─ /api/batch-stream        → SSE sin buffering, timeout 1800s
                                   ├─ /api/lists/*/scan-stream → SSE sin buffering, timeout 1800s
                                   └─ /                        → SPA estática (HTML/JS/CSS)
```

- **nginx** sirve el frontend y hace proxy reverso a la API — un único puerto expuesto al host
- **FastAPI** (`web/api/main.py`) usa el paquete Python `wss` para ejecutar tests de forma asíncrona
- **wss** (`wss/`) — motor de scanning: decorador `@test`, auto-discovery de bloques, `ScanContext`
- **SQLite** (volumen Docker) almacena historial, listas, catálogo de tests y usuarios
- **ForcedIPTransport** de httpx replica el comportamiento de `curl --resolve HOST:PORT:IP`

---

## API REST

| Método | Endpoint | Descripción |
|---|---|---|
| `POST` | `/api/auth/login` | Login → JWT |
| `GET` | `/api/auth/me` | Info del usuario autenticado |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/tests` | Catálogo de los 55 tests |
| `GET` | `/api/discover-cookies` | Descubre cookies del dominio indicado |
| `POST` | `/api/scan` | Scan individual → JSON |
| `POST` | `/api/batch` | Scan batch síncrono → JSON |
| `POST` | `/api/batch-stream` | Scan batch SSE → stream dominio a dominio |
| `GET` | `/api/history` | Historial paginado |
| `GET` | `/api/history/{id}` | Detalle de scan |
| `GET` | `/api/history/compare` | Comparar dos scans |
| `GET` | `/api/history/evolution/{domain}` | Evolución temporal de un dominio |
| `GET/POST/PUT/DELETE` | `/api/lists/…` | CRUD listas de dominios |
| `POST` | `/api/lists/{id}/import-csv` | Importar CSV a lista |
| `GET` | `/api/lists/{id}/export-csv` | Exportar lista como CSV |
| `GET` | `/api/lists/{id}/scan-stream` | Escanear lista completa (SSE) |
| `POST` | `/api/lists/{id}/scan` | Escanear lista completa (síncrono) |
| `GET` | `/api/lists/{id}/summary` | Resumen de última ejecución |
| `GET/PATCH/POST` | `/api/admin/tests/…` | Gestión de catálogo de tests |
| `GET/POST/PUT/DELETE` | `/api/admin/users/…` | Gestión de usuarios |
| `DELETE` | `/api/admin/history` | Borrar historial completo |
| `GET/PUT` | `/api/settings` | Ajustes globales |
| `POST/DELETE` | `/api/users/me/avatar` | Avatar del usuario autenticado |
| `PUT` | `/api/users/me/password` | Cambiar contraseña propia |

Todos los endpoints (excepto `/api/health` y `/api/auth/login`) requieren `Authorization: Bearer <JWT>`.

---

## Resultados

| Resultado | Significado |
|---|---|
| `PASS` | Configuración correcta |
| `FAIL` | Vulnerabilidad detectada — requiere corrección |
| `WARN` | Advertencia no crítica — se recomienda revisar |
| `SKIP` | Test omitido (falta contexto o herramienta) |

---

## Tests incluidos

| Bloque | Nombre | Tests | Qué detecta |
|---|---|---:|---|
| **1** | Cookies | 4 | Secure, HttpOnly, SameSite, Path |
| **2** | Transporte y TLS | 5 | HTTP→HTTPS, HSTS, TLS 1.0/1.1, cert expiry |
| **3** | Cabeceras HTTP | 5 | X-Frame-Options, XCTO, CSP, Referrer-Policy, Permissions-Policy |
| **4** | Fuga de información | 3 | Server version, X-Powered-By, X-AspNet headers |
| **5** | Configuración del servidor | 3 | CORS wildcard, HTTP TRACE, Cache-Control |
| **6** | Headers modernos y deprecados | 5 | Headers deprecados, COOP, COEP, CORP, X-Permitted-Cross-Domain-Policies |
| **7** | Archivos y rutas expuestas | 15 | .env, .git, backups, paneles admin, logs, etc. |
| **8** | DNS, Email y Dominio | 7 | SPF, DMARC, DNSSEC, CAA, MX, WHOIS |
| **9** | Fingerprinting y Contenido | 8 | Stack disclosure, mixed content, subresource integrity, etc. |

---

## Estructura del repositorio

```
web-security-suite/
├── README.md
├── AGENTS.md                      # Instrucciones para agentes Copilot
├── deploy.sh                      # git pull + docker compose up --build
├── scan-cli.sh                    # Script CLI legacy (Bash)
├── scan.sh                        # Motor CLI con salida JSON
├── domains.csv.example            # Plantilla CSV para batch CLI
├── domains.csv                    # Lista activa (gitignored)
├── pyproject.toml                 # Paquete wss
├── wss/                           # Motor Python de scanning
│   ├── core/
│   │   ├── scanner.py             # scan(), auto-discovery de bloques
│   │   ├── registry.py            # Decorador @test, TEST_REGISTRY
│   │   ├── context.py             # ScanContext
│   │   ├── result.py              # Result (pass/fail/warn/skip)
│   │   └── http_client.py         # httpx + ForcedIPTransport
│   └── tests/
│       ├── block_1_cookies.py
│       ├── block_2_transport.py
│       └── …                      # 9 bloques, 55 tests
├── web/
│   ├── docker-compose.yml
│   ├── api/
│   │   ├── main.py                # FastAPI — todos los endpoints
│   │   ├── auth.py                # JWT helpers
│   │   ├── database.py            # SQLModel + SQLite + sync_test_catalog()
│   │   ├── models.py              # Modelos SQLite
│   │   └── requirements.txt
│   └── frontend/
│       ├── index.html             # SPA Bootstrap 5.3 Bootswatch Vapor
│       ├── app.js                 # Lógica SPA completa (1600+ líneas)
│       ├── custom.css             # Estilos adicionales
│       ├── nginx.conf             # Proxy reverso + bloques SSE sin buffering
│       ├── version.json           # { "version": "7.0", "build": "…" }
│       └── wiki.html              # Wiki estática de tests
├── reports/                       # Reportes generados (gitignored)
└── docs/
    ├── usage-guide.md             # Guía operativa: web, CLI, CI/CD
    ├── tests-reference.md         # Especificación técnica bloques 1-6
    ├── creating-tests.md          # Cómo añadir un test Python (@test, ScanContext)
    ├── deploy-nginx-proxy.md      # Despliegue detrás de proxy nginx (subpath)
    └── planificacion-interfaz-web.md
```

---

## Documentación

- [Guía de uso](docs/usage-guide.md) — interfaz web, CLI, CI/CD, variables de entorno, correcciones comunes
- [Referencia de tests](docs/tests-reference.md) — especificación técnica bloques 1-6 con snippets bash
- [Cómo crear un test](docs/creating-tests.md) — `@test`, `ScanContext`, `Result`, auto-discovery, tests unitarios
- [Despliegue con proxy nginx](docs/deploy-nginx-proxy.md) — subpath, `sub_filter`, headers

---

*Generado con asistencia de GitHub Copilot — DUOTICS 2026.*
