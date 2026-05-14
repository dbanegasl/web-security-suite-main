# Guía de uso — web-security-suite

Guía operativa del script `scan-cli.sh` (v3.3). Para la especificación técnica de cada test, ver [tests-reference.md](tests-reference.md).

---

## Menú principal

Al ejecutar el script en modo interactivo aparece el menú principal al inicio de cada ciclo:

```
  ┌───────────────────────────────────────┐
  │  Menú principal                       │
  └───────────────────────────────────────┘

  [1] Análisis individual
  [2] Análisis automatizado  (batch desde CSV)
  [3] Salir
```

- **[1]** lanza el wizard interactivo de 3 pasos para un solo dominio.
- **[2]** lee `domains.csv` (u otro archivo indicado) y analiza todos los dominios en secuencia, mostrando al final una tabla comparativa.
- **[3]** cierra el script limpiamente.

Si cualquier análisis falla o el usuario cancela, el script regresa al menú en lugar de cerrarse.

---

## Modos de ejecución

### Modo interactivo (wizard)

```bash
bash scan-cli.sh
```

Selecciona **[1]** en el menú. El wizard solicita el dominio, valida su existencia y accesibilidad, descubre cookies y opcionalmente acepta una IP para forzar resolucón DNS.

**Paso 1 — Dominio:**
```
Paso 1/3 — Dominio a analizar
  Ejemplos: app.ejemplo.com  /  ejemplo.com
  Ingresa el dominio:
```

El dominio pasa por cuatro validaciones automáticas:

1. **Separación host/path** — si se ingresa una URL completa (ej: `servicios.ejemplo.com/tracker/`), el script separa el host del path. Los tests DNS y TLS se realizan contra el host; los tests HTTP contra la URL completa.
2. **DNS** — verifica que el dominio resuelva a una IP válida (`dig` + fallback a `getent hosts`). Aborta si no resuelve.
3. **IP privada** — si la IP resuelta es RFC 1918 (`10.x`, `172.16-31.x`, `192.168.x`), muestra advertencia y pide confirmación para continuar.
4. **Accesibilidad HTTPS** — verifica que el servidor responda en `https://dominio/`. Aborta si no hay respuesta.

**Paso 2 — Cookie de sesión:**
```
Paso 2/3 — Cookie de sesión
  Descubriendo cookies disponibles en https://sso.ejemplo.com/ ...

  Cookies encontradas:
    [1] XSRF-TOKEN
    [2] app_session

  ¿Cuál es la cookie de sesión principal?
    [0] Ingresar manualmente
  Selecciona número o 0:
```

**Paso 3 — IP opcional:**
```
Paso 3/3 — Resolución DNS (opcional)
  Deja vacío para usar DNS normal, o ingresa una IP para forzar resolución.
  IP del servidor [Enter para omitir]:
```

---

### Modo batch (análisis automatizado)

Selecciona **[2]** en el menú. El script solicita la ruta al archivo CSV (por defecto `domains.csv` en la misma carpeta).

#### Archivo CSV

Formato: `dominio,cookie_sesion,ip_forzada` — las dos últimas columnas son opcionales.

```csv
# Comentarios con #, espacios ignorados
lms.ejemplo.com,MoodleSession,192.168.1.10
cas.ejemplo.com,CASTGC,192.168.1.11
servicios.ejemplo.com,,192.168.1.12
app2.ejemplo.com,,
```

Al clonar el repositorio, `domains.csv.example` sirve de plantilla. El script crea `domains.csv` automáticamente en el primer arranque (copiando el ejemplo si existe). El archivo `domains.csv` está en `.gitignore` para no exponer datos de infraestructura.

#### Ejecución batch

El script procesa cada dominio aplicando las mismas validaciones DNS/HTTPS del modo individual (de forma silenciosa) y muestra una línea de progreso:

```
  [ 1] lms.ejemplo.com                     OK  (9P 4F 3W 4S)
  [ 2] app.ejemplo.com                      OK  (17P 0F 3W 0S)
  [ 3] tracker.ejemplo.com                  DNS no resuelve
```

Al terminar, imprime la tabla comparativa:

```
▸ TABLA DE RESULTADOS — ANÁLISIS AUTOMATIZADO

  DOMINIO                          01 02 03 04 05 06 07 ... 20    OK   FL   WN
  ──────────────────────────────────────────────────────────────────────
  lms.ejemplo.com                  P  F  F  P  P  F  P ...  P     9    4    3
  cas.ejemplo.com                   P  P  P  P  P  P  P ...  P    17    0    3
  tracker.ejemplo.com               DNS no resuelve

  Leyenda:  P=PASS  F=FAIL  W=WARN  S=SKIP
```

---

### Modo no interactivo (variables de entorno)

Ideal para CI/CD, cron jobs o ejecución en lote. Si `DOMAIN` está definido, el wizard se omite.

```bash
# Mínimo — solo dominio (TEST-02 queda en SKIP sin SESSION_COOKIE_NAME)
DOMAIN=app.ejemplo.com bash scan-cli.sh

# Completo — dominio + cookie de sesión
DOMAIN=sso.ejemplo.com \
  SESSION_COOKIE_NAME=app_session \
  bash scan-cli.sh

# Con IP forzada (red interna / staging sin DNS)
DOMAIN=sso.ejemplo.com \
  SESSION_COOKIE_NAME=app_session \
  IP=192.168.1.10 \
  bash scan-cli.sh
```

### Variables de entorno

| Variable | Requerida | Descripción |
|---|---|---|
| `DOMAIN` | Sí (o interactivo) | Dominio a analizar — sin `https://` |
| `SESSION_COOKIE_NAME` | No | Nombre exacto de la cookie de sesión principal |
| `IP` | No | IP del servidor para forzar resolución DNS |

---

## Ejemplos por stack

```bash
# Laravel / PHP-FPM
DOMAIN=sso.ejemplo.com SESSION_COOKIE_NAME=app_session \
  bash scan-cli.sh

# Java / Tomcat (CAS, Keycloak, etc.)
DOMAIN=app.ejemplo.com SESSION_COOKIE_NAME=JSESSIONID \
  bash scan-cli.sh

# Django / Python
DOMAIN=admisiones.ejemplo.com SESSION_COOKIE_NAME=sessionid \
  bash scan-cli.sh

# PHP genérico
DOMAIN=servicios.ejemplo.com SESSION_COOKIE_NAME=PHPSESSID \
  bash scan-cli.sh

# Dominio nuevo — wizard para descubrir cookies
DOMAIN=nuevo.ejemplo.com bash scan-cli.sh
```

---

## Interpretación del resumen final

```
RESUMEN: 19 PASS  0 FAIL  1 WARN  5 SKIP  /  25 tests

⚠️  SCORECARD: SIN FALLOS CRÍTICOS, 1 advertencia(s) — app.ejemplo.com
```

| Mensaje final | Condición |
|---|---|
| `✅ SCORECARD OK` | FAIL = 0 y WARN = 0 |
| `⚠️  SIN FALLOS CRÍTICOS, N advertencia(s)` | FAIL = 0, WARN > 0 |
| `❌ SCORECARD: N fallo(s) crítico(s)` | FAIL > 0 |

---

## Correcciones comunes

### TEST-01/02/03 — Cookie sin Secure / HttpOnly / SameSite

**Laravel** — agregar a `.env`:
```
SESSION_SECURE_COOKIE=true
```
Verificar en `config/session.php`:
```php
'secure'    => env('SESSION_SECURE_COOKIE', true),
'http_only' => true,
'same_site' => 'strict',
```

**Nginx** — solo cuando se usa `proxy_pass` (NO funciona con `fastcgi_pass`):
```nginx
proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;
```
> ⚠️ Con `fastcgi_pass` (PHP-FPM directo), la directiva anterior es inefectiva. La corrección debe hacerse en la capa de aplicación.

---

### TEST-06 — HSTS ausente o `max-age` insuficiente

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

### TEST-10 — X-Frame-Options ausente

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
```

---

### TEST-11 — X-Content-Type-Options ausente

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

---

### TEST-12 — CSP ausente

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
```
> Ajustar la política según los recursos que cargue cada aplicación.

---

### TEST-14 — Permissions-Policy ausente (WARN)

```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

### TEST-15 — Server header revela versión

```nginx
# En nginx.conf (bloque http):
server_tokens off;
```

---

### TEST-16 — X-Powered-By presente

```nginx
# Nginx — ocultar header generado por PHP-FPM:
fastcgi_hide_header X-Powered-By;
```
```php
# PHP — en php.ini:
expose_php = Off
```

---

### TEST-19 — HTTP TRACE activo

```nginx
if ($request_method = TRACE) { return 405; }
```

---

## Interfaz web (Docker)

La suite incluye un stack Docker completo con frontend web SPA y API FastAPI que expone los mismos 25 tests desde el navegador.

### Levantar el stack

```bash
cd web
cp .env.example .env        # ajustar FRONTEND_PORT si es necesario
docker compose up -d
# → http://localhost:8778
```

Para reconstruir tras cambios en el código:

```bash
cd web && docker compose up --build
```

Para ver logs en tiempo real:

```bash
cd web && docker compose logs -f
```

### Variables de entorno (`web/.env`)

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `FRONTEND_PORT` | Puerto del host para el frontend | `8778` |
| `FRONTEND_ORIGIN` | Origen CORS permitido por la API | `http://localhost:8778` |
| `SCAN_TIMEOUT_SECONDS` | Timeout por dominio en segundos | `120` |

### Arquitectura del stack

```
navegador → nginx :FRONTEND_PORT ─┬─ /api/ → FastAPI :8000 (red interna Docker)
                                   └─ /     → SPA (HTML/JS/CSS estático)
```

El puerto de la API **no se expone directamente al host** — todo el tráfico pasa por nginx. El frontend usa rutas relativas (`/api/scan`) y nginx hace el proxy reverso al contenedor `api`.

### Verificar estado

```bash
# Health check de la API (a través de nginx)
curl http://localhost:8778/api/health
# → {"status":"ok","scriptExists":true}
```

### Análisis individual desde la web

El formulario acepta los mismos parámetros que el CLI:

| Campo | Equivalente CLI | Descripción |
|---|---|---|
| Dominio | `DOMAIN` | Sin `https://`; se admite path (ej: `servicios.ejemplo.com/app/`) |
| Cookie de sesión | `SESSION_COOKIE_NAME` | Nombre de la cookie (no su valor); opcional |
| IP forzada | `IP` | IP del servidor para `--resolve`; opcional |

### Análisis batch desde la web

Se carga el mismo `domains.csv` que usa el CLI (arrastrar o seleccionar). El endpoint `/api/batch` procesa los dominios en secuencia y devuelve los 25 tests de cada uno en JSON.

### Dominios internos desde Docker

Para auditar dominios con IPs privadas (`192.168.x.x`, `10.x.x.x`) el contenedor necesita acceso a esa red. Si Docker corre en una máquina dentro de la red institucional, el modo bridge por defecto es suficiente; solo hay que indicar la IP forzada en el campo correspondiente.

---

## Integración CI/CD

### GitHub Actions

```yaml
- name: Web Security Tests
  run: |
    DOMAIN=${{ vars.TARGET_DOMAIN }} \
    SESSION_COOKIE_NAME=${{ vars.SESSION_COOKIE_NAME }} \
    bash scan-cli.sh
```

### GitLab CI

```yaml
security-tests:
  stage: test
  script:
    - DOMAIN=$TARGET_DOMAIN SESSION_COOKIE_NAME=$SESSION_COOKIE bash scan-cli.sh
  variables:
    TARGET_DOMAIN: app.ejemplo.com
    SESSION_COOKIE: app_session
```

> El script retorna **exit code 1** si hay al menos un FAIL, lo que detiene el pipeline correctamente.

---

## Notas técnicas

- Los tests solo realizan peticiones `HEAD` / `GET` pasivas. No modifican el servidor.
- Los tests de TLS (07/08) requieren curl ≥ 7.54 para soporte de `--tls-max`.
- TEST-09 necesita acceso al puerto 443 del dominio desde el host donde se ejecuta.
- En entornos sin DNS interno, usar `IP=<dirección>` para forzar la resolución.
