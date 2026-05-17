# Guía de uso — web-security-suite

Guía operativa v6.5. Motor Python `wss`, interfaz web Docker (FastAPI + SPA nginx + SQLite). Para la especificación técnica de cada test, ver [tests-reference.md](tests-reference.md). Para añadir tests, ver [creating-tests.md](creating-tests.md).

---

## Inicio rápido — interfaz web

```bash
# Levantar (git pull + docker compose up --build)
bash deploy.sh
# → http://localhost:8778
```

Credenciales por defecto: el usuario administrador se crea al primer arranque (ver logs del contenedor `api`).

Para ver logs en tiempo real:

```bash
cd web && docker compose logs -f api
```

### Variables de entorno (`web/.env`)

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `FRONTEND_PORT` | Puerto del host para la interfaz | `8778` |
| `FRONTEND_ORIGIN` | Origen CORS permitido por la API | `http://localhost:8778` |
| `SCAN_TIMEOUT_SECONDS` | Timeout máximo por dominio (segundos) | `180` |
| `IP_PROBE_TIMEOUT` | Timeout TCP probe para IP forzada (segundos) | `3.0` |

---

## Arquitectura del stack

```
navegador → nginx :FRONTEND_PORT ─┬─ /api/                    → FastAPI :8001 (red interna Docker)
                                   ├─ /api/batch-stream        → SSE sin buffering, timeout 1800s
                                   ├─ /api/lists/*/scan-stream → SSE sin buffering, timeout 1800s
                                   └─ /                        → SPA estática (HTML/JS/CSS)
```

El puerto de la API **no se expone al host** — todo el tráfico pasa por nginx. La API ejecuta el motor Python `wss` con `asyncio.Semaphore(5)` para hasta 5 dominios en paralelo.

---

## Funcionalidades de la interfaz web

### Análisis individual

El formulario acepta:

| Campo | Descripción |
|---|---|
| Dominio | Sin `https://`; se admite path (ej: `servicios.ejemplo.com/app/`) |
| IP forzada | IP del servidor para `ForcedIPTransport`; opcional — fallback a DNS si no responde TCP |

La petición va a `POST /api/scan` y devuelve JSON con los 55 resultados. Cada celda de test es clicable para abrir la wiki del test (descripción, severidad, CWE, referencias).

### Análisis batch (SSE)

Pega una lista de dominios (uno por línea) o carga un CSV. La petición va a `POST /api/batch-stream` (SSE) y los resultados aparecen dominio a dominio conforme terminan, sin esperar al lote completo.

### Listas de dominios

Colecciones de dominios guardadas en SQLite:
- Crear/editar/eliminar listas desde la vista "Listas"
- Importar CSV (`dominio,ip_forzada`)
- Exportar como CSV
- Escanear toda la lista con SSE (`GET /api/lists/{id}/scan-stream`)
- Ver resumen de la última ejecución por lista

### Historial

Todos los scans se guardan automáticamente en SQLite:
- Historial paginado con filtros
- Comparación de dos scans del mismo dominio
- Evolución temporal (gráfico por test a lo largo del tiempo)

### Wiki de tests

Modal accesible desde cualquier celda de resultado o cabecera de test. Muestra descripción, severidad, CWE, referencias y la descripción extendida editable desde el panel admin.

### Panel de administración

- Gestión de usuarios (crear, editar, desactivar)
- Catálogo de tests: editar descripción, severidad, referencias (almacenadas en SQLite)
- Ajustes globales del sistema

---

## Health check

```bash
# A través de nginx (recomendado)
curl http://localhost:8778/api/health
# → {"status":"ok"}
```

---

## SQLite — datos persistentes

Los datos se almacenan en un volumen Docker. Si se elimina el volumen (`docker compose down -v`), se pierden todos los datos. Para restaurar:

```bash
# Re-seed de descripciones de tests
python3 temp/seed_descriptions.py
```

El catálogo de tests (`sync_test_catalog()`) se sincroniza automáticamente al arrancar la API — añade tests nuevos sin borrar descripciones existentes.

---

## Dominios internos (IPs privadas)

Para auditar dominios con IPs privadas (`192.168.x.x`, `10.x.x.x`), indicar la IP en el campo "IP forzada". El motor usará `ForcedIPTransport` en httpx, equivalente a `curl --resolve HOST:443:IP`.

Si la IP no responde al probe TCP (`IP_PROBE_TIMEOUT` segundos), el motor hace fallback a DNS automáticamente — no es un error fatal.

---

## Integración CI/CD

### API REST directa

```bash
# Obtener token
TOKEN=$(curl -s -X POST http://localhost:8778/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<pass>"}' | jq -r .access_token)

# Scan individual
curl -s -X POST http://localhost:8778/api/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"app.ejemplo.com"}' | jq .
```

### GitHub Actions

```yaml
- name: Web Security Tests
  run: |
    TOKEN=$(curl -s -X POST ${{ vars.WSS_URL }}/api/auth/login \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${{ secrets.WSS_USER }}\",\"password\":\"${{ secrets.WSS_PASS }}\"}" \
      | jq -r .access_token)
    curl -s -X POST ${{ vars.WSS_URL }}/api/scan \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"domain\":\"${{ vars.TARGET_DOMAIN }}\"}"
```

---

## CLI legacy (Bash)

El script `scan-cli.sh` sigue disponible para uso directo sin Docker:

```bash
# Modo interactivo
bash scan-cli.sh

# Modo no interactivo (CI/CD, cron)
DOMAIN=app.ejemplo.com SESSION_COOKIE_NAME=sessionid bash scan-cli.sh

# Con IP forzada
DOMAIN=app.ejemplo.com SESSION_COOKIE_NAME=sessionid IP=192.168.1.10 bash scan-cli.sh
```

> El CLI legacy ejecuta únicamente los bloques 1-6 (tests Bash). Los tests de bloques 7-9 solo están disponibles en el motor Python `wss`.

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

## Notas técnicas

- Los tests solo realizan peticiones `HEAD` / `GET` pasivas — no modifican el servidor.
- Los tests TLS requieren acceso al puerto 443 del dominio desde el host donde corre Docker.
- En entornos sin DNS interno, usar el campo "IP forzada" o la variable `IP` en CLI.
- El motor Python `wss` usa `httpx` con `asyncio` — no hay dependencia de `curl`, `openssl` ni `dig` para los tests de bloques 7-9.
