# Despliegue detrás de un proxy nginx

Guía para exponer Web Security Suite en un servidor que ya tiene un nginx como proxy inverso. Cubre los tres escenarios de despliegue posibles:

| Escenario | URL de acceso | `API_BASE` | `sub_filter` necesario |
|---|---|---|---|
| [Dominio o subdominio dedicado](#caso-1--dominio-o-subdominio-dedicado) | `https://security.ejemplo.ec/` | `""` (vacío) | No |
| [Subfolder en dominio existente](#caso-2--subfolder-en-dominio-existente) | `https://ejemplo.ec/security/` | `"/security"` | Sí |

---

## Arquitectura

```
Internet
   │ HTTPS :443
   ▼
[nginx del host — proxy externo]
   │  proxy_pass http://192.168.3.164:8778
   ▼
[frontend container — nginx interno :80]
   │  proxy_pass http://api:8001  (DNS Docker interno)
   ▼
[api container — FastAPI :8001]
   │  bash web-security-scan.sh
   ▼
Dominios escaneados (internet + red interna)
```

- El proxy externo es el único punto de entrada. Solo necesita conocer la IP/puerto del frontend.
- El frontend reenvía `/api/` al contenedor API por nombre de servicio Docker (`http://api:8001`).
- Los contenedores están en una red bridge interna (`internal`). La API alcanza IPs privadas de la misma subred del host vía NAT bridge.

---

## Caso 1 — Dominio o subdominio dedicado

La app ocupa la raíz del dominio: `https://security.ejemplo.ec/` o `https://ejemplo.ec/`.

- `API_BASE` queda vacío (`""`), que es el valor por defecto en `app.js` — **no se necesita `sub_filter`**.
- El `server {}` es exclusivo para esta app.

```nginx
server {
    listen 443 ssl;
    server_name security.ejemplo.ec;   # o tu dominio raíz

    # SSL (certificados gestionados por certbot u otro):
    ssl_certificate     /etc/letsencrypt/live/security.ejemplo.ec/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/security.ejemplo.ec/privkey.pem;

    # SSE — timeout extendido y sin buffering (ANTES del bloque /)
    location ~ ^/api/lists/[0-9]+/scan-stream {
        proxy_pass http://127.0.0.1:8778;
        proxy_http_version 1.1;

        proxy_set_header Host               $host;
        proxy_set_header X-Real-IP          $remote_addr;
        proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  $scheme;
        proxy_set_header Connection         '';

        proxy_buffering           off;
        proxy_cache               off;
        chunked_transfer_encoding on;

        proxy_read_timeout  1800s;
        proxy_send_timeout   300s;
    }

    # Todo lo demás — proxy al frontend
    location / {
        proxy_pass http://127.0.0.1:8778;
        proxy_http_version 1.1;

        proxy_set_header Host               $host;
        proxy_set_header X-Real-IP          $remote_addr;
        proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  $scheme;

        proxy_connect_timeout  60s;
        proxy_send_timeout    300s;
        proxy_read_timeout    300s;
    }
}
```

> Reemplaza `127.0.0.1:8778` por la IP y `FRONTEND_PORT` donde corre el contenedor frontend.

---

## Caso 2 — Subfolder en dominio existente

La app se expone en una ruta del dominio: `https://ejemplo.ec/security/`. El `server {}` ya existe y sirve otras cosas en `/`.

Aquí sí es necesario el truco `sub_filter` porque el JS necesita saber el prefijo de ruta para construir las llamadas a la API.

### Cómo funciona el subpath

El archivo `app.js` define:

```js
const API_BASE = "";   // línea 23 — valor por defecto vacío
```

Todas las llamadas a la API usan este prefijo:
```js
fetch(`${API_BASE}/api/scan`, ...)
```

El proxy usa `sub_filter` para inyectar el valor correcto **en tiempo de proxy**, sin tocar el repositorio:

```nginx
sub_filter 'const API_BASE = ""' 'const API_BASE = "/security"';
```

Esto hace que el JS del cliente llame a `/security/api/scan` en lugar de `/api/scan`.

### Configuración

Añade estos bloques al `server {}` existente de tu nginx:

```nginx
# ──────────────────────────────────────────────────────────────────────────
# Web Security Suite — desplegada en /security/
#
# ARQUITECTURA:
#   Un único proxy target: frontend:8778 (nginx interno del contenedor).
#   El nginx del frontend maneja /api/ → http://api:8001 internamente.
#   sub_filter inyecta API_BASE="/security" en el JS servido, sin tocar el repo.
#
# Para desplegar en otra ruta (ej. /tools/security/):
#   1. Cambia el prefijo de los 3 bloques location
#   2. Cambia el valor en sub_filter
#   3. Cambia X-Forwarded-Prefix
# ──────────────────────────────────────────────────────────────────────────

location = /security {
    return 301 /security/;
}

# SSE (Server-Sent Events): scan masivo — sin buffering, timeout extendido
# DEBE ir ANTES del bloque /security/ para que el regex tenga prioridad
location ~ ^/security/api/lists/[0-9]+/scan-stream {
    rewrite ^/security/(.*)$ /$1 break;
    proxy_pass http://127.0.0.1:8778;
    proxy_http_version 1.1;

    proxy_set_header Host               $host;
    proxy_set_header X-Real-IP          $remote_addr;
    proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_set_header Connection         '';

    proxy_buffering            off;
    proxy_cache                off;
    chunked_transfer_encoding  on;

    proxy_read_timeout  1800s;
    proxy_send_timeout   300s;
}

# Todo lo demás bajo /security/ — proxy único al frontend
location /security/ {
    rewrite ^/security/(.*)$ /$1 break;
    proxy_pass http://127.0.0.1:8778;
    proxy_http_version 1.1;

    proxy_set_header Host               $host;
    proxy_set_header X-Real-IP          $remote_addr;
    proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_set_header X-Forwarded-Prefix /security;
    proxy_set_header Accept-Encoding    "";   # Evita gzip para que sub_filter funcione

    # Inyecta la ruta base en el JS del repo sin modificar el código fuente
    sub_filter_types *;
    sub_filter 'const API_BASE = ""' 'const API_BASE = "/security"';
    sub_filter_once on;

    proxy_connect_timeout  60s;
    proxy_send_timeout    300s;
    proxy_read_timeout    300s;
}
```

### Adaptar a otra ruta base

Para desplegar en `/tools/security/` en lugar de `/security/`:

| Qué cambiar | Antes | Después |
|---|---|---|
| Prefijo de los 3 bloques `location` | `/security` | `/tools/security` |
| Valor en `sub_filter` | `"/security"` | `"/tools/security"` |
| Header `X-Forwarded-Prefix` | `/security` | `/tools/security` |
| Redirect del primer `location =` | `return 301 /security/` | `return 301 /tools/security/` |

---

## Variables de entorno del contenedor (`web/.env`)

```ini
FRONTEND_PORT=8778          # puerto publicado por el frontend — el proxy apunta aquí
FRONTEND_ORIGIN=https://tudominio.ec   # usado por FastAPI para CORS
JWT_SECRET=cadena-aleatoria-larga
APP_FIRST_ADMIN_USER=admin
APP_FIRST_ADMIN_PASSWORD=contraseña-segura
```

El puerto `FRONTEND_PORT` en `.env` debe coincidir con el `proxy_pass` del nginx externo.

---

## Levantamiento

```bash
cd web
docker compose up -d --build
```

Verificar que los contenedores estén en pie:
```bash
docker compose ps
```

Recargar nginx del host tras editar su configuración:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## Solución de problemas

### `sub_filter` no reemplaza nada (solo aplica al Caso 2 — subfolder)

**Causa:** el frontend comprime la respuesta con gzip antes de que nginx pueda hacer el reemplazo de texto.

**Solución:** el header `Accept-Encoding: ""` en el bloque `location /security/` desactiva la compresión. Verificar que esté presente.

---

### SSE de scan masivo se corta antes de terminar

**Causa:** el bloque general tiene `proxy_read_timeout 300s`, insuficiente para análisis largos.

**Solución:** verificar que el bloque regex (`~ ^/security/api/lists/...` o `~ ^/api/lists/...` según el caso) esté **antes** del bloque general en el archivo y tenga `proxy_read_timeout 1800s` con `proxy_buffering off`.

---

### La API no responde / error 502

1. Verificar que el contenedor frontend está corriendo: `docker compose ps`
2. Verificar que el puerto coincide entre `FRONTEND_PORT` en `.env` y `proxy_pass` en nginx
3. Verificar conectividad desde el host del proxy: `curl http://127.0.0.1:8778/`
4. Revisar logs: `docker compose logs api --tail=50`

---

### El login no funciona / error CORS

El contenedor API verifica `FRONTEND_ORIGIN` para CORS. Debe coincidir con el origen real del navegador (solo esquema + dominio, sin path):

```ini
# En web/.env — siempre el dominio raíz, sin subfolder
FRONTEND_ORIGIN=https://tudominio.ejemplo.ec

# Correcto para subfolder /security/:
FRONTEND_ORIGIN=https://tudominio.ejemplo.ec   # sin /security al final

# Correcto para subdominio:
FRONTEND_ORIGIN=https://security.ejemplo.ec
```
