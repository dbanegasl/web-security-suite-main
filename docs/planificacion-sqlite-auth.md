# Planificación: SQLite, Autenticación e Historial

> **Estado**: Planificado — pendiente de implementación (mayo 2026).
> Continuación natural de la interfaz web (ver `planificacion-interfaz-web.md`).
> Stack actual corriendo en `localhost:8778`.

---

## Objetivo

Evolucionar Web Security Suite de una herramienta de análisis puntual a una **plataforma de auditoría con memoria**, añadiendo:

1. Control de acceso con usuarios y JWT
2. Historial persistente de scans con comparativa temporal
3. Listas de dominios guardadas en DB (reemplaza CSV efímero)

Todo sobre **SQLite** — una única base de datos en archivo, sin servicios externos, montada como volumen Docker.

---

## Arquitectura de datos

### Esquema de tablas

```
┌─────────────────┐        ┌──────────────────────┐        ┌──────────────────────────┐
│      users      │        │    domain_lists      │        │      scan_history        │
├─────────────────┤        ├──────────────────────┤        ├──────────────────────────┤
│ id              │        │ id                   │        │ id                       │
│ username        │──┐     │ name                 │──┐     │ domain                   │
│ password_hash   │  └────►│ description          │  │     │ scanned_at (timestamp)   │
│ role            │        │ created_by (FK→users)│  │     │ pass_count               │
│ is_active       │        │ created_at           │  │     │ fail_count               │
│ created_at      │        └──────────┬───────────┘  │     │ warn_count               │
│ last_login      │                   │               │     │ skip_count               │
└─────────────────┘                   ▼               │     │ results (JSON blob)      │
                              ┌──────────────────┐    │     │ scan_mode (individual/   │
                              │  list_domains    │    │     │           batch/         │
                              ├──────────────────┤    │     │           scheduled)     │
                              │ id               │    └────►│ list_id (FK→domain_lists,│
                              │ list_id (FK)     │          │          nullable)        │
                              │ domain           │          │ triggered_by (FK→users)  │
                              │ session_cookie   │          └──────────────────────────┘
                              │ ip               │
                              │ notes            │
                              │ is_active        │
                              │ added_at         │
                              └──────────────────┘
```

### Archivo de base de datos

```
web/
└── data/                  ← volumen Docker persistente (gitignored)
    └── wss.db             ← SQLite, se crea automáticamente en el primer arranque
```

---

## Stack técnico a añadir

| Librería | Versión mínima | Para qué |
|---|---|---|
| `sqlmodel` | ≥0.0.21 | ORM + modelos Pydantic unificados (SQLAlchemy bajo el capó) |
| `python-jose[cryptography]` | ≥3.3 | Generación y verificación de JWT |
| `passlib[bcrypt]` | ≥1.7 | Hash seguro de contraseñas (bcrypt) |

Sin PostgreSQL, sin Redis, sin nada externo. Solo Python y un archivo `.db`.

---

## Variables de entorno nuevas

Añadir a `web/.env.example` y `web/.env`:

```bash
# ── Autenticación ───────────────────────────────────────────────
# Usuario admin inicial (se crea solo si no existe al arrancar)
APP_FIRST_ADMIN_USER=admin
APP_FIRST_ADMIN_PASSWORD=cambia-esto-antes-de-produccion

# Clave secreta para firmar JWT — generar con: openssl rand -hex 32
JWT_SECRET=reemplazar-por-un-valor-largo-y-aleatorio
JWT_EXPIRE_MINUTES=480        # 8 horas de sesión

# ── Base de datos ───────────────────────────────────────────────
DB_PATH=/app/data/wss.db
```

---

## Plan de implementación por fases

---

### Fase A — Base: autenticación + historial persistente

> **Prerequisito de todo lo demás. No rompe nada del estado actual.**

#### Backend (`web/api/`)

**A.1 — Modelos SQLModel**

Crear `web/api/models.py` con las clases `User` y `ScanHistory`. SQLModel crea las tablas automáticamente en el primer arranque si no existen (no se necesitan migraciones manuales en esta fase).

**A.2 — Inicialización de DB**

En `main.py`, al arrancar la aplicación:
- Crear `wss.db` si no existe
- Si la tabla `users` está vacía, crear el usuario admin desde `APP_FIRST_ADMIN_USER` / `APP_FIRST_ADMIN_PASSWORD`

**A.3 — Endpoints de autenticación**

```
POST /api/auth/login        → { username, password } → { access_token, token_type }
GET  /api/auth/me           → datos del usuario autenticado (requiere JWT)
POST /api/auth/logout       → invalida token en cliente (stateless JWT, solo limpia cookie/header)
```

**A.4 — Middleware de autenticación**

Dependencia FastAPI (`Depends(get_current_user)`) aplicada a todos los endpoints existentes:
- `POST /api/scan`
- `POST /api/batch`
- `GET  /api/health` queda público

**A.5 — Guardar cada scan en historial**

Al completar `_run_scan()`, insertar en `scan_history`:
- domain, timestamp, pass/fail/warn/skip counts
- results (JSON completo del scan)
- triggered_by (id del usuario autenticado)

**A.6 — Endpoint de historial**

```
GET /api/history?domain=&limit=50&offset=0   → lista paginada
GET /api/history/{id}                         → detalle de un scan
GET /api/history/compare?a={id}&b={id}        → diff entre dos scans
```

El endpoint `/compare` devuelve para cada test: resultado anterior, resultado nuevo y si hubo cambio.

#### Frontend (`web/frontend/`)

**A.7 — Pantalla de login**

Antes de mostrar la app, si no hay token válido en `localStorage`, mostrar un formulario de login centrado (misma paleta de la app). Al hacer login exitoso, guardar el JWT y cargar la SPA normalmente.

**A.8 — Header de autorización**

Todas las llamadas `fetch` existentes añaden `Authorization: Bearer <token>`. Si la API devuelve 401, redirigir al login y limpiar el token.

**A.9 — Vista Historial mejorada**

La vista "Historial" actual (solo sesión en memoria) se reemplaza por:
- Tabla con todos los scans pasados (paginada)
- Filtro por dominio y rango de fechas
- Botón "Comparar" entre dos filas seleccionadas → abre modal con diff

**Criterio de completado de Fase A:**
- [ ] Login funcional, app inaccesible sin credenciales
- [ ] Cada scan queda guardado en `wss.db`
- [ ] Vista de historial muestra scans persistentes entre reinicios de Docker
- [ ] Comparativa funcional entre dos scans del mismo dominio

---

### Fase B — Listas de dominios

> **Reemplaza el CSV efímero por listas guardadas y reutilizables.**

#### Backend

**B.1 — Modelos SQLModel adicionales**

Añadir `DomainList` y `ListDomain` a `models.py`.

**B.2 — Endpoints CRUD de listas**

```
GET    /api/lists                     → todas las listas del usuario
POST   /api/lists                     → crear lista { name, description }
GET    /api/lists/{id}                → detalle con sus dominios
PUT    /api/lists/{id}                → renombrar/describir lista
DELETE /api/lists/{id}                → eliminar lista y sus dominios

GET    /api/lists/{id}/domains        → dominios de una lista
POST   /api/lists/{id}/domains        → añadir dominio { domain, session_cookie?, ip?, notes? }
PUT    /api/lists/{id}/domains/{did}  → editar dominio
DELETE /api/lists/{id}/domains/{did}  → eliminar dominio

POST   /api/lists/{id}/import-csv     → importar CSV → añade dominios a lista existente
GET    /api/lists/{id}/export-csv     → exportar lista como CSV descargable

POST   /api/lists/{id}/scan           → lanzar batch sobre todos los dominios activos de la lista
```

**B.3 — Batch desde lista**

El endpoint `POST /api/lists/{id}/scan` itera los dominios activos de la lista y llama internamente a `_run_scan()` por cada uno, guardando cada resultado en `scan_history` con `list_id` relleno.

#### Frontend

**B.4 — Vista "Listas de dominios"** (nueva entrada en sidebar)

- Panel izquierdo: listado de listas con botón crear
- Panel derecho: tabla editable de dominios de la lista seleccionada
- Botones: "Añadir dominio", "Importar CSV", "Exportar CSV", "Lanzar scan completo"

**B.5 — Vista Análisis batch actualizada**

Mantiene la opción de pegar/subir CSV puntual (comportamiento actual), pero añade un selector "o usar lista guardada →" que despliega las listas disponibles.

**Criterio de completado de Fase B:**
- [ ] Crear/editar/eliminar listas desde la UI
- [ ] Importar CSV existente a una lista
- [ ] Lanzar batch desde lista con un clic
- [ ] Exportar lista como CSV
- [ ] Los scans batch quedan enlazados a la lista en el historial

---

### Fase C — Comparativa y análisis temporal

> **Convierte el historial en una herramienta de inteligencia de seguridad.**

#### Backend

**C.1 — Endpoint de evolución por dominio**

```
GET /api/history/evolution/{domain}?days=90
```

Devuelve series temporales: para cada test, array de `{ date, result }` ordenado por fecha. Permite graficar la evolución de cada test a lo largo del tiempo.

**C.2 — Endpoint de resumen de lista**

```
GET /api/lists/{id}/summary
```

Para cada dominio de la lista: último scan, tendencia (mejorando/empeorando/estable), número de FAILs actuales.

**C.3 — Alertas básicas (opcional)**

Tabla `alerts` que registra cuando un dominio pasa de PASS→FAIL entre dos scans consecutivos. Endpoint `GET /api/alerts` para consultarlas.

#### Frontend

**C.4 — Vista "Comparativa"** (accesible desde historial)

- Selector de dominio + dos fechas (o dos IDs de scan)
- Tabla diff: cada fila = un test, columnas = resultado anterior / resultado nuevo / cambio (→PASS, →FAIL, sin cambio)
- Color coding: verde si mejoró, rojo si empeoró, gris si no cambió

**C.5 — Vista "Evolución"**

- Selector de lista o dominio individual
- Mini-tabla: dominios en filas, tests en columnas, celda = último resultado con indicador de tendencia
- Click en celda → modal con histórico completo de ese test para ese dominio

**C.6 — Panel de administración de usuarios** (solo rol `admin`)

```
GET    /api/admin/users          → lista usuarios
POST   /api/admin/users          → crear usuario
PUT    /api/admin/users/{id}     → cambiar rol / activar / desactivar
DELETE /api/admin/users/{id}     → eliminar usuario (no puede eliminar su propia cuenta)
PUT    /api/admin/users/{id}/reset-password → forzar cambio de contraseña
```

Vista en frontend accesible solo para administradores desde la sidebar.

**Criterio de completado de Fase C:**
- [ ] Comparativa visual entre dos scans funcional
- [ ] Vista de evolución temporal por dominio
- [ ] Panel de usuarios operativo para rol admin
- [ ] Alertas de regresión registradas

---

## Cambios en infraestructura Docker

### `docker-compose.yml` — cambios requeridos para Fase A

```yaml
services:
  api:
    environment:
      # Existentes
      SCAN_TIMEOUT_SECONDS: "${SCAN_TIMEOUT_SECONDS:-120}"
      FRONTEND_ORIGIN: "${FRONTEND_ORIGIN:-http://localhost:8778}"
      # Nuevas
      APP_FIRST_ADMIN_USER: "${APP_FIRST_ADMIN_USER:-admin}"
      APP_FIRST_ADMIN_PASSWORD: "${APP_FIRST_ADMIN_PASSWORD}"
      JWT_SECRET: "${JWT_SECRET}"
      JWT_EXPIRE_MINUTES: "${JWT_EXPIRE_MINUTES:-480}"
      DB_PATH: "/app/data/wss.db"
    volumes:
      - ../reports:/app/reports
      - ../data:/app/data      # ← nuevo: persistencia de wss.db
```

El directorio `data/` se añade a `.gitignore` (contenido). La carpeta se trackea con `.gitkeep` igual que `reports/`.

---

## Consideraciones de seguridad

- **Contraseñas**: bcrypt con cost factor 12 mínimo. Nunca almacenar en texto plano.
- **JWT**: firmado con HS256, clave de mínimo 256 bits. Expiración máxima recomendada: 8 horas. Sin refresh tokens en Fase A (se puede añadir en Fase C).
- **SQLite y concurrencia**: FastAPI es async; usar `check_same_thread=False` y connection pooling de SQLAlchemy (incluido en SQLModel). Para carga alta considerar WAL mode (`PRAGMA journal_mode=WAL`).
- **Validación**: todos los campos de dominio/cookie/IP ya tienen validación en los modelos Pydantic actuales — se reutilizan sin cambios.
- **CORS**: sin cambios; ya está restringido al origen del frontend.
- **Roles**: `admin` puede gestionar usuarios; `analyst` solo puede lanzar scans y ver su propio historial. En Fase A se puede simplificar a un único rol mientras no hay panel de usuarios.

---

## Prioridad y dependencias entre fases

```
Fase A (auth + historial)
    └── Fase B (listas de dominios)
            └── Fase C (comparativa + evolución + admin users)
```

Cada fase es **desplegable y utilizable de forma independiente**. No es necesario completar la fase siguiente para que la anterior sea completamente funcional.

---

## Estado

| Fase | Estado | Inicio estimado |
|---|---|---|
| **A** — Auth + historial persistente | 🔲 Pendiente | Siguiente iteración |
| **B** — Listas de dominios | 🔲 Pendiente | Tras validar Fase A |
| **C** — Comparativa + admin users | 🔲 Pendiente | Tras validar Fase B |

---

*Planificado con asistencia de GitHub Copilot — UNAE TICS 2026.*
