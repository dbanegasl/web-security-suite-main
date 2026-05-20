# Guía: cómo crear un test nuevo en Web Security Suite

Este documento explica cómo añadir un test de seguridad al sistema, desde el código Python hasta la documentación.

---

## 1. Estructura de un módulo de tests

Todos los tests se organizan en archivos bajo `wss/tests/` con el nombre `block_N_nombre.py`.
El auto-discovery del scanner los detecta automáticamente gracias a `pkgutil` — **no hace falta editar ningún archivo de configuración**.

```
wss/
  tests/
    __init__.py
    block_1_cookies.py
    block_2_transport.py
    ...
    block_N_nombre.py   ← tu nuevo bloque
```

---

## 2. El decorador `@test`

Cada función de test se registra con el decorador `@test` importado desde `wss.core.registry`.

### Campos obligatorios

| Parámetro    | Tipo    | Descripción |
|---|---|---|
| `code`       | `str`   | Código funcional descriptivo único: `COOKIE-SECURE`, `EXPOSED-ENV`, `CVE-NGINX-2026-42945-VERSION` |
| `block`      | `int`   | Número de bloque (1-9 reservados; usa 10+ para bloques nuevos) |
| `name`       | `str`   | Nombre corto visible en reportes y UI |
| `severity`   | `str`   | `"LOW"` \| `"MEDIUM"` \| `"HIGH"` \| `"CRITICAL"` |

### Campos opcionales (recomendados)

| Parámetro     | Tipo         | Descripción |
|---|---|---|
| `block_name`  | `str`        | Nombre del bloque. Si se omite se toma de `BLOCK_META`. |
| `cwe`         | `str`        | Referencia CWE, p. ej. `"CWE-614"` |
| `description` | `str`        | Descripción de una o dos frases — aparece en la wiki y el catálogo |
| `references`  | `list[str]`  | URLs de referencia (OWASP, Mozilla, NIST…) |

---

## 3. Implementación de un test

```python
# wss/tests/block_10_ejemplo.py
"""Bloque 10 — Tests de ejemplo."""
from __future__ import annotations

from wss.core.registry import test
from wss.core.context import ScanContext
from wss.core.result import Result


@test(
    "HEADER-X-EJEMPLO",            # code funcional único, no secuencial
    block=10,
    order=1,
    block_name="Ejemplo",
    name="Mi nuevo test",
    severity="MEDIUM",
    cwe="CWE-999",
    description="Verifica que el servidor no exponga la cabecera X-Ejemplo.",
    references=[
        "https://owasp.org/www-project-web-security-testing-guide/",
    ],
)
async def test_mi_nuevo_test(ctx: ScanContext) -> Result:
    """Comprueba que X-Ejemplo no aparezca en la respuesta."""
    headers = ctx.response_headers or {}

    if "x-ejemplo" in {h.lower() for h in headers}:
        return Result.fail(detail="Cabecera X-Ejemplo expuesta — eliminar del servidor.")

    return Result.pass_(detail="Cabecera X-Ejemplo no presente.")
```

### Reglas fundamentales

- La función **debe ser `async`** y recibir un `ScanContext` como único argumento.
- **Siempre devuelve un `Result`**: usa `Result.pass_()`, `Result.fail()`, `Result.warn()` o `Result.skip()`.
- No uses `print()` ni `logging` dentro del test; usa solo el campo `detail` del `Result`.
- El campo `detail` debe ser una cadena de máximo ~120 caracteres.

### `ScanContext` — atributos disponibles

| Atributo             | Tipo                   | Descripción |
|---|---|---|
| `ctx.domain`         | `str`                  | Dominio sin esquema ni path |
| `ctx.base_url`       | `str`                  | URL base (`https://dominio/ruta`) |
| `ctx.session_cookie` | `str`                  | Nombre de la cookie de sesión (puede estar vacío) |
| `ctx.ip`             | `str`                  | IP forzada para `--resolve` (puede estar vacío) |
| `ctx.response`       | `httpx.Response`       | Respuesta inicial cacheada (cargada con `fetch_initial`) |
| `ctx.response_headers` | `dict[str, str]`     | Cabeceras de la respuesta inicial (nombre en minúsculas) |
| `ctx.cookies`        | `dict[str, dict]`      | Cookies parseadas de la respuesta inicial |
| `ctx.http`           | `httpx.AsyncClient`    | Cliente HTTP reutilizable para peticiones adicionales |

Para peticiones adicionales:

```python
resp = await ctx.http.get(f"{ctx.base_url}/.env", follow_redirects=False)
```

---

## 4. Test unitario

Crea un archivo en `tests/test_block_N_nombre.py`:

```python
# tests/test_block_10_ejemplo.py
"""Tests unitarios para block_10_ejemplo."""
import pytest
import httpx

import wss.tests.block_10_ejemplo as _run_block   # alias _run_ evita colisión con pytest
from wss.core.context import ScanContext


def _ctx(**overrides):
    defaults = dict(
        domain="example.com",
        base_url="https://example.com",
        session_cookie="",
        ip="",
    )
    return ScanContext(**{**defaults, **overrides})


@pytest.mark.asyncio
async def test_mi_nuevo_test_pass():
    ctx = _ctx()
    ctx._response_headers = {}           # sin la cabecera problemática
    result = await _run_block.test_mi_nuevo_test(ctx)
    assert result.status.value == "PASS"


@pytest.mark.asyncio
async def test_mi_nuevo_test_fail():
    ctx = _ctx()
    ctx._response_headers = {"x-ejemplo": "presente"}
    result = await _run_block.test_mi_nuevo_test(ctx)
    assert result.status.value == "FAIL"
```

Ejecutar:

```bash
python3 -m pytest tests/test_block_10_ejemplo.py -v
```

---

## 5. Actualizar la documentación

Al añadir un bloque nuevo o añadir/modificar tests, actualiza estos archivos en la **misma operación**:

| Archivo | Qué actualizar |
|---|---|
| `AGENTS.md` | Tabla de bloques (rango, nombre, total) |
| `README.md` | Tabla de bloques y contadores hero |
| `docs/tests-reference.md` | Especificación técnica de cada test |
| `docs/security-tests-wiki.html` | Contadores en hero y footer |
| `wss/descriptions.py` | Descripción HTML del test nuevo (ver sección 5.1) |
| `web/frontend/index.html` | Hero stats y coverage grid (ahora dinámicos vía `/api/tests`) |

El home y la wiki de la plataforma web se actualizan **automáticamente** en cada arranque de la API gracias a `sync_test_catalog()` — no necesitas editar el frontend.

---

## 5.1. Añadir la descripción en `wss/descriptions.py`

`wss/descriptions.py` es la **única fuente de verdad** para las descripciones HTML de los tests.
Al arrancar, `sync_test_catalog()` rellena automáticamente cualquier descripción vacía en la DB
usando este módulo — sin necesidad de ejecutar ningún script adicional.

### Formato

Añade una entrada al dict `DESCRIPTIONS` con la clave igual al ID del test (mismo valor
que el primer argumento de `@test`):

```python
# wss/descriptions.py

DESCRIPTIONS: dict[str, str] = {
    # ... tests existentes ...

    "HEADER-X-EJEMPLO": desc(
        # ¿Qué verifica?
        "Que el header <code>X-Custom-Header</code> esté presente con el valor correcto.",
        # ¿Por qué importa? (puede ser cadena vacía "")
        "Sin este header, el navegador no puede aplicar la política de seguridad personalizada.",
        # Resultados posibles: lista de (estado, texto)
        [("PASS", "Header presente y con valor válido"),
         ("FAIL", "Header ausente o con valor incorrecto")],
        # Remediación: HTML libre o resultado de tabs(...)
        tabs("HEADER-X-EJEMPLO", [
            ("Nginx", 'add_header X-Custom-Header "valor" always;'),
            ("Apache", 'Header always set X-Custom-Header "valor"'),
        ]),
    ),
}
```

### Helpers disponibles

| Helper | Descripción |
|---|---|
| `desc(what, why, results, rem)` | Genera el bloque HTML estándar con las 4 secciones |
| `tabs(code, panels)` | Genera tabs Bootstrap 5 con paneles `<pre>` de código |
| `_esc(s)` | HTML-escapa una cadena (uso interno en `tabs`) |

- `results` es una lista de tuplas `(estado, texto)`, donde `estado` puede ser `PASS`, `FAIL`, `WARN`, `SKIP` o `INFO`.
- `rem` (remediación) puede ser una cadena HTML directa o el resultado de `tabs(...)`.

### Comportamiento de `sync_test_catalog()` al arrancar

| Estado del row en DB | `description_custom` | ¿Se actualiza? |
|---|---|---|
| Row nuevo | — | Sí, desde `DESCRIPTIONS` |
| Row existente, descripción vacía | `False` | Sí, desde `DESCRIPTIONS` |
| Row existente, descripción presente | `False` | **No** (no sobreescribe) |
| Row existente, cualquier descripción | `True` | **Nunca** (editada por admin) |

### Script de emergencia `temp/seed_descriptions.py`

Si necesitas forzar la propagación de cambios en `wss/descriptions.py` a la DB **sin** hacer
`docker compose down -v`, usa el script de emergencia. A diferencia del arranque automático,
este script sobrescribe descripciones existentes vía PATCH a la API y marca `description_custom=True`:

```bash
# Propagar todos los cambios
python3 temp/seed_descriptions.py --pass <admin_password>

# Propagar solo un test específico
python3 temp/seed_descriptions.py --pass <admin_password> --test COOKIE-SECURE

# Apuntar a otra instancia
python3 temp/seed_descriptions.py --pass <admin_password> --url http://servidor:8778
```

---

## 6. Cómo funciona el auto-discovery

Al arrancar la API o ejecutar un scan:

1. `_ensure_tests_loaded()` en `wss/core/scanner.py` llama a `_discover_test_modules()`.
2. `_discover_test_modules()` usa `pkgutil.iter_modules` para listar todos los módulos bajo `wss/tests/` cuyo nombre empiece por `block_`.
3. Cada módulo se importa → sus decoradores `@test` se ejecutan → `TEST_REGISTRY` se puebla.
4. `sync_test_catalog()` en `web/api/database.py` hace upsert de `TEST_REGISTRY` en la tabla `test_catalog` de SQLite.
5. `GET /api/tests` sirve el catálogo desde la DB con metadatos de bloque (`BLOCK_META`).

Para añadir un bloque nuevo **solo tienes que crear el archivo** `wss/tests/block_N_nombre.py` y reiniciar la API.

---

## 7. Futuro: paquetes externos (entry-points)

En una fase futura se añadirá soporte para que paquetes pip externos registren tests usando el entry-point `wss.tests`. Esto permitirá distribuir bloques de tests como paquetes independientes instalables con `pip install`.
