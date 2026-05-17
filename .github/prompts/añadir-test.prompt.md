---
description: "Añade un nuevo test de seguridad al motor Python wss siguiendo las convenciones del proyecto"
argument-hint: "Describe el test: qué cabecera/comportamiento HTTP verificar"
agent: "agent"
---

Voy a añadir un nuevo test de seguridad al motor Python `wss`. Sigue exactamente las convenciones definidas en [AGENTS.md](../../AGENTS.md) y en [docs/creating-tests.md](../../docs/creating-tests.md).

## Pasos

1. **Lee** `wss/core/registry.py` y los archivos de bloque existentes para determinar el próximo ID disponible (el mayor ID actual + 1, con cero padding: `"56"`, etc.) y el bloque correspondiente.

2. **Identifica el bloque** donde encaja el nuevo test:
   - Bloque 1 (01–04): Cookies
   - Bloque 2 (05–09): Transporte / TLS
   - Bloque 3 (10–14): Cabeceras HTTP
   - Bloque 4 (15–17): Fuga de información
   - Bloque 5 (18–20): Configuración del servidor
   - Bloque 6 (21–25): Headers modernos y deprecados
   - Bloque 7 (26–40): Archivos y rutas expuestas
   - Bloque 8 (41–47): DNS, Email y Dominio
   - Bloque 9 (48–55): Fingerprinting y Contenido
   - Si no encaja en ninguno, crea un nuevo archivo `wss/tests/block_N_nombre.py`.

3. **Implementa** el test en el archivo de bloque correspondiente usando el decorador `@test`:
   ```python
   from wss.core.registry import test
   from wss.core.context import ScanContext
   from wss.core.result import Result

   @test("ID", "Descripción corta", block=N)
   async def test_nombre(ctx: ScanContext) -> Result:
       # ctx.domain, ctx.ip, ctx.cookies, ctx.session_cookie, ctx.http_client
       resp = await ctx.http_client.get(f"https://{ctx.domain}/ruta")
       if condicion_fallo:
           return Result.fail("Descripción del fallo")
       return Result.ok()
   ```
   - Usa `ctx.http_client` (httpx.AsyncClient con ForcedIPTransport si aplica) — no uses `subprocess` ni `curl`.
   - Si falta contexto necesario (cookie no definida, herramienta no disponible), devuelve `Result.skip("razón")`.

4. **Actualiza** `web/frontend/app.js`:
   - Amplía el array `TESTS` con el nuevo ID.
   - Añade entrada en `TESTS_META` con nombre y detalle del test.

5. **Añade la entrada** en [docs/tests-reference.md](../../docs/tests-reference.md):
   - Sección `### TEST-XX — <descripción>`
   - Campos: qué verifica, criterio de fallo, bloque.

6. **Actualiza** contadores en `README.md`, `AGENTS.md` (tabla de bloques) y `web/frontend/index.html` si cambia el total.

7. **Verifica** que el test se registra correctamente con `python3 -c "from wss.core.registry import TEST_REGISTRY; print(len(TEST_REGISTRY))"`.

## Restricciones

- No modifiques tests existentes.
- No uses `subprocess`, `curl`, `openssl` ni `dig` — solo httpx y la stdlib de Python.
- IDs siempre con cero padding (string: `"56"`, `"57"`, …).
- `Result.skip()` cuando falta contexto; nunca `Result.fail()` por contexto ausente.
