---
description: "Añade un nuevo test de seguridad a scan-cli.sh siguiendo las convenciones del proyecto"
argument-hint: "Describe el test: qué cabecera/comportamiento HTTP verificar"
agent: "agent"
---

Voy a añadir un nuevo test de seguridad al script `scan-cli.sh`. Sigue exactamente las convenciones del proyecto definidas en [AGENTS.md](../../AGENTS.md).

## Pasos

1. **Lee** el script completo para determinar el próximo ID disponible (el mayor ID actual + 1, con cero padding: `21`, `22`, etc.) y ubicar la función `run_tests()`.

2. **Identifica el bloque** donde encaja el nuevo test según la petición del usuario:
   - Bloque 1 (01–04): Cookies
   - Bloque 2 (05–09): Transporte / TLS
   - Bloque 3 (10–14): Cabeceras HTTP
   - Bloque 4 (15–17): Fuga de información
   - Bloque 5 (18–20): Configuración del servidor
   - Si no encaja en ninguno, crea un nuevo bloque con `section "Nombre"`.

3. **Implementa** el test dentro de `run_tests()` usando `run_test`:
   ```bash
   run_test "ID" "Descripción corta" "PASS|FAIL|WARN|SKIP" "detalle opcional"
   ```
   - Usa `RESPONSE` / `COOKIES` ya cacheados — no hagas `curl` extra salvo que sea imprescindible.
   - Si el test requiere contexto ausente (herramienta no disponible, cookie no definida), devuelve `SKIP`.
   - Actualiza el array `TESTS` en `batch_print_table` si el nuevo ID excede `20`.

4. **Añade la entrada** en [docs/tests-reference.md](../../docs/tests-reference.md):
   - Sección con nombre `### TEST-XX — <descripción>`
   - Campos: qué verifica, criterio de fallo, snippet bash independiente.

5. **Verifica** que el script sigue siendo ejecutable con `bash -n scan-cli.sh`.

## Restricciones

- No modifiques tests existentes.
- No cambies el formato de `run_test` ni de `section`.
- No añadas dependencias externas nuevas (`curl`, `openssl`, `dig`/`getent` son las únicas permitidas).
