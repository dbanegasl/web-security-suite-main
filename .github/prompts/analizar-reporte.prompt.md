---
description: "Analiza un reporte Markdown de reports/ y genera un resumen ejecutivo con prioridades de remediación"
argument-hint: "Ruta al reporte (ej: reports/20260512-162312-evea.unae.edu.ec.md) o 'último' para el más reciente"
agent: "agent"
---

Analiza el reporte de seguridad indicado y produce un resumen ejecutivo orientado a la remediación.

## Pasos

1. **Localiza el reporte**:
   - Si el argumento es `último` o está vacío, busca el archivo más reciente en `reports/` (mayor timestamp en el nombre).
   - Si el argumento es una ruta, léela directamente.

2. **Lee el reporte** y extrae todos los resultados: ID, descripción, resultado (`PASS`/`FAIL`/`WARN`/`SKIP`) y detalle.

3. **Consulta** [docs/tests-reference.md](../../docs/tests-reference.md) para obtener el impacto de cada test con FAIL (puntos de scorecard perdidos si están documentados).

4. **Genera el resumen ejecutivo** con esta estructura:

   ```
   ## Resumen ejecutivo — <dominio> (<fecha>)

   **Estado general:** CRÍTICO / CON ADVERTENCIAS / APROBADO

   ### Fallos críticos (FAIL) — acción inmediata
   | # | Test | Problema | Remediación recomendada |
   ...ordenados por impacto estimado (mayor primero)

   ### Advertencias (WARN) — acción recomendada
   | # | Test | Observación | Acción sugerida |
   ...

   ### Tests omitidos (SKIP)
   Listado breve con motivo.

   ### Tests superados (PASS): X/20
   ```

5. **Para cada FAIL**, incluye:
   - Qué significa en términos de riesgo (XSS, MITM, clickjacking, etc.)
   - Una recomendación concreta de remediación (header HTTP, configuración de cookie, etc.)
   - Referencia a OWASP si aplica.

6. **Estado general**:
   - `CRÍTICO` si hay ≥ 1 FAIL
   - `CON ADVERTENCIAS` si hay 0 FAIL pero ≥ 1 WARN
   - `APROBADO` si todo es PASS o SKIP

## Restricciones

- No modifiques el archivo de reporte original.
- El resumen es solo texto en chat — no generes un nuevo archivo salvo que el usuario lo pida explícitamente.
