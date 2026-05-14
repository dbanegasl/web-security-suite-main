---
mode: agent
description: Detecta cambios pendientes, decide el bump de versión (MAJOR/MINOR/PATCH), actualiza version.json y hace commit + push.
---

Eres el agente de release de Web Security Suite. Ejecuta estos pasos en orden sin pedir confirmaciones intermedias, salvo en el Paso 4 antes del push.

## Paso 1 — Ver qué cambió

Ejecuta en terminal:

```
git -C ${workspaceFolder} status --short
git -C ${workspaceFolder} diff --stat HEAD
```

Con esa información identifica qué archivos cambiaron y qué parte del sistema afectan (API, frontend, script bash, Docker, docs, tests).

## Paso 2 — Decidir el tipo de bump

Aplica estas reglas en orden de prioridad (la primera que aplique gana):

**MAJOR** si alguno de estos:
- Se eliminó o cambió la firma de un endpoint existente de la API
- Cambio en el esquema SQLite que requiere migración manual
- Cambio en el formato de `domains.csv`
- ≥5 tests de seguridad redefinidos

**MINOR** si alguno de estos (y no aplica MAJOR):
- Endpoint nuevo añadido sin romper los existentes
- Nueva vista o sección funcional en el frontend
- Nuevo test de seguridad (TEST-21+)
- Nuevo modo de operación en `scan.sh` o `web-security-scan.sh`
- Nueva funcionalidad en panel de admin o listas de dominios

**PATCH** en cualquier otro caso:
- Bugfix, estilos CSS, textos/mensajes UI, dependencias
- Ajustes en `deploy.sh`, `Dockerfile`, `docker-compose.yml`
- Documentación, instrucciones de agente, archivos de config

## Paso 3 — Actualizar version.json

Lee el valor actual de `web/frontend/version.json`.

Calcula la nueva versión según el tipo de bump:
- **MAJOR**: incrementa el primer número, el segundo va a 0 → `5.0`
- **MINOR**: incrementa el segundo número → `4.2`
- **PATCH**: incrementa el segundo número igual que MINOR (formato `MAJOR.MINOR`, sin tercer segmento)

Edita `web/frontend/version.json` manteniendo `build` como `"__BUILD_DATE__"`:
```json
{
  "version": "NUEVA_VERSION",
  "build": "__BUILD_DATE__"
}
```

## Paso 4 — Commit y push

Muestra al usuario el resumen de lo que vas a commitear y pide confirmación explícita antes de ejecutar el push.

Una vez confirmado, ejecuta:
```
git -C ${workspaceFolder} add -A
git -C ${workspaceFolder} commit -m "release: vNUEVA_VERSION — TIPO: descripción breve de los cambios"
git -C ${workspaceFolder} push
```

Ejemplos de mensaje de commit:
- `release: v4.1 — minor: nueva vista de reportes programados`
- `release: v4.1 — patch: fix mensaje de error en login y cache-busting en CSS`
- `release: v5.0 — major: rediseño de endpoints API de historial`

## Paso 5 — Confirmar resultado

Informa al usuario:
- Versión anterior → nueva versión y tipo de bump aplicado
- Justificación: qué cambio específico activó el nivel de bump
- Archivos incluidos en el commit
- Resultado del push (rama y hash del commit)
- Recordatorio: correr `bash deploy.sh` para que Docker tome la nueva versión
