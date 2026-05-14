---
applyTo: "**/version.json"
---

# Reglas de versionado — Web Security Suite

Cuando se te pida actualizar la versión, analiza los cambios descritos o el
`git log` reciente y aplica las siguientes reglas. **Solo edita `version.json`.**

## MAJOR (X.0) — cuando:
- Se rompe compatibilidad con la API (endpoint eliminado o con firma distinta)
- Cambio en el esquema de la base de datos SQLite que requiere migración manual
- Cambio en el formato del CSV de dominios (`domains.csv`)
- Reescritura de un bloque entero de tests de seguridad (≥5 tests redefinidos)

## MINOR (x.Y) — cuando:
- Se añade un endpoint nuevo sin romper los existentes
- Nueva vista o sección funcional en el frontend
- Se añaden nuevos tests de seguridad (TEST-21 en adelante)
- Nuevo modo de operación en `web-security-scan.sh` o `scan.sh`
- Nueva funcionalidad en el panel de administración o en listas de dominios

## PATCH (x.y.Z) — cuando:
- Bugfix en código existente (API, frontend, script bash)
- Mejora de rendimiento o seguridad sin cambio de interfaz
- Cambio en estilos CSS sin nueva funcionalidad
- Corrección de mensajes, typos o textos de la UI
- Actualización de dependencias (`requirements.txt`, imágenes Docker base)
- Ajuste en `deploy.sh`, `Dockerfile` o `docker-compose.yml` sin nueva feature

## Formato del archivo — solo estos dos campos
```json
{
  "version": "X.Y",
  "build": "__BUILD_DATE__"
}
```
- `version`: el valor que tú calculas según las reglas anteriores
- `build`: **siempre dejar como `"__BUILD_DATE__"`** — el Dockerfile lo reemplaza en cada build
- No edites `app.js` ni ningún otro archivo para el bump de versión

## Formato de versión
- Usa solo `MAJOR.MINOR` (ej. `4.1`, `5.0`)
- No uses tres segmentos (`4.1.2`) — los patches se reflejan con MINOR
- La versión actual siempre se puede leer del propio `version.json`
