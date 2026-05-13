---
name: exportar-csv
description: "Genera o actualiza domains.csv para web-security-suite. Úsala cuando necesites añadir dominios al análisis batch, detectar cookies de sesión automáticamente o actualizar IPs de servidores."
argument-hint: "Lista de dominios separados por coma o espacio (ej: cas.unae.edu.ec, evea.unae.edu.ec)"
---

# Skill: exportar-csv

Genera o actualiza `domains.csv` con los dominios indicados, intentando detectar automáticamente la cookie de sesión y la IP del servidor.

## Procedimiento

### 1. Leer el estado actual

Lee `domains.csv` (si existe) para no duplicar entradas. Usa `domains.csv.example` como referencia del formato esperado.

**Formato CSV:**
```
dominio,cookie_sesion,ip_forzada
# Las líneas con # son comentarios. Los dos últimos campos son opcionales.
```

### 2. Para cada dominio nuevo

Ejecuta en terminal los siguientes pasos de detección:

**Detectar IP:**
```bash
dig +short <dominio> | grep -oP '^\d+\.\d+\.\d+\.\d+$' | tail -1
```

**Detectar cookies de sesión** (excluir XSRF-TOKEN — debe ser legible por JS):
```bash
curl -sk -I "https://<dominio>/" | grep -i "^set-cookie" | grep -vi "xsrf"
```
- Prioriza cookies con nombre que sugiera sesión: `sessionid`, `JSESSIONID`, `PHPSESSID`, `MoodleSession`, `*_session`, `CASTGC`, etc.
- Si hay ambigüedad, lista las opciones y pide confirmación al usuario.

**Verificar accesibilidad:**
```bash
curl --max-time 5 -sk -o /dev/null -w "%{http_code}" "https://<dominio>/"
```
- Si devuelve `000` o falla, registra el dominio sin IP forzada y advierte al usuario.

### 3. Construir la entrada CSV

```
<dominio>,<cookie_detectada>,<ip_detectada>
```
- Si no se detecta cookie → dejar campo vacío: `dominio,,ip`
- Si no se detecta IP (DNS público) → dejar campo vacío: `dominio,cookie,`

### 4. Actualizar domains.csv

- Si el dominio ya existe en el archivo: actualiza solo los campos vacíos (no sobreescribas datos existentes sin confirmar).
- Si es nuevo: añádelo al final, agrupado bajo un comentario de sección si encaja (ej.: `# Servidores Moodle`).
- Muestra al usuario la línea exacta que se añadirá o modificará antes de escribir.

### 5. Validar el resultado

Tras escribir, muestra las líneas añadidas/modificadas y confirma que el archivo sigue siendo válido (sin líneas malformadas).

## Restricciones

- No elimines ni sobreescribas entradas existentes sin confirmación explícita del usuario.
- No uses herramientas externas más allá de `curl` y `dig`/`getent`.
- El campo `ip_forzada` solo se incluye si la IP detectada es RFC 1918 (`10.x`, `172.16–31.x`, `192.168.x`) o si el usuario la especifica explícitamente.
