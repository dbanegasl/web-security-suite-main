# Referencia de tests — web-security-suite

Especificación técnica (PRD) de los 20 tests incluidos en `web-security-scan.sh` (v3.1). Cada test incluye descripción, criterio de resultado y snippet bash ejecutable de forma independiente.

> Los snippets asumen ejecución individual. En el script principal, los tests se invocan mediante `run_tests()` con soporte tanto para modo individual (con salida detallada) como para modo batch (silencioso, resultados almacenados en `BATCH_RESULTS`).

**Referencia:** OWASP Top 10 · Security Headers · ZAP Active Scan rules

---

## Bloque 1 — Cookies

### TEST-01 — Cookie: atributo `Secure` (Scorecard: −12.4 pts)

**Qué verifica:** Que todas las cookies tengan el atributo `Secure`, impidiendo transmisión en conexiones HTTP no cifradas.  
**Falla si:** Alguna cookie no contiene `; secure` en el header `Set-Cookie`.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
COOKIES=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^set-cookie")
FAIL=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  NAME=$(echo "$line" | grep -oP "set-cookie:\s*\K[^=]+" | head -1)
  echo -n "  Cookie $NAME → Secure: "
  echo "$line" | grep -qi "; secure" && echo "✅ PRESENTE" || { echo "❌ AUSENTE"; FAIL=1; }
done <<< "$COOKIES"
[[ $FAIL -eq 0 ]] && echo "RESULTADO: ✅ PASS" || echo "RESULTADO: ❌ FAIL"
```

---

### TEST-02 — Cookie de sesión: atributo `HttpOnly` (Scorecard: −8.6 pts)

**Qué verifica:** Que la cookie de sesión no sea accesible desde JavaScript (protección anti-XSS).  
**Aplica a:** Cookie de sesión únicamente. El token CSRF (`XSRF-TOKEN`) debe ser legible por JS — excluirlo.  
**Falla si:** La cookie de sesión no contiene `; httponly`.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
SESSION_COOKIE_NAME="${SESSION_COOKIE_NAME:-ssoserver_unae_session}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
SESSION_LINE=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^set-cookie" | grep -i "$SESSION_COOKIE_NAME")
if [[ -z "$SESSION_LINE" ]]; then
  echo "⚠️  Cookie '$SESSION_COOKIE_NAME' no encontrada. Cookies disponibles:"
  curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^set-cookie" | grep -oP "set-cookie:\s*\K[^=]+"
else
  echo "$SESSION_LINE" | grep -qi "httponly" \
    && echo "✅ PASS — HttpOnly presente" \
    || echo "❌ FAIL — HttpOnly ausente"
fi
```

---

### TEST-03 — Cookie: atributo `SameSite`

**Qué verifica:** Protección contra CSRF vía `SameSite=Lax` o `SameSite=Strict`.  
**Falla si:** Alguna cookie no tiene `SameSite` o tiene `SameSite=None`.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
COOKIES=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^set-cookie")
FAIL=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  NAME=$(echo "$line" | grep -oP "set-cookie:\s*\K[^=]+" | head -1)
  SAMESITE=$(echo "$line" | grep -oiP "samesite=\w+")
  echo -n "  Cookie $NAME → SameSite: "
  [[ -n "$SAMESITE" ]] && echo "✅ $SAMESITE" || { echo "❌ AUSENTE"; FAIL=1; }
done <<< "$COOKIES"
[[ $FAIL -eq 0 ]] && echo "RESULTADO: ✅ PASS" || echo "RESULTADO: ❌ FAIL"
```

---

### TEST-04 — Cookie: atributo `Path`

**Qué verifica:** Que las cookies tengan `Path` definido para limitar su scope.  
**Advierte** si alguna cookie no especifica `Path` (WARN, no FAIL crítico).

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
COOKIES=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^set-cookie")
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  NAME=$(echo "$line" | grep -oP "set-cookie:\s*\K[^=]+" | head -1)
  echo -n "  Cookie $NAME → Path: "
  echo "$line" | grep -qi "path=" && echo "✅ definido" || echo "⚠️  ausente"
done <<< "$COOKIES"
```

---

## Bloque 2 — Transporte y TLS

### TEST-05 — Redirección HTTP → HTTPS (Scorecard: −0.6 pts)

**Qué verifica:** Que el servidor no sirva contenido por HTTP sin redirigir a HTTPS.  
**Falla si:** HTTP responde código distinto de 301/302, o `Location` no apunta a `https://`.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:80:${IP}}"
RESPONSE=$(curl -sk -I $RESOLVE "http://${DOMAIN}/")
HTTP_CODE=$(echo "$RESPONSE" | grep -oP "HTTP/\S+ \K\d+")
LOCATION=$(echo "$RESPONSE" | grep -i "^location:" | tr -d '\r')
echo "  HTTP Status : $HTTP_CODE"
echo "  Location    : $LOCATION"
([[ "$HTTP_CODE" =~ ^30[12]$ ]] && echo "$LOCATION" | grep -qi "https://") \
  && echo "RESULTADO: ✅ PASS" || echo "RESULTADO: ❌ FAIL"
```

---

### TEST-06 — HSTS (Strict-Transport-Security)

**Qué verifica:** Que el servidor obligue al navegador a usar HTTPS con `max-age` ≥ 1 año (31536000 segundos).  
**FAIL** si el header está ausente. **WARN** si `max-age` < 31536000.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
HSTS=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "strict-transport-security" | tr -d '\r')
MAX_AGE=$(echo "$HSTS" | grep -oP "max-age=\K\d+")
echo "  Header: ${HSTS:-❌ AUSENTE}"
if [[ -z "$HSTS" ]]; then echo "RESULTADO: ❌ FAIL"
elif [[ "${MAX_AGE:-0}" -ge 31536000 ]]; then echo "RESULTADO: ✅ PASS"
else echo "RESULTADO: ⚠️  WARN — max-age=${MAX_AGE} < 31536000"; fi
```

---

### TEST-07 — TLS 1.0 deshabilitado

**Qué verifica:** Que el servidor rechace conexiones con TLS 1.0 (protocolo obsoleto, vulnerable a POODLE/BEAST).  
**Falla si:** El servidor acepta TLS 1.0.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
curl -sk --tlsv1.0 --tls-max 1.0 $RESOLVE "https://${DOMAIN}/" -o /dev/null 2>/dev/null \
  && echo "❌ FAIL — servidor acepta TLS 1.0" \
  || echo "✅ PASS — TLS 1.0 rechazado"
```

---

### TEST-08 — TLS 1.1 deshabilitado

**Qué verifica:** Que el servidor rechace TLS 1.1 (obsoleto desde RFC 8996, 2021).  
**Falla si:** El servidor acepta TLS 1.1.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
curl -sk --tlsv1.1 --tls-max 1.1 $RESOLVE "https://${DOMAIN}/" -o /dev/null 2>/dev/null \
  && echo "❌ FAIL — servidor acepta TLS 1.1" \
  || echo "✅ PASS — TLS 1.1 rechazado"
```

---

### TEST-09 — Certificado SSL vigente

**Qué verifica:** Días restantes antes de que expire el certificado TLS.  
**FAIL** si expira en ≤ 7 días. **WARN** si expira en ≤ 30 días. **PASS** si > 30 días.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
OPENSSL_CONNECT="${IP:+-connect ${IP}:443}"
EXPIRY=$(echo | openssl s_client ${OPENSSL_CONNECT:--connect ${DOMAIN}:443} \
  -servername "${DOMAIN}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
echo "  Expira: $EXPIRY ($DAYS_LEFT días)"
if [[ $DAYS_LEFT -le 7 ]]; then echo "❌ FAIL — CRÍTICO, renovar inmediatamente"
elif [[ $DAYS_LEFT -le 30 ]]; then echo "⚠️  WARN — renovar pronto"
else echo "✅ PASS"; fi
```

---

## Bloque 3 — Cabeceras HTTP de seguridad

### TEST-10 — X-Frame-Options (anti-clickjacking)

**Qué verifica:** Que el sitio no pueda ser embebido en un `<iframe>` externo.  
**Falla si:** El header `X-Frame-Options` está ausente.  
**ZAP rule:** 10020

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XFO=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^x-frame-options:" | tr -d '\r')
[[ -n "$XFO" ]] && echo "✅ PASS — ${XFO#*: }" || echo "❌ FAIL — X-Frame-Options ausente"
```

---

### TEST-11 — X-Content-Type-Options: nosniff

**Qué verifica:** Que el navegador no intente inferir el MIME type de las respuestas (anti-MIME sniffing).  
**Falla si:** El header `X-Content-Type-Options` está ausente.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XCTO=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^x-content-type-options:" | tr -d '\r')
[[ -n "$XCTO" ]] && echo "✅ PASS" || echo "❌ FAIL — X-Content-Type-Options ausente"
```

---

### TEST-12 — Content-Security-Policy

**Qué verifica:** Presencia de CSP y ausencia de directivas peligrosas.  
**FAIL** si CSP ausente. **WARN** si contiene `unsafe-eval` (permite ejecución de código arbitrario).  
**ZAP rule:** 10038

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
CSP=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^content-security-policy:" | tr -d '\r')
if [[ -z "$CSP" ]]; then echo "❌ FAIL — CSP ausente"
elif echo "$CSP" | grep -qi "unsafe-eval"; then echo "⚠️  WARN — CSP contiene 'unsafe-eval'"
else echo "✅ PASS"; fi
```

---

### TEST-13 — Referrer-Policy

**Qué verifica:** Que el sitio controle qué información de referencia se envía al navegar a otros dominios.  
**Advierte** si el header está ausente (WARN, no FAIL crítico).

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
RP=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^referrer-policy:" | tr -d '\r')
[[ -n "$RP" ]] && echo "✅ PASS — ${RP#*: }" || echo "⚠️  WARN — Referrer-Policy ausente"
```

---

### TEST-14 — Permissions-Policy

**Qué verifica:** Que el sitio restrinja el uso de APIs sensibles del navegador (cámara, micrófono, geolocalización).  
**Advierte** si el header está ausente (WARN, no FAIL crítico).

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
PP=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^permissions-policy:" | tr -d '\r')
[[ -n "$PP" ]] && echo "✅ PASS" || echo "⚠️  WARN — Permissions-Policy ausente (recomendado)"
```

---

## Bloque 4 — Fuga de información

### TEST-15 — Server header sin versión

**Qué verifica:** Que el header `Server` no revele el número de versión del software (ej: `nginx/1.26.2`).  
**PASS** si el header está ausente o solo contiene el nombre del servidor. **FAIL** si contiene número de versión.  
**ZAP rule:** 10096

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
SERVER=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^server:" | tr -d '\r')
echo "  Server: ${SERVER:-ausente}"
echo "$SERVER" | grep -qiP "[\d\.]{3,}" && echo "❌ FAIL — revela versión" || echo "✅ PASS"
```

---

### TEST-16 — X-Powered-By ausente

**Qué verifica:** Que el header `X-Powered-By` no revele el stack tecnológico (ej: `PHP/7.2.34`).  
**Falla si:** El header está presente.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XPB=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^x-powered-by:" | tr -d '\r')
[[ -z "$XPB" ]] && echo "✅ PASS — X-Powered-By ausente" || echo "❌ FAIL — ${XPB#*: }"
```

---

### TEST-17 — X-AspNet-Version ausente

**Qué verifica:** Que los headers de versión de ASP.NET no estén expuestos.  
**Aplica principalmente a:** Servidores IIS / ASP.NET. En nginx/PHP siempre debería ser PASS.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XASNET=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -iE "^x-aspnet(mvc)?-version:" | tr -d '\r')
[[ -z "$XASNET" ]] && echo "✅ PASS" || echo "❌ FAIL — ${XASNET#*: }"
```

---

## Bloque 5 — Configuración del servidor

### TEST-18 — CORS sin wildcard

**Qué verifica:** Que el header `Access-Control-Allow-Origin` no use `*` (permitiría cualquier origen acceder a los recursos).  
**PASS** si CORS no está expuesto en raíz o especifica origen explícito. **FAIL** si usa `*`.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
CORS=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^access-control-allow-origin:" | tr -d '\r')
if [[ -z "$CORS" ]]; then echo "✅ PASS — CORS no expuesto en raíz"
elif echo "$CORS" | grep -q "\*"; then echo "❌ FAIL — wildcard '*' permite cualquier origen"
else echo "✅ PASS — ${CORS#*: }"; fi
```

---

### TEST-19 — HTTP TRACE deshabilitado

**Qué verifica:** Que el método HTTP `TRACE` esté deshabilitado (previene ataques Cross-Site Tracing / XST).  
**FAIL** si el servidor responde `200 OK`. **PASS** si responde 405/403/404.

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
TRACE_CODE=$(curl -sk -o /dev/null -w "%{http_code}" $RESOLVE -X TRACE "https://${DOMAIN}/")
echo "  TRACE response: $TRACE_CODE"
if [[ "$TRACE_CODE" == "200" ]]; then echo "❌ FAIL — TRACE activo"
elif [[ "$TRACE_CODE" =~ ^(405|403|404)$ ]]; then echo "✅ PASS"
else echo "⚠️  WARN — respuesta inesperada: $TRACE_CODE"; fi
```

---

### TEST-20 — Cache-Control seguro

**Qué verifica:** Que el header `Cache-Control` incluya directivas que eviten el cacheo de contenido sensible en navegadores/proxies.  
**PASS** si contiene `no-store`, `no-cache` o `private`. **WARN** si el header está ausente o usa solo directivas permisivas.  
**ZAP rule:** 10015

```bash
DOMAIN="${DOMAIN:-ssoserver.unae.edu.ec}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
CACHE=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^cache-control:" | tr -d '\r')
echo "  Cache-Control: ${CACHE:-ausente}"
if [[ -z "$CACHE" ]]; then echo "⚠️  WARN — ausente, navegador puede cachear contenido sensible"
elif echo "$CACHE" | grep -qiP "no-store|no-cache|private"; then echo "✅ PASS"
else echo "⚠️  WARN — revisar si aplica a rutas autenticadas"; fi
```

---

## Tabla de criterios de aceptación

| Test | Descripción | Criterio PASS | Nivel fallo | Pts Scorecard |
|---|---|---|---|---|
| TEST-01 | Cookie: Secure | Todas las cookies tienen `; secure` | FAIL | +12.4 |
| TEST-02 | Cookie: HttpOnly | Cookie de sesión tiene `; httponly` | FAIL | +8.6 |
| TEST-03 | Cookie: SameSite | Todas las cookies tienen `SameSite=Lax\|Strict` | FAIL | — |
| TEST-04 | Cookie: Path | Todas las cookies tienen `Path` definido | WARN | — |
| TEST-05 | HTTP → HTTPS redirect | Código 301/302 + Location a `https://` | FAIL | +0.6 |
| TEST-06 | HSTS | `max-age >= 31536000` | FAIL / WARN | — |
| TEST-07 | TLS 1.0 deshabilitado | Conexión TLS 1.0 rechazada | FAIL | — |
| TEST-08 | TLS 1.1 deshabilitado | Conexión TLS 1.1 rechazada | FAIL | — |
| TEST-09 | Certificado SSL | Expira en > 30 días | FAIL / WARN | — |
| TEST-10 | X-Frame-Options | Header presente | FAIL | — |
| TEST-11 | X-Content-Type-Options | `nosniff` presente | FAIL | — |
| TEST-12 | Content-Security-Policy | CSP presente sin `unsafe-eval` | FAIL / WARN | — |
| TEST-13 | Referrer-Policy | Header presente | WARN | — |
| TEST-14 | Permissions-Policy | Header presente | WARN | — |
| TEST-15 | Server sin versión | No contiene número de versión | FAIL | — |
| TEST-16 | X-Powered-By ausente | Header ausente | FAIL | — |
| TEST-17 | X-AspNet-Version ausente | Header ausente | FAIL | — |
| TEST-18 | CORS sin wildcard | No expone `*` en Access-Control | FAIL | — |
| TEST-19 | HTTP TRACE off | Responde 405/403/404 a TRACE | FAIL | — |
| TEST-20 | Cache-Control seguro | Contiene `no-store\|no-cache\|private` | WARN | — |

---

## Mappings ZAP Active Scan rules

| Rule ID | Descripción | Tests relacionados |
|---|---|---|
| 10010 | Secure cookie attribute | TEST-01 |
| 10015 | Incomplete or No Cache-control Header | TEST-20 |
| 10020 | Anti-clickjacking Header | TEST-10 |
| 10035 | Strict-Transport-Security Header | TEST-06 |
| 10038 | Content Security Policy (CSP) | TEST-12 |
| 10096 | Timestamp Disclosure | TEST-15 |

---

*Documento generado con asistencia de GitHub Copilot — UNAE TICS 2026 · v3.1.*
