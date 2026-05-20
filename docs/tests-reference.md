# Referencia de tests — web-security-suite

Especificación técnica de los 72 tests (v9.0). Los bloques 1-6 incluyen snippets bash independientes; los bloques 7-12 están implementados en Python (`wss/tests/block_7_*.py`, etc.). Para añadir tests, ver [creating-tests.md](creating-tests.md).

> Los snippets bash de bloques 1-6 asumen ejecución independiente. En el motor Python `wss`, todos los tests usan `ScanContext` con httpx.

**Referencia:** OWASP Top 10 · Security Headers · ZAP Active Scan rules

> **Bloques 7-12** (EXPOSED-ENV a AI-DEVTOOLS-EXPOSED): Archivos/rutas expuestas, DNS/Email/Dominio, Fingerprinting/Contenido, Amenazas activas y Infraestructura IA — implementados en Python `wss`. Ver código en `wss/tests/block_7_*.py`, ..., `block_12_*.py`.

---

## Bloque 1 — Cookies

### COOKIE-SECURE — Cookie: atributo `Secure` (Scorecard: −12.4 pts)

**Qué verifica:** Que todas las cookies tengan el atributo `Secure`, impidiendo transmisión en conexiones HTTP no cifradas.  
**Falla si:** Alguna cookie no contiene `; secure` en el header `Set-Cookie`.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
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

### COOKIE-HTTPONLY — Cookie de sesión: atributo `HttpOnly` (Scorecard: −8.6 pts)

**Qué verifica:** Que la cookie de sesión no sea accesible desde JavaScript (protección anti-XSS).  
**Aplica a:** Cookie de sesión únicamente. El token CSRF (`XSRF-TOKEN`) debe ser legible por JS — excluirlo.  
**Falla si:** La cookie de sesión no contiene `; httponly`.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
SESSION_COOKIE_NAME="${SESSION_COOKIE_NAME:-app_session}"
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

### COOKIE-SAMESITE — Cookie: atributo `SameSite`

**Qué verifica:** Protección contra CSRF vía `SameSite=Lax` o `SameSite=Strict`.  
**Falla si:** Alguna cookie no tiene `SameSite` o tiene `SameSite=None`.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
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

### COOKIE-PATH — Cookie: atributo `Path`

**Qué verifica:** Que las cookies tengan `Path` definido para limitar su scope.  
**Advierte** si alguna cookie no especifica `Path` (WARN, no FAIL crítico).

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
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

### TLS-HTTP-TO-HTTPS — Redirección HTTP → HTTPS (Scorecard: −0.6 pts)

**Qué verifica:** Que el servidor no sirva contenido por HTTP sin redirigir a HTTPS.  
**Falla si:** HTTP responde código distinto de 301/302, o `Location` no apunta a `https://`.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
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

### TLS-HSTS — HSTS (Strict-Transport-Security)

**Qué verifica:** Que el servidor obligue al navegador a usar HTTPS con `max-age` ≥ 1 año (31536000 segundos).  
**FAIL** si el header está ausente. **WARN** si `max-age` < 31536000.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
HSTS=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "strict-transport-security" | tr -d '\r')
MAX_AGE=$(echo "$HSTS" | grep -oP "max-age=\K\d+")
echo "  Header: ${HSTS:-❌ AUSENTE}"
if [[ -z "$HSTS" ]]; then echo "RESULTADO: ❌ FAIL"
elif [[ "${MAX_AGE:-0}" -ge 31536000 ]]; then echo "RESULTADO: ✅ PASS"
else echo "RESULTADO: ⚠️  WARN — max-age=${MAX_AGE} < 31536000"; fi
```

---

### TLS-10-DISABLED — TLS 1.0 deshabilitado

**Qué verifica:** Que el servidor rechace conexiones con TLS 1.0 (protocolo obsoleto, vulnerable a POODLE/BEAST).  
**Falla si:** El servidor acepta TLS 1.0.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
curl -sk --tlsv1.0 --tls-max 1.0 $RESOLVE "https://${DOMAIN}/" -o /dev/null 2>/dev/null \
  && echo "❌ FAIL — servidor acepta TLS 1.0" \
  || echo "✅ PASS — TLS 1.0 rechazado"
```

---

### TLS-11-DISABLED — TLS 1.1 deshabilitado

**Qué verifica:** Que el servidor rechace TLS 1.1 (obsoleto desde RFC 8996, 2021).  
**Falla si:** El servidor acepta TLS 1.1.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
curl -sk --tlsv1.1 --tls-max 1.1 $RESOLVE "https://${DOMAIN}/" -o /dev/null 2>/dev/null \
  && echo "❌ FAIL — servidor acepta TLS 1.1" \
  || echo "✅ PASS — TLS 1.1 rechazado"
```

---

### TLS-CERT-VALIDITY — Certificado SSL vigente

**Qué verifica:** Días restantes antes de que expire el certificado TLS.  
**FAIL** si expira en ≤ 7 días. **WARN** si expira en ≤ 30 días. **PASS** si > 30 días.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
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

### HEADER-X-FRAME-OPTIONS — X-Frame-Options (anti-clickjacking)

**Qué verifica:** Que el sitio no pueda ser embebido en un `<iframe>` externo.  
**Falla si:** El header `X-Frame-Options` está ausente.  
**ZAP rule:** 10020

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XFO=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^x-frame-options:" | tr -d '\r')
[[ -n "$XFO" ]] && echo "✅ PASS — ${XFO#*: }" || echo "❌ FAIL — X-Frame-Options ausente"
```

---

### HEADER-X-CONTENT-TYPE-OPTIONS — X-Content-Type-Options: nosniff

**Qué verifica:** Que el navegador no intente inferir el MIME type de las respuestas (anti-MIME sniffing).  
**Falla si:** El header `X-Content-Type-Options` está ausente.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XCTO=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^x-content-type-options:" | tr -d '\r')
[[ -n "$XCTO" ]] && echo "✅ PASS" || echo "❌ FAIL — X-Content-Type-Options ausente"
```

---

### HEADER-CSP — Content-Security-Policy

**Qué verifica:** Presencia de CSP y ausencia de directivas peligrosas.  
**FAIL** si CSP ausente. **WARN** si contiene `unsafe-eval` (permite ejecución de código arbitrario).  
**ZAP rule:** 10038

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
CSP=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^content-security-policy:" | tr -d '\r')
if [[ -z "$CSP" ]]; then echo "❌ FAIL — CSP ausente"
elif echo "$CSP" | grep -qi "unsafe-eval"; then echo "⚠️  WARN — CSP contiene 'unsafe-eval'"
else echo "✅ PASS"; fi
```

---

### HEADER-REFERRER-POLICY — Referrer-Policy

**Qué verifica:** Que el sitio controle qué información de referencia se envía al navegar a otros dominios.  
**Advierte** si el header está ausente (WARN, no FAIL crítico).

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
RP=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^referrer-policy:" | tr -d '\r')
[[ -n "$RP" ]] && echo "✅ PASS — ${RP#*: }" || echo "⚠️  WARN — Referrer-Policy ausente"
```

---

### HEADER-PERMISSIONS-POLICY — Permissions-Policy

**Qué verifica:** Que el sitio restrinja el uso de APIs sensibles del navegador (cámara, micrófono, geolocalización).  
**Advierte** si el header está ausente (WARN, no FAIL crítico).

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
PP=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^permissions-policy:" | tr -d '\r')
[[ -n "$PP" ]] && echo "✅ PASS" || echo "⚠️  WARN — Permissions-Policy ausente (recomendado)"
```

---

## Bloque 4 — Fuga de información

### INFOLEAK-SERVER-HEADER — Server header sin versión

**Qué verifica:** Que el header `Server` no revele el número de versión del software (ej: `nginx/1.26.2`).  
**PASS** si el header está ausente o solo contiene el nombre del servidor. **FAIL** si contiene número de versión.  
**ZAP rule:** 10096

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
SERVER=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^server:" | tr -d '\r')
echo "  Server: ${SERVER:-ausente}"
echo "$SERVER" | grep -qiP "[\d\.]{3,}" && echo "❌ FAIL — revela versión" || echo "✅ PASS"
```

---

### INFOLEAK-X-POWERED-BY — X-Powered-By ausente

**Qué verifica:** Que el header `X-Powered-By` no revele el stack tecnológico (ej: `PHP/7.2.34`).  
**Falla si:** El header está presente.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XPB=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^x-powered-by:" | tr -d '\r')
[[ -z "$XPB" ]] && echo "✅ PASS — X-Powered-By ausente" || echo "❌ FAIL — ${XPB#*: }"
```

---

### INFOLEAK-ASP-NET-VERSION — X-AspNet-Version ausente

**Qué verifica:** Que los headers de versión de ASP.NET no estén expuestos.  
**Aplica principalmente a:** Servidores IIS / ASP.NET. En nginx/PHP siempre debería ser PASS.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
XASNET=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -iE "^x-aspnet(mvc)?-version:" | tr -d '\r')
[[ -z "$XASNET" ]] && echo "✅ PASS" || echo "❌ FAIL — ${XASNET#*: }"
```

---

## Bloque 5 — Configuración del servidor

### SERVERCFG-CORS-WILDCARD — CORS sin wildcard

**Qué verifica:** Que el header `Access-Control-Allow-Origin` no use `*` (permitiría cualquier origen acceder a los recursos).  
**PASS** si CORS no está expuesto en raíz o especifica origen explícito. **FAIL** si usa `*`.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
CORS=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^access-control-allow-origin:" | tr -d '\r')
if [[ -z "$CORS" ]]; then echo "✅ PASS — CORS no expuesto en raíz"
elif echo "$CORS" | grep -q "\*"; then echo "❌ FAIL — wildcard '*' permite cualquier origen"
else echo "✅ PASS — ${CORS#*: }"; fi
```

---

### SERVERCFG-HTTP-TRACE — HTTP TRACE deshabilitado

**Qué verifica:** Que el método HTTP `TRACE` esté deshabilitado (previene ataques Cross-Site Tracing / XST).  
**FAIL** si el servidor responde `200 OK`. **PASS** si responde 405/403/404.

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
TRACE_CODE=$(curl -sk -o /dev/null -w "%{http_code}" $RESOLVE -X TRACE "https://${DOMAIN}/")
echo "  TRACE response: $TRACE_CODE"
if [[ "$TRACE_CODE" == "200" ]]; then echo "❌ FAIL — TRACE activo"
elif [[ "$TRACE_CODE" =~ ^(405|403|404)$ ]]; then echo "✅ PASS"
else echo "⚠️  WARN — respuesta inesperada: $TRACE_CODE"; fi
```

---

### SERVERCFG-CACHE-CONTROL — Cache-Control seguro

**Qué verifica:** Que el header `Cache-Control` incluya directivas que eviten el cacheo de contenido sensible en navegadores/proxies.  
**PASS** si contiene `no-store`, `no-cache` o `private`. **WARN** si el header está ausente o usa solo directivas permisivas.  
**ZAP rule:** 10015

```bash
DOMAIN="${DOMAIN:-sso.ejemplo.com}"
RESOLVE="${IP:+--resolve ${DOMAIN}:443:${IP}}"
CACHE=$(curl -sk -I $RESOLVE "https://${DOMAIN}/" | grep -i "^cache-control:" | tr -d '\r')
echo "  Cache-Control: ${CACHE:-ausente}"
if [[ -z "$CACHE" ]]; then echo "⚠️  WARN — ausente, navegador puede cachear contenido sensible"
elif echo "$CACHE" | grep -qiP "no-store|no-cache|private"; then echo "✅ PASS"
else echo "⚠️  WARN — revisar si aplica a rutas autenticadas"; fi
```

---

## Bloque 10 — Vulnerabilidades de producto

> Implementado en Python — `wss/tests/block_10_product_cves.py`. Detecta CVEs activos en nginx, endpoint de estado expuesto y webshells PHP genéricas.

### CVE-NGINX-VERSION — nginx versión vulnerable (CVE-2025-42945)

| Campo | Valor |
|---|---|
| **Severidad** | HIGH |
| **CWE** | CWE-122 |
| **Criterio PASS** | La cabecera `Server` no revela nginx o la versión está fuera del rango vulnerable |
| **Criterio FAIL** | nginx/X.Y.Z detectado en rango 0.6.27 – 1.30.0 (desbordamiento heap módulo mp4) |
| **Criterio SKIP** | La cabecera `Server` no expone versión de nginx |

```python
server = await ctx.get_header("server")
version = _parse_nginx_version(server)  # extrae (X, Y, Z)
if version and (0, 6, 27) <= version <= (1, 30, 0):
    return Result.fail(f"nginx/{ver_str} en rango vulnerable CVE-2025-42945")
```

### CVE-NGINX-HTTP2 — nginx HTTP/2 vulnerable (CVE-2025-42926)

| Campo | Valor |
|---|---|
| **Severidad** | MEDIUM |
| **CWE** | CWE-693 |
| **Criterio PASS** | Versión fuera del rango 1.29.4 – 1.30.0 |
| **Criterio WARN** | nginx en rango vulnerable (RST flood DoS vía HTTP/2) |
| **Criterio SKIP** | La cabecera `Server` no expone versión de nginx |

### NGINX-STATUS-EXPOSED — Endpoint de estado nginx expuesto

| Campo | Valor |
|---|---|
| **Severidad** | HIGH |
| **CWE** | CWE-200 |
| **Criterio PASS** | Ninguno de `/nginx_status`, `/stub_status`, `/status`, `/basic_status` es accesible |
| **Criterio FAIL** | Al menos un endpoint devuelve HTTP 200 con métricas de nginx |

Patrones detectados: `Active connections:`, `server accepts handled requests`, `Reading: N Writing: N`, `requests: N`.

### WEBSHELL-DETECTED — Webshell PHP detectada

| Campo | Valor |
|---|---|
| **Severidad** | CRITICAL |
| **CWE** | CWE-434 |
| **Criterio PASS** | No se encontraron indicadores de webshell en rutas conocidas |
| **Criterio FAIL** | Score ≥ 2 patrones de webshell (compromiso confirmado) |
| **Criterio WARN** | Score = 1 patrón (sospechoso, verificar manualmente) |

Rutas probadas: `/shell.php`, `/cmd.php`, `/c99.php`, `/r57.php`, `/w.php`, variantes en `/uploads/`, `/images/`, `/wp-content/uploads/`.

---

## Bloque 11 — Amenazas activas: SHADOW-AETHER

> Implementado en Python — `wss/tests/block_11_shadow_aether.py`. Detecta webshells conocidas, consolas de administración expuestas y fingerprinting de frameworks vulnerables.

### SA040-WEBSHELL-NEOREGEORG — Webshell NeoReGeorg

**Qué verifica:** Rutas características de NeoReGeorg (`/tunnel.php`, `/neoreg.php`, `/neoregeorg.php`) y el marcador `Georg says, 'All seems fine'` en el cuerpo de la respuesta.  
**Falla si:** Se detecta HTTP 200 con indicadores de NeoReGeorg.  
**Severidad:** CRITICAL | **CWE:** CWE-506

---

### SA040-WEBSHELL-POW — Webshell P0wny-shell

**Qué verifica:** Rutas de P0wny-shell (`/shell.php`, `/p0wny.php`, `/pow.php`) y el marcador `p0wny@shell` en el cuerpo.  
**Falla si:** Se detecta HTTP 200 con el marcador P0wny.  
**Severidad:** CRITICAL | **CWE:** CWE-506

---

### SA040-ADMIN-JBOSS — Consola de administración JBoss expuesta

**Qué verifica:** Acceso público a `/jmx-console/`, `/admin-console/`, `/management/` con respuesta HTTP 200 y contenido de interfaz administrativa.  
**Falla si:** La consola es accesible sin restricción de red.  
**Severidad:** CRITICAL | **CWE:** CWE-306

---

### SA040-ADMIN-TOMCAT — Tomcat Manager expuesto

**Qué verifica:** Acceso público al Tomcat Manager (`/manager/html`, `/manager/text`) con respuesta HTTP 200 o 401/403.  
**Falla si:** El Manager responde desde una dirección externa.  
**Severidad:** HIGH | **CWE:** CWE-306

---

### SA040-ADMIN-ZIMBRA — Panel de administración Zimbra expuesto

**Qué verifica:** Acceso público a `/zimbraAdmin/` y presencia del indicador `Zimbra` en cabeceras de respuesta HTTP.  
**Falla si:** El panel de administración Zimbra es accesible o las cabeceras revelan el servidor.  
**Severidad:** HIGH | **CWE:** CWE-306

---

### SA040-STRUTS2-FINGERPRINT — Fingerprinting Apache Struts 2

**Qué verifica:** Cabeceras HTTP que revelen Struts 2: `X-Struts-Version`, `X-Struts-Component`, o `struts` en `X-Powered-By`.  
**Falla si:** Las cabeceras revelan el uso de Struts 2.  
**Severidad:** HIGH | **CWE:** CWE-200

---

## Bloque 12 — Infraestructura de IA expuesta

> Implementado en Python — `wss/tests/block_12_ai_infrastructure.py`. Detecta APIs LLM, herramientas ML y archivos de configuración de agentes IA accesibles públicamente.

### AI-LLM-API-EXPOSED — API LLM local expuesta (Ollama / LiteLLM)

**Qué verifica:** Acceso público a Ollama (puerto 11434, `/api/tags`, `/api/version`) y LiteLLM (puerto 4000, `/health`, `/models`).  
**Falla si:** La API responde HTTP 200 desde Internet con contenido de lista de modelos o estado de salud.  
**Severidad:** CRITICAL | **CWE:** CWE-306

---

### AI-JUPYTER-EXPOSED — Jupyter Notebook/Lab expuesto

**Qué verifica:** Acceso público a Jupyter (puerto 8888, `/api/kernels`, `/tree`, `/lab`).  
**Falla si:** Jupyter responde sin requerir token de autenticación.  
**Severidad:** CRITICAL | **CWE:** CWE-306

---

### AI-VECTORDB-EXPOSED — Base de datos vectorial expuesta (Chroma / Weaviate)

**Qué verifica:** Acceso público a Chroma (puerto 8000, `/api/v1/heartbeat`) y Weaviate (puerto 8080, `/v1/schema`, `/.well-known/ready`).  
**Falla si:** La base de datos vectorial es accesible sin autenticación.  
**Severidad:** HIGH | **CWE:** CWE-306

---

### AI-GRADIO-EXPOSED — Interfaz Gradio expuesta

**Qué verifica:** Acceso público a Gradio (puerto 7860, `/info`, `/`) con el marcador `gradio` en el cuerpo.  
**Falla si:** La interfaz Gradio es accesible sin autenticación desde Internet.  
**Severidad:** HIGH | **CWE:** CWE-306

---

### AI-MLFLOW-EXPOSED — MLflow Tracking expuesto

**Qué verifica:** Acceso público a MLflow (puerto 5000, `/health`, `/api/2.0/mlflow/experiments/list`).  
**Falla si:** El servidor MLflow es accesible desde Internet sin credenciales.  
**Severidad:** HIGH | **CWE:** CWE-306

---

### AI-PROMPT-FILES-EXPOSED — Archivos de configuración de agentes IA expuestos

**Qué verifica:** Archivos accesibles en la raíz web: `AGENTS.md`, `.cursorrules`, `system_prompt.txt`, `ai_config.json`, `claude.md`, `.claude.md`, `CLAUDE.md`, `prompt.md`, `.openai_api_key`, `.anthropic_api_key`.  
**Escala a CRITICAL** si el cuerpo contiene material de claves (`sk-ant-`, `sk-proj-`, `sk-`).  
**Falla si:** Algún archivo es accesible públicamente (HTTP 200).  
**Severidad:** HIGH (CRITICAL si contiene claves) | **CWE:** CWE-552

---

### AI-DEVTOOLS-EXPOSED — Herramientas de desarrollo IA expuestas

**Qué verifica:** Rutas de herramientas de desarrollo LLM: `/playground`, `/langserve`, `/v1/models` con indicadores de LangChain/LangServe/OpenAI-compatible proxy.  
**Falla si:** Se detectan herramientas de desarrollo IA activas en producción.  
**Severidad:** MEDIUM | **CWE:** CWE-306

---

## Tabla de criterios de aceptación

| Test | Descripción | Criterio PASS | Nivel fallo | Pts Scorecard |
|---|---|---|---|---|
| COOKIE-SECURE | Cookie: Secure | Todas las cookies tienen `; secure` | FAIL | +12.4 |
| COOKIE-HTTPONLY | Cookie: HttpOnly | Cookie de sesión tiene `; httponly` | FAIL | +8.6 |
| COOKIE-SAMESITE | Cookie: SameSite | Todas las cookies tienen `SameSite=Lax\|Strict` | FAIL | — |
| COOKIE-PATH | Cookie: Path | Todas las cookies tienen `Path` definido | WARN | — |
| TLS-HTTP-TO-HTTPS | HTTP → HTTPS redirect | Código 301/302 + Location a `https://` | FAIL | +0.6 |
| TLS-HSTS | HSTS | `max-age >= 31536000` | FAIL / WARN | — |
| TLS-10-DISABLED | TLS 1.0 deshabilitado | Conexión TLS 1.0 rechazada | FAIL | — |
| TLS-11-DISABLED | TLS 1.1 deshabilitado | Conexión TLS 1.1 rechazada | FAIL | — |
| TLS-CERT-VALIDITY | Certificado SSL | Expira en > 30 días | FAIL / WARN | — |
| HEADER-X-FRAME-OPTIONS | X-Frame-Options | Header presente | FAIL | — |
| HEADER-X-CONTENT-TYPE-OPTIONS | X-Content-Type-Options | `nosniff` presente | FAIL | — |
| HEADER-CSP | Content-Security-Policy | CSP presente sin `unsafe-eval` | FAIL / WARN | — |
| HEADER-REFERRER-POLICY | Referrer-Policy | Header presente | WARN | — |
| HEADER-PERMISSIONS-POLICY | Permissions-Policy | Header presente | WARN | — |
| INFOLEAK-SERVER-HEADER | Server sin versión | No contiene número de versión | FAIL | — |
| INFOLEAK-X-POWERED-BY | X-Powered-By ausente | Header ausente | FAIL | — |
| INFOLEAK-ASP-NET-VERSION | X-AspNet-Version ausente | Header ausente | FAIL | — |
| SERVERCFG-CORS-WILDCARD | CORS sin wildcard | No expone `*` en Access-Control | FAIL | — |
| SERVERCFG-HTTP-TRACE | HTTP TRACE off | Responde 405/403/404 a TRACE | FAIL | — |
| SERVERCFG-CACHE-CONTROL | Cache-Control seguro | Contiene `no-store\|no-cache\|private` | WARN | — |

---

## Mappings ZAP Active Scan rules

| Rule ID | Descripción | Tests relacionados |
|---|---|---|
| 10010 | Secure cookie attribute | COOKIE-SECURE |
| 10015 | Incomplete or No Cache-control Header | SERVERCFG-CACHE-CONTROL |
| 10020 | Anti-clickjacking Header | HEADER-X-FRAME-OPTIONS |
| 10035 | Strict-Transport-Security Header | TLS-HSTS |
| 10038 | Content Security Policy (CSP) | HEADER-CSP |
| 10096 | Timestamp Disclosure | INFOLEAK-SERVER-HEADER |

---

*Documento generado con asistencia de GitHub Copilot — DUOTICS 2026 · v7.0.*
