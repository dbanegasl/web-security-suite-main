"""descriptions.py — Descripciones HTML canónicas de los 55 tests de seguridad.

Este módulo es la única fuente de verdad para las descripciones de los tests.
``sync_test_catalog()`` lo usa al arrancar para rellenar automáticamente cualquier
descripción vacía en la base de datos SQLite.

Al añadir un test nuevo, añade su entrada en el dict ``DESCRIPTIONS`` con la
misma clave que el ID del test (ej: ``"56"``).  Ver docs/creating-tests.md.
"""
from __future__ import annotations

# ─── helpers de construcción HTML ────────────────────────────────────────────


def _esc(s: str) -> str:
    """HTML-escapa caracteres especiales para uso dentro de <pre>."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def tabs(tid: str, panels: list) -> str:
    """Genera HTML Bootstrap 5 con tabs nativos.

    panels = [(label, code_str), ...]  — code_str se HTML-escapa automáticamente.
    """
    nav = ""
    content = ""
    for i, (label, code) in enumerate(panels):
        slug = (
            label.lower()
            .replace(".", "")
            .replace("/", "")
            .replace(" ", "")
            .replace("(", "")
            .replace(")", "")[:8]
        )
        pid = f"d{tid}-{slug}"
        active_cls = " active" if i == 0 else ""
        nav += (
            f'<li class="nav-item">'
            f'<button class="nav-link py-1 px-2{active_cls}" data-tab-target="#{pid}" '
            f"type=\"button\">{label}</button></li>"
        )
        content += (
            f'<div class="tab-pane{active_cls}" id="{pid}">'
            f'<pre class="mb-0 small">{_esc(code)}</pre></div>'
        )
    return (
        f'<ul class="nav nav-tabs mb-0">{nav}</ul>'
        f'<div class="tab-content border border-top-0 rounded-bottom p-2 mb-2 small">{content}</div>'
    )


def desc(what: str, why: str, results: list, rem: str) -> str:
    """Construye el bloque HTML estándar de descripción de un test.

    results = [(status, text), ...]  donde status es PASS|FAIL|WARN|SKIP|INFO
    """
    BADGE = {
        "PASS": "bg-success",
        "FAIL": "bg-danger",
        "WARN": "bg-warning text-dark",
        "SKIP": "bg-secondary",
        "INFO": "bg-info text-dark",
    }
    H = '<div class="wiki-sect-head">%s</div>'
    html = f'{H % "¿Qué verifica?"}<p class="small mb-2">{what}</p>'
    if why:
        html += f'{H % "¿Por qué importa?"}<p class="small mb-2">{why}</p>'
    if results:
        rows = ""
        for status, text in results:
            color = BADGE.get(status, "bg-secondary")
            rows += f'<div class="mb-1 small"><span class="badge {color} me-1">{status}</span>{text}</div>'
        html += f'{H % "Resultados posibles"}<div class="mb-2">{rows}</div>'
    html += f'{H % "Remediación"}{rem}'
    return html


# ─── Descripciones de los 55 tests ───────────────────────────────────────────
# Clave = ID del test (mismo valor que el primer argumento de @test).
# Valor = HTML generado por desc() o cadena HTML directa.

DESCRIPTIONS: dict[str, str] = {

    # ══════════════ BLOQUE 1 — COOKIES ══════════════

    "01": desc(
        "Que todas las cookies en la respuesta HTTP tengan el atributo <code>Secure</code>, "
        "que obliga al navegador a enviarlas solo por HTTPS.",
        "Sin <code>Secure</code>, un atacante en la misma red (Wi-Fi pública, MITM) puede capturar "
        "cookies en claro mediante SSL stripping y suplantar la sesión.",
        [("PASS", "Todas las cookies tienen <code>Secure</code>"),
         ("FAIL", "Al menos una cookie carece de <code>Secure</code>")],
        tabs("01", [
            ("Nginx", "proxy_cookie_flags ~ secure samesite=lax;\n# O bien:\nproxy_cookie_path / \"/; Secure; SameSite=Lax\";"),
            ("Apache", 'Header always edit Set-Cookie ^(.*)$ "$1; Secure"'),
            ("Tomcat", "<session-config>\n  <cookie-config>\n    <secure>true</secure>\n  </cookie-config>\n</session-config>"),
            ("PHP", "session.cookie_secure = 1\n# O en código:\nsession_set_cookie_params(['secure' => true]);"),
            ("Node.js", "app.use(session({\n  cookie: { secure: true, httpOnly: true, sameSite: 'lax' }\n}));"),
        ]),
    ),

    "02": desc(
        "Que la cookie de sesión principal tenga el atributo <code>HttpOnly</code>, "
        "impidiendo su lectura desde JavaScript (<code>document.cookie</code>).",
        "Defensa principal contra XSS: aunque un atacante inyecte JavaScript, no puede robar "
        "la cookie de sesión si <code>HttpOnly</code> está presente.",
        [("PASS", "Cookie tiene <code>HttpOnly</code>"),
         ("FAIL", "Cookie carece de <code>HttpOnly</code>"),
         ("SKIP", "No se encontró cookie de sesión en la raíz")],
        tabs("02", [
            ("Nginx", "proxy_cookie_flags ~ secure httponly samesite=lax;"),
            ("Apache", 'Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure"'),
            ("PHP", "session.cookie_httponly = 1\nsession.cookie_secure = 1"),
            ("Node.js", "cookie: { httpOnly: true, secure: true, sameSite: 'lax' }"),
            ("Moodle", "$CFG->cookiehttponly = true;\n$CFG->cookiesecure = true;"),
        ]),
    ),

    "03": desc(
        "Que las cookies tengan <code>SameSite=Lax</code> o <code>SameSite=Strict</code>, "
        "que controla cuándo se envían en peticiones cross-site.",
        "Protege contra CSRF: <code>SameSite=Strict</code> bloquea cookies en peticiones "
        "cross-site; <code>Lax</code> solo las permite en navegación top-level.",
        [("PASS", "Cookies con <code>SameSite=Lax</code> o <code>Strict</code>"),
         ("FAIL", "Cookies con <code>SameSite=None</code> o sin atributo")],
        tabs("03", [
            ("Nginx", "proxy_cookie_flags ~ secure httponly samesite=lax;"),
            ("Apache", 'Header always edit Set-Cookie ^(.*)$ "$1; SameSite=Lax"'),
            ("PHP", 'session.cookie_samesite = "Lax"  # PHP 7.3+'),
            ("Node.js", "cookie: { sameSite: 'lax' }"),
        ]),
    ),

    "04": desc(
        "Que las cookies tengan el atributo <code>Path</code> definido, limitando a qué rutas "
        "del dominio se envía la cookie.",
        "Sin <code>Path</code>, la cookie se envía en cualquier ruta del dominio, incluyendo "
        "sub-aplicaciones que no deberían tener acceso a ella.",
        [("PASS", "Cookies tienen <code>Path</code> definido"),
         ("FAIL", "Cookies sin atributo <code>Path</code>")],
        tabs("04", [
            ("Apache", 'Header always edit Set-Cookie ^(.*)$ "$1; Path=/app; SameSite=Lax"'),
            ("PHP", 'session.cookie_path = "/app"'),
        ]),
    ),

    # ══════════════ BLOQUE 2 — TRANSPORTE ══════════════

    "05": desc(
        "Que una petición HTTP al puerto 80 reciba un redirect 301/302 hacia la URL HTTPS equivalente.",
        "Sin redirect, los usuarios que accedan por HTTP navegan en claro. Con SSL stripping, "
        "un atacante puede interceptar todas las comunicaciones aunque el sitio soporte HTTPS.",
        [("PASS", "Redirect 301/302 → HTTPS"),
         ("FAIL", "Sin redirect o servidor responde en claro por HTTP")],
        tabs("05", [
            ("Nginx", "server {\n  listen 80;\n  server_name ejemplo.com;\n  return 301 https://$host$request_uri;\n}"),
            ("Apache", "Redirect permanent / https://ejemplo.com/\n# O con mod_rewrite:\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"),
            ("Tomcat", "<user-data-constraint>\n  <transport-guarantee>CONFIDENTIAL</transport-guarantee>\n</user-data-constraint>"),
            ("IIS", '<action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />'),
        ]),
    ),

    "06": desc(
        "Que la respuesta incluya <code>Strict-Transport-Security</code> con "
        "<code>max-age ≥ 31536000</code> (1 año).",
        "HSTS obliga al navegador a usar HTTPS siempre, eliminando la ventana de ataque "
        "SSL stripping incluso si el usuario escribe HTTP manualmente.",
        [("PASS", "HSTS con max-age ≥ 31536000"),
         ("WARN", "HSTS con max-age &lt; 31536000"),
         ("FAIL", "Header ausente")],
        tabs("06", [
            ("Nginx", 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'),
            ("Apache", 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'),
            ("Tomcat", "<param-name>hstsEnabled</param-name><param-value>true</param-value>\n<param-name>hstsMaxAgeSeconds</param-name><param-value>31536000</param-value>"),
            ("IIS", '<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />'),
        ]),
    ),

    "07": desc(
        "Que el servidor rechace conexiones TLS 1.0. Si acepta TLS 1.0, el test falla.",
        "TLS 1.0 (1999) tiene vulnerabilidades conocidas como <strong>POODLE</strong> y "
        "<strong>BEAST</strong> que permiten descifrar tráfico. PCI-DSS exige su "
        "deshabilitación desde 2018.",
        [("PASS", "Servidor rechaza TLS 1.0"),
         ("FAIL", "Servidor acepta TLS 1.0")],
        tabs("07", [
            ("Nginx", "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;"),
            ("Apache", "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\nSSLHonorCipherOrder off"),
            ("Tomcat", '<SSLHostConfig protocols="TLSv1.2+TLSv1.3">\n  <Certificate certificateKeystoreFile="..." />\n</SSLHostConfig>'),
        ]),
    ),

    "08": desc(
        "Que el servidor rechace conexiones TLS 1.1, deprecado por la IETF en 2021 (RFC 8996).",
        "Misma problemática que TLS 1.0. Deshabilitar ambos en el mismo bloque, "
        "dejando solo TLS 1.2 y TLS 1.3.",
        [("PASS", "Servidor rechaza TLS 1.1"),
         ("FAIL", "Servidor acepta TLS 1.1")],
        tabs("08", [
            ("Nginx", "ssl_protocols TLSv1.2 TLSv1.3;"),
            ("Apache", "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"),
        ]),
    ),

    "09": desc(
        "La fecha de expiración del certificado SSL/TLS X.509. Calcula los días restantes "
        "y clasifica según umbrales de 30 y 7 días.",
        "Un certificado expirado provoca errores en el navegador e impide el acceso. "
        "La renovación debe hacerse antes de la expiración para evitar interrupciones.",
        [("PASS", "Vigente &gt; 30 días"),
         ("WARN", "Expira en ≤ 30 días — renovar pronto"),
         ("FAIL", "Expira en ≤ 7 días — CRÍTICO"),
         ("SKIP", "No se pudo leer el certificado")],
        tabs("09", [
            ("Certbot", "sudo certbot renew --dry-run   # Prueba sin aplicar\nsudo certbot renew             # Renovación real\nsudo certbot certificates      # Ver estado"),
            ("OpenSSL", "echo | openssl s_client -connect ejemplo.com:443 2>/dev/null \\\n  | openssl x509 -noout -dates"),
            ("Cron", "0 8 * * 1 root certbot renew --quiet --deploy-hook 'nginx -s reload'"),
        ]),
    ),

    # ══════════════ BLOQUE 3 — CABECERAS HTTP ══════════════

    "10": desc(
        "Que la respuesta incluya <code>X-Frame-Options</code>. Controla si la página puede "
        "mostrarse dentro de un <code>&lt;iframe&gt;</code>.",
        "Sin este header, un atacante puede embeber la app en un iframe invisible y usar "
        "<strong>clickjacking</strong> para engañar al usuario para que haga clic en acciones "
        "no deseadas (cambiar contraseña, confirmar pagos).",
        [("PASS", "Header con DENY o SAMEORIGIN"),
         ("FAIL", "Header ausente")],
        tabs("10", [
            ("Nginx", 'add_header X-Frame-Options "SAMEORIGIN" always;'),
            ("Apache", 'Header always set X-Frame-Options "SAMEORIGIN"'),
            ("Tomcat", "<param-name>antiClickJackingEnabled</param-name>\n<param-value>true</param-value>"),
            ("Node.js", "app.use(helmet.frameguard({ action: 'sameorigin' }));"),
            ("IIS", '<add name="X-Frame-Options" value="SAMEORIGIN" />'),
        ]),
    ),

    "11": desc(
        "Que la respuesta incluya <code>X-Content-Type-Options: nosniff</code>, impidiendo "
        "que el navegador adivine el tipo MIME de un recurso ignorando el <code>Content-Type</code>.",
        "Sin este header, un atacante que logre subir un archivo malicioso (HTML disfrazado de "
        "imagen) puede hacer que el navegador lo ejecute como HTML/script, causando XSS.",
        [("PASS", "Header con valor <code>nosniff</code>"),
         ("FAIL", "Header ausente o con valor incorrecto")],
        tabs("11", [
            ("Nginx", 'add_header X-Content-Type-Options "nosniff" always;'),
            ("Apache", 'Header always set X-Content-Type-Options "nosniff"'),
            ("Node.js", "app.use(helmet.noSniff());"),
        ]),
    ),

    "12": desc(
        "Que la respuesta incluya <code>Content-Security-Policy</code>. También detecta si "
        "contiene <code>unsafe-eval</code> que debilita la política.",
        "CSP es la defensa más potente contra XSS: define desde qué orígenes puede cargar el "
        "navegador scripts, estilos e imágenes, bloqueando scripts inyectados.",
        [("PASS", "CSP presente sin <code>unsafe-eval</code>"),
         ("WARN", "CSP presente pero contiene <code>unsafe-eval</code>"),
         ("FAIL", "Header ausente")],
        tabs("12", [
            ("Nginx", "add_header Content-Security-Policy \\\n  \"default-src 'self'; script-src 'self' 'unsafe-inline'; \\\n   style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\" always;"),
            ("Apache", "Header always set Content-Security-Policy \\\n  \"default-src 'self'; script-src 'self' 'unsafe-inline';\""),
            ("Moodle", "$CFG->additionalhtmlhead = '<meta http-equiv=\"Content-Security-Policy\"\n  content=\"default-src \\'self\\';\">'; "),
            ("Node.js", "app.use(helmet.contentSecurityPolicy({\n  directives: { defaultSrc: [\"'self'\"] }\n}));"),
            ("Report-Only", "add_header Content-Security-Policy-Report-Only \\\n  \"default-src 'self'; report-uri /csp-endpoint;\" always;"),
        ]),
    ),

    "13": desc(
        "Que la respuesta incluya <code>Referrer-Policy</code>, controlando qué información "
        "del <code>Referer</code> se envía al navegar a otros sitios.",
        "Sin este header, al hacer clic en un enlace externo se envía la URL completa en "
        "<code>Referer</code>, pudiendo filtrar tokens, IDs de sesión o rutas internas a terceros.",
        [("PASS", "Header presente"),
         ("FAIL", "Header ausente")],
        tabs("13", [
            ("Nginx", 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'),
            ("Apache", 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'),
        ]),
    ),

    "14": desc(
        "Que la respuesta incluya <code>Permissions-Policy</code>, controlando qué APIs "
        "del navegador (cámara, micrófono, geolocalización) puede usar la página.",
        "Sin este header, iframes de terceros o scripts embebidos pueden solicitar acceso "
        "a hardware sensible sin restricción explícita.",
        [("PASS", "Header presente"),
         ("FAIL", "Header ausente")],
        tabs("14", [
            ("Nginx", 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;'),
            ("Apache", 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"'),
        ]),
    ),

    # ══════════════ BLOQUE 4 — FUGA DE INFORMACIÓN ══════════════

    "15": desc(
        "Si el header <code>Server</code> contiene un número de versión "
        "(ej: <code>nginx/1.18.0</code>). Si lo contiene, el test falla.",
        "Revelar la versión exacta del servidor facilita a atacantes identificar versiones "
        "vulnerables y usar exploits conocidos sin fingerprinting adicional.",
        [("PASS", "Header sin versión (ej: <code>nginx</code>)"),
         ("FAIL", "Header con versión expuesta")],
        tabs("15", [
            ("Nginx", "server_tokens off;"),
            ("Apache", "ServerTokens Prod\nServerSignature Off"),
            ("Tomcat", '<Connector port="8080" server="Apache" />\n# O usar HttpHeaderSecurityFilter'),
        ]),
    ),

    "16": desc(
        "Que no exista el header <code>X-Powered-By</code>, enviado automáticamente "
        "por PHP, Express y otros frameworks.",
        "Este header revela el stack tecnológico (ej: <code>PHP/8.1.2</code>), "
        "permitiendo a atacantes buscar exploits específicos.",
        [("PASS", "Header ausente"),
         ("FAIL", "Header presente")],
        tabs("16", [
            ("Nginx", "proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;"),
            ("PHP", "expose_php = Off"),
            ("Node.js", "app.disable('x-powered-by');\n// O con Helmet:\napp.use(helmet.hidePoweredBy());"),
            ("Apache", "Header always unset X-Powered-By"),
        ]),
    ),

    "17": desc(
        "Que no existan los headers <code>X-AspNet-Version</code> o "
        "<code>X-AspNetMvc-Version</code>, emitidos automáticamente por ASP.NET.",
        "Revelan la versión exacta del framework .NET, facilitando ataques "
        "dirigidos a vulnerabilidades de esa versión específica.",
        [("PASS", "Headers ausentes"),
         ("FAIL", "Al menos un header de versión ASP.NET presente")],
        tabs("17", [
            ("web.config", "<httpRuntime enableVersionHeader=\"false\" />\n\n<customHeaders>\n  <remove name=\"X-Powered-By\" />\n  <remove name=\"X-AspNet-Version\" />\n</customHeaders>"),
            ("C# .NET 6+", 'app.Use(async (context, next) => {\n    context.Response.Headers.Remove("X-AspNet-Version");\n    await next();\n});'),
        ]),
    ),

    # ══════════════ BLOQUE 5 — CONFIGURACIÓN ══════════════

    "18": desc(
        "El valor del header <code>Access-Control-Allow-Origin</code>. "
        "Si es <code>*</code> (wildcard), el test falla.",
        "Con <code>ACAO: *</code>, cualquier sitio externo puede hacer peticiones AJAX y leer "
        "la respuesta, incluyendo datos del usuario autenticado.",
        [("PASS", "ACAO con origen específico o ausente"),
         ("FAIL", "ACAO con valor <code>*</code>")],
        tabs("18", [
            ("Nginx", 'add_header Access-Control-Allow-Origin "https://app.miempresa.com" always;\n\n# Para múltiples orígenes:\nmap $http_origin $cors_origin {\n    "https://app.miempresa.com" $http_origin;\n    default "";\n}\nadd_header Access-Control-Allow-Origin $cors_origin always;'),
            ("Apache", "SetEnvIf Origin \"^https://app\\.miempresa\\.com$\" ORIGIN=$0\nHeader always set Access-Control-Allow-Origin \"%{ORIGIN}e\" env=ORIGIN"),
            ("Node.js", "app.use(cors({\n  origin: ['https://app.miempresa.com'],\n  credentials: true\n}));"),
        ]),
    ),

    "19": desc(
        "Que el servidor rechace peticiones con el método <code>TRACE</code>. "
        "Si responde con HTTP 200, el test falla.",
        "TRACE habilita XST (Cross-Site Tracing): scripts maliciosos pueden leer headers "
        "sensibles incluyendo cookies HttpOnly en algunos navegadores antiguos.",
        [("PASS", "Servidor rechaza TRACE (405/403)"),
         ("FAIL", "Servidor responde 200 a TRACE")],
        tabs("19", [
            ("Nginx", "if ($request_method = TRACE) {\n    return 405;\n}"),
            ("Apache", "TraceEnable off"),
            ("Tomcat", "<http-method>TRACE</http-method>\n# En security-constraint con auth-constraint vacío"),
        ]),
    ),

    "20": desc(
        "Que el header <code>Cache-Control</code> esté presente con directivas como "
        "<code>no-store</code>, <code>no-cache</code> o <code>private</code>.",
        "Sin directivas adecuadas, el navegador puede cachear páginas con datos sensibles "
        "accesibles desde el historial en equipos compartidos.",
        [("PASS", "Cache-Control con directivas de no-caché"),
         ("FAIL", "Header ausente o con caché permisiva")],
        tabs("20", [
            ("Nginx", 'location /app/ {\n  add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;\n}\n# Para recursos estáticos:\nlocation ~* \\.(js|css|png)$ {\n  add_header Cache-Control "public, max-age=31536000, immutable";\n}'),
            ("Apache", 'Header always set Cache-Control "no-store, no-cache, must-revalidate, private"'),
            ("PHP", 'header("Cache-Control: no-store, no-cache, must-revalidate, private");\nheader("Pragma: no-cache");'),
            ("Node.js", "res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');"),
        ]),
    ),

    # ══════════════ BLOQUE 6 — HEADERS AVANZADOS ══════════════

    "21": desc(
        "Que <code>X-XSS-Protection</code> y <code>Expect-CT</code> "
        "<strong>no</strong> estén presentes. Ambos están deprecados.",
        "<code>X-XSS-Protection</code> ya no tiene soporte en navegadores modernos y "
        "puede ser explotado. <code>Expect-CT</code> fue deprecado en favor de CT "
        "integrada en TLS.",
        [("PASS", "Headers deprecados ausentes"),
         ("FAIL", "Al menos un header deprecado presente")],
        tabs("21", [
            ("Nginx", "more_clear_headers X-XSS-Protection;\nmore_clear_headers Expect-CT;"),
            ("Apache", "Header unset X-XSS-Protection\nHeader unset Expect-CT"),
            ("PHP", "header_remove('X-XSS-Protection');\nheader_remove('Expect-CT');"),
        ]),
    ),

    "22": desc(
        "Que la respuesta incluya <code>Cross-Origin-Opener-Policy</code> (COOP), que "
        "controla si el documento puede compartir un contexto de navegación cross-origin.",
        "Previene ataques de tipo Spectre y manipulación de ventanas cross-origin. "
        "Requerido para habilitar <code>SharedArrayBuffer</code> de forma segura.",
        [("PASS", "COOP con valor <code>same-origin</code>"),
         ("FAIL", "Header ausente")],
        tabs("22", [
            ("Nginx", 'add_header Cross-Origin-Opener-Policy "same-origin" always;'),
            ("Apache", 'Header always set Cross-Origin-Opener-Policy "same-origin"'),
            ("PHP", "header('Cross-Origin-Opener-Policy: same-origin');"),
        ]),
    ),

    "23": desc(
        "Que la respuesta incluya <code>Cross-Origin-Embedder-Policy</code> (COEP), que "
        "impide cargar recursos cross-origin sin permiso explícito.",
        "Requerido junto con COOP para habilitar APIs de alto rendimiento como "
        "<code>SharedArrayBuffer</code>. Aísla el contexto de ejecución del documento.",
        [("PASS", "COEP con <code>require-corp</code>"),
         ("FAIL", "Header ausente")],
        tabs("23", [
            ("Nginx", 'add_header Cross-Origin-Embedder-Policy "require-corp" always;'),
            ("Apache", 'Header always set Cross-Origin-Embedder-Policy "require-corp"'),
            ("PHP", "header('Cross-Origin-Embedder-Policy: require-corp');"),
        ]),
    ),

    "24": desc(
        "Que la respuesta incluya <code>Cross-Origin-Resource-Policy</code> (CORP), "
        "especificando qué orígenes pueden cargar los recursos del servidor.",
        "Sin CORP, cualquier sitio puede incluir tus recursos mediante "
        "<code>&lt;img&gt;</code> o <code>&lt;script&gt;</code>, exponiéndolos a "
        "lecturas cross-origin.",
        [("PASS", "CORP con <code>same-origin</code> o <code>same-site</code>"),
         ("FAIL", "Header ausente")],
        tabs("24", [
            ("Nginx", 'add_header Cross-Origin-Resource-Policy "same-origin" always;'),
            ("Apache", 'Header always set Cross-Origin-Resource-Policy "same-origin"'),
            ("PHP", "header('Cross-Origin-Resource-Policy: same-origin');"),
        ]),
    ),

    "25": desc(
        "Que la respuesta incluya <code>X-Permitted-Cross-Domain-Policies: none</code>, "
        "bloqueando políticas crossdomain para Flash/PDF.",
        "Sin este header, aplicaciones Flash o PDF pueden leer recursos del dominio. "
        "Aunque Flash está obsoleto, PDFs interactivos y aplicaciones heredadas aún pueden "
        "aprovecharlo.",
        [("PASS", "Header con valor <code>none</code>"),
         ("FAIL", "Header ausente o con valor permisivo")],
        tabs("25", [
            ("Nginx", 'add_header X-Permitted-Cross-Domain-Policies "none" always;'),
            ("Apache", 'Header always set X-Permitted-Cross-Domain-Policies "none"'),
            ("PHP", "header('X-Permitted-Cross-Domain-Policies: none');"),
        ]),
    ),

    # ══════════════ BLOQUE 7 — ARCHIVOS Y RUTAS EXPUESTAS ══════════════

    "26": desc(
        "Que el archivo <code>.env</code> no sea accesible públicamente vía HTTP. "
        "Respuesta 200 a <code>/.env</code> o <code>/.env.local</code> indica exposición.",
        "Los archivos <code>.env</code> contienen credenciales de base de datos, claves API, "
        "tokens de servicios externos y secretos de aplicación. Su exposición es crítica.",
        [("PASS", "/.env devuelve 403/404"),
         ("FAIL", "/.env accesible (200)")],
        tabs("26", [
            ("Nginx", "location ~ /\\.env {\n  deny all;\n  return 404;\n}\n# O bloquear todos los dotfiles:\nlocation ~ /\\. {\n  deny all;\n}"),
            ("Apache", "<Files \".env\">\n  Require all denied\n</Files>\n# O regex:\nRedirectMatch 404 /\\.env(\\..*)?$"),
        ]),
    ),

    "27": desc(
        "Que el directorio <code>.git</code> no sea accesible públicamente. "
        "Respuesta 200 a <code>/.git/config</code> indica que el repositorio está expuesto.",
        "Un repositorio <code>.git</code> expuesto permite reconstruir el código fuente "
        "completo, incluyendo commits pasados con credenciales que fueron eliminadas.",
        [("PASS", "/.git/config devuelve 403/404"),
         ("FAIL", "Repositorio git accesible")],
        tabs("27", [
            ("Nginx", "location ~ /\\.git {\n  deny all;\n  return 404;\n}"),
            ("Apache", "<DirectoryMatch \"/\\.git\">\n  Require all denied\n</DirectoryMatch>"),
        ]),
    ),

    "28": desc(
        "Que los directorios <code>.svn</code> y <code>.hg</code> no sean accesibles "
        "públicamente.",
        "Un repositorio SVN o Mercurial expuesto permite reconstruir el código fuente. "
        "SVN incluye el historial completo en <code>.svn/wc.db</code>.",
        [("PASS", "Directorios .svn/.hg devuelven 403/404"),
         ("FAIL", "Al menos un repositorio VCS accesible")],
        tabs("28", [
            ("Nginx", "location ~ /\\.(svn|hg|bzr) {\n  deny all;\n}"),
            ("Apache", "<DirectoryMatch \"/(svn|hg)$\">\n  Require all denied\n</DirectoryMatch>"),
        ]),
    ),

    "29": desc(
        "Que no haya volcados SQL (<code>.sql</code>) accesibles en rutas comunes "
        "como <code>/backup.sql</code>, <code>/dump.sql</code>, <code>/database.sql</code>.",
        "Un volcado SQL expuesto contiene toda la base de datos: usuarios, hashes de "
        "contraseñas, datos personales. Implica una brecha crítica de datos.",
        [("PASS", "Ningún volcado SQL accesible"),
         ("FAIL", "Al menos un volcado SQL encontrado (200)")],
        tabs("29", [
            ("Nginx", "location ~* \\.(sql|sql\\.gz|sql\\.zip)$ {\n  deny all;\n  return 404;\n}"),
            ("Apache", "<FilesMatch \"\\.(sql|bak|dump)$\">\n  Require all denied\n</FilesMatch>"),
            ("Prevención", "# Nunca almacenar backups en el DocumentRoot.\n# Usar /var/backups/ fuera del webroot.\n# Permisos: chmod 600 /var/backups/*.sql"),
        ]),
    ),

    "30": desc(
        "Que no haya archivos de backup (<code>.bak</code>, <code>.old</code>, "
        "<code>.backup</code>, <code>~</code>) accesibles en rutas del servidor.",
        "Archivos de backup contienen versiones anteriores del código fuente y "
        "configuraciones, pudiendo exponer credenciales que ya fueron eliminadas.",
        [("PASS", "Ningún archivo de backup accesible"),
         ("FAIL", "Al menos un archivo de backup encontrado")],
        tabs("30", [
            ("Nginx", "location ~* \\.(bak|old|backup|orig|swp|tmp)$ {\n  deny all;\n}"),
            ("Apache", "<FilesMatch \"\\.(bak|old|backup|orig|~)$\">\n  Require all denied\n</FilesMatch>"),
        ]),
    ),

    "31": desc(
        "Que <code>phpinfo()</code> no esté expuesto en rutas comunes como "
        "<code>/phpinfo.php</code>, <code>/info.php</code>, <code>/test.php</code>.",
        "<code>phpinfo()</code> revela la configuración completa del servidor PHP: versión, "
        "módulos cargados, variables de entorno, rutas del sistema y valores de php.ini.",
        [("PASS", "Ninguna página phpinfo accesible"),
         ("FAIL", "phpinfo() accesible (200)")],
        tabs("31", [
            ("Eliminar", "# Eliminar en producción:\nrm /var/www/html/phpinfo.php\nrm /var/www/html/info.php"),
            ("Nginx (bloqueo)", "location ~* /(phpinfo|info|php_info|test)\\.php$ {\n  deny all;\n}"),
        ]),
    ),

    "32": desc(
        "Que exista el archivo <code>/.well-known/security.txt</code> (RFC 9116), "
        "que define el canal de reporte de vulnerabilidades.",
        "Sin <code>security.txt</code>, los investigadores de seguridad no saben cómo "
        "reportar vulnerabilidades responsablemente. Facilita el disclosure coordinado.",
        [("PASS", "security.txt presente y accesible"),
         ("FAIL", "security.txt ausente o no accesible")],
        '<p class="small">Crea <code>/.well-known/security.txt</code>:</p>'
        '<pre class="small p-2 rounded border">Contact: mailto:security@miempresa.com\n'
        'Expires: 2027-01-01T00:00:00.000Z\n'
        'Preferred-Languages: es, en\n'
        'Policy: https://miempresa.com/security-policy</pre>'
        '<p class="small mt-1">Generador: <a href="https://securitytxt.org" target="_blank">securitytxt.org</a></p>',
    ),

    "33": desc(
        "Que las páginas de estado del servidor (<code>/server-status</code>, "
        "<code>/nginx_status</code>) no sean accesibles públicamente.",
        "Estas páginas revelan métricas internas: peticiones activas, IPs de clientes, "
        "workers e IDs de transacción. Facilita el reconocimiento del atacante.",
        [("PASS", "Páginas de estado devuelven 403/404"),
         ("FAIL", "Al menos una página de estado accesible")],
        tabs("33", [
            ("Nginx", "location /nginx_status {\n  stub_status on;\n  allow 127.0.0.1;\n  deny all;\n}"),
            ("Apache", "<Location /server-status>\n  Require local\n</Location>"),
        ]),
    ),

    "34": desc(
        "Que los paneles de administración (<code>/admin</code>, <code>/wp-admin</code>, "
        "<code>/phpmyadmin</code>) estén protegidos y no devuelvan 200 sin autenticación.",
        "Paneles de administración accesibles son objetivo de ataques de fuerza bruta y "
        "explotación de vulnerabilidades del panel (RCE en versiones desactualizadas).",
        [("PASS", "Panel devuelve 401/403 o redirige a login"),
         ("FAIL", "Panel accesible sin autenticación (200)")],
        tabs("34", [
            ("Nginx (IP)", "location /admin {\n  allow 192.168.1.0/24;\n  deny all;\n}"),
            ("HTTP Auth", "location /admin {\n  auth_basic \"Admin Area\";\n  auth_basic_user_file /etc/nginx/.htpasswd;\n}"),
            ("Apache", "<Location /admin>\n  Require ip 192.168.1.0/24\n</Location>"),
        ]),
    ),

    "35": desc(
        "Que archivos de configuración sensibles (<code>web.config</code>, "
        "<code>config.php</code>, <code>settings.py</code>, <code>application.yml</code>) "
        "no sean accesibles.",
        "Archivos de configuración suelen contener credenciales de base de datos, claves "
        "secretas y conexiones a servicios externos.",
        [("PASS", "Archivos de configuración devuelven 403/404"),
         ("FAIL", "Al menos un archivo de configuración accesible")],
        tabs("35", [
            ("Nginx", "location ~* /(config|settings|application|database)\\.(php|py|yml|yaml|xml|json)$ {\n  deny all;\n}"),
            ("Apache", "<FilesMatch \"(web\\.config|config\\.php|settings\\.py|application\\.yml)$\">\n  Require all denied\n</FilesMatch>"),
        ]),
    ),

    "36": desc(
        "Que manifiestos de dependencias (<code>package.json</code>, <code>composer.json</code>, "
        "<code>requirements.txt</code>) no sean accesibles públicamente.",
        "Estos archivos revelan todas las dependencias y sus versiones, permitiendo a "
        "atacantes identificar paquetes vulnerables sin necesidad de escanear.",
        [("PASS", "Manifiestos devuelven 403/404"),
         ("FAIL", "Al menos un manifiesto accesible")],
        tabs("36", [
            ("Nginx", "location ~* /(package|composer|requirements|Gemfile)(\\.(json|lock|txt))?$ {\n  deny all;\n}"),
            ("Apache", "<FilesMatch \"(package\\.json|composer\\.json|requirements\\.txt)$\">\n  Require all denied\n</FilesMatch>"),
        ]),
    ),

    "37": desc(
        "Que <code>/crossdomain.xml</code> no tenga un wildcard "
        "<code>&lt;allow-access-from domain=\"*\"&gt;</code>.",
        "Un <code>crossdomain.xml</code> con wildcard permite a aplicaciones Flash de "
        "cualquier dominio leer datos autenticados (CSRF equivalente para Flash).",
        [("PASS", "Ausente o sin wildcard"),
         ("FAIL", "crossdomain.xml con <code>domain=\"*\"</code>")],
        '<p class="small">Si Flash no es necesario, devuelve 404. Si es necesario:</p>'
        '<pre class="small p-2 rounded border">&lt;cross-domain-policy&gt;\n'
        '  &lt;site-control permitted-cross-domain-policies="none" /&gt;\n'
        '&lt;/cross-domain-policy&gt;</pre>',
    ),

    "38": desc(
        "Que la documentación de API (Swagger/OpenAPI, <code>/api/docs</code>, "
        "<code>/swagger-ui.html</code>) no sea accesible públicamente.",
        "La documentación de API expuesta revela todos los endpoints, parámetros y modelos "
        "de datos, facilitando enormemente el reconocimiento del atacante.",
        [("PASS", "Documentación devuelve 403/404 o requiere autenticación"),
         ("FAIL", "Documentación API accesible sin autenticación")],
        tabs("38", [
            ("Nginx (IP)", "location ~* /(swagger|api-docs|openapi|redoc) {\n  allow 10.0.0.0/8;\n  deny all;\n}"),
            ("FastAPI", "# En producción, deshabilitar docs:\napp = FastAPI(docs_url=None, redoc_url=None)"),
            ("Spring Boot", "# application.properties:\nspringdoc.swagger-ui.enabled=false"),
        ]),
    ),

    "39": desc(
        "Que los endpoints de Spring Boot Actuator (<code>/actuator</code>, "
        "<code>/actuator/env</code>) no sean accesibles sin autenticación.",
        "Actuator expone métricas, variables de entorno, beans Spring, heap dumps y "
        "puede permitir cambiar la configuración en tiempo real.",
        [("PASS", "Actuator devuelve 403/404"),
         ("FAIL", "Al menos un endpoint Actuator accesible")],
        tabs("39", [
            ("application.properties", "management.endpoints.web.exposure.include=health\nmanagement.endpoint.health.show-details=never\nmanagement.server.port=8081  # Puerto separado"),
            ("Nginx (bloqueo)", "location /actuator {\n  deny all;\n}"),
        ]),
    ),

    "40": desc(
        "Que el archivo <code>/.DS_Store</code> no sea accesible. "
        "Este archivo lo genera macOS automáticamente al acceder a directorios.",
        "Un <code>.DS_Store</code> accesible revela nombres de archivos y carpetas "
        "que existen en el servidor, incluyendo archivos sensibles.",
        [("PASS", "/.DS_Store devuelve 403/404"),
         ("FAIL", "/.DS_Store accesible")],
        tabs("40", [
            ("Nginx", "location ~ /\\.DS_Store {\n  deny all;\n  return 404;\n}"),
            ("Apache", "<Files \".DS_Store\">\n  Require all denied\n</Files>"),
            (".gitignore", "echo '.DS_Store' >> .gitignore\ngit rm --cached .DS_Store 2>/dev/null || true"),
        ]),
    ),

    # ══════════════ BLOQUE 8 — DNS, EMAIL Y DOMINIO ══════════════

    "41": desc(
        "Que el registro SPF (Sender Policy Framework) del dominio esté correctamente "
        "configurado con un mecanismo <code>-all</code> o <code>~all</code>.",
        "Sin SPF, cualquier servidor puede enviar emails suplantando tu dominio. "
        "SPF define qué servidores están autorizados a enviar en nombre del dominio.",
        [("PASS", "SPF válido con <code>-all</code> o <code>~all</code>"),
         ("WARN", "SPF con <code>+all</code> (muy permisivo)"),
         ("FAIL", "Sin registro SPF"),
         ("SKIP", "No se pudo resolver DNS")],
        '<pre class="small p-2 rounded border"># Registro TXT en DNS:\ndominio.com. TXT "v=spf1 include:_spf.google.com ip4:203.0.113.10 -all"\n'
        '# -all = rechazar todo lo no autorizado (recomendado)\n# ~all = softfail (modo transición)</pre>',
    ),

    "42": desc(
        "Que el registro DMARC del dominio esté presente con política "
        "<code>quarantine</code> o <code>reject</code>.",
        "DMARC instruye a los receptores qué hacer con emails que no superen SPF/DKIM. "
        "Sin DMARC, los emails falsos se entregan aunque SPF/DKIM estén configurados.",
        [("PASS", "DMARC con <code>p=quarantine</code> o <code>p=reject</code>"),
         ("WARN", "DMARC con <code>p=none</code>"),
         ("FAIL", "Sin registro DMARC"),
         ("SKIP", "No se pudo resolver DNS")],
        '<pre class="small p-2 rounded border"># Registro TXT en DNS:\n_dmarc.dominio.com. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@dominio.com; pct=100"\n'
        '# Evolución: p=none (monitoreo) → p=quarantine → p=reject</pre>',
    ),

    "43": desc(
        "Que el dominio tenga al menos un selector DKIM activo, verificando registros "
        "TXT comunes (<code>default._domainkey</code>, <code>mail._domainkey</code>).",
        "DKIM firma criptográficamente los emails, permitiendo a los receptores verificar "
        "que no han sido alterados en tránsito.",
        [("PASS", "Al menos un selector DKIM activo"),
         ("FAIL", "Ningún selector DKIM encontrado"),
         ("SKIP", "No se pudo resolver DNS")],
        '<pre class="small p-2 rounded border"># Verificar selector DKIM:\ndig TXT default._domainkey.dominio.com\n# Resultado esperado:\n# v=DKIM1; k=rsa; p=MIIBIjANBg...</pre>',
    ),

    "44": desc(
        "Que el dominio tenga un registro CAA (Certification Authority Authorization), "
        "limitando qué CAs pueden emitir certificados.",
        "Sin CAA, cualquier CA del mundo puede emitir un certificado para tu dominio. "
        "Un registro CAA previene la emisión no autorizada incluso si una CA es comprometida.",
        [("PASS", "Registro CAA presente"),
         ("FAIL", "Sin registro CAA")],
        '<pre class="small p-2 rounded border"># Registros CAA en DNS:\ndominio.com. CAA 0 issue "letsencrypt.org"\ndominio.com. CAA 0 issue "digicert.com"\ndominio.com. CAA 0 iodef "mailto:security@dominio.com"</pre>',
    ),

    "45": desc(
        "Que el dominio tenga DNSSEC habilitado, verificando la presencia de registros "
        "RRSIG en la respuesta DNS.",
        "DNSSEC firma criptográficamente las respuestas DNS, previniendo ataques de "
        "envenenamiento de caché (DNS spoofing) que redirigen a servidores maliciosos.",
        [("PASS", "DNSSEC habilitado (RRSIG presente)"),
         ("FAIL", "DNSSEC no habilitado"),
         ("SKIP", "No se pudo resolver DNS")],
        '<p class="small">DNSSEC se activa en el registrador del dominio. Consulta la '
        'documentación de tu proveedor DNS (Cloudflare, Route53, GoDaddy) para activarlo. '
        'Verificación: <code>dig +dnssec A dominio.com</code></p>',
    ),

    "46": desc(
        "Que ningún subdominio del dominio apunte a un servicio externo que ya no existe "
        "(subdomain takeover).",
        "Si un registro CNAME apunta a un servicio dado de baja (Heroku, GitHub Pages, "
        "S3 bucket eliminado), un atacante puede reclamar ese servicio y controlar "
        "el subdominio.",
        [("PASS", "Sin subdominios con CNAME huérfano"),
         ("FAIL", "Potencial subdomain takeover detectado"),
         ("SKIP", "No se pudo verificar")],
        '<p class="small">Audita todos los registros CNAME y elimina los que apunten a '
        'servicios dados de baja. Herramientas: '
        '<code>subjack</code>, <code>subzy</code>, <code>nuclei -t takeovers/</code></p>',
    ),

    "47": desc(
        "Que los puertos de bases de datos comunes (3306 MySQL, 5432 PostgreSQL, "
        "27017 MongoDB, 6379 Redis, 1433 MSSQL) no estén accesibles desde Internet.",
        "Una base de datos expuesta puede ser accedida directamente por atacantes con "
        "credenciales válidas o explotada mediante vulnerabilidades del motor de BD.",
        [("PASS", "Todos los puertos de DB cerrados/filtrados"),
         ("FAIL", "Al menos un puerto de BD accesible desde Internet")],
        tabs("47", [
            ("iptables", "iptables -A INPUT -p tcp --dport 3306 -s 0.0.0.0/0 -j DROP\niptables -A INPUT -p tcp --dport 5432 -s 0.0.0.0/0 -j DROP\niptables -A INPUT -p tcp --dport 27017 -s 0.0.0.0/0 -j DROP"),
            ("UFW", "ufw deny 3306\nufw deny 5432\nufw deny 27017\nufw deny 6379\nufw deny 1433"),
            ("AWS SG / bind", "# MySQL (bind a localhost):\nbind-address = 127.0.0.1\n\n# MongoDB:\nnet:\n  bindIp: 127.0.0.1"),
        ]),
    ),

    # ══════════════ BLOQUE 9 — FINGERPRINTING Y CONTENIDO ══════════════

    "48": desc(
        "Que Django no esté en modo <code>DEBUG=True</code> en producción. Se detecta "
        "por la página de error 404 característica de Django.",
        "Django en modo debug expone: tracebacks con variables locales, lista de todas "
        "las URLs de la aplicación, configuración del proyecto y código fuente en cada error.",
        [("PASS", "Sin página de debug de Django"),
         ("FAIL", "Django DEBUG=True detectado"),
         ("SKIP", "Sin respuesta HTTP")],
        '<pre class="small p-2 rounded border"># settings.py — producción:\nDEBUG = False\nALLOWED_HOSTS = [\'midominio.com\']\n\n# Con variable de entorno:\nDEBUG = os.environ.get(\'DJANGO_DEBUG\', \'False\') == \'True\'</pre>',
    ),

    "49": desc(
        "Que Laravel no esté en modo debug en producción. Se detecta por el stacktrace "
        "de Whoops/Ignition característico de Laravel.",
        "Laravel en modo debug expone el stacktrace completo, variables de entorno "
        "(incluyendo DB_PASSWORD, APP_KEY), rutas y código fuente del framework.",
        [("PASS", "Sin página de debug Laravel"),
         ("FAIL", "Laravel debug mode detectado"),
         ("SKIP", "Sin respuesta HTTP")],
        '<pre class="small p-2 rounded border"># .env — producción:\nAPP_ENV=production\nAPP_DEBUG=false\n\n# config/app.php:\n\'debug\' => env(\'APP_DEBUG\', false),</pre>',
    ),

    "50": desc(
        "Que los endpoints de Spring Boot Actuator (<code>/actuator</code>, "
        "<code>/actuator/env</code>, <code>/actuator/beans</code>) devuelvan 403/404.",
        "Actuator expone información interna del servidor Java: beans Spring, variables "
        "de entorno, propiedades, métricas y puede permitir reiniciar la aplicación.",
        [("PASS", "Actuator devuelve 403/404/401"),
         ("FAIL", "Actuator accesible sin autenticación")],
        '<pre class="small p-2 rounded border"># application.properties\nmanagement.endpoints.web.exposure.include=health\nmanagement.endpoint.health.show-details=never\n# Puerto separado (no exponer en 8080):\nmanagement.server.port=8081</pre>',
    ),

    "51": desc(
        "Que la etiqueta <code>&lt;meta name=\"generator\"&gt;</code> no revele el "
        "nombre y versión del CMS (WordPress, Joomla, Drupal, etc.).",
        "Revelar la versión exacta del CMS permite a atacantes buscar exploits y CVEs "
        "conocidos para esa versión sin necesidad de fingerprinting adicional.",
        [("PASS", "Sin meta generator con versión"),
         ("WARN", "Meta generator con nombre de CMS pero sin versión"),
         ("SKIP", "Sin respuesta HTTP")],
        tabs("51", [
            ("WordPress", "// En functions.php del tema:\nremove_action('wp_head', 'wp_generator');"),
            ("Joomla", "# Configuración → Sistema → Metadatos del sitio → vaciar campo 'Meta Keywords'"),
            ("Drupal", "// En hook_page_attachments_alter() para eliminar metatag generator"),
            ("Nginx (fallback)", "proxy_hide_header X-Generator;\nproxy_hide_header X-Drupal-Cache;"),
        ]),
    ),

    "52": desc(
        "Que los comentarios HTML de la página no contengan datos sensibles: "
        "contraseñas, TODOs con credenciales, rutas internas, IPs o tokens.",
        "Los comentarios HTML son visibles en el código fuente para cualquier usuario. "
        "Credenciales dejadas en comentarios de desarrollo es un error frecuente.",
        [("PASS", "Sin comentarios con datos sensibles"),
         ("WARN", "Comentarios con información técnica potencialmente sensible"),
         ("SKIP", "Sin respuesta HTTP")],
        '<p class="small">Revisar el código fuente y eliminar comentarios de desarrollo. '
        'Detectar antes del commit:</p>'
        '<pre class="small p-2 rounded border">grep -r "password\\|passwd\\|TODO.*cred\\|<!--.*key" \\\n  --include="*.html" ./templates/</pre>',
    ),

    "53": desc(
        "Que la página HTTPS no cargue recursos (imágenes, scripts, estilos) por HTTP. "
        "El contenido mixto debilita la seguridad de HTTPS.",
        "Recursos HTTP en una página HTTPS permiten ataques MITM sobre esos recursos. "
        "Scripts HTTP pueden ejecutar código malicioso tras ser interceptados.",
        [("PASS", "Todos los recursos cargados por HTTPS"),
         ("WARN", "Recursos por HTTP detectados (contenido mixto)")],
        tabs("53", [
            ("CSP upgrade", 'add_header Content-Security-Policy "upgrade-insecure-requests;" always;'),
            ("HTML (meta)", '<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">'),
            ("Auditoría", "# Chrome DevTools → Security tab\n# O: lighthouse --only-categories=best-practices URL"),
        ]),
    ),

    "54": desc(
        "Que los formularios HTML tengan el atributo <code>action</code> con URL HTTPS "
        "o relativa (nunca URL HTTP explícita).",
        "Un formulario con <code>action=\"http://\"</code> envía datos en claro por HTTP, "
        "incluso si la página se sirvió por HTTPS, exponiendo contraseñas y datos sensibles.",
        [("PASS", "Formularios con action HTTPS o relativo"),
         ("FAIL", "Al menos un formulario con action HTTP explícito")],
        '<pre class="small p-2 rounded border">&lt;!-- MAL: --&gt;\n'
        '&lt;form action="http://ejemplo.com/login"&gt;\n\n'
        '&lt;!-- BIEN: --&gt;\n'
        '&lt;form action="/login"&gt;  &lt;!-- relativo --&gt;\n'
        '&lt;form action="https://ejemplo.com/login"&gt;</pre>',
    ),

    "55": desc(
        "Que los campos <code>&lt;input type=\"password\"&gt;</code> no se sirvan en "
        "páginas HTTP sin redirección a HTTPS.",
        "Servir formularios de contraseña por HTTP permite que las credenciales sean "
        "capturadas en claro por cualquier atacante en la red. Aplica aunque el "
        "<code>action</code> sea HTTPS.",
        [("PASS", "Campos de contraseña servidos solo por HTTPS"),
         ("FAIL", "Campos de contraseña detectados en página HTTP"),
         ("SKIP", "Sin respuesta HTTP o sin campos de contraseña")],
        tabs("55", [
            ("Nginx", "server {\n  listen 80;\n  return 301 https://$host$request_uri;\n}"),
            ("Apache", "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"),
            ("HSTS", 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'),
        ]),
    ),
}
