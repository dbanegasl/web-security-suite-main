# web-security-suite

Suite de pruebas de seguridad HTTP para auditoría de dominios web. Ejecuta **20 tests** organizados en 5 bloques, detectando las vulnerabilidades más comunes que afectan a scorecards de seguridad (OWASP Top 10 basics, Security Headers).

**Versión:** 3.1 · **Autor:** Daniel Banegas · **Organización:** UNAE TICS

---

## Características

- Sin dependencias externas — solo `curl`, `openssl` y `dig`/`getent` (disponibles por defecto en Ubuntu/Debian)
- **Menú interactivo** con 3 opciones: análisis individual, análisis batch automático y salida
- **Validaciones de dominio** antes de ejecutar: DNS, IP privada (advertencia), accesibilidad HTTPS y separación automática de host/path
- **Modo batch** desde archivo CSV: analiza múltiples dominios en secuencia y presenta tabla de resultados comparativa
- **Modo no interactivo** con variables de entorno: ideal para CI/CD y cron jobs
- Resultados por niveles: `PASS` / `FAIL` / `WARN` / `SKIP`
- Resolución DNS forzada por IP (útil en entornos internos o staging)
- Carpeta `reports/` incluida en la estructura (trackeada vía `.gitkeep`, contenido ignorado por git)

---

## Requisitos

- Bash ≥ 4.0
- `curl` con soporte TLS
- `openssl` (para TEST-09 — verificación de certificado SSL)
- Acceso de red al dominio desde el host donde se ejecuta

---

## Inicio rápido

```bash
# Modo interactivo — menú principal
bash web-security-scan.sh

# Modo directo — dominio + cookie de sesión identificada
DOMAIN=ssoserver.unae.edu.ec \
  SESSION_COOKIE_NAME=ssoserver_unae_session \
  bash web-security-scan.sh

# Con IP forzada (entorno interno / staging)
DOMAIN=ssoserver.unae.edu.ec \
  SESSION_COOKIE_NAME=ssoserver_unae_session \
  IP=192.168.3.203 \
  bash web-security-scan.sh

# Batch desde CSV (modo no interactivo)
bash web-security-scan.sh   # → opción [2] en el menú
```

### Variables de entorno

| Variable | Descripción |
|---|---|
| `DOMAIN` | Dominio a analizar (sin `https://`) |
| `SESSION_COOKIE_NAME` | Nombre de la cookie de sesión principal |
| `IP` | IP del servidor para forzar resolución DNS (opcional) |

---

## Resultados

| Símbolo | Significado |
|---|---|
| `✅ PASS` | Configuración correcta |
| `❌ FAIL` | Vulnerabilidad detectada — requiere corrección |
| `⚠️  WARN` | Advertencia no crítica — se recomienda revisar |
| `⏭  SKIP` | Test omitido (falta contexto o herramienta) |

**Ejemplo de salida:**

```
RESUMEN: 19 PASS  0 FAIL  1 WARN  0 SKIP  /  20 tests

⚠️  SECURITY SCAN: SIN FALLOS CRÍTICOS, 1 advertencia(s) — ssoserver.unae.edu.ec
```

---

## Tests incluidos

| Bloque | Tests | Qué detecta |
|---|---|---|
| **1 — Cookies** | TEST-01 a TEST-04 | Secure, HttpOnly, SameSite, Path |
| **2 — Transporte / TLS** | TEST-05 a TEST-09 | HTTP→HTTPS, HSTS, TLS 1.0/1.1, cert expiry |
| **3 — Cabeceras HTTP** | TEST-10 a TEST-14 | X-Frame-Options, XCTO, CSP, Referrer-Policy, Permissions-Policy |
| **4 — Fuga de información** | TEST-15 a TEST-17 | Server version, X-Powered-By, X-AspNet headers |
| **5 — Config servidor** | TEST-18 a TEST-20 | CORS wildcard, HTTP TRACE, Cache-Control |

---

## Cookie de sesión por dominio (referencia UNAE)

| Dominio | `SESSION_COOKIE_NAME` | Stack |
|---|---|---|
| `ssoserver.unae.edu.ec` | `ssoserver_unae_session` | Laravel / PHP-FPM |
| `admisiones.unae.edu.ec` | `sessionid` | Django / Python |
| `soporte.unae.edu.ec` | `sessionid` | Django / Python |
| `cas.unae.edu.ec` | `JSESSIONID` | Java / Tomcat |
| `servicios.unae.edu.ec` | `PHPSESSID` | PHP (confirmar con curl) |

> Para descubrir la cookie de un dominio nuevo:
> ```bash
> curl -sk -I https://<DOMAIN>/ | grep -i set-cookie
> ```

---

## Estructura del repositorio

```
web-security-suite/
├── README.md                      # Este archivo
├── web-security-scan.sh           # Script principal (v3.1)
├── domains.csv.example            # Plantilla de dominios para análisis batch
├── domains.csv                    # Tu lista de dominios (gitignored — copiar del .example)
├── .gitignore
├── reports/                       # Reportes generados (gitignored, carpeta trackeada)
│   └── .gitkeep
└── docs/
    ├── usage-guide.md             # Guía detallada de uso, modos, ejemplos y correcciones
    └── tests-reference.md         # Especificación técnica (PRD) de cada test con snippets bash
```

---

## Documentación

- [Guía de uso](docs/usage-guide.md) — modos de ejecución, ejemplos por dominio, interpretación de resultados, correcciones comunes, CI/CD
- [Referencia de tests](docs/tests-reference.md) — especificación técnica de los 20 tests con bash snippets individuales y criterios de aceptación

---

*Generado con asistencia de GitHub Copilot — UNAE TICS 2026.*
