# Planificación e implementación de la interfaz web

> **Estado**: Implementado y validado — Opción B completada (mayo 2026).
> Stack Docker corriendo en `localhost:8778`. Ver `web/` para el código fuente y `web/docker-compose.yml` para levantar.

## Pregunta

Evaluar si el proyecto actual, basado en `scan-cli.sh`, puede escalar a una interfaz web y ejecutarse completamente desde el navegador usando solo HTML y JavaScript.

## Respuesta corta

No, no puede ejecutarse completamente en el navegador con HTML y JavaScript puro manteniendo los 20 tests actuales.

Si puede escalar muy bien a una interfaz web, pero la arquitectura correcta seria:

- Frontend web: HTML/CSS/JavaScript para formulario, tabla de resultados, batch CSV, historial y reportes.
- Backend/API: servicio que ejecute los tests reales usando red del servidor, `curl`, `openssl`, DNS y control de metodos HTTP.
- Worker/cola: ejecucion asincrona para analisis batch o dominios lentos.
- Almacenamiento: reportes Markdown/JSON y resultados historicos.

El navegador puede ser la interfaz, pero no debe ser el motor completo de auditoria.

## Por que el navegador no alcanza

El script actual necesita capacidades que los navegadores bloquean deliberadamente:

- Leer headers restringidos como `Set-Cookie`.
- Ver atributos de cookies como `HttpOnly`, `Secure`, `SameSite` y `Path` desde respuestas de otros dominios.
- Hacer requests cross-origin arbitrarios sin permiso CORS.
- Forzar resolucion DNS con una IP equivalente a `curl --resolve`.
- Consultar DNS real como `dig` o `getent`.
- Elegir version TLS exacta, por ejemplo TLS 1.0 o TLS 1.1.
- Leer certificados TLS remotos y calcular expiracion como con `openssl s_client`.
- Enviar algunos metodos o inspeccionar respuestas con el mismo control que `curl`, por ejemplo `TRACE`.
- Ignorar certificados invalidos como `curl -k`.
- Acceder a dominios internos si el navegador del usuario no esta en esa red o si CORS lo impide.

Estas limitaciones no son accidentales. Son parte del modelo de seguridad web para impedir que cualquier pagina web se convierta en un scanner de red desde el navegador del usuario.

## Matriz de viabilidad por test

| Test | Nombre | JS puro en navegador | Motivo |
|---|---|---:|---|
| 01 | Cookie `Secure` | No | `Set-Cookie` es header prohibido para JavaScript y no se expone en `fetch`. |
| 02 | Cookie de sesion `HttpOnly` | No | `HttpOnly` existe precisamente para que JavaScript no pueda leer la cookie. |
| 03 | Cookie `SameSite` | No | Los atributos de `Set-Cookie` no son accesibles desde JS cross-origin. |
| 04 | Cookie `Path` | No | Mismo bloqueo sobre `Set-Cookie`. |
| 05 | HTTP a HTTPS redirect | Parcial | `fetch` sigue redirecciones, pero no siempre permite inspeccionar bien cadenas cross-origin; ademas depende de CORS. |
| 06 | HSTS | Parcial/No | Si CORS permite leer headers podria verse, pero normalmente no estara expuesto. |
| 07 | TLS 1.0 deshabilitado | No | El navegador no permite elegir version TLS por request. |
| 08 | TLS 1.1 deshabilitado | No | Igual que TLS-10-DISABLED. |
| 09 | Certificado SSL vigente | No | JS no puede abrir un socket TLS crudo ni leer el certificado remoto. |
| 10 | X-Frame-Options | Parcial/No | Puede inferirse con iframe en algunos casos, pero leer el header cross-origin no es confiable. |
| 11 | X-Content-Type-Options | Parcial/No | Solo seria visible si el servidor expone el header mediante CORS. |
| 12 | Content-Security-Policy | Parcial/No | Igual: depende de CORS; no es confiable para auditoria externa. |
| 13 | Referrer-Policy | Parcial/No | Puede observarse desde el documento propio, no auditar dominios arbitrarios sin CORS. |
| 14 | Permissions-Policy | Parcial/No | Lectura de header limitada por CORS. |
| 15 | Server header | Parcial/No | `Server` normalmente no es legible desde JS cross-origin. |
| 16 | X-Powered-By | Parcial/No | Depende de CORS y de `Access-Control-Expose-Headers`. |
| 17 | X-AspNet-Version | Parcial/No | Igual que INFOLEAK-X-POWERED-BY. |
| 18 | CORS wildcard | Parcial | Se puede probar desde el navegador, pero no con el mismo control ni cobertura que `curl`. |
| 19 | HTTP TRACE deshabilitado | No | Navegadores restringen metodos peligrosos o requieren CORS/preflight; no sirve como prueba confiable. |
| 20 | Cache-Control | Parcial/No | Header visible solo si CORS lo permite; para auditoria general requiere backend. |

## Que si podria hacerse en el navegador

Una version 100% frontend podria servir como herramienta educativa o de autodiagnostico limitado:

- Validar formato de dominio.
- Cargar y parsear CSV local.
- Mostrar checklist de buenas practicas.
- Generar reportes desde resultados importados.
- Ejecutar pruebas simples contra un dominio que controle CORS y exponga headers.
- Consultar APIs externas publicas si existieran, por ejemplo una API propia de escaneo.

Pero no seria equivalente al script actual. Perderia precision justo en los tests mas importantes: cookies, TLS, certificado, DNS, `TRACE` y headers cross-origin.

## Arquitectura recomendada

### Opcion A: Web app con backend propio

Esta es la opcion mas natural para escalar el proyecto.

Componentes:

- Frontend:
  - formulario de dominio, cookie de sesion e IP forzada;
  - carga de CSV;
  - tabla batch;
  - vista de detalle por test;
  - descarga de reportes Markdown/JSON.
- Backend:
  - endpoint `POST /api/scans`;
  - endpoint `GET /api/scans/:id`;
  - endpoint `GET /api/scans/:id/report`;
  - motor de escaneo que reutilice o porte la logica del Bash.
- Worker:
  - cola para ejecutar scans largos;
  - timeouts por dominio;
  - concurrencia limitada.
- Persistencia:
  - SQLite/PostgreSQL para resultados;
  - carpeta `reports/` o storage para Markdown.

Ventajas:

- Mantiene los 20 tests actuales.
- Permite UI moderna sin perder capacidades de auditoria.
- Facilita historicos, comparativas y reportes.
- Permite controlar red interna desde el servidor donde corre el scanner.

Riesgos a controlar:

- Evitar que la app se convierta en un SSRF abierto.
- Limitar dominios permitidos o exigir autenticacion.
- Rate limiting por usuario.
- Bloquear rangos internos salvo que sea una instalacion autorizada.
- Registrar auditoria de quien escaneo que dominio.

### Opcion B: Frontend + API wrapper del script Bash

Es la evolucion mas rapida.

El backend no reescribe todo. Ejecuta `scan-cli.sh` en modo no interactivo con variables de entorno:

```bash
DOMAIN=dominio.ejemplo.ec \
SESSION_COOKIE_NAME=sessionid \
IP=192.168.x.x \
bash scan-cli.sh
```

Para que esto sea robusto, convendria agregar al script un modo de salida JSON:

```bash
OUTPUT_FORMAT=json DOMAIN=example.com bash scan-cli.sh
```

Hoy el script imprime salida coloreada para terminal y genera Markdown. Para una web conviene que el contrato principal sea JSON estructurado:

```json
{
  "domain": "example.com",
  "baseUrl": "https://example.com/",
  "startedAt": "2026-05-13T00:00:00Z",
  "summary": { "pass": 12, "fail": 5, "warn": 3, "skip": 0 },
  "tests": [
    {
      "code": "COOKIE-SECURE",
      "name": "Cookie attribute: Secure",
      "result": "PASS",
      "detail": ""
    }
  ]
}
```

Ventajas:

- Menor esfuerzo inicial.
- Reutiliza comportamiento ya probado.
- Permite construir la UI primero.

Desventajas:

- Parsear salida de terminal seria fragil si no se agrega JSON.
- Ejecutar Bash desde una API requiere mucho cuidado de seguridad.
- Menos portable a Windows o entornos serverless.

### Opcion C: Reescritura del motor en Node.js, Python o Go

Es la opcion mas limpia a largo plazo si el producto crecera bastante.

Recomendacion por lenguaje:

- Node.js: buena integracion con una app web, pero TLS/certificados y DNS avanzados requieren librerias y cuidado.
- Python: excelente para scripting, `ssl`, sockets, DNS, reportes y workers.
- Go: binario unico, concurrencia fuerte y muy bueno para red/TLS.

La logica actual del Bash puede convertirse en una matriz de tests con entradas/salidas claras. Esto haria mas facil agregar:

- paralelismo controlado;
- retries;
- JSON nativo;
- tests unitarios;
- API HTTP;
- reportes HTML/PDF;
- integracion CI/CD.

## Recomendacion practica para este repositorio

La ruta mas conveniente seria por fases:

1. ✅ **Separar el motor del script en una salida estructurada.**
   - `scan.sh` — copia de `scan-cli.sh` con modo `OUTPUT_FORMAT=json`.
   - `emit_json()` emite JSON limpio a stdout; todo output de terminal suprimido con `BATCH_SILENT=1`.

2. ✅ **Crear una API pequena.**
   - `web/api/main.py` — FastAPI con endpoints `POST /api/scan` y `POST /api/batch`.
   - Validacion estricta de dominio, cookie e IP; rate limiting; subprocess sin shell=True.

3. ✅ **Construir la interfaz web.**
   - `web/frontend/` — HTML/CSS/JS vanilla, tema oscuro tipo GitHub.
   - Formulario individual, batch por CSV drag-and-drop, historial de sesion, descarga Markdown.

4. ✅ **Empaquetar con Docker.**
   - `web/docker-compose.yml` — servicios `api` (FastAPI en Debian bookworm-slim) y `frontend` (nginx:alpine).
   - nginx sirve el SPA y hace proxy reverso de `/api/` al backend — un único puerto expuesto.
   - `web/.env.example` con variables `FRONTEND_PORT`, `FRONTEND_ORIGIN`, `SCAN_TIMEOUT_SECONDS`.
   - Stack validado contra dominios: `app.ejemplo.com`, `duotics.com`, `sso.ejemplo.com`.

5. ⏳ **Endurecer seguridad.** *(pendiente)*
   - Autenticacion.
   - Lista blanca de dominios o sufijos permitidos.
   - Rate limit por usuario (actualmente es global).
   - Sanitizacion aun mas estricta de entradas.

6. ⏳ **Luego evaluar reescritura del motor.** *(pendiente)*
   - Si la herramienta se vuelve critica, portar Bash a Python/Go.
   - Si es de uso interno y controlado, el wrapper puede ser suficiente.

## Uso con Docker y contenedores

Levantar el backend o el motor reescrito dentro de contenedores Docker si deberia funcionar. Docker no es un impedimento tecnico para este proyecto; al contrario, puede ayudar a empaquetar dependencias como `curl`, `openssl`, DNS tools, workers y API.

Lo importante es entender que el scanner correra desde la red del contenedor, no desde la red directa del navegador ni necesariamente desde la red del host.

### Que funcionaria bien en Docker

- Ejecutar `curl` contra dominios publicos.
- Ejecutar `openssl s_client` para leer certificados.
- Hacer requests HTTP/HTTPS con timeouts.
- Probar TLS 1.0/TLS 1.1 si la imagen y la libreria OpenSSL/cURL lo permiten.
- Generar reportes Markdown/JSON.
- Procesar batch CSV.
- Exponer una API web para que el frontend consuma resultados.
- Separar frontend, backend, worker y base de datos en servicios distintos.

### Que dependeria de la red del contenedor

Estos puntos no dependen tanto del codigo, sino de como este definido el `docker-compose.yml`, la red Docker, DNS y las rutas disponibles:

- Acceso a dominios internos o privados.
- Resolucion DNS corporativa/institucional.
- Acceso a IPs `10.x.x.x`, `172.16.x.x` - `172.31.x.x` o `192.168.x.x`.
- Uso de una IP forzada equivalente a `curl --resolve`.
- Salida a internet desde el contenedor.
- Reglas de firewall entre contenedor, host y red institucional.
- Certificados corporativos o CA internas.

En resumen: para dominios publicos, Docker deberia funcionar casi sin friccion. Para dominios internos, dependera de que el contenedor tenga la misma visibilidad de red que la maquina desde donde hoy corres el Bash.

### Modos de red posibles

#### Red bridge por defecto

Es el modo normal de Docker Compose.

Ventajas:

- Aislado.
- Portable.
- Suficiente para escanear dominios publicos.
- Bueno para desplegar API + worker + base de datos.

Limitaciones:

- Puede no resolver DNS internos.
- Puede no alcanzar servicios accesibles solo desde la red del host.
- Puede requerir configurar DNS en Compose.

Ejemplo conceptual:

```yaml
services:
  scanner-api:
    build: .
    ports:
      - "8080:8080"
    dns:
      - "8.8.8.8"
    environment:
      SCAN_TIMEOUT_SECONDS: "30"
```

#### Network host

En Linux, `network_mode: host` hace que el contenedor use la red del host.

Ventajas:

- El contenedor ve la red casi igual que la maquina host.
- Puede facilitar acceso a DNS interno, VPN o rutas institucionales.
- Util para entornos de auditoria interna.

Limitaciones:

- Menos aislamiento.
- No funciona igual en Docker Desktop para Windows/macOS.
- Puede generar conflictos de puertos.

Ejemplo conceptual:

```yaml
services:
  scanner-api:
    build: .
    network_mode: host
```

Esta opcion seria atractiva si hoy el script Bash funciona en tu maquina porque tu maquina esta dentro de la red institucional o conectada por VPN.

#### DNS corporativo en Compose

Si el problema principal es resolucion DNS, puedes mantener bridge y declarar DNS internos:

```yaml
services:
  scanner-api:
    build: .
    dns:
      - "192.168.1.10"
      - "192.168.1.11"
```

Esto ayuda cuando el contenedor tiene ruta a la red, pero no sabe resolver nombres internos.

#### Acceso a servicios del host

Si el scanner necesita llamar algo que corre en el host, puede usarse `host.docker.internal` en Docker Desktop o configurarlo en Linux:

```yaml
services:
  scanner-api:
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

No resuelve todos los casos de red interna, pero ayuda cuando el backend necesita hablar con servicios locales.

### Cuidado con TLS 1.0 y TLS 1.1 dentro de contenedores

Un detalle importante: aunque el script actual prueba TLS 1.0 y TLS 1.1 con `curl`, algunas imagenes modernas pueden venir con OpenSSL configurado para bloquear protocolos antiguos por politica de seguridad.

Eso podria producir falsos `PASS`: no porque el servidor rechace TLS 1.0, sino porque el cliente dentro del contenedor ni siquiera intenta usarlo.

Para evitarlo:

- Elegir una imagen base donde `curl` permita probar TLS legacy.
- Documentar la version de `curl` y `openssl`.
- Agregar un self-check del motor que confirme soporte local para `--tlsv1.0` y `--tlsv1.1`.
- Si se reescribe en Python/Go/Node, validar que la libreria TLS permita configurar versiones antiguas para pruebas.

### Cuidado con certificados internos

Si escaneas sitios internos con certificados firmados por una CA institucional, el contenedor podria no confiar en esa CA.

Opciones:

- Mantener comportamiento tipo `curl -k` para auditoria de headers aunque el certificado no sea confiable.
- Instalar la CA interna dentro de la imagen.
- Reportar por separado "certificado no confiable" vs "certificado expirado".

El script actual usa `curl -k`, por lo que ignora validacion de confianza para varias pruebas. Si se reescribe el motor, hay que decidir si se conserva ese comportamiento.

### Seguridad al ejecutar scans desde una API en Docker

Si expones el scanner como servicio web, hay que tratarlo como una herramienta sensible. Un backend de escaneo puede convertirse en SSRF si cualquier usuario puede pedirle que consulte cualquier IP o dominio.

Recomendaciones:

- Autenticacion obligatoria.
- Lista blanca de dominios permitidos, por ejemplo `*.ejemplo.com`.
- Bloqueo o control explicito de rangos privados si no es una instalacion interna autorizada.
- Rate limiting.
- Timeouts estrictos.
- Limite de concurrencia.
- Logs de auditoria: usuario, dominio, fecha, IP destino y resultado.
- No ejecutar comandos con interpolacion insegura.
- Si se usa Bash, llamar el proceso con argumentos/env vars controladas, no concatenar strings de shell.

### Veredicto sobre Docker

Docker si es una buena ruta para escalar el proyecto. No bloquea el enfoque backend ni la reescritura del motor.

La condicion real es esta:

> El scanner podra auditar todo aquello que sea alcanzable desde la red del contenedor. Si el contenedor tiene DNS, rutas, firewall y certificados adecuados, funcionara. Si no los tiene, fallara aunque el codigo este correcto.

Por eso, para el `docker-compose.yml`, el punto critico sera decidir si el servicio scanner debe correr en red bridge normal, con DNS institucional configurado, o con `network_mode: host` en despliegues internos.

## Decision final

El proyecto si puede escalar completamente a una experiencia de interfaz web, pero no a una ejecucion completamente dentro del navegador.

La frase precisa seria:

> Web Security Suite puede convertirse en una aplicacion web completa, pero el navegador debe ser la capa visual. El motor de auditoria debe correr en backend o en un agente local porque los tests actuales requieren capacidades de red, TLS, DNS y lectura de headers que JavaScript del navegador no puede ni debe tener.

## Siguiente mejora sugerida

Antes de construir la UI, el paso mas valioso es agregar un modo JSON al script actual. Eso convierte el Bash en un motor consumible por una web, por CI/CD y por futuras integraciones sin romper la experiencia actual de terminal.
