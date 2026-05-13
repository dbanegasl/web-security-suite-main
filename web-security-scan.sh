#!/usr/bin/env bash
# ============================================================
# UNAE Web Security Suite — v3.0
# Autor: Daniel Banegas
# Uso interactivo: bash web-security-scan.sh
# Uso directo:     DOMAIN=cas.unae.edu.ec bash web-security-scan.sh
# ============================================================

_ENV_DOMAIN="${DOMAIN:-}"
_ENV_SESSION="${SESSION_COOKIE_NAME:-}"
_ENV_IP="${IP:-}"

# ── Batch globals ─────────────────────────────────────────────
declare -A BATCH_RESULTS
declare -a BATCH_DOMAINS_LIST
BATCH_CURRENT_DOMAIN=""
BATCH_SILENT=0

# ── Scan report globals ──────────────────────────────────────
declare -A SCAN_DATA   # [ID]="RESULT|DESC|DETAIL"
declare -a SCAN_ORDER  # IDs en orden de ejecución
SCAN_DOMAIN=""; SCAN_DATE=""

# ── Colores ──────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'; MAGENTA='\033[0;35m'

run_test() {
  local ID="$1" DESC="$2" RESULT="$3" DETAIL="${4:-}"
  [[ -n "$BATCH_CURRENT_DOMAIN" ]] && BATCH_RESULTS["${BATCH_CURRENT_DOMAIN}:${ID}"]="$RESULT"
  [[ -z "$BATCH_CURRENT_DOMAIN" ]] && SCAN_DATA["$ID"]="${RESULT}|${DESC}|${DETAIL}" && SCAN_ORDER+=("$ID")
  case "$RESULT" in
    PASS) ((++PASS)) ;; FAIL) ((++FAIL)) ;; WARN) ((++WARN)) ;; SKIP) ((++SKIP)) ;;
  esac
  [[ "$BATCH_SILENT" == "1" ]] && return
  local SUFFIX="${DETAIL:+  → $DETAIL}"
  case "$RESULT" in
    PASS) echo -e "  [${GREEN}✅ PASS${RESET}] TEST-$ID — $DESC${SUFFIX}" ;;
    FAIL) echo -e "  [${RED}❌ FAIL${RESET}] TEST-$ID — $DESC${SUFFIX}" ;;
    WARN) echo -e "  [${YELLOW}⚠️  WARN${RESET}] TEST-$ID — $DESC${SUFFIX}" ;;
    SKIP) echo -e "  [${MAGENTA}⏭  SKIP${RESET}] TEST-$ID — $DESC${SUFFIX}" ;;
  esac
}

section() { [[ "$BATCH_SILENT" != "1" ]] && echo -e "\n${BOLD}${CYAN}▸ $1${RESET}"; }

# ── Header ───────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║                                                        ║"
echo "  ║   🔐  Web Security Scanner  v3.1                      ║"
echo "  ║   HTTP headers · TLS · Cookies · Info disclosure      ║"
echo "  ║                                                        ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ════════════════════════════════════════════════════════════════════
# FUNCIÓN: batch_print_table — imprime la tabla de resultados
# ════════════════════════════════════════════════════════════════════
batch_print_table() {
  local DOMAINS=("${BATCH_DOMAINS_LIST[@]}")
  [[ ${#DOMAINS[@]} -eq 0 ]] && return

  local TESTS=(01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20)

  # Calcular ancho máximo del campo dominio
  local MAX_W=30
  for d in "${DOMAINS[@]}"; do [[ ${#d} -gt $MAX_W ]] && MAX_W=${#d}; done
  (( MAX_W += 2 ))

  echo -e "\n${BOLD}${CYAN}▸ TABLA DE RESULTADOS — ANÁLISIS AUTOMATIZADO${RESET}\n"

  # Cabecera de columnas
  printf "  ${BOLD}%-${MAX_W}s" "DOMINIO"
  for t in "${TESTS[@]}"; do printf " %2s" "$t"; done
  printf "  %4s %4s %4s${RESET}\n" " OK" " FL" " WN"

  # Línea separadora
  printf "  %s" "$(printf '─%.0s' $(seq 1 $MAX_W))"
  for t in "${TESTS[@]}"; do printf "───"; done
  printf "──────────────\n"

  # Filas de datos
  for d in "${DOMAINS[@]}"; do
    local STATUS="${BATCH_RESULTS["${d}:STATUS"]:-?}"
    printf "  %-${MAX_W}s" "$d"
    if [[ "$STATUS" == "DNS_FAIL" ]]; then
      printf " ${RED}%-$(( ${#TESTS[@]} * 3 + 13 ))s${RESET}\n" "DNS no resuelve"
      continue
    elif [[ "$STATUS" == "NO_RESP" ]]; then
      printf " ${RED}%-$(( ${#TESTS[@]} * 3 + 13 ))s${RESET}\n" "Servidor no responde"
      continue
    fi
    local p=0 f=0 w=0
    for t in "${TESTS[@]}"; do
      local R="${BATCH_RESULTS["${d}:${t}"]:-?}"
      case "$R" in
        PASS) printf " ${GREEN} P${RESET}"; ((p++)) ;;
        FAIL) printf " ${RED} F${RESET}"; ((f++)) ;;
        WARN) printf " ${YELLOW} W${RESET}"; ((w++)) ;;
        SKIP) printf " ${MAGENTA} S${RESET}" ;;
        *)    printf "  ${BOLD}?${RESET}" ;;
      esac
    done
    printf "  ${GREEN}%4d${RESET} ${RED}%4d${RESET} ${YELLOW}%4d${RESET}\n" "$p" "$f" "$w"
  done

  printf "  %s" "$(printf '─%.0s' $(seq 1 $MAX_W))"
  for t in "${TESTS[@]}"; do printf "───"; done
  printf "──────────────\n"
  echo -e "\n  ${BOLD}Leyenda:${RESET}  ${GREEN}P${RESET}=PASS  ${RED}F${RESET}=FAIL  ${YELLOW}W${RESET}=WARN  ${MAGENTA}S${RESET}=SKIP\n"
}

# ════════════════════════════════════════════════════════════════════
# FUNCIÓN: batch_run — ejecuta el análisis sobre un archivo CSV
# Formato CSV: dominio,cookie_sesion,ip_forzada  (las 2 últimas opcionales)
# ════════════════════════════════════════════════════════════════════
batch_run() {
  local CSV_FILE="$1"
  BATCH_DOMAINS_LIST=()

  if [[ ! -f "$CSV_FILE" ]]; then
    echo -e "${RED}❌ Archivo no encontrado: ${CSV_FILE}${RESET}"
    return 1
  fi

  echo -e "${CYAN}  Cargando dominios desde: ${BOLD}${CSV_FILE}${RESET}\n"

  local _dom _cookie _ip _rest
  while IFS=',' read -r _dom _cookie _ip _rest || [[ -n "$_dom" ]]; do
    # Eliminar espacios y saltos de línea
    _dom="${_dom//[[:space:]]/}"
    _cookie="${_cookie//[[:space:]]/}"
    _ip="${_ip//[[:space:]]/}"
    # Ignorar vacíos y comentarios
    [[ -z "$_dom" || "$_dom" == \#* ]] && continue

    BATCH_DOMAINS_LIST+=("$_dom")
    printf "  [%2d] %-40s " "${#BATCH_DOMAINS_LIST[@]}" "$_dom"

    # ── Preparar variables ──────────────────────────────────
    PASS=0; FAIL=0; SKIP=0; WARN=0
    BATCH_CURRENT_DOMAIN="$_dom"
    BATCH_SILENT=1

    DOMAIN="${_dom#https://}"; DOMAIN="${DOMAIN#http://}"
    HOST="${DOMAIN%%/*}"
    _RAWPATH="${DOMAIN#$HOST}"
    BASE_PATH="${_RAWPATH:-/}"
    [[ "${BASE_PATH:0:1}" != "/" ]] && BASE_PATH="/${BASE_PATH}"
    DOMAIN="$HOST"
    BASE_URL="https://${DOMAIN}${BASE_PATH}"
    SESSION_COOKIE_NAME="$_cookie"
    IP="$_ip"

    # ── Validación DNS silenciosa ───────────────────────────
    DNS_RESULT=$(dig +short "$DOMAIN" 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+$' | tail -1)
    [[ -z "$DNS_RESULT" ]] && DNS_RESULT=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | grep -oP '^\d+\.\d+\.\d+\.\d+$' | tail -1)
    if [[ -z "$DNS_RESULT" ]]; then
      echo -e "${RED}DNS no resuelve${RESET}"
      BATCH_RESULTS["${_dom}:STATUS"]="DNS_FAIL"
      BATCH_CURRENT_DOMAIN=""; BATCH_SILENT=0; continue
    fi

    # ── Validación servidor silenciosa ──────────────────────
    HTTP_CHECK=$(curl --max-time 5 -sk -o /dev/null -w "%{http_code}" "$BASE_URL" 2>/dev/null)
    if [[ "$HTTP_CHECK" == "000" || -z "$HTTP_CHECK" ]]; then
      echo -e "${RED}no responde${RESET}"
      BATCH_RESULTS["${_dom}:STATUS"]="NO_RESP"
      BATCH_CURRENT_DOMAIN=""; BATCH_SILENT=0; continue
    fi

    RESOLVE_443="${IP:+--resolve ${DOMAIN}:443:${IP}}"
    RESOLVE_80="${IP:+--resolve ${DOMAIN}:80:${IP}}"
    RESPONSE=$(curl --max-time 8 --connect-timeout 4 -sk -I $RESOLVE_443 "$BASE_URL")
    COOKIES=$(echo "$RESPONSE" | grep -i "^set-cookie")

    # Auto-detectar cookie si no está definida
    if [[ -z "$SESSION_COOKIE_NAME" ]]; then
      SESSION_COOKIE_NAME=$(echo "$COOKIES" | grep -oP "set-cookie:\s*\K[^=]+" | head -1)
    fi

    BATCH_RESULTS["${_dom}:STATUS"]="OK"
    run_tests

    echo -e "${GREEN}OK${RESET}  (${GREEN}${PASS}P${RESET} ${RED}${FAIL}F${RESET} ${YELLOW}${WARN}W${RESET} ${MAGENTA}${SKIP}S${RESET})"
    BATCH_CURRENT_DOMAIN=""; BATCH_SILENT=0

  done < "$CSV_FILE"

  echo ""
  batch_print_table
  export_wizard "batch"
}

# ════════════════════════════════════════════════════════════════════
# FUNCIÓN: generate_report_individual — genera reporte Markdown individual
# ════════════════════════════════════════════════════════════════════
generate_report_individual() {
  local OUTFILE="$1"
  local TOTAL=$(( PASS + FAIL + WARN + SKIP ))
  {
    echo "# Reporte de Seguridad Web — ${SCAN_DOMAIN}"
    echo ""
    echo "| Campo | Valor |"
    echo "|-------|-------|"
    echo "| **Fecha** | ${SCAN_DATE} |"
    echo "| **URL base** | https://${SCAN_DOMAIN}${BASE_PATH} |"
    [[ -n "$IP" ]] && echo "| **IP forzada** | ${IP} |"
    echo ""
    echo "---"
    echo ""
    echo "## Resumen"
    echo ""
    echo "| Resultado | Cantidad |"
    echo "|-----------|:--------:|"
    echo "| ✅ PASS   | ${PASS} |"
    echo "| ❌ FAIL   | ${FAIL} |"
    echo "| ⚠️  WARN  | ${WARN} |"
    echo "| ⏭  SKIP  | ${SKIP} |"
    echo "| **Total** | **${TOTAL}** |"
    echo ""
    if   [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
      echo "**Estado general:** 🟢 EXCELENTE — sin fallos ni advertencias"
    elif [[ $FAIL -eq 0 ]]; then
      echo "**Estado general:** 🟡 ACEPTABLE — sin fallos críticos, ${WARN} advertencia(s)"
    elif [[ $FAIL -le 2 ]]; then
      echo "**Estado general:** 🟠 MEJORABLE — ${FAIL} fallo(s) a corregir"
    else
      echo "**Estado general:** 🔴 CRÍTICO — ${FAIL} fallos detectados"
    fi
    echo ""
    echo "---"
    echo ""
    echo "## Detalle de tests"
    echo ""
    echo "| Test | Descripción | Resultado | Detalle |"
    echo "|:----:|-------------|:---------:|---------|"
    for id in "${SCAN_ORDER[@]}"; do
      local RAW="${SCAN_DATA[$id]}"
      local RES="${RAW%%|*}"; RAW="${RAW#*|}"
      local DSC="${RAW%%|*}"; RAW="${RAW#*|}"
      local DTL="${RAW}"
      local ICON
      case "$RES" in
        PASS) ICON="✅ PASS" ;;
        FAIL) ICON="❌ FAIL" ;;
        WARN) ICON="⚠️  WARN" ;;
        SKIP) ICON="⏭  SKIP" ;;
        *)    ICON="?" ;;
      esac
      echo "| ${id} | ${DSC} | ${ICON} | ${DTL:--} |"
    done
    echo ""
    echo "---"
    echo ""
    # Hallazgos críticos
    local HAS_FAIL=0
    for id in "${SCAN_ORDER[@]}"; do [[ "${SCAN_DATA[$id]%%|*}" == "FAIL" ]] && HAS_FAIL=1 && break; done
    if [[ $HAS_FAIL -eq 1 ]]; then
      echo "## ❌ Hallazgos críticos (FAIL)"
      echo ""
      for id in "${SCAN_ORDER[@]}"; do
        local RAW="${SCAN_DATA[$id]}"
        local RES="${RAW%%|*}"; RAW="${RAW#*|}"
        local DSC="${RAW%%|*}"; RAW="${RAW#*|}"
        local DTL="${RAW}"
        [[ "$RES" == "FAIL" ]] && echo "- **TEST-${id} — ${DSC}**${DTL:+: ${DTL}}"
      done
      echo ""
    fi
    # Advertencias
    local HAS_WARN=0
    for id in "${SCAN_ORDER[@]}"; do [[ "${SCAN_DATA[$id]%%|*}" == "WARN" ]] && HAS_WARN=1 && break; done
    if [[ $HAS_WARN -eq 1 ]]; then
      echo "## ⚠️  Advertencias (WARN)"
      echo ""
      for id in "${SCAN_ORDER[@]}"; do
        local RAW="${SCAN_DATA[$id]}"
        local RES="${RAW%%|*}"; RAW="${RAW#*|}"
        local DSC="${RAW%%|*}"; RAW="${RAW#*|}"
        local DTL="${RAW}"
        [[ "$RES" == "WARN" ]] && echo "- **TEST-${id} — ${DSC}**${DTL:+: ${DTL}}"
      done
      echo ""
    fi
    echo "---"
    echo ""
    echo "## Referencia de tests"
    echo ""
    echo "| ID | Nombre | Bloque | Riesgo si falla |"
    echo "|----|--------|--------|-----------------|"
    echo "| 01 | Cookie flag: **Secure** | Cookies | Medio — cookie enviada por HTTP |"
    echo "| 02 | Cookie flag: **HttpOnly** | Cookies | **Alto** — robo de sesión via XSS |"
    echo "| 03 | Cookie flag: **SameSite** | Cookies | Medio — CSRF cross-site |"
    echo "| 04 | Cookie attribute: **Path** | Cookies | Bajo — scope de cookie sin restringir |"
    echo "| 05 | **HTTP → HTTPS** redirect 301/302 | Transporte | Medio — tráfico en claro posible |"
    echo "| 06 | **HSTS** Strict-Transport-Security | Transporte | **Alto** — SSL stripping attack |"
    echo "| 07 | **TLS 1.0** deshabilitado | Transporte | **Alto** — protocolo roto (POODLE) |"
    echo "| 08 | **TLS 1.1** deshabilitado | Transporte | Medio — protocolo obsoleto |"
    echo "| 09 | Certificado SSL **vigente** | Transporte | Crítico — conexión insegura si expira |"
    echo "| 10 | **X-Frame-Options** (anti-clickjacking) | Cabeceras | **Alto** — iframes maliciosos |"
    echo "| 11 | **X-Content-Type-Options**: nosniff | Cabeceras | Medio — MIME confusion attack |"
    echo "| 12 | **Content-Security-Policy** (CSP) | Cabeceras | **Alto** — XSS sin restricción de scripts |"
    echo "| 13 | **Referrer-Policy** | Cabeceras | Bajo — fuga de URLs a terceros |"
    echo "| 14 | **Permissions-Policy** | Cabeceras | Bajo — acceso a APIs del navegador |"
    echo "| 15 | **Server** header oculto | Fuga de info | Medio — revela versión del servidor |"
    echo "| 16 | **X-Powered-By** ausente | Fuga de info | Medio — revela stack (PHP, etc.) |"
    echo "| 17 | **X-AspNet-Version** ausente | Fuga de info | Medio — revela versión de .NET |"
    echo "| 18 | **CORS** sin wildcard | Config. servidor | **Alto** — acceso cross-origin irrestricto |"
    echo "| 19 | **HTTP TRACE** deshabilitado | Config. servidor | Medio — XST (Cross-Site Tracing) |"
    echo "| 20 | **Cache-Control** adecuado | Config. servidor | Medio — datos sensibles en caché |"
    echo ""
    echo "---"
    echo ""
    echo "_Generado con Web Security Scanner v3.1 — $(date '+%Y-%m-%d %H:%M:%S')_"
  } > "$OUTFILE"
}

# ════════════════════════════════════════════════════════════════════
# FUNCIÓN: generate_report_batch — genera reporte Markdown del análisis batch
# ════════════════════════════════════════════════════════════════════
generate_report_batch() {
  local OUTFILE="$1"
  local DOMAINS=("${BATCH_DOMAINS_LIST[@]}")
  local TESTS=(01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20)
  {
    echo "# Reporte de Seguridad Batch"
    echo ""
    echo "| Campo | Valor |"
    echo "|-------|-------|"
    echo "| **Fecha** | $(date '+%Y-%m-%d %H:%M:%S') |"
    echo "| **Archivo CSV** | ${1%/*}/domains.csv |"
    echo "| **Dominios analizados** | ${#DOMAINS[@]} |"
    echo ""
    echo "---"
    echo ""
    echo "## Tabla resumen por dominio"
    echo ""
    echo "| Dominio | OK | FL | WN | Estado |"
    echo "|---------|:--:|:--:|:--:|--------|"
    for d in "${DOMAINS[@]}"; do
      local STATUS="${BATCH_RESULTS["${d}:STATUS"]:-?}"
      if [[ "$STATUS" == "DNS_FAIL" ]]; then
        echo "| ${d} | — | — | — | 🔴 DNS no resuelve |"
        continue
      elif [[ "$STATUS" == "NO_RESP" ]]; then
        echo "| ${d} | — | — | — | 🔴 Servidor no responde |"
        continue
      fi
      local p=0 f=0 w=0
      for t in "${TESTS[@]}"; do
        local R="${BATCH_RESULTS["${d}:${t}"]:-?}"
        case "$R" in PASS) ((p++)) ;; FAIL) ((f++)) ;; WARN) ((w++)) ;; esac
      done
      local ESTADO
      if   [[ $f -eq 0 && $w -eq 0 ]]; then ESTADO="🟢 Excelente"
      elif [[ $f -eq 0 ]];             then ESTADO="🟡 Aceptable"
      elif [[ $f -le 2 ]];             then ESTADO="🟠 Mejorable"
      else                                  ESTADO="🔴 Crítico"
      fi
      echo "| ${d} | ${p} | ${f} | ${w} | ${ESTADO} |"
    done
    echo ""
    echo "---"
    echo ""
    echo "## Tabla detalle por test (P=PASS F=FAIL W=WARN S=SKIP)"
    echo ""
    # Cabecera columnas
    printf "| %-42s |" "Dominio"
    for t in "${TESTS[@]}"; do printf " %s |" "$t"; done
    printf "\n"
    # Separador
    printf "|%s|" "$(printf '%44s' | tr ' ' '-')"
    for t in "${TESTS[@]}"; do printf '%s' "-----|"; done
    printf "\n"
    for d in "${DOMAINS[@]}"; do
      local STATUS="${BATCH_RESULTS["${d}:STATUS"]:-?}"
      printf "| %-42s |" "$d"
      if [[ "$STATUS" == "DNS_FAIL" || "$STATUS" == "NO_RESP" ]]; then
        printf " %s |\n" "$STATUS"
        continue
      fi
      for t in "${TESTS[@]}"; do
        local R="${BATCH_RESULTS["${d}:${t}"]:-?}"
        case "$R" in
          PASS) printf "  P |" ;; FAIL) printf "  F |" ;;
          WARN) printf "  W |" ;; SKIP) printf "  S |" ;;
          *)    printf "  ? |" ;;
        esac
      done
      printf "\n"
    done
    echo ""
    echo "---"
    echo ""
    echo "## Fallos más frecuentes por test"
    echo ""
    echo "| Test | Descripción | Dominios con FAIL |"
    echo "|:----:|-------------|:-----------------:|"
    local -A TEST_NAMES=(
      ["01"]="Cookie: Secure" ["02"]="Cookie: HttpOnly" ["03"]="Cookie: SameSite" ["04"]="Cookie: Path"
      ["05"]="HTTP→HTTPS redirect" ["06"]="HSTS" ["07"]="TLS 1.0 deshabilitado" ["08"]="TLS 1.1 deshabilitado"
      ["09"]="Certificado SSL" ["10"]="X-Frame-Options" ["11"]="X-Content-Type-Options" ["12"]="Content-Security-Policy"
      ["13"]="Referrer-Policy" ["14"]="Permissions-Policy" ["15"]="Server header oculto"
      ["16"]="X-Powered-By ausente" ["17"]="X-AspNet-Version ausente" ["18"]="CORS wildcard"
      ["19"]="HTTP TRACE" ["20"]="Cache-Control"
    )
    for t in "${TESTS[@]}"; do
      local cnt=0
      for d in "${DOMAINS[@]}"; do
        [[ "${BATCH_RESULTS["${d}:${t}"]}" == "FAIL" ]] && ((cnt++))
      done
      [[ $cnt -gt 0 ]] && echo "| ${t} | ${TEST_NAMES[$t]} | ${cnt} |"
    done
    echo ""
    echo "---"
    echo ""
    echo "## Referencia de tests"
    echo ""
    echo "| ID | Nombre | Bloque | Riesgo si falla |"
    echo "|----|--------|--------|-----------------|"
    echo "| 01 | Cookie flag: **Secure** | Cookies | Medio — cookie enviada por HTTP |"
    echo "| 02 | Cookie flag: **HttpOnly** | Cookies | **Alto** — robo de sesión via XSS |"
    echo "| 03 | Cookie flag: **SameSite** | Cookies | Medio — CSRF cross-site |"
    echo "| 04 | Cookie attribute: **Path** | Cookies | Bajo — scope de cookie sin restringir |"
    echo "| 05 | **HTTP → HTTPS** redirect 301/302 | Transporte | Medio — tráfico en claro posible |"
    echo "| 06 | **HSTS** Strict-Transport-Security | Transporte | **Alto** — SSL stripping attack |"
    echo "| 07 | **TLS 1.0** deshabilitado | Transporte | **Alto** — protocolo roto (POODLE) |"
    echo "| 08 | **TLS 1.1** deshabilitado | Transporte | Medio — protocolo obsoleto |"
    echo "| 09 | Certificado SSL **vigente** | Transporte | Crítico — conexión insegura si expira |"
    echo "| 10 | **X-Frame-Options** (anti-clickjacking) | Cabeceras | **Alto** — iframes maliciosos |"
    echo "| 11 | **X-Content-Type-Options**: nosniff | Cabeceras | Medio — MIME confusion attack |"
    echo "| 12 | **Content-Security-Policy** (CSP) | Cabeceras | **Alto** — XSS sin restricción de scripts |"
    echo "| 13 | **Referrer-Policy** | Cabeceras | Bajo — fuga de URLs a terceros |"
    echo "| 14 | **Permissions-Policy** | Cabeceras | Bajo — acceso a APIs del navegador |"
    echo "| 15 | **Server** header oculto | Fuga de info | Medio — revela versión del servidor |"
    echo "| 16 | **X-Powered-By** ausente | Fuga de info | Medio — revela stack (PHP, etc.) |"
    echo "| 17 | **X-AspNet-Version** ausente | Fuga de info | Medio — revela versión de .NET |"
    echo "| 18 | **CORS** sin wildcard | Config. servidor | **Alto** — acceso cross-origin irrestricto |"
    echo "| 19 | **HTTP TRACE** deshabilitado | Config. servidor | Medio — XST (Cross-Site Tracing) |"
    echo "| 20 | **Cache-Control** adecuado | Config. servidor | Medio — datos sensibles en caché |"
    echo ""
    echo "---"
    echo ""
    echo "_Generado con Web Security Scanner v3.1 — $(date '+%Y-%m-%d %H:%M:%S')_"
  } > "$OUTFILE"
}

# ════════════════════════════════════════════════════════════════════
# FUNCIÓN: export_wizard — wizard interactivo de exportación de reporte
# ════════════════════════════════════════════════════════════════════
export_wizard() {
  local MODE="$1"  # "individual" o "batch"
  echo ""
  read -rp "  ¿Exportar reporte? [S/N]: " _EXP_ANS
  [[ ! "$_EXP_ANS" =~ ^[sS]$ ]] && return
  echo ""
  local DEFAULT_RDIR="${_SCRIPT_DIR}/reports"
  read -rp "  Directorio de destino [Enter = ${DEFAULT_RDIR}]: " _RDIR
  [[ -z "$_RDIR" ]] && _RDIR="$DEFAULT_RDIR"
  [[ "$_RDIR" != /* ]] && _RDIR="${_SCRIPT_DIR}/${_RDIR}"
  mkdir -p "$_RDIR" 2>/dev/null || { echo -e "${RED}  Error: no se pudo crear ${_RDIR}${RESET}"; return 1; }
  local TS; TS=$(date '+%Y%m%d-%H%M%S')
  local OUTFILE
  if [[ "$MODE" == "individual" ]]; then
    OUTFILE="${_RDIR}/${TS}-${SCAN_DOMAIN}.md"
    generate_report_individual "$OUTFILE"
  else
    OUTFILE="${_RDIR}/${TS}-batch.md"
    generate_report_batch "$OUTFILE"
  fi
  echo -e "  ${GREEN}✅ Reporte guardado en:${RESET} ${OUTFILE}"
  echo ""
}

# ── Inicializar domains.csv si no existe ─────────────────────
_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
_CSV_PATH="${_SCRIPT_DIR}/domains.csv"
_CSV_EXAMPLE="${_SCRIPT_DIR}/domains.csv.example"
if [[ ! -f "$_CSV_PATH" ]]; then
  if [[ -f "$_CSV_EXAMPLE" ]]; then
    cp "$_CSV_EXAMPLE" "$_CSV_PATH"
    echo -e "  ${CYAN}ℹ  domains.csv creado desde el ejemplo. Edítalo con tus dominios.${RESET}\n"
  else
    printf "# UNAE Web Security Suite — dominios para análisis automatizado\n" > "$_CSV_PATH"
    printf "# Formato: dominio,cookie_sesion,ip_forzada  (últimas 2 opcionales)\n" >> "$_CSV_PATH"
    echo -e "  ${CYAN}ℹ  domains.csv creado vacío. Agrégale dominios para usar el análisis batch.${RESET}\n"
  fi
fi

# Pre-cargar run_tests() — definida más abajo en este archivo
source <(sed -nE '/^run_tests[(][)] [{]$/,/^[}] # end run_tests$/p' "${BASH_SOURCE[0]}")

while true; do

  # ── Reset de estado por iteración ────────────────────────────
  PASS=0; FAIL=0; SKIP=0; WARN=0
  DOMAIN="$_ENV_DOMAIN"
  SESSION_COOKIE_NAME="$_ENV_SESSION"
  IP="$_ENV_IP"

  # ── Menú principal (solo modo interactivo) ───────────────────
  if [[ -z "$_ENV_DOMAIN" ]]; then
    echo -e "${BOLD}${CYAN}  ┌───────────────────────────────────────┐"
    echo -e "  │  Menú principal                       │"
    echo -e "  └───────────────────────────────────────┘${RESET}"
    echo ""
    echo -e "  [1] Análisis individual"
    echo -e "  [2] Análisis automatizado  ${CYAN}(batch desde CSV)${RESET}"
    echo -e "  [0] Salir"
    echo ""
    read -rp "  Selecciona una opción: " _MENU
    echo ""
    case "$_MENU" in
      1) : ;;
      2)
        echo -e "${CYAN}  Archivo CSV de dominios${RESET}"
        echo -e "  Formato: dominio,cookie_sesion,ip_forzada  (últimas 2 columnas opcionales)"
        echo -e "  Ejemplo: ${_SCRIPT_DIR}/domains.csv.example"
        echo ""
        read -rp "  Ruta al archivo CSV [Enter = domains.csv]: " _CSV_INPUT
        if [[ -z "$_CSV_INPUT" ]]; then
          _CSV_INPUT="${_SCRIPT_DIR}/domains.csv"
        elif [[ "$_CSV_INPUT" != /* ]] && [[ "$_CSV_INPUT" != ./* ]]; then
          _CSV_INPUT="${_SCRIPT_DIR}/${_CSV_INPUT}"
        fi
        echo ""
        batch_run "$_CSV_INPUT"
        read -rp "  Presiona Enter para volver al menú..." _
        echo ""
        continue
        ;;
      0) echo -e "${GREEN}  Hasta luego.${RESET}"; echo ""; exit 0 ;;
      *) echo -e "${YELLOW}  Opción no válida. Intenta de nuevo.${RESET}"; echo ""; continue ;;
    esac
  fi

  # ── PASO 1: Dominio ────────────────────────────────────────
  if [[ -n "$DOMAIN" ]]; then
    echo -e "${CYAN}Dominio:${RESET} $DOMAIN (variable de entorno)"
  else
    echo -e "${CYAN}Paso 1/3 — Dominio a analizar${RESET}"
    echo -e "  Ejemplos: example.com  /  app.miempresa.com  /  10.0.0.1"
    read -rp "  Ingresa el dominio: " DOMAIN
    [[ -z "$DOMAIN" ]] && echo -e "${RED}Error: dominio requerido.${RESET}" && continue
  fi
  echo ""

# ── Validación 4: limpiar esquema y separar host/path ────────
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN#http://}"
HOST="${DOMAIN%%/*}"
_RAWPATH="${DOMAIN#$HOST}"
BASE_PATH="${_RAWPATH:-/}"
[[ "${BASE_PATH:0:1}" != "/" ]] && BASE_PATH="/${BASE_PATH}"
DOMAIN="$HOST"
BASE_URL="https://${DOMAIN}${BASE_PATH}"

# ── Validación 1: DNS ────────────────────────────────────────
echo -ne "  Verificando DNS para ${DOMAIN}... "
DNS_RESULT=$(dig +short "$DOMAIN" 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+$' | tail -1)
if [[ -z "$DNS_RESULT" ]]; then
  DNS_RESULT=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | grep -oP '^\d+\.\d+\.\d+\.\d+$' | tail -1)
fi
if [[ -z "$DNS_RESULT" ]]; then
  echo ""
  echo -e "${RED}❌ ERROR: El dominio '${DOMAIN}' no existe en DNS. Verifica que esté escrito correctamente.${RESET}"
  echo ""; read -rp "  Presiona Enter para volver al menú..." _; echo ""
  continue
fi
echo -e "${GREEN}OK${RESET} (${DNS_RESULT})"
RESOLVED_IP="$DNS_RESULT"

# ── Validación 2: IP privada RFC 1918 ────────────────────────
if [[ "$RESOLVED_IP" =~ ^10\. ]] || \
   [[ "$RESOLVED_IP" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
   [[ "$RESOLVED_IP" =~ ^192\.168\. ]]; then
  echo ""
  echo -e "  ${YELLOW}⚠️  ADVERTENCIA: '${DOMAIN}' resuelve a una IP privada (${RESOLVED_IP}).${RESET}"
  echo -e "      Solo es accesible desde la red interna. Algunos tests pueden fallar."
  read -rp "      ¿Deseas continuar de todas formas? [s/N]: " CONFIRM
  [[ ! "$CONFIRM" =~ ^[sS]$ ]] && echo "" && continue
fi
echo ""

# ── Validación 3: servidor responde ──────────────────────────
echo -ne "  Verificando acceso HTTPS a ${BASE_URL}... "
HTTP_CHECK=$(curl --max-time 5 -sk -o /dev/null -w "%{http_code}" "$BASE_URL" 2>/dev/null)
if [[ "$HTTP_CHECK" == "000" ]] || [[ -z "$HTTP_CHECK" ]]; then
  echo ""
  echo -e "${RED}❌ ERROR: El servidor no responde en ${BASE_URL}. No se puede continuar.${RESET}"
  echo ""; read -rp "  Presiona Enter para volver al menú..." _; echo ""
  continue
fi
echo -e "${GREEN}OK${RESET} (HTTP ${HTTP_CHECK})"
echo ""

# ── PASO 2: Descubrir cookies ────────────────────────────────
echo -e "${CYAN}Paso 2/3 — Cookie de sesión${RESET}"
echo "  Descubriendo cookies disponibles en ${BASE_URL} ..."
echo ""

DISCOVERED=$(curl --max-time 8 --connect-timeout 4 -sk -I "$BASE_URL" | grep -i "^set-cookie" | grep -oP "set-cookie:\s*\K[^=]+")

if [[ -z "$DISCOVERED" ]]; then
  echo -e "  ${YELLOW}No se encontraron cookies en la raíz del dominio.${RESET}"
  echo "  Puede que requiera autenticación previa para generarlas."
  SESSION_COOKIE_NAME=""
else
  echo "  Cookies encontradas:"
  i=1; declare -a COOKIE_LIST
  while IFS= read -r name; do
    echo "    [$i] $name"; COOKIE_LIST+=("$name"); ((i++))
  done <<< "$DISCOVERED"
  echo ""
  if [[ -n "$SESSION_COOKIE_NAME" ]]; then
    echo -e "  Cookie de sesión: ${CYAN}$SESSION_COOKIE_NAME${RESET} (variable de entorno)"
  else
    echo "  ¿Cuál es la cookie de sesión principal?"
    echo "    [0] Ingresar manualmente"
    read -rp "  Selecciona número o 0: " CHOICE
    if [[ "$CHOICE" == "0" ]] || [[ -z "$CHOICE" ]]; then
      read -rp "  Ingresa el nombre de la cookie de sesión: " SESSION_COOKIE_NAME
    else
      SESSION_COOKIE_NAME="${COOKIE_LIST[$((CHOICE-1))]}"
    fi
  fi
fi
echo ""

# ── PASO 3: IP opcional ──────────────────────────────────────
if [[ -z "$IP" ]]; then
  echo -e "${CYAN}Paso 3/3 — Resolución DNS (opcional)${RESET}"
  echo "  Deja vacío para usar DNS normal, o ingresa una IP para forzar resolución."
  read -rp "  IP del servidor [Enter para omitir]: " IP
fi
echo ""

RESOLVE_443="${IP:+--resolve ${DOMAIN}:443:${IP}}"
RESOLVE_80="${IP:+--resolve ${DOMAIN}:80:${IP}}"

# ── Cabecera de ejecución ────────────────────────────────────
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  Dominio  : %s\n" "$DOMAIN"
[[ -n "$IP" ]] && printf "  IP forzada: %s\n" "$IP"
printf "  Fecha    : %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# ── Obtener respuesta base ────────────────────────────────────
RESPONSE=$(curl --max-time 8 --connect-timeout 4 -sk -I $RESOLVE_443 "$BASE_URL")
COOKIES=$(echo "$RESPONSE" | grep -i "^set-cookie")

run_tests

  if [[ -n "$_ENV_DOMAIN" ]]; then
    [[ $FAIL -eq 0 ]] && exit 0 || exit 1
  fi
  export_wizard "individual"
  read -rp "  Presiona Enter para volver al menú..." _
  echo ""

done

# ══════════════════════════════════════════════════
run_tests() {
SCAN_DATA=(); SCAN_ORDER=()
SCAN_DOMAIN="$DOMAIN"; SCAN_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
section "COOKIES"

# TEST-01: Secure
ALL_SECURE=PASS
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  echo "$line" | grep -qi "; secure" || ALL_SECURE=FAIL
done <<< "$COOKIES"
run_test "01" "Cookie attribute: Secure (+12.4 pts)" "$ALL_SECURE"

# TEST-02: HttpOnly
if [[ -n "$SESSION_COOKIE_NAME" ]]; then
  SESSION_LINE=$(echo "$COOKIES" | grep -i "$SESSION_COOKIE_NAME")
  if [[ -n "$SESSION_LINE" ]]; then
    echo "$SESSION_LINE" | grep -qi "httponly" \
      && run_test "02" "Cookie attribute: HttpOnly — $SESSION_COOKIE_NAME (+8.6 pts)" "PASS" \
      || run_test "02" "Cookie attribute: HttpOnly — $SESSION_COOKIE_NAME (+8.6 pts)" "FAIL"
  else
    run_test "02" "Cookie attribute: HttpOnly" "SKIP" "cookie '$SESSION_COOKIE_NAME' no hallada en raíz"
  fi
else
  run_test "02" "Cookie attribute: HttpOnly" "SKIP" "sin cookie de sesión identificada"
fi

# TEST-03: SameSite
ALL_SAMESITE=PASS
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  echo "$line" | grep -qiP "samesite=(lax|strict)" || ALL_SAMESITE=FAIL
done <<< "$COOKIES"
run_test "03" "Cookie attribute: SameSite=Lax|Strict" "$ALL_SAMESITE"

# TEST-04: Cookie Path
ALL_PATH=PASS
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  echo "$line" | grep -qi "path=" || ALL_PATH=WARN
done <<< "$COOKIES"
[[ "$ALL_PATH" == "WARN" ]] \
  && run_test "04" "Cookie attribute: Path definido" "WARN" "alguna cookie sin Path — scope sin restringir" \
  || run_test "04" "Cookie attribute: Path definido" "PASS"

# ════════════════════════════════════════════════════
# BLOQUE 2 — TRANSPORTE
# ════════════════════════════════════════════════════
section "TRANSPORTE Y TLS"

# TEST-05: HTTP → HTTPS redirect
HTTP_RESP=$(curl --max-time 8 --connect-timeout 4 -sk -I $RESOLVE_80 "http://${DOMAIN}${BASE_PATH}" 2>/dev/null)
HTTP_CODE=$(echo "$HTTP_RESP" | grep -oP "HTTP/\S+ \K\d+")
LOCATION=$(echo "$HTTP_RESP" | grep -i "^location:")
([[ "$HTTP_CODE" =~ ^30[12]$ ]] && echo "$LOCATION" | grep -qi "https://") \
  && run_test "05" "HTTP → HTTPS redirect 301/302 (+0.6 pts)" "PASS" \
  || run_test "05" "HTTP → HTTPS redirect 301/302 (+0.6 pts)" "FAIL"

# TEST-06: HSTS
HSTS=$(echo "$RESPONSE" | grep -i "strict-transport-security" | head -1)
MAX_AGE=$(echo "$HSTS" | grep -oP "max-age=\K\d+" | head -1)
if [[ -z "$HSTS" ]]; then
  run_test "06" "HSTS Strict-Transport-Security" "FAIL" "header ausente"
elif [[ "${MAX_AGE:-0}" -lt 31536000 ]]; then
  run_test "06" "HSTS Strict-Transport-Security" "WARN" "max-age=${MAX_AGE} < 31536000 (1 año)"
else
  run_test "06" "HSTS Strict-Transport-Security max-age >= 1 año" "PASS"
fi

# TEST-07: TLS 1.0 deshabilitado
curl --max-time 6 --connect-timeout 4 -sk --tlsv1.0 --tls-max 1.0 $RESOLVE_443 "https://${DOMAIN}/" -o /dev/null 2>/dev/null \
  && run_test "07" "TLS 1.0 deshabilitado" "FAIL" "servidor acepta TLS 1.0 (inseguro)" \
  || run_test "07" "TLS 1.0 deshabilitado" "PASS"

# TEST-08: TLS 1.1 deshabilitado
curl --max-time 6 --connect-timeout 4 -sk --tlsv1.1 --tls-max 1.1 $RESOLVE_443 "https://${DOMAIN}/" -o /dev/null 2>/dev/null \
  && run_test "08" "TLS 1.1 deshabilitado" "FAIL" "servidor acepta TLS 1.1 (obsoleto)" \
  || run_test "08" "TLS 1.1 deshabilitado" "PASS"

# TEST-09: Certificado SSL — días para expirar
if command -v openssl &>/dev/null; then
  OPENSSL_CONNECT="${IP:+-connect ${IP}:443}"
  EXPIRY=$(echo | timeout 6 openssl s_client ${OPENSSL_CONNECT:--connect ${DOMAIN}:443} \
    -servername "${DOMAIN}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [[ -n "$EXPIRY" ]]; then
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - $(date +%s)) / 86400 ))
    if [[ $DAYS_LEFT -le 7 ]]; then
      run_test "09" "Certificado SSL vigente" "FAIL" "expira en ${DAYS_LEFT} días — CRÍTICO"
    elif [[ $DAYS_LEFT -le 30 ]]; then
      run_test "09" "Certificado SSL vigente" "WARN" "expira en ${DAYS_LEFT} días — renovar pronto"
    else
      run_test "09" "Certificado SSL vigente" "PASS" "expira en ${DAYS_LEFT} días"
    fi
  else
    run_test "09" "Certificado SSL vigente" "SKIP" "no se pudo leer el certificado"
  fi
else
  run_test "09" "Certificado SSL vigente" "SKIP" "openssl no disponible"
fi

# ════════════════════════════════════════════════════
# BLOQUE 3 — CABECERAS DE SEGURIDAD
# ════════════════════════════════════════════════════
section "CABECERAS HTTP"

# TEST-10: X-Frame-Options (clickjacking)
XFO=$(echo "$RESPONSE" | grep -i "^x-frame-options:" | tr -d '\r')
if [[ -n "$XFO" ]]; then
  run_test "10" "X-Frame-Options (anti-clickjacking)" "PASS" "${XFO#*: }"
else
  run_test "10" "X-Frame-Options (anti-clickjacking)" "FAIL" "header ausente"
fi

# TEST-11: X-Content-Type-Options (MIME sniffing)
XCTO=$(echo "$RESPONSE" | grep -i "^x-content-type-options:" | tr -d '\r')
[[ -n "$XCTO" ]] \
  && run_test "11" "X-Content-Type-Options: nosniff" "PASS" \
  || run_test "11" "X-Content-Type-Options: nosniff" "FAIL" "header ausente"

# TEST-12: Content-Security-Policy
CSP=$(echo "$RESPONSE" | grep -i "^content-security-policy:" | tr -d '\r')
if [[ -z "$CSP" ]]; then
  run_test "12" "Content-Security-Policy" "FAIL" "header ausente"
elif echo "$CSP" | grep -qi "unsafe-eval"; then
  run_test "12" "Content-Security-Policy" "WARN" "contiene 'unsafe-eval'"
else
  run_test "12" "Content-Security-Policy" "PASS"
fi

# TEST-13: Referrer-Policy
RP=$(echo "$RESPONSE" | grep -i "^referrer-policy:" | tr -d '\r')
[[ -n "$RP" ]] \
  && run_test "13" "Referrer-Policy" "PASS" "${RP#*: }" \
  || run_test "13" "Referrer-Policy" "WARN" "header ausente — recomendado"

# TEST-14: Permissions-Policy
PP=$(echo "$RESPONSE" | grep -i "^permissions-policy:" | tr -d '\r')
[[ -n "$PP" ]] \
  && run_test "14" "Permissions-Policy" "PASS" \
  || run_test "14" "Permissions-Policy" "WARN" "header ausente — recomendado"

# ════════════════════════════════════════════════════
# BLOQUE 4 — FUGA DE INFORMACIÓN
# ════════════════════════════════════════════════════
section "FUGA DE INFORMACIÓN"

# TEST-15: Server header — no revelar versión
SERVER=$(echo "$RESPONSE" | grep -i "^server:" | tr -d '\r')
if [[ -z "$SERVER" ]]; then
  run_test "15" "Server header oculto" "PASS"
elif echo "$SERVER" | grep -qiP "[\d\.]{3,}"; then
  run_test "15" "Server header oculto" "FAIL" "${SERVER#*: } — revela versión"
else
  run_test "15" "Server header sin versión" "PASS" "${SERVER#*: }"
fi

# TEST-16: X-Powered-By ausente
XPB=$(echo "$RESPONSE" | grep -i "^x-powered-by:" | tr -d '\r')
[[ -z "$XPB" ]] \
  && run_test "16" "X-Powered-By ausente (no revela stack)" "PASS" \
  || run_test "16" "X-Powered-By ausente (no revela stack)" "FAIL" "${XPB#*: }"

# TEST-17: X-AspNet-Version ausente
XASNET=$(echo "$RESPONSE" | grep -i "^x-aspnet-version:\|^x-aspnetmvc-version:" | tr -d '\r')
[[ -z "$XASNET" ]] \
  && run_test "17" "X-AspNet-Version ausente" "PASS" \
  || run_test "17" "X-AspNet-Version ausente" "FAIL" "${XASNET#*: }"

# ════════════════════════════════════════════════════
# BLOQUE 5 — CONFIGURACIÓN DEL SERVIDOR
# ════════════════════════════════════════════════════
section "CONFIGURACIÓN DEL SERVIDOR"

# TEST-18: CORS — sin wildcard Access-Control-Allow-Origin
CORS=$(echo "$RESPONSE" | grep -i "^access-control-allow-origin:" | tr -d '\r')
if [[ -z "$CORS" ]]; then
  run_test "18" "CORS no expuesto en raíz" "PASS"
elif echo "$CORS" | grep -q "\*"; then
  run_test "18" "CORS Access-Control-Allow-Origin" "FAIL" "wildcard '*' — cualquier origen permitido"
else
  run_test "18" "CORS Access-Control-Allow-Origin" "PASS" "${CORS#*: }"
fi

# TEST-19: HTTP TRACE deshabilitado
TRACE_RESP=$(curl --max-time 6 --connect-timeout 4 -sk -o /dev/null -w "%{http_code}" $RESOLVE_443 \
  -X TRACE "$BASE_URL" 2>/dev/null)
if [[ "$TRACE_RESP" == "200" ]]; then
  run_test "19" "HTTP TRACE deshabilitado" "FAIL" "responde 200 — método TRACE activo"
elif [[ "$TRACE_RESP" == "405" ]] || [[ "$TRACE_RESP" == "403" ]] || [[ "$TRACE_RESP" == "404" ]]; then
  run_test "19" "HTTP TRACE deshabilitado" "PASS" "responde $TRACE_RESP"
else
  run_test "19" "HTTP TRACE deshabilitado" "WARN" "respuesta inesperada: $TRACE_RESP"
fi

# TEST-20: Cache-Control en respuestas autenticadas
CACHE=$(echo "$RESPONSE" | grep -i "^cache-control:" | tr -d '\r')
if [[ -z "$CACHE" ]]; then
  run_test "20" "Cache-Control presente" "WARN" "ausente — navegador puede cachear contenido sensible"
elif echo "$CACHE" | grep -qiP "no-store|no-cache|private"; then
  run_test "20" "Cache-Control seguro" "PASS" "${CACHE#*: }"
else
  run_test "20" "Cache-Control seguro" "WARN" "${CACHE#*: } — revisar si aplica a rutas autenticadas"
fi

# ── Resumen ──────────────────────────────────────────────────
if [[ "$BATCH_SILENT" != "1" ]]; then
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  RESUMEN: ${GREEN}$PASS PASS${RESET}${BOLD}  ${RED}$FAIL FAIL${RESET}${BOLD}  ${YELLOW}$WARN WARN${RESET}${BOLD}  ${MAGENTA}$SKIP SKIP${RESET}${BOLD}  /  $(( PASS + FAIL + WARN + SKIP )) tests"
  echo ""
  if [[ $FAIL -eq 0 ]] && [[ $WARN -eq 0 ]]; then
    echo -e "  ${GREEN}✅ SECURITY SCAN: TODOS LOS TESTS PASARON — $DOMAIN${RESET}${BOLD}"
  elif [[ $FAIL -eq 0 ]]; then
    echo -e "  ${YELLOW}⚠️  SECURITY SCAN: SIN FALLOS CRÍTICOS, $WARN advertencia(s) — $DOMAIN${RESET}${BOLD}"
  else
    echo -e "  ${RED}❌ SECURITY SCAN: $FAIL FALLO(S) CRÍTICO(S) — $DOMAIN${RESET}${BOLD}"
  fi
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
fi
} # end run_tests

