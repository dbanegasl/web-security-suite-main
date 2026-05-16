#!/usr/bin/env bash
# scan-cli.sh — shim v4 (delega al core Python wss)
# Compatibilidad hacia atrás con variables de entorno de v3.
# El script original se conserva en scan-cli.sh.legacy
set -euo pipefail

exec python3 -m wss \
  ${DOMAIN:+--domain "$DOMAIN"} \
  ${SESSION_COOKIE_NAME:+--session-cookie "$SESSION_COOKIE_NAME"} \
  ${IP:+--ip "$IP"} \
  "$@"
