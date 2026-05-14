#!/usr/bin/env bash
# deploy.sh — Descarga cambios del repo y reconstruye los contenedores.
# Uso: bash deploy.sh [--no-pull]
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${REPO_DIR}/web"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo -e "\n${CYAN}${BOLD}▶ $*${RESET}"; }
ok()    { echo -e "${GREEN}✔ $*${RESET}"; }
error() { echo -e "${RED}✘ $*${RESET}" >&2; exit 1; }

# ── 1. Git pull ──────────────────────────────────────────────────────────────
if [[ "${1:-}" != "--no-pull" ]]; then
  step "Descargando cambios (git pull)"
  cd "${REPO_DIR}"
  git pull || error "git pull falló. Revisa conflictos o conexión."
  ok "Repositorio actualizado"
else
  echo "(--no-pull: se omite git pull)"
fi

# ── 2. Verificar .env ────────────────────────────────────────────────────────
if [[ ! -f "${COMPOSE_DIR}/.env" ]]; then
  error ".env no encontrado en web/. Cópialo desde web/.env.example y configúralo."
fi

# ── 3. Rebuild + levantar ────────────────────────────────────────────────────
step "Reconstruyendo imágenes y levantando contenedores"
cd "${COMPOSE_DIR}"
docker compose up --build -d

ok "Contenedores en marcha"

# ── 4. Estado final ──────────────────────────────────────────────────────────
echo ""
docker compose ps

# ── 5. URL de acceso ─────────────────────────────────────────────────────────
FRONTEND_PORT="$(grep -E '^FRONTEND_PORT=' "${COMPOSE_DIR}/.env" | cut -d= -f2 | tr -d '[:space:]')"
FRONTEND_PORT="${FRONTEND_PORT:-8080}"
echo -e "\n${BOLD}Accede a la plataforma en:${RESET}"
echo -e "  ${GREEN}http://localhost:${FRONTEND_PORT}${RESET}"
