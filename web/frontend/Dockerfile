# ── Frontend nginx ─────────────────────────────────────────────
FROM nginx:alpine

# Configuración mínima para SPA
RUN rm /etc/nginx/conf.d/default.conf
COPY web/frontend/nginx.conf /etc/nginx/conf.d/default.conf

COPY web/frontend/ /usr/share/nginx/html/

EXPOSE 80
