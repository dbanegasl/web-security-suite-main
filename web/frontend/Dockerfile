# ── Frontend nginx ─────────────────────────────────────────────
FROM nginx:alpine

# Configuración mínima para SPA
RUN rm /etc/nginx/conf.d/default.conf
COPY web/frontend/nginx.conf /etc/nginx/conf.d/default.conf

COPY web/frontend/ /usr/share/nginx/html/

# Cache-busting: reemplaza app.js y custom.css por app.js?v=<timestamp>
# El timestamp se genera en tiempo de build → cada rebuild fuerza recarga en el navegador
RUN BUILD_VER=$(date +%Y%m%d%H%M) && \
    sed -i "s|src=\"app.js\"|src=\"app.js?v=${BUILD_VER}\"|g" /usr/share/nginx/html/index.html && \
    sed -i "s|href=\"custom.css\"|href=\"custom.css?v=${BUILD_VER}\"|g" /usr/share/nginx/html/index.html && \
    sed -i "s|__BUILD_DATE__|${BUILD_VER}|g" /usr/share/nginx/html/version.json

EXPOSE 80
