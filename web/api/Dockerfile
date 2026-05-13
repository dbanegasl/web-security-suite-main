# ── API Backend ──────────────────────────────────────────────────────────────
# Base: Debian slim para tener curl/openssl/dig disponibles
FROM debian:bookworm-slim

# Instalar dependencias del sistema (las mismas que usa scan.sh)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    openssl \
    dnsutils \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencias Python primero (mejor cache)
COPY web/api/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Script de escaneo
COPY scan.sh /app/scan.sh
RUN chmod +x /app/scan.sh

# Código de la API
COPY web/api/main.py /app/main.py

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
