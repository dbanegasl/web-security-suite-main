# ── API Backend ──────────────────────────────────────────────────────────────
# Base: Debian slim
FROM debian:bookworm-slim

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    openssl \
    dnsutils \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencias Python (mejor cache si no cambia requirements.txt)
COPY web/api/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Paquete wss (core Python — reemplaza scan.sh)
COPY pyproject.toml /app/pyproject.toml
COPY wss/ /app/wss/
RUN pip3 install --no-cache-dir --break-system-packages /app

# Código de la API
COPY web/api/main.py /app/main.py
COPY web/api/auth.py /app/auth.py
COPY web/api/database.py /app/database.py
COPY web/api/models.py /app/models.py

EXPOSE 8001

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
