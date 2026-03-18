# 3GPP Public Domain Explorer
# ─────────────────────────────────────────────────────────────────────────────
# Default mode : CLI  (ENABLE_WEBUI=0)
# Web UI mode  : set ENABLE_WEBUI=1 and expose port 8501
#
# Build:
#   docker build -t 3gpp-explorer .
#
# Run CLI:
#   docker run --rm -v $(pwd)/epdg/database.db:/data/database.db 3gpp-explorer stats
#   docker run --rm -v $(pwd)/epdg/database.db:/data/database.db 3gpp-explorer score --top 10
#
# Run Web UI:
#   docker run --rm -e ENABLE_WEBUI=1 -p 8501:8501 \
#              -v $(pwd)/epdg/database.db:/data/database.db 3gpp-explorer
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

WORKDIR /app

# System deps (for dnspython's C extension fallback and curl-less wget)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached unless requirements.txt changes)
COPY epdg/requirements.txt /app/epdg/requirements.txt
RUN pip install --no-cache-dir -r /app/epdg/requirements.txt

# Copy application code
COPY epdg/ /app/epdg/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Database is mounted at runtime — never baked into the image
VOLUME ["/data"]

# Feature flag: 0 = CLI (default), 1 = Streamlit web UI
ENV ENABLE_WEBUI=0
# Path to the mounted database
ENV DB_PATH=/data/database.db

# Streamlit web UI port (unused in CLI mode)
EXPOSE 8501

ENTRYPOINT ["/app/entrypoint.sh"]

# Default command when no args given in CLI mode
CMD ["stats"]
