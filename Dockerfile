# 3GPP Public Domain Explorer
# ─────────────────────────────────────────────────────────────────────────────
# Quick start (mount a directory — Docker creates it automatically):
#
#   mkdir -p data
#   docker build -t 3gpp-explorer .
#
#   # Step 1: populate the database
#   docker run --rm -v $(pwd)/data:/data 3gpp-explorer scan --workers 20
#
#   # Step 2: query
#   docker run --rm -v $(pwd)/data:/data 3gpp-explorer stats
#   docker run --rm -v $(pwd)/data:/data 3gpp-explorer score --top 10
#
#   # Step 3 (optional): web UI
#   docker run -e ENABLE_WEBUI=1 -p 8501:8501 -v $(pwd)/data:/data 3gpp-explorer
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

# Data directory — mount a host directory here at runtime
VOLUME ["/data"]

# Feature flag: 0 = CLI (default), 1 = Streamlit web UI
ENV ENABLE_WEBUI=0
ENV DATA_DIR=/data
ENV DB_PATH=/data/database.db

# Streamlit web UI port (unused in CLI mode)
EXPOSE 8501

ENTRYPOINT ["/app/entrypoint.sh"]

# Default: show stats. Run 'scan' first if database.db doesn't exist yet.
CMD ["stats"]
