#!/bin/sh
# Docker entrypoint for 3GPP Public Domain Explorer
#
# Feature flag:
#   ENABLE_WEBUI=0  (default) — run the CLI; any extra args forwarded to 3gpppub-cli.py
#   ENABLE_WEBUI=1            — start the Streamlit web UI on port 8501
#
# Examples:
#   docker run 3gpp-explorer stats
#   docker run 3gpp-explorer score --top 10
#   docker run -e ENABLE_WEBUI=1 -p 8501:8501 3gpp-explorer

set -e

DB_PATH="${DB_PATH:-/data/database.db}"
export DB_PATH

if [ "${ENABLE_WEBUI:-0}" = "1" ]; then
    echo "Starting Streamlit web UI on :8501 ..."
    exec streamlit run /app/epdg/stream-oplookup.py \
        --server.port 8501 \
        --server.address 0.0.0.0 \
        --server.headless true \
        --browser.gatherUsageStats false
else
    # Forward all docker run arguments to the CLI
    exec python3 /app/epdg/3gpppub-cli.py --db "$DB_PATH" "$@"
fi
