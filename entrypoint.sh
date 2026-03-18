#!/bin/sh
# Docker entrypoint for 3GPP Public Domain Explorer
#
# Mount a writable data directory — Docker will create it if it doesn't exist:
#   mkdir -p data
#   docker run --rm -v $(pwd)/data:/data 3gpp-explorer <command>
#
# Commands:
#   scan    [--workers N]   Run DNS scanner → writes /data/database.db
#   stats                   Database overview
#   countries               FQDNs per country
#   services                Service breakdown
#   operator --mcc M --mnc N
#   search   <term>
#   score    [--top N]
#   export   [--format csv|json|tsv]
#
# Web UI (feature flag):
#   docker run -e ENABLE_WEBUI=1 -p 8501:8501 -v $(pwd)/data:/data 3gpp-explorer

set -e

DATA_DIR="${DATA_DIR:-/data}"
DB_PATH="${DB_PATH:-${DATA_DIR}/database.db}"
export DB_PATH

if [ "${ENABLE_WEBUI:-0}" = "1" ]; then
    echo "Starting Streamlit web UI on :8501 ..."
    exec streamlit run /app/epdg/stream-oplookup.py \
        --server.port 8501 \
        --server.address 0.0.0.0 \
        --server.headless true \
        --browser.gatherUsageStats false
fi

# Route the 'scan' command to the population script
# (DB file may not exist yet — that's fine, the scanner creates it)
if [ "${1:-}" = "scan" ]; then
    shift
    echo "Scanning 3GPP public DNS → ${DB_PATH}"
    exec python3 /app/epdg/3gpppub-dns-database-population.py --db "$DB_PATH" "$@"
fi

# All other commands go to the CLI
exec python3 /app/epdg/3gpppub-cli.py --db "$DB_PATH" "$@"
