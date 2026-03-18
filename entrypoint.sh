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

# Catch the common Docker mount mistake: host file missing → Docker creates a directory
if [ -d "$DB_PATH" ]; then
    echo "Error: $DB_PATH is a directory, not a database file." >&2
    echo "The database file does not exist on the host — Docker created an empty directory." >&2
    echo "Run 3gpppub-dns-database-population.py first, then mount the file:" >&2
    echo "  docker run --rm -v \$(pwd)/epdg/database.db:/data/database.db 3gpp-explorer stats" >&2
    exit 1
fi

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
