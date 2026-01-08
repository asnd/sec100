#!/bin/bash
set -e

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "Installing requirements..."
pip install -r requirements.txt

echo "Starting server in background..."
python main.py &
SERVER_PID=$!

# Wait for server to start
sleep 3

echo "Testing health endpoint..."
curl -s http://localhost:8000/health || echo "Health check failed"

echo "Server is running with PID $SERVER_PID"
# Keep script alive or just exit and let it run? 
# Usually in these environments we might want to keep it in foreground if it's the main task.
wait $SERVER_PID
