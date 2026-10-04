#!/bin/bash
# TraceSeal Production Startup Script
# Listens on 0.0.0.0 using Render dynamic $PORT or defaults to 8000

set -e

PORT="${PORT:-8000}"
DATA_DIR="${TRACESEAL_DATA_DIR:-}"

echo "=== TraceSeal Production Startup ==="
echo "Binding to: 0.0.0.0:$PORT"

if [ -n "$DATA_DIR" ]; then
    echo "DATA_DIR: $DATA_DIR (persistent-volume mode)"

    # Create all required subdirectories under persistent volume
    mkdir -p "$DATA_DIR/storage/encrypted"
    mkdir -p "$DATA_DIR/storage/decrypted"
    mkdir -p "$DATA_DIR/storage/leaked"
    mkdir -p "$DATA_DIR/storage/evidence"
    mkdir -p "$DATA_DIR/ledger_data"

    # On FIRST deploy: seed persistent volume from bundled data
    if [ ! -f "$DATA_DIR/traceseal.db" ]; then
        echo "First deploy — seeding persistent volume..."
        [ -f "/app/traceseal.db" ]   && cp /app/traceseal.db "$DATA_DIR/traceseal.db"   && echo "  ✓ DB"
        [ -d "/app/ledger_data" ]    && cp -r /app/ledger_data/. "$DATA_DIR/ledger_data/" && echo "  ✓ Ledger"
        [ -d "/app/storage" ]        && cp -r /app/storage/. "$DATA_DIR/storage/"         && echo "  ✓ Storage"
        echo "Seeding complete."
    else
        echo "Persistent data found — skipping seed."
    fi
else
    echo "Using bundled data in application directory (Render / container mode)"
    mkdir -p storage/encrypted storage/decrypted storage/leaked storage/evidence ledger_data
fi

echo "Starting TraceSeal on 0.0.0.0:$PORT ..."
exec python -m uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --workers 1 \
    --log-level info
