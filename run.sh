#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

PYTHON_CMD=""

if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "[ERROR] Python 3 not found in PATH!"
    exit 1
fi

echo "Starting ZVault Proxy using: $PYTHON_CMD"
echo "Server address: http://127.0.0.1:8765"
echo ""
exec "$PYTHON_CMD" server.py
