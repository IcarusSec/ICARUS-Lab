#!/usr/bin/env bash
# Start the ICARUS lab locally without Docker.
# Usage: ./start.sh [port]
set -e

PORT="${1:-5000}"
VENV="$(dirname "$0")/.venv"

if [ ! -d "$VENV" ]; then
  echo "→ Creating virtualenv..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q flask PyJWT
fi

echo "→ Starting ICARUS Lab on http://0.0.0.0:$PORT"
echo "→ Set Burp target scope to: http://localhost:$PORT"

FLASK_APP=app/app.py \
FLASK_ENV=development \
  exec "$VENV/bin/python" app/app.py
