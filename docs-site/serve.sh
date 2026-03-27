#!/bin/bash
# serve.sh — Serve OpenClaw Secure Docker documentation site
# Port: 8320
# Usage: bash serve.sh [--background]
#
# Serves the static documentation site using Python's built-in HTTP server.
# Navigate to http://localhost:8320/ in your browser.

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=8320

echo ""
echo "═══════════════════════════════════════════════════"
echo "  OpenClaw Secure Docker — Documentation Site"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  📖  Serving from: $DIR"
echo "  🌐  URL: http://localhost:${PORT}/"
echo "  ⏹   Stop: Ctrl+C (or kill \$PORT)"
echo ""

# Check if port is already in use
if lsof -Pi :${PORT} -sTCP:LISTEN -t >/dev/null 2>&1; then
  echo "⚠️  Port ${PORT} is already in use."
  echo "   Kill existing: lsof -ti:${PORT} | xargs kill -9"
  echo ""
fi

cd "$DIR"

if [ "$1" = "--background" ]; then
  python3 -m http.server ${PORT} --bind 127.0.0.1 &>/tmp/docs-serve-8320.log &
  echo "  Started in background. PID: $!"
  echo "  Logs: /tmp/docs-serve-8320.log"
else
  echo "  Serving... (Ctrl+C to stop)"
  echo ""
  python3 -m http.server ${PORT} --bind 127.0.0.1
fi
