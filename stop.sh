#!/bin/bash
# =============================================================================
# OpenClaw Secure Docker — Stop Script
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║     OpenClaw Secure Docker — Stopping                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Stop containers (SIGTERM triggers the auto-shred in the app)
echo "Stopping containers (SIGTERM → auto-shred fires)..."
docker compose down

# Note: named volumes are preserved by default so workspace data persists.
# To also remove volumes (fresh start):
#   docker compose down -v

echo ""
echo "All containers stopped."
echo ""
echo "Note: Workspace volume (encrypted) is preserved."
echo "To remove volumes too: docker compose down -v"
echo ""
