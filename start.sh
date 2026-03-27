#!/bin/bash
# =============================================================================
# OpenClaw Secure Docker — Start Script
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║     OpenClaw Secure Docker — Starting                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running."
    exit 1
fi

# Build and start
echo "Building images and starting containers..."
docker compose up -d --build

echo ""
echo "Waiting for services to become healthy..."

# Wait for OpenBao
echo -n "  OpenBao: "
for i in $(seq 1 30); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8210/v1/sys/health 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "429" ]; then
        echo "✓ healthy"
        break
    fi
    echo -n "."
    sleep 2
done

# Wait for app
echo -n "  OpenClaw app: "
for i in $(seq 1 30); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8300/health 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ]; then
        echo "✓ healthy"
        break
    fi
    echo -n "."
    sleep 3
done

echo ""
echo "Services:"
docker compose ps

echo ""
echo "Endpoints:"
echo "  OpenBao:       http://localhost:8210 (root token: root-token-for-testing)"
echo "  OpenClaw App:  http://localhost:8300"
echo "  Health check:  curl http://localhost:8300/health"
echo "  Status:        curl http://localhost:8300/status"
echo ""
echo "Quick test:"
echo "  bash test_secure.sh"
echo ""
echo "Full test (includes SIGTERM shred):"
echo "  bash test_secure.sh --full"
echo ""
