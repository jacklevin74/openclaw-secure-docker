#!/bin/sh
# Entrypoint wrapper:
# 1. chown tmpfs mounts (they come in as root)
# 2. Drop to non-root user and exec the app

set -e

# Fix tmpfs ownership (Docker mounts them as root)
chown -R openclaw:openclaw /openclaw/sessions /openclaw/secrets /openclaw/cache 2>/dev/null || true

# Drop to non-root and run the app
exec su -s /bin/sh openclaw -c "node /app/dist/index.js"
