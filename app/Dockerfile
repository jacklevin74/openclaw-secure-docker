# ─────────────────────────────────────────────────────────────────────────────
# OpenClaw Secure App — Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Security hardening:
#   - Non-root user (UID 10001)
#   - Minimal slim base image
#   - No secrets in image layers or ENV
#   - Read-only root filesystem (enforced via docker-compose)
#   - Directories pre-created for tmpfs + volume mounts
#   - cryptography library for Fernet encryption
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

LABEL maintainer="OpenClaw Secure Docker"
LABEL description="OpenClaw agent simulator with Fernet encryption, tmpfs sessions, OpenBao secrets"

# ── System setup ──────────────────────────────────────────────────────────────

# Install only what's needed for the cryptography library (libffi, openssl headers)
# and for secure-delete operations (coreutils provides shred as fallback)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libffi-dev \
        libssl-dev \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with fixed UID/GID matching docker-compose user: directive
# UID 10001 is in safe non-system range
RUN groupadd -r -g 10001 openclaw && \
    useradd -r -u 10001 -g openclaw -s /bin/false -d /app openclaw

# ── Working directory ──────────────────────────────────────────────────────────

WORKDIR /app

# ── Install Python dependencies ────────────────────────────────────────────────

COPY requirements.txt .

# Install deps as root (before user switch)
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application code ──────────────────────────────────────────────────────

COPY app.py .

# ── Directory scaffold ─────────────────────────────────────────────────────────
# Pre-create mount points so they exist before docker-compose mounts tmpfs/volumes.
# Ownership must match the non-root UID so the app can write to them.

RUN mkdir -p \
        /openclaw/sessions \
        /openclaw/workspace \
        /openclaw/secrets \
        /openclaw/cache \
        /approle-creds \
        /tmp \
    && chown -R openclaw:openclaw \
        /openclaw \
        /approle-creds \
        /app \
        /tmp

# ── Copy entrypoint ────────────────────────────────────────────────────────────

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# We start as root so entrypoint can chown tmpfs mounts,
# then drop to the openclaw user for the actual app.
# Security enforced via: read-only rootfs, cap_drop ALL, no-new-privileges

# ── Runtime configuration ──────────────────────────────────────────────────────

EXPOSE 8300

# These are non-secret defaults — actual secrets come from OpenBao at runtime
ENV BAO_ADDR="http://openbao:8200"
ENV APPROLE_CREDS_PATH="/approle-creds"
ENV HEARTBEAT_INTERVAL="30"
ENV PYTHONUNBUFFERED="1"
ENV PYTHONDONTWRITEBYTECODE="1"

# Health check uses Python (no curl needed — keeps image minimal)
HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8300/health')" || exit 1

# ── Entrypoint ────────────────────────────────────────────────────────────────

CMD ["/entrypoint.sh"]
