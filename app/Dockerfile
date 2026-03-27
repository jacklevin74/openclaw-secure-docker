# ──────────────────��──────────────────────────────────────────────────────────
# OpenClaw Secure App — Dockerfile (TypeScript/Node.js)
# ────────────────────────────────────────────────────────────���────────────────
# Security hardening:
#   - Multi-stage build (build stage has devDeps, production stage does not)
#   - Non-root user (UID 10001)
#   - Minimal slim base image (glibc for native crypto)
#   - No secrets in image layers or ENV
#   - Read-only root filesystem (enforced via docker-compose)
#   - Directories pre-created for tmpfs + volume mounts
#   - Node.js built-in crypto module for Fernet encryption
# ────────────────��────────────────────────────────────────────────────────────

# ── Build stage ─────────────────────��─────────────────────────────────────────
FROM node:22-slim AS builder

WORKDIR /build

# Copy package files and install all deps (including devDependencies for tsc)
COPY package.json package-lock.json* ./
RUN npm install

# Copy TypeScript source and compile
COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

# ── Production stage ────────────────────���───────────────────────────────��─────
FROM node:22-slim

LABEL maintainer="OpenClaw Secure Docker"
LABEL description="OpenClaw agent simulator with Fernet encryption, tmpfs sessions, OpenBao secrets (TypeScript)"

# ── System setup ──────────────────────────────────────────────���───────────────

# Install coreutils for shred fallback. Node 22 slim has glibc for native crypto.
RUN apt-get update && apt-get install -y --no-install-recommends \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with fixed UID/GID matching docker-compose user: directive
# UID 10001 is in safe non-system range
RUN groupadd -r -g 10001 openclaw && \
    useradd -r -u 10001 -g openclaw -s /bin/false -d /app openclaw

# ── Working directory ───────────────��──────────────────────────────────────────

WORKDIR /app

# ── Install Node.js production dependencies ───────────────────────────────────

COPY package.json package-lock.json* ./

# Install production deps only (no devDependencies in final image)
RUN npm install --omit=dev --ignore-scripts

# ── Copy compiled JavaScript from build stage ���────────────────────────────────

COPY --from=builder /build/dist/ ./dist/

# ── Directory scaffold ───────────────���─────────────────────────────────────────
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

# ── Copy entrypoint ──────────────────────��─────────────────────────────────────

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# We start as root so entrypoint can chown tmpfs mounts,
# then drop to the openclaw user for the actual app.
# Security enforced via: read-only rootfs, cap_drop ALL, no-new-privileges

# ── Runtime configuration ─────────────────���────────────────────────────────────

EXPOSE 8300

# These are non-secret defaults — actual secrets come from OpenBao at runtime
ENV BAO_ADDR="http://openbao:8200"
ENV APPROLE_CREDS_PATH="/approle-creds"
ENV HEARTBEAT_INTERVAL="30"
ENV NODE_ENV="production"

# Health check uses Node.js (no curl needed — keeps image minimal)
HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=3 \
    CMD node -e "fetch('http://localhost:8300/health').then(r=>{process.exit(r.ok?0:1)}).catch(()=>process.exit(1))" || exit 1

# ── Entrypoint ─────────────────────────────���────────────────��─────────────────

CMD ["/entrypoint.sh"]
