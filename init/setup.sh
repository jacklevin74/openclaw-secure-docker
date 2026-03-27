#!/bin/sh
# =============================================================================
# OpenBao Init Script — OpenClaw Secure Docker
# =============================================================================
# Extends the openbao-test pattern to also:
#   - Generate and store a Fernet encryption key for the OpenClaw app
#   - Store OpenClaw API keys and config
#   - Set up AppRole with access to the new secrets
#
# The Fernet key stored at kv/openclaw/encryption/fernet_key is the ONLY
# copy — the app fetches it at runtime and never writes it to disk.
# =============================================================================

set -e

echo "========================================="
echo "  OpenBao Init — OpenClaw Secure Docker"
echo "========================================="
echo "Target: $BAO_ADDR"

# ─────────────────────────────────────────────
# Step 1: Wait for OpenBao
# ─────────────────────────────────────────────
echo ""
echo "[1/7] Waiting for OpenBao to be ready..."

MAX_ATTEMPTS=30
ATTEMPT=0

until wget --quiet --tries=1 --spider "http://openbao:8200/v1/sys/health" 2>/dev/null; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
        echo "ERROR: OpenBao did not become ready after $MAX_ATTEMPTS attempts."
        exit 1
    fi
    echo "  Attempt $ATTEMPT/$MAX_ATTEMPTS — waiting 2s..."
    sleep 2
done

echo "  ✓ OpenBao is ready!"
bao status

# ─────────────────────────────────────────────
# Step 2: Enable KV v2 engine
# ─────────────────────────────────────────────
echo ""
echo "[2/7] Enabling KV v2 secrets engine at path 'kv/'..."

if bao secrets list | grep -q "^kv/"; then
    echo "  → kv/ already mounted, skipping."
else
    bao secrets enable -version=2 -path=kv kv
    echo "  ✓ KV v2 engine enabled at kv/"
fi

# ─────────────────────────────────────────────
# Step 3: Generate and store Fernet encryption key
# ─────────────────────────────────────────────
# This is the critical secret — the app uses this Fernet key to encrypt
# all session data before writing to the workspace volume. The key is:
#   - Generated here (never in the app image)
#   - Stored only in OpenBao
#   - Fetched at runtime by the app via AppRole auth
#   - Never written to any file on disk (tmpfs only during the fetch)
#
# Fernet key format: URL-safe base64-encoded 32 random bytes
# Must be exactly 44 characters: 32 bytes base64url encoded (43 chars) + padding (=)

# OpenBao Alpine image needs openssl. Install it.
echo ""
echo "[3/7] Installing OpenSSL and generating Fernet encryption key..."
apk add --no-cache openssl > /dev/null 2>&1 || true

# Generate 32 random bytes, base64url-encode for Fernet format
# Using /dev/urandom + base64 + tr for URL-safe encoding
RAW_B64=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_')
# Ensure exactly 44 chars with proper padding
if [ ${#RAW_B64} -eq 43 ]; then
    FERNET_KEY="${RAW_B64}="
elif [ ${#RAW_B64} -eq 44 ]; then
    FERNET_KEY="${RAW_B64}"
else
    # Pad or truncate to exactly 44
    FERNET_KEY="${RAW_B64}==="
    FERNET_KEY="$(echo "$FERNET_KEY" | head -c 44)"
fi

echo "  ✓ Fernet key generated (32 bytes, base64url-encoded)"
echo "    Key length: ${#FERNET_KEY} chars (expected 44)"

# Store the Fernet key in OpenBao
bao kv put kv/openclaw/encryption \
    fernet_key="$FERNET_KEY" \
    key_version="1" \
    created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "  ✓ Written: kv/openclaw/encryption (Fernet key)"
echo "    Key prefix: ${FERNET_KEY:0:8}... (first 8 chars shown)"

# ─────────────────────────────────────────────
# Step 4: Write OpenClaw app secrets
# ─────────────────────────────────────────────
echo ""
echo "[4/7] Writing OpenClaw app secrets..."

# Simulated API keys (replace with real values in production)
bao kv put kv/openclaw/api-keys \
    anthropic_key="sk-ant-demo-$(openssl rand -hex 16 2>/dev/null || echo 'demo-key')" \
    openai_key="sk-demo-$(openssl rand -hex 16 2>/dev/null || echo 'demo-key')" \
    telegram_token="$(openssl rand -hex 20 2>/dev/null || echo 'demo-token'):demo_bot_token"

echo "  ✓ Written: kv/openclaw/api-keys"

# App configuration
bao kv put kv/openclaw/config \
    jwt_secret="jwt-$(openssl rand -hex 32 2>/dev/null || echo 'demo-jwt-secret')" \
    session_secret="session-$(openssl rand -hex 16 2>/dev/null || echo 'demo-session')" \
    workspace_path="/openclaw/workspace" \
    sessions_path="/openclaw/sessions" \
    log_level="INFO"

echo "  ✓ Written: kv/openclaw/config"

# Verify
echo ""
echo "  Secrets written (keys only, no values):"
bao kv list kv/openclaw/ | sed 's/^/    /'

# ─────────────────────────────────────────────
# Step 5: Create OpenClaw policy
# ─────────────────────────────────────────────
echo ""
echo "[5/7] Creating OpenClaw app policy..."

cat > /tmp/openclaw-policy.hcl << 'POLICY_EOF'
# OpenClaw App Policy — least privilege access

# CRITICAL: Allow reading the Fernet encryption key
path "kv/data/openclaw/encryption" {
  capabilities = ["read"]
}

# Allow reading API keys (needed for agent operation)
path "kv/data/openclaw/api-keys" {
  capabilities = ["read"]
}

# Allow reading app config
path "kv/data/openclaw/config" {
  capabilities = ["read"]
}

# Allow listing what's available (for health checks)
path "kv/metadata/openclaw/*" {
  capabilities = ["list", "read"]
}

# Allow token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token self-lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
POLICY_EOF

bao policy write openclaw-policy /tmp/openclaw-policy.hcl
echo "  ✓ Policy 'openclaw-policy' created"

# ─────────────────────────────────────────────
# Step 6: Configure AppRole
# ─────────────────────────────────────────────
echo ""
echo "[6/7] Configuring AppRole authentication..."

if bao auth list | grep -q "^approle/"; then
    echo "  → approle already enabled, skipping."
else
    bao auth enable approle
    echo "  ✓ AppRole auth method enabled"
fi

bao write auth/approle/role/openclaw-role \
    token_policies="openclaw-policy" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    secret_id_ttl="24h" \
    secret_id_num_uses=0 \
    bind_secret_id=true

echo "  ✓ AppRole 'openclaw-role' created"
echo "    Policy: openclaw-policy (read: encryption key + api-keys + config)"
echo "    Token TTL: 1h (max 4h)"

# Fetch credentials
ROLE_ID=$(bao read -field=role_id auth/approle/role/openclaw-role/role-id)
SECRET_ID=$(bao write -field=secret_id -f auth/approle/role/openclaw-role/secret-id)

echo "  Role ID: $ROLE_ID"
echo "  Secret ID: [generated]"

# ─────────────────────────────────────────────
# Step 7: Save AppRole credentials to shared volume
# ─────────────────────────────────────────────
echo ""
echo "[7/7] Saving AppRole credentials to shared volume..."

mkdir -p /approle-creds
echo -n "$ROLE_ID"   > /approle-creds/role_id
echo -n "$SECRET_ID" > /approle-creds/secret_id
chmod 644 /approle-creds/role_id
chmod 644 /approle-creds/secret_id

echo "  ✓ Credentials saved to /approle-creds/"

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "========================================="
echo "  OpenBao Init Complete!"
echo "========================================="
echo ""
echo "Secrets in vault:"
echo "  kv/openclaw/encryption  — Fernet key (the crown jewel)"
echo "  kv/openclaw/api-keys    — Anthropic, OpenAI, Telegram"
echo "  kv/openclaw/config      — JWT secret, paths, log level"
echo ""
echo "Security guarantees:"
echo "  ✓ Fernet key generated fresh on every init run"
echo "  ✓ Key never written to disk outside OpenBao"
echo "  ✓ AppRole uses least-privilege policy"
echo "  ✓ App gets read-only access, no write/delete on vault"
echo ""
echo "App will fetch Fernet key at startup via AppRole auth."
echo "All session saves will be encrypted with this key."
echo ""
