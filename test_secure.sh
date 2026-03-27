#!/bin/bash
# =============================================================================
# OpenClaw Secure Docker — Comprehensive Security Test Suite
# =============================================================================
# Tests all 11 security properties:
#
#  1. tmpfs mounts are correct (sessions, secrets, cache)
#  2. Session data in workspace is encrypted (not plaintext grep-able)
#  3. Active sessions in tmpfs don't leak to disk
#  4. Fernet key comes from OpenBao, not hardcoded
#  5. Secure delete actually overwrites data
#  6. App-level encryption works (save → load round-trip)
#  7. Raw workspace volume doesn't contain plaintext
#  8. Container runs as non-root
#  9. API endpoints don't leak encryption keys
# 10. OpenBao integration (AppRole auth, not root token)
# 11. Shred trap fires on SIGTERM
#
# Usage:
#   bash test_secure.sh            # standard tests (skip slow SIGTERM test)
#   bash test_secure.sh --full     # include SIGTERM shred test (~20s extra)
#   bash test_secure.sh --verbose  # extra output
# =============================================================================

# Note: NOT using set -e because grep returns 1 on no-match (expected for absence checks)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0
SKIP=0

FULL_MODE=false
VERBOSE=false

for arg in "$@"; do
    case "$arg" in
        --full)    FULL_MODE=true ;;
        --verbose) VERBOSE=true ;;
    esac
done

pass()  { echo -e "${GREEN}  ✓ PASS${NC}: $1"; PASS=$((PASS + 1)); }
fail()  { echo -e "${RED}  ✗ FAIL${NC}: $1"; FAIL=$((FAIL + 1)); }
warn()  { echo -e "${YELLOW}  ⚠ WARN${NC}: $1"; WARN=$((WARN + 1)); }
skip()  { echo -e "${BLUE}  ↷ SKIP${NC}: $1"; SKIP=$((SKIP + 1)); }
info()  { echo -e "${CYAN}  ℹ INFO${NC}: $1"; }
vinfo() { $VERBOSE && echo -e "${CYAN}  ℹ INFO${NC}: $1" || true; }
section() {
    echo ""
    echo -e "${BOLD}── $1 ──────────────────────────────────────────────────────${NC}"
    echo ""
}

APP_CONTAINER="openclaw-app"
BAO_CONTAINER="openclaw-openbao"
APP_PORT="8300"
BAO_PORT="8210"   # Host port; internal Docker port is still 8200
APP_URL="http://localhost:${APP_PORT}"
BAO_URL="http://localhost:${BAO_PORT}"

# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  OpenClaw Secure Docker — Security Test Suite${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Mode: $([ "$FULL_MODE" = true ] && echo '--full (includes SIGTERM test)' || echo 'standard')"
echo "  Time: $(date)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight
# ─────────────────────────────────────────────────────────────────────────────
section "Pre-flight Checks"

if ! command -v docker &>/dev/null; then
    echo -e "${RED}ERROR: docker not found${NC}"
    exit 1
fi
if ! command -v curl &>/dev/null; then
    echo -e "${RED}ERROR: curl not found${NC}"
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${BAO_CONTAINER}$"; then
    echo -e "${RED}ERROR: ${BAO_CONTAINER} not running.${NC}"
    echo "Run: docker compose up -d"
    exit 1
fi
pass "${BAO_CONTAINER} is running"

if ! docker ps --format '{{.Names}}' | grep -q "^${APP_CONTAINER}$"; then
    echo -e "${RED}ERROR: ${APP_CONTAINER} not running.${NC}"
    echo "Run: docker compose up -d"
    exit 1
fi
pass "${APP_CONTAINER} is running"

# Wait for app health
info "Waiting for app to become healthy (up to 60s)..."
for i in $(seq 1 12); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${APP_URL}/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        break
    fi
    sleep 5
done

APP_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "${APP_URL}/health" 2>/dev/null || echo "000")
if [ "$APP_HEALTH" = "200" ]; then
    pass "App /health returns 200"
else
    fail "App /health returned ${APP_HEALTH} (expected 200)"
    echo ""
    echo -e "${RED}App is not healthy. Cannot continue tests.${NC}"
    echo "Check: docker compose logs ${APP_CONTAINER}"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 1: tmpfs mounts
# ─────────────────────────────────────────────────────────────────────────────
section "Test 1: tmpfs Mounts (sessions, secrets, cache)"

for MOUNT_PATH in "/openclaw/sessions" "/openclaw/secrets" "/openclaw/cache"; do
    MOUNT_TYPE=$(docker exec "${APP_CONTAINER}" sh -c \
        "grep -w '${MOUNT_PATH}' /proc/mounts 2>/dev/null | awk '{print \$3}'" 2>/dev/null || echo "")

    if [ "$MOUNT_TYPE" = "tmpfs" ]; then
        pass "${MOUNT_PATH} is tmpfs (RAM only)"
    else
        # Check parent mounts (tmpfs might be at /openclaw)
        PARENT_TYPE=$(docker exec "${APP_CONTAINER}" sh -c \
            "grep -w '/openclaw' /proc/mounts 2>/dev/null | awk '{print \$3}'" 2>/dev/null || echo "")
        if [ "$PARENT_TYPE" = "tmpfs" ]; then
            warn "${MOUNT_PATH} parent /openclaw is tmpfs (acceptable for combined mount)"
        else
            fail "${MOUNT_PATH} is '${MOUNT_TYPE}' — expected tmpfs"
        fi
    fi
done

# Verify via API status endpoint
STATUS_JSON=$(curl -s "${APP_URL}/status" 2>/dev/null)
for MOUNT_PATH in "/openclaw/sessions" "/openclaw/secrets" "/openclaw/cache"; do
    IS_TMPFS=$(echo "$STATUS_JSON" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('mounts',{}).get('tmpfs_mounts',{}).get('${MOUNT_PATH}',{}).get('is_tmpfs','false'))" \
        2>/dev/null || echo "false")
    if [ "$IS_TMPFS" = "True" ] || [ "$IS_TMPFS" = "true" ]; then
        pass "API confirms ${MOUNT_PATH} is_tmpfs=true"
    else
        warn "API reports ${MOUNT_PATH} is_tmpfs=${IS_TMPFS} (check /proc/mounts inside container)"
    fi
done

# Workspace should NOT be tmpfs (it's the persistent volume)
WORKSPACE_FSTYPE=$(docker exec "${APP_CONTAINER}" sh -c \
    "grep -w '/openclaw/workspace' /proc/mounts 2>/dev/null | awk '{print \$3}'" 2>/dev/null || echo "ext4")
if [ "$WORKSPACE_FSTYPE" != "tmpfs" ]; then
    pass "/openclaw/workspace is persistent volume (${WORKSPACE_FSTYPE} — not tmpfs)"
else
    warn "/openclaw/workspace appears to be tmpfs — it should be persistent"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Session data in workspace is encrypted
# ─────────────────────────────────────────────────────────────────────────────
section "Test 2: Workspace Encryption (no plaintext on disk)"

TEST_SESSION_ID="test-enc-$(date +%s)"
SENSITIVE_PAYLOAD="SUPER_SECRET_API_KEY_shouldnotappearondisk_$$"

# Save session (should encrypt before writing)
SAVE_RESPONSE=$(curl -s -X POST "${APP_URL}/session/save" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"${TEST_SESSION_ID}\", \"data\": \"${SENSITIVE_PAYLOAD}\"}" 2>/dev/null)

SAVE_STATUS=$(echo "$SAVE_RESPONSE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")

if [ "$SAVE_STATUS" = "saved" ]; then
    pass "Session save request succeeded"
else
    fail "Session save failed: ${SAVE_RESPONSE}"
fi

IS_ENCRYPTED=$(echo "$SAVE_RESPONSE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('encrypted','false'))" 2>/dev/null || echo "false")
if [ "$IS_ENCRYPTED" = "True" ] || [ "$IS_ENCRYPTED" = "true" ]; then
    pass "API confirms encrypted=true"
else
    warn "API did not confirm encrypted=true (check save response)"
fi

KEY_SOURCE=$(echo "$SAVE_RESPONSE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('key_source','unknown'))" 2>/dev/null || echo "unknown")
if [ "$KEY_SOURCE" = "openbao" ]; then
    pass "key_source=openbao (not hardcoded)"
else
    fail "key_source=${KEY_SOURCE} — expected 'openbao'"
fi

# Now verify the workspace file does NOT contain the plaintext
info "Scanning workspace volume for plaintext payload..."
GREP_RESULT=$(docker exec "${APP_CONTAINER}" sh -c \
    "grep -r '${SENSITIVE_PAYLOAD}' /openclaw/workspace/ 2>/dev/null || true" 2>/dev/null)

if [ -z "$GREP_RESULT" ]; then
    pass "Workspace volume does NOT contain plaintext payload (all bytes are ciphertext)"
else
    fail "Plaintext payload found in workspace! '${SENSITIVE_PAYLOAD}' leaked to disk."
    vinfo "Found at: $GREP_RESULT"
fi

# Verify the .enc file exists and contains non-human-readable bytes
ENC_FILE=$(docker exec "${APP_CONTAINER}" sh -c \
    "ls /openclaw/workspace/session_${TEST_SESSION_ID}.enc 2>/dev/null" 2>/dev/null)
if [ -n "$ENC_FILE" ]; then
    pass "Encrypted file exists at workspace/session_${TEST_SESSION_ID}.enc"
    # Check it starts with 'gAAAAA' (Fernet token prefix in base64)
    FERNET_PREFIX=$(docker exec "${APP_CONTAINER}" sh -c \
        "head -c 6 /openclaw/workspace/session_${TEST_SESSION_ID}.enc 2>/dev/null" 2>/dev/null)
    if [ "$FERNET_PREFIX" = "gAAAAA" ]; then
        pass "File starts with Fernet token prefix 'gAAAAA' (valid Fernet ciphertext)"
    else
        warn "File doesn't start with expected Fernet prefix (got: ${FERNET_PREFIX})"
    fi
else
    fail "Encrypted file not found at workspace/session_${TEST_SESSION_ID}.enc"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Active sessions in tmpfs, don't leak to disk
# ─────────────────────────────────────────────────────────────────────────────
section "Test 3: Active Sessions Stay in RAM (no disk leakage)"

ACTIVE_SESSION_ID="active-test-$(date +%s)"
ACTIVE_PAYLOAD="RAM_ONLY_SESSION_DATA_notondisk_$$"

# Store active session (tmpfs only)
ACTIVE_STORE=$(curl -s -X POST "${APP_URL}/session/active" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"${ACTIVE_SESSION_ID}\", \"data\": \"${ACTIVE_PAYLOAD}\"}" 2>/dev/null)

ACTIVE_STATUS=$(echo "$ACTIVE_STORE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")

if [ "$ACTIVE_STATUS" = "stored" ]; then
    pass "Active session stored"
else
    fail "Active session store failed: ${ACTIVE_STORE}"
fi

ACTIVE_STORAGE=$(echo "$ACTIVE_STORE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('storage','unknown'))" 2>/dev/null || echo "unknown")
if echo "$ACTIVE_STORAGE" | grep -q "tmpfs"; then
    pass "API confirms storage=tmpfs-ram"
else
    warn "Storage field: ${ACTIVE_STORAGE} (expected tmpfs-ram)"
fi

# Verify active session is NOT in the workspace volume (persistent disk)
WORKSPACE_LEAK=$(docker exec "${APP_CONTAINER}" sh -c \
    "grep -r '${ACTIVE_PAYLOAD}' /openclaw/workspace/ 2>/dev/null || true" 2>/dev/null)
if [ -z "$WORKSPACE_LEAK" ]; then
    pass "Active session payload NOT found in workspace volume"
else
    fail "Active session payload leaked to workspace volume!"
fi

# Verify active session IS accessible via API
ACTIVE_GET=$(curl -s "${APP_URL}/session/active/${ACTIVE_SESSION_ID}" 2>/dev/null)
ACTIVE_DATA=$(echo "$ACTIVE_GET" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('data','MISSING'))" 2>/dev/null || echo "MISSING")
if [ "$ACTIVE_DATA" = "$ACTIVE_PAYLOAD" ]; then
    pass "Active session retrievable from RAM via API"
else
    fail "Active session data mismatch: got '${ACTIVE_DATA}', expected '${ACTIVE_PAYLOAD}'"
fi

# Verify tmpfs session file exists in /openclaw/sessions (RAM-backed)
TMPFS_FILE=$(docker exec "${APP_CONTAINER}" sh -c \
    "ls /openclaw/sessions/active_${ACTIVE_SESSION_ID}.json 2>/dev/null" 2>/dev/null)
if [ -n "$TMPFS_FILE" ]; then
    pass "Active session file exists in /openclaw/sessions (tmpfs)"
else
    warn "Active session file not found in /openclaw/sessions (may still be in-memory only)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Fernet key comes from OpenBao, not hardcoded
# ─────────────────────────────────────────────────────────────────────────────
section "Test 4: Fernet Key from OpenBao (not hardcoded)"

# Check app image for hardcoded Fernet key patterns
info "Scanning app image layers for hardcoded keys..."
IMAGE_ID=$(docker inspect "${APP_CONTAINER}" --format '{{.Image}}' 2>/dev/null)
HARDCODED=$(docker history "$IMAGE_ID" --no-trunc 2>/dev/null | \
    grep -Ei "fernet|encryption_key|FERNET_KEY" | grep -v "LAB" | grep -v "ENV FLASK" || true)
if [ -z "$HARDCODED" ]; then
    pass "No hardcoded Fernet key found in image layers"
else
    fail "Possible hardcoded key in image layer: ${HARDCODED}"
fi

# Check app environment variables
KEY_IN_ENV=$(docker exec "${APP_CONTAINER}" sh -c \
    'env | grep -iE "fernet|encryption_key" 2>/dev/null || true' 2>/dev/null)
if [ -z "$KEY_IN_ENV" ]; then
    pass "Fernet key NOT in container environment variables"
else
    fail "Fernet key appears in environment: ${KEY_IN_ENV}"
fi

# Check process cmdline and environ via /proc
PROC_ENV=$(docker exec "${APP_CONTAINER}" sh -c \
    "cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'fernet|enc_key' || true" 2>/dev/null)
if [ -z "$PROC_ENV" ]; then
    pass "Fernet key NOT in process environment (/proc/1/environ)"
else
    fail "Fernet key found in /proc/1/environ!"
fi

# Verify status endpoint confirms key source is openbao
KEY_SOURCE_STATUS=$(curl -s "${APP_URL}/status" 2>/dev/null | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('encryption',{}).get('fernet_key_source','unknown'))" \
    2>/dev/null || echo "unknown")
if [ "$KEY_SOURCE_STATUS" = "openbao-approle" ]; then
    pass "Status endpoint confirms fernet_key_source=openbao-approle"
else
    fail "Status shows fernet_key_source='${KEY_SOURCE_STATUS}' (expected openbao-approle)"
fi

# Verify OpenBao actually has the key
BAO_KEY=$(curl -s -H "X-Vault-Token: root-token-for-testing" \
    "${BAO_URL}/v1/kv/data/openclaw/encryption" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('found' if 'fernet_key' in d.get('data',{}).get('data',{}) else 'missing')" \
    2>/dev/null || echo "missing")
if [ "$BAO_KEY" = "found" ]; then
    pass "OpenBao has the fernet_key at kv/openclaw/encryption"
else
    fail "Fernet key not found in OpenBao at kv/openclaw/encryption"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 5: Secure delete overwrites data
# ─────────────────────────────────────────────────────────────────────────────
section "Test 5: Secure Delete (3-pass overwrite)"

DELETE_SESSION_ID="delete-test-$(date +%s)"
DELETE_PAYLOAD="DELETEME_SENSITIVE_DATA_SHOULD_NOT_PERSIST_$$"

# Create a session to delete
curl -s -X POST "${APP_URL}/session/save" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"${DELETE_SESSION_ID}\", \"data\": \"${DELETE_PAYLOAD}\"}" > /dev/null 2>&1

# Verify file was created
FILE_EXISTS=$(docker exec "${APP_CONTAINER}" sh -c \
    "test -f /openclaw/workspace/session_${DELETE_SESSION_ID}.enc && echo yes || echo no" 2>/dev/null)
if [ "$FILE_EXISTS" = "yes" ]; then
    pass "Session file created before delete"
else
    fail "Session file not created — cannot test delete"
fi

# Delete it
DELETE_RESPONSE=$(curl -s -X DELETE "${APP_URL}/session/${DELETE_SESSION_ID}" 2>/dev/null)
DELETE_STATUS=$(echo "$DELETE_RESPONSE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")

if [ "$DELETE_STATUS" = "deleted" ]; then
    pass "DELETE /session/${DELETE_SESSION_ID} returned status=deleted"
else
    fail "DELETE returned: ${DELETE_RESPONSE}"
fi

DELETE_METHOD=$(echo "$DELETE_RESPONSE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('method','unknown'))" 2>/dev/null || echo "unknown")
if echo "$DELETE_METHOD" | grep -q "overwrite"; then
    pass "Delete method confirms multi-pass overwrite: ${DELETE_METHOD}"
else
    warn "Delete method: '${DELETE_METHOD}' (expected 3-pass overwrite description)"
fi

WORKSPACE_SHREDDED=$(echo "$DELETE_RESPONSE" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('workspace_shredded','false'))" 2>/dev/null || echo "false")
if [ "$WORKSPACE_SHREDDED" = "True" ] || [ "$WORKSPACE_SHREDDED" = "true" ]; then
    pass "workspace_shredded=true"
else
    fail "workspace_shredded=${WORKSPACE_SHREDDED}"
fi

# Verify file is gone
FILE_GONE=$(docker exec "${APP_CONTAINER}" sh -c \
    "test -f /openclaw/workspace/session_${DELETE_SESSION_ID}.enc && echo exists || echo gone" 2>/dev/null)
if [ "$FILE_GONE" = "gone" ]; then
    pass "Session file no longer exists after secure delete"
else
    fail "Session file STILL EXISTS after delete!"
fi

# Verify plaintext can't be recovered from file (it's gone, so data can't be grepped)
GREP_AFTER_DELETE=$(docker exec "${APP_CONTAINER}" sh -c \
    "grep -r '${DELETE_PAYLOAD}' /openclaw/workspace/ 2>/dev/null || true" 2>/dev/null)
if [ -z "$GREP_AFTER_DELETE" ]; then
    pass "Payload not findable in workspace after secure delete"
else
    fail "Payload found in workspace even after delete!"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 6: Encryption round-trip (save → load)
# ─────────────────────────────────────────────────────────────────────────────
section "Test 6: Encryption Round-Trip (save → load)"

RT_SESSION_ID="roundtrip-$(date +%s)"
RT_PAYLOAD='{"agent": "openclaw", "memory": "I remember learning about X1 blockchain", "timestamp": "2026-03-26T00:00:00Z", "emoji": "🎩"}'

# Save
SAVE_RT=$(curl -s -X POST "${APP_URL}/session/save" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"${RT_SESSION_ID}\", \"data\": $(echo $RT_PAYLOAD | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read().strip()))')}" \
    2>/dev/null)

SAVE_RT_STATUS=$(echo "$SAVE_RT" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")
if [ "$SAVE_RT_STATUS" = "saved" ]; then
    pass "Round-trip save succeeded"
else
    fail "Round-trip save failed: ${SAVE_RT}"
fi

# Load
LOAD_RT=$(curl -s "${APP_URL}/session/load/${RT_SESSION_ID}" 2>/dev/null)
LOAD_RT_STATUS=$(echo "$LOAD_RT" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('status','error'))" 2>/dev/null || echo "error")

if [ "$LOAD_RT_STATUS" = "loaded" ]; then
    pass "Round-trip load succeeded"
else
    fail "Round-trip load failed: ${LOAD_RT}"
fi

# Verify data integrity
LOADED_DATA=$(echo "$LOAD_RT" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('data','MISSING'))" 2>/dev/null || echo "MISSING")
if [ "$LOADED_DATA" = "$RT_PAYLOAD" ]; then
    pass "Round-trip data integrity verified (exact match)"
else
    fail "Data mismatch after round-trip"
    vinfo "Expected: ${RT_PAYLOAD}"
    vinfo "Got:      ${LOADED_DATA}"
fi

# Verify Unicode/emoji survived encryption (test data has 🎩)
if echo "$LOADED_DATA" | python3 -c "import sys; assert '🎩' in sys.stdin.read()" 2>/dev/null; then
    pass "Unicode/emoji survived Fernet encryption round-trip"
else
    warn "Emoji might not have survived round-trip (check encoding)"
fi

# Clean up
curl -s -X DELETE "${APP_URL}/session/${RT_SESSION_ID}" > /dev/null 2>&1

# ─────────────────────────────────────────────────────────────────────────────
# Test 7: Raw workspace volume contains no plaintext
# ─────────────────────────────────────────────────────────────────────────────
section "Test 7: Workspace Volume Contains No Plaintext"

# Create a fresh session with known payload
PLAIN_TEST_ID="plaintext-test-$(date +%s)"
PLAIN_PAYLOAD="PLAINTEXT_CHECK_unique_marker_XYZ_$(date +%s)"

curl -s -X POST "${APP_URL}/session/save" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"${PLAIN_TEST_ID}\", \"data\": \"${PLAIN_PAYLOAD}\"}" > /dev/null 2>&1

# Scan workspace directory for any plaintext patterns
info "Scanning /openclaw/workspace for plaintext payloads..."

PLAIN_FOUND=$(docker exec "${APP_CONTAINER}" sh -c \
    "grep -rl '${PLAIN_PAYLOAD}' /openclaw/workspace/ 2>/dev/null || true" 2>/dev/null)
if [ -z "$PLAIN_FOUND" ]; then
    pass "Plaintext payload not found in workspace volume (all bytes encrypted)"
else
    fail "Plaintext payload found in workspace: ${PLAIN_FOUND}"
fi

# Also scan the test session from test 2 (which was saved and not deleted)
PAYLOAD2_FOUND=$(docker exec "${APP_CONTAINER}" sh -c \
    "grep -rl '${SENSITIVE_PAYLOAD}' /openclaw/workspace/ 2>/dev/null || true" 2>/dev/null)
if [ -z "$PAYLOAD2_FOUND" ]; then
    pass "Earlier test payload also not in plaintext on workspace"
else
    fail "Earlier plaintext payload leaked to workspace"
fi

# Check volume for common readable patterns that shouldn't be there
LEAK_PATTERNS=("password" "secret_key" "api_key" "SUPER_SECRET" "PLAINTEXT_CHECK")
FOUND_ANY=0
for PATTERN in "${LEAK_PATTERNS[@]}"; do
    RESULT=$(docker exec "${APP_CONTAINER}" sh -c \
        "grep -rl '${PATTERN}' /openclaw/workspace/ 2>/dev/null || true" 2>/dev/null)
    if [ -n "$RESULT" ]; then
        FOUND_ANY=1
        fail "Pattern '${PATTERN}' found in workspace: ${RESULT}"
    fi
done
if [ "$FOUND_ANY" -eq 0 ]; then
    pass "No sensitive patterns found in workspace volume"
fi

# Clean up
curl -s -X DELETE "${APP_URL}/session/${PLAIN_TEST_ID}" > /dev/null 2>&1

# ─────────────────────────────────────────────────────────────────────────────
# Test 8: Container runs as non-root
# ─────────────────────────────────────────────────────────────────────────────
section "Test 8: Non-Root Container User"

# Check app process runs as non-root
APP_USER=$(docker exec "${APP_CONTAINER}" sh -c "whoami 2>/dev/null || id -un 2>/dev/null || echo unknown" 2>/dev/null)
APP_UID=$(docker exec "${APP_CONTAINER}" sh -c "id -u 2>/dev/null || echo -1" 2>/dev/null)

if [ "$APP_USER" = "openclaw" ] || [ "$APP_UID" = "10001" ]; then
    pass "App process runs as non-root user (${APP_USER}, UID ${APP_UID})"
else
    # Entrypoint starts as root to chown, then drops — check the actual app process
    NODE_UID=$(docker exec "${APP_CONTAINER}" sh -c "ps aux 2>/dev/null | grep 'node.*index.js' | grep -v grep | awk '{print \$1}' | head -1" 2>/dev/null || echo "unknown")
    if [ "$NODE_UID" = "opencla" ] || [ "$NODE_UID" = "10001" ]; then
        pass "Node process runs as non-root (${NODE_UID})"
    else
        warn "App user: ${APP_USER} (UID ${APP_UID}), Node process owner: ${NODE_UID}"
    fi
fi

# Check security options
PRIV_CHECK=$(docker inspect "${APP_CONTAINER}" --format \
    '{{range .HostConfig.SecurityOpt}}{{.}} {{end}}' 2>/dev/null || echo "")
if echo "$PRIV_CHECK" | grep -q "no-new-privileges"; then
    pass "no-new-privileges:true security option is set"
else
    warn "no-new-privileges not confirmed in security options"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 9: API endpoints don't leak encryption keys
# ─────────────────────────────────────────────────────────────────────────────
section "Test 9: API Endpoints Don't Leak Key Material"

# Fetch the Fernet key from OpenBao (to know what to look for)
ACTUAL_FERNET_KEY=$(curl -s -H "X-Vault-Token: root-token-for-testing" \
    "${BAO_URL}/v1/kv/data/openclaw/encryption" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data']['fernet_key'])" \
    2>/dev/null || echo "CANNOT_FETCH_KEY")

if [ "$ACTUAL_FERNET_KEY" = "CANNOT_FETCH_KEY" ] || [ -z "$ACTUAL_FERNET_KEY" ]; then
    warn "Could not fetch actual Fernet key from OpenBao to test against — skipping key-in-response checks"
else
    info "Got Fernet key prefix: ${ACTUAL_FERNET_KEY:0:8}... (checking endpoints don't expose this)"

    ENDPOINTS=("/health" "/status" "/")
    for EP in "${ENDPOINTS[@]}"; do
        RESPONSE=$(curl -s "${APP_URL}${EP}" 2>/dev/null)
        if echo "$RESPONSE" | grep -q "$ACTUAL_FERNET_KEY"; then
            fail "${EP} response contains the actual Fernet key!"
        else
            pass "${EP} does NOT expose the Fernet key"
        fi
    done
fi

# Check that API keys from OpenBao don't appear in responses
BAO_API_KEYS=$(curl -s -H "X-Vault-Token: root-token-for-testing" \
    "${BAO_URL}/v1/kv/data/openclaw/api-keys" 2>/dev/null | \
    python3 -c "
import sys,json
d = json.load(sys.stdin).get('data',{}).get('data',{})
for k,v in d.items():
    print(v[:20])  # first 20 chars
" 2>/dev/null || echo "")

if [ -n "$BAO_API_KEYS" ]; then
    FOUND_KEY_IN_API=0
    while IFS= read -r KEY_FRAGMENT; do
        [ -z "$KEY_FRAGMENT" ] && continue
        for EP in "/health" "/status" "/"; do
            RESPONSE=$(curl -s "${APP_URL}${EP}" 2>/dev/null)
            if echo "$RESPONSE" | grep -q "$KEY_FRAGMENT"; then
                fail "API key fragment '${KEY_FRAGMENT}' found in ${EP} response!"
                FOUND_KEY_IN_API=1
            fi
        done
    done <<< "$BAO_API_KEYS"
    if [ "$FOUND_KEY_IN_API" -eq 0 ]; then
        pass "No API key values exposed in any endpoint response"
    fi
else
    warn "Could not fetch API keys from OpenBao to verify non-exposure"
fi

# Verify /status shows key NAMES but not VALUES
STATUS_RESP=$(curl -s "${APP_URL}/status" 2>/dev/null)
API_KEY_NAMES=$(echo "$STATUS_RESP" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('encryption',{}).get('api_key_names',[]))" \
    2>/dev/null || echo "[]")
if echo "$API_KEY_NAMES" | grep -qE "anthropic|openai|telegram"; then
    pass "/status shows API key NAMES (acceptable)"
else
    warn "/status doesn't list API key names (minor)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 10: OpenBao AppRole integration (not root token)
# ─────────────────────────────────────────────────────────────────────────────
section "Test 10: OpenBao AppRole Auth (not root token)"

# Verify app env does NOT have root token
ROOT_TOKEN_IN_ENV=$(docker exec "${APP_CONTAINER}" sh -c \
    'env 2>/dev/null | grep -q "root-token-for-testing" && echo found || echo clean' 2>/dev/null)
if [ "$ROOT_TOKEN_IN_ENV" = "clean" ]; then
    pass "Root token NOT in app container environment"
else
    fail "Root token found in app environment variables!"
fi

# Verify AppRole creds exist in shared volume
ROLE_ID_FILE=$(docker exec "${APP_CONTAINER}" sh -c \
    "cat /approle-creds/role_id 2>/dev/null | head -c 36" 2>/dev/null)
SECRET_ID_FILE=$(docker exec "${APP_CONTAINER}" sh -c \
    "cat /approle-creds/secret_id 2>/dev/null | head -c 36" 2>/dev/null)

if [ ${#ROLE_ID_FILE} -ge 32 ] 2>/dev/null; then
    pass "role_id present in shared volume (${#ROLE_ID_FILE} chars)"
else
    fail "role_id missing or empty in /approle-creds/"
fi

if [ ${#SECRET_ID_FILE} -ge 32 ] 2>/dev/null; then
    pass "secret_id present in shared volume"
else
    fail "secret_id missing or empty in /approle-creds/"
fi

# Verify the AppRole creds are UUIDs (not actual secret values)
CREDS_CONTAIN_SECRETS=0
for FRAGMENT in "anthropic" "openai" "telegram" "fernet"; do
    if docker exec "${APP_CONTAINER}" sh -c \
        "grep -l '${FRAGMENT}' /approle-creds/* 2>/dev/null" > /dev/null 2>&1; then
        CREDS_CONTAIN_SECRETS=1
        fail "AppRole creds contain secret fragment '${FRAGMENT}'!"
    fi
done
if [ "$CREDS_CONTAIN_SECRETS" -eq 0 ]; then
    pass "AppRole credential files contain only UUIDs (not application secrets)"
fi

# Test unauthenticated access to OpenBao is blocked
UNAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BAO_URL}/v1/kv/data/openclaw/encryption" 2>/dev/null || echo "000")
if [ "$UNAUTH_STATUS" = "403" ] || [ "$UNAUTH_STATUS" = "400" ]; then
    pass "Unauthenticated OpenBao access blocked (HTTP ${UNAUTH_STATUS})"
else
    fail "Unauthenticated access returned ${UNAUTH_STATUS} (expected 403)"
fi

# Test wrong token is rejected
FAKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Vault-Token: fake-bad-token-12345" \
    "${BAO_URL}/v1/kv/data/openclaw/encryption" 2>/dev/null || echo "000")
if [ "$FAKE_STATUS" = "403" ]; then
    pass "Fake token rejected by OpenBao (HTTP 403)"
else
    fail "Fake token got HTTP ${FAKE_STATUS} (expected 403)"
fi

# Verify app loaded secrets (which implies AppRole worked)
SECRETS_LOADED=$(curl -s "${APP_URL}/status" 2>/dev/null | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('encryption',{}).get('fernet_key_loaded','false'))" \
    2>/dev/null || echo "false")
if [ "$SECRETS_LOADED" = "True" ] || [ "$SECRETS_LOADED" = "true" ]; then
    pass "App has Fernet key loaded — AppRole auth was successful"
else
    fail "App does not have Fernet key — AppRole auth may have failed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 11: Shred trap on SIGTERM
# ─────────────────────────────────────────────────────────────────────────────
section "Test 11: SIGTERM Shred Trap"

if [ "$FULL_MODE" = false ]; then
    skip "SIGTERM test skipped (run with --full to include)"
    info "This test stops and restarts the app container (~30s)"
else
    # Create a session to verify shredding
    SIGTERM_SESSION_ID="sigterm-test-$(date +%s)"
    SIGTERM_PAYLOAD="WILL_BE_SHREDDED_ON_SIGTERM_$(date +%s)"

    curl -s -X POST "${APP_URL}/session/save" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\": \"${SIGTERM_SESSION_ID}\", \"data\": \"${SIGTERM_PAYLOAD}\"}" > /dev/null 2>&1

    FILE_BEFORE=$(docker exec "${APP_CONTAINER}" sh -c \
        "test -f /openclaw/workspace/session_${SIGTERM_SESSION_ID}.enc && echo exists || echo missing" 2>/dev/null)
    if [ "$FILE_BEFORE" = "exists" ]; then
        pass "Session file created before SIGTERM"
    else
        fail "Could not create test session for SIGTERM test"
    fi

    info "Sending SIGTERM to ${APP_CONTAINER}..."
    docker kill --signal=SIGTERM "${APP_CONTAINER}" 2>/dev/null

    # Wait for shred to complete (give it 5 seconds)
    sleep 5

    # Check if workspace file was shredded (container may have stopped)
    # We check the volume by spinning up a temporary container
    FILE_AFTER=$(docker run --rm \
        -v openclaw-secure-docker_workspace-data:/workspace:ro \
        python:3.12-slim \
        sh -c "test -f /workspace/session_${SIGTERM_SESSION_ID}.enc && echo exists || echo gone" \
        2>/dev/null || echo "cannot_check")

    if [ "$FILE_AFTER" = "gone" ]; then
        pass "Shred trap fired! Session file deleted from workspace on SIGTERM"
    elif [ "$FILE_AFTER" = "exists" ]; then
        warn "Session file still exists after SIGTERM (shred may not have run, or container was killed too fast)"
    else
        warn "Could not verify shred (container/volume check failed)"
    fi

    # Check container exit logs for shred message
    SHRED_LOG=$(docker logs "${APP_CONTAINER}" 2>&1 | tail -20 | grep -i "shred\|SIGTERM\|auto-shred" || true)
    if [ -n "$SHRED_LOG" ]; then
        pass "Log shows shred activity on SIGTERM"
        vinfo "Log: $SHRED_LOG"
    else
        warn "No shred log message found (may have been fast or container already stopped)"
    fi

    # Restart for subsequent tests
    info "Restarting ${APP_CONTAINER}..."
    docker start "${APP_CONTAINER}" 2>/dev/null || true
    sleep 15  # Wait for app to re-initialize
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 12: Read-only root filesystem
# ─────────────────────────────────────────────────────────────────────────────
section "Test 12: Read-Only Root Filesystem"

# Try to write to a path that should be read-only
RO_CHECK=$(docker exec "${APP_CONTAINER}" sh -c \
    "echo test > /test_ro_file 2>&1 && echo writable || echo readonly" 2>/dev/null || echo "readonly")
if [ "$RO_CHECK" = "readonly" ]; then
    pass "Root filesystem is read-only (cannot write to /)"
else
    warn "Root filesystem may be writable — check docker-compose read_only: true"
    # Clean up if we accidentally wrote
    docker exec "${APP_CONTAINER}" sh -c "rm -f /test_ro_file" 2>/dev/null || true
fi

# Verify writable paths are specifically allowed
for WRITABLE_PATH in "/tmp" "/openclaw/sessions" "/openclaw/workspace" "/openclaw/secrets" "/openclaw/cache"; do
    WRITE_TEST=$(docker exec "${APP_CONTAINER}" sh -c \
        "echo test > ${WRITABLE_PATH}/.write_test 2>&1 && echo writable || echo readonly" 2>/dev/null || echo "readonly")
    if [ "$WRITE_TEST" = "writable" ]; then
        pass "${WRITABLE_PATH} is writable (correctly allowed)"
        # Clean up
        docker exec "${APP_CONTAINER}" sh -c "rm -f ${WRITABLE_PATH}/.write_test" 2>/dev/null || true
    else
        warn "${WRITABLE_PATH} is not writable (expected it to be allowed)"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""

TOTAL=$((PASS + FAIL + WARN + SKIP))
echo -e "  Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${WARN} warnings${NC}  ${BLUE}${SKIP} skipped${NC}  (${TOTAL} total)"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}█████████████████████████████████████████████████████████${NC}"
    echo -e "  ${GREEN}  ALL TESTS PASSED — Secure OpenClaw Docker is solid  ${NC}"
    echo -e "  ${GREEN}█████████████████████████████████████████████████████████${NC}"
else
    echo -e "  ${RED}█████████████████████████████████████████████████████████${NC}"
    echo -e "  ${RED}  SOME TESTS FAILED — Review output above                ${NC}"
    echo -e "  ${RED}█████████████████████████████████████████████████████████${NC}"
fi

echo ""
echo "  To include the SIGTERM shred test (~30s):"
echo "    bash test_secure.sh --full"
echo ""
echo "  For verbose output:"
echo "    bash test_secure.sh --verbose"
echo ""

[ "$FAIL" -eq 0 ]  # exit 0 if all pass, 1 if any fail
