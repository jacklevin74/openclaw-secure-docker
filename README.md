# OpenClaw Secure Docker Environment (TypeScript)

A production-grade, security-hardened Docker Compose setup that simulates
how OpenClaw (an autonomous AI agent) manages secrets, session data, and
long-term memory with zero tolerance for plaintext data on disk.

**TypeScript rewrite** of the original Python/Flask version. Drop-in replacement
with identical API contract and security guarantees.

**Stack:** TypeScript • Express • Node.js 22 • Fernet (native crypto) • OpenBao

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Docker Host                                                │
│                                                             │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │   OpenBao    │────▶│  Init Sidecar│                     │
│  │   :8200      │     │  (one-shot)  │                     │
│  └──────┬───────┘     └──────┬───────┘                     │
│         │                    │ AppRole creds                │
│         │                    ▼                              │
│         │           ┌────────────────────┐                 │
│         │           │  /approle-creds/   │                 │
│         │           │  (named volume)    │                 │
│         │           └────────┬───────────┘                 │
│         │                    │                              │
│         └──────────┐         │                              │
│     AppRole auth   │         │                              │
│     (token TTL 1h) │         │                              │
│                    ▼         ▼                              │
│           ┌─────────────────────────────────────┐          │
│           │  openclaw-app  :8300                 │          │
│           │  (Node.js 22 + Express + Fernet)     │          │
│           │                                      │          │
│           │  /openclaw/sessions/  ← tmpfs (RAM)  │          │
│           │  /openclaw/secrets/   ← tmpfs (RAM)  │          │
│           │  /openclaw/cache/     ← tmpfs (RAM)  │          │
│           │  /openclaw/workspace/ ← enc volume   │          │
│           └─────────────────────────────────────┘          │
│                                                             │
│  Volumes:                                                   │
│    workspace-data  ← Fernet-encrypted session data         │
│    approle-creds   ← role_id + secret_id (UUIDs only)      │
└─────────────────────────────────────────────────────────────┘
```

### Security Layers at a Glance

| Layer | What It Does |
|-------|-------------|
| **OpenBao AppRole** | Machine auth — no root token in app environment |
| **Fernet encryption** | All workspace writes encrypted before hitting disk |
| **tmpfs mounts** | Sessions/secrets/cache exist in RAM only — wiped on stop |
| **Dead man's switch** | Wipes in-memory Fernet key if OpenBao unreachable (3 checks) |
| **SIGTERM shred trap** | Auto-overwrites workspace files on container stop |
| **Non-root user** | App runs as UID 10001 (never root) |
| **Read-only rootfs** | Root filesystem is immutable at runtime |
| **No secrets in env/image** | Fernet key fetched live from OpenBao only |

---

## What's in OpenBao

```
kv/openclaw/encryption
  fernet_key        ← Fernet key (32 bytes, base64url) — crown jewel
  key_version       ← "1"
  created_at        ← ISO timestamp

kv/openclaw/api-keys
  anthropic_key     ← Simulated Anthropic API key
  openai_key        ← Simulated OpenAI API key
  telegram_token    ← Simulated Telegram bot token

kv/openclaw/config
  jwt_secret        ← JWT signing secret
  session_secret    ← Session HMAC secret
  workspace_path    ← "/openclaw/workspace"
  log_level         ← "INFO"
```

The **AppRole** (`openclaw-role`) has read-only access to these paths.
The app never sees the root token.

---

## Quick Start

```bash
# 1. Build TypeScript first (requires Node.js 22+)
cd app && npm install && npm run build && cd ..

# 2. Start everything
bash start.sh

# 3. Run security tests
bash test_secure.sh

# 4. Try the API
curl http://localhost:8300/health
curl http://localhost:8300/status | python3 -m json.tool

# Save an encrypted session
curl -X POST http://localhost:8300/session/save \
  -H "Content-Type: application/json" \
  -d '{"session_id": "my-session", "data": "sensitive agent memory"}'

# Load and decrypt it
curl http://localhost:8300/session/load/my-session

# Store an active session (RAM only)
curl -X POST http://localhost:8300/session/active \
  -H "Content-Type: application/json" \
  -d '{"session_id": "live-session", "data": "current conversation state"}'

# Secure delete
curl -X DELETE http://localhost:8300/session/my-session

# 5. Stop (SIGTERM → auto-shred fires)
bash stop.sh
```

---

## API Reference

### `GET /health`
Health check. Returns 200 if Fernet key is loaded and encryption is working.

```json
{
  "status": "healthy",
  "encryption": true,
  "fernet_key_source": "openbao (not hardcoded)",
  "sessions": {
    "active_count": 0,
    "workspace_count": 0
  },
  "storage": {
    "sessions_tmpfs": true,
    "secrets_tmpfs": true,
    "cache_tmpfs": true
  }
}
```

### `GET /status`
Detailed status including mount types, session counts, security info.
**No key material exposed.**

### `POST /session/save`
Encrypt a session with the Fernet key from OpenBao and write to workspace.

```json
// Request
{ "session_id": "sess-123", "data": "any string data" }

// Response
{
  "status": "saved",
  "session_id": "sess-123",
  "encrypted": true,
  "key_source": "openbao"
}
```

### `GET /session/load/<id>`
Decrypt and return a session from the workspace volume.

### `POST /session/active`
Store an active session in RAM (tmpfs) only. **Never persisted.**

```json
// Request
{ "session_id": "active-456", "data": "live conversation state" }
```

### `GET /session/active/<id>`
Retrieve an active session from RAM.

### `DELETE /session/<id>`
Secure delete: 3-pass overwrite (zeros → ones → 0xa5) + unlink.

---

## File Structure

```
openclaw-secure-docker-ts/
├── docker-compose.yml       ← Services, tmpfs, volumes, security opts
├── README.md                ← This file
├── start.sh                 ← Start + wait for health
├── stop.sh                  ← Stop (SIGTERM triggers shred)
├── test_secure.sh           ← 12-test security suite
│
├── app/
│   ├── Dockerfile           ← Node.js 22 slim, non-root, read-only rootfs
│   ├── entrypoint.sh        ← chown tmpfs + drop to non-root
│   ├── package.json         ← Dependencies (express only)
│   ├── tsconfig.json        ← TypeScript config
│   ├── src/
│   │   ├── index.ts         ← Entry point — startup + Express app
│   │   ├── state.ts         ← SecureState class — in-memory secrets/sessions
│   │   ├── crypto.ts        ← Fernet encryption/decryption (native crypto)
│   │   ├── openbao.ts       ← OpenBao API helpers + AppRole auth
│   │   ├── storage.ts       ← Workspace save/load/delete, secure shred
│   │   ├── mounts.ts        ← tmpfs mount detection from /proc/mounts
│   │   ├── routes.ts        ← Express route handlers
│   │   ├── deadman.ts       ← Dead man's switch background loop
│   │   └── types.ts         ← TypeScript interfaces
│   └── dist/                ← Compiled JavaScript (generated by `npm run build`)
│
└── init/
    └── setup.sh             ← OpenBao bootstrap: KV, Fernet key, AppRole
```

---

## Security Properties Tested

The test suite (`test_secure.sh`) verifies all 12 properties:

1. **tmpfs mounts** — sessions/secrets/cache are RAM-only
2. **Workspace encryption** — files are Fernet ciphertext, not plaintext
3. **Active session isolation** — active sessions don't leak to workspace
4. **Key provenance** — Fernet key comes from OpenBao, not env/image
5. **Secure delete** — DELETE overwrites before unlinking
6. **Round-trip integrity** — encrypt → decrypt returns original data
7. **Volume opacity** — workspace volume contains no plaintext payloads
8. **Non-root execution** — UID ≠ 0, no-new-privileges set
9. **No key leakage** — no API endpoint exposes key material
10. **AppRole auth** — root token absent from app environment
11. **SIGTERM shred** — container stop triggers workspace overwrite
12. **Read-only rootfs** — root filesystem is immutable

---

## Design Notes

### Why implement Fernet manually instead of using the npm `fernet` package?

The `fernet` npm package depends on `crypto-js`, which is a JavaScript
reimplementation of cryptographic primitives. We use Node.js built-in
`node:crypto` instead, which delegates to OpenSSL — battle-tested, hardware-
accelerated, and FIPS-capable. The implementation follows the
[Fernet spec](https://github.com/kr/fernet-spec) exactly:
AES-128-CBC + HMAC-SHA256.

### Fernet Compatibility

The TypeScript implementation is wire-compatible with Python's
`cryptography.fernet.Fernet`. A token encrypted by one can be decrypted
by the other. The init script generates a standard Fernet key (URL-safe
base64 of 32 random bytes) that works with both implementations.

### Why Node.js 22 slim (not Alpine)?

Alpine uses musl libc, which can cause subtle issues with Node.js native
crypto bindings. The slim image uses glibc and is only slightly larger.

---

## Reference

TypeScript rewrite of `built/openclaw-secure-docker/` (Python/Flask version).
Built on top of `built/openbao-test/` — see that directory for the base
OpenBao + AppRole + dead man's switch pattern.
