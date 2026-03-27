"""
OpenClaw Secure Agent Simulator
================================
Demonstrates production-grade secrets and session management:

  Architecture:
    /openclaw/sessions/   — tmpfs (RAM) — active conversations
    /openclaw/workspace/  — encrypted named volume — persistent memory
    /openclaw/secrets/    — tmpfs (RAM) — fetched API keys
    /openclaw/cache/      — tmpfs (RAM) — model cache

  Security layers:
    1. Fernet encryption key fetched from OpenBao at startup (not hardcoded)
    2. Active sessions stored in tmpfs — never touch disk
    3. Long-term saves encrypted with Fernet before writing to workspace volume
    4. Dead man's switch — wipes in-memory secrets if OpenBao unreachable
    5. Auto-shred trap — overwrites workspace files on SIGTERM/SIGINT
    6. Non-root user + read-only root filesystem
    7. Secure delete (overwrite + unlink) via DELETE /session/<id>

  Endpoints:
    GET  /health                  — health status
    GET  /status                  — detailed status (mounts, encryption, counts)
    POST /session/save            — encrypt + save to workspace volume
    GET  /session/load/<id>       — decrypt + return from workspace
    POST /session/active          — store in RAM (tmpfs) only
    GET  /session/active/<id>     — retrieve from RAM
    DELETE /session/<id>          — secure delete (shred)

  Auth flow:
    AppRole login → short-lived token → fetch Fernet key → encrypt/decrypt sessions
"""

import os
import sys
import time
import signal
import threading
import logging
import json
import hashlib
import struct
import glob
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, request
from cryptography.fernet import Fernet, InvalidToken

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

BAO_ADDR          = os.environ.get("BAO_ADDR", "http://localhost:8200")
APPROLE_CREDS_PATH = os.environ.get("APPROLE_CREDS_PATH", "/approle-creds")
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))

# Mount paths
SESSIONS_PATH  = "/openclaw/sessions"   # tmpfs — active sessions (RAM)
WORKSPACE_PATH = "/openclaw/workspace"  # encrypted named volume
SECRETS_PATH   = "/openclaw/secrets"    # tmpfs — API keys (RAM)
CACHE_PATH     = "/openclaw/cache"      # tmpfs — model cache (RAM)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

app = Flask(__name__)


# ─────────────────────────────────────────────
# In-Memory State Store
# ─────────────────────────────────────────────

class SecureState:
    """
    Thread-safe state container for in-memory secrets and active sessions.

    The Fernet key is the crown jewel — it lives only in RAM (fetched from
    OpenBao at startup, never written to any file). All workspace writes
    are encrypted with this key before hitting the volume.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Secrets (from OpenBao)
        self._fernet_key: bytes | None = None     # raw Fernet key bytes
        self._fernet: Fernet | None = None        # initialized Fernet instance
        self._api_keys: dict = {}
        self._config: dict = {}

        # Token lifecycle
        self._token: str | None = None
        self._token_expires_at: float = 0.0

        # Active sessions (tmpfs / RAM only — never persist to disk)
        self._active_sessions: dict = {}          # session_id → data (plaintext)

        # Stats
        self._loaded_at: datetime | None = None
        self._openbao_healthy: bool = False
        self._last_health_check: str | None = None
        self._wipe_count: int = 0
        self._sessions_saved: int = 0
        self._sessions_loaded: int = 0

    # ── Token management ──────────────────────────────────────────────────────

    def set_token(self, token: str, ttl_seconds: int):
        with self._lock:
            self._token = token
            self._token_expires_at = time.time() + ttl_seconds - 60
        log.info(f"Token stored. TTL ~{ttl_seconds}s.")

    def get_token(self) -> str | None:
        with self._lock:
            return self._token

    def is_token_expired(self) -> bool:
        with self._lock:
            return time.time() >= self._token_expires_at

    # ── Secrets management ────────────────────────────────────────────────────

    def store_fernet_key(self, key_b64: str):
        """Store the Fernet key in memory and initialize the Fernet instance."""
        with self._lock:
            self._fernet_key = key_b64.encode() if isinstance(key_b64, str) else key_b64
            self._fernet = Fernet(self._fernet_key)
            self._loaded_at = datetime.now(timezone.utc)
        log.info("Fernet encryption key loaded into memory.")

    def store_api_keys(self, keys: dict):
        with self._lock:
            self._api_keys = dict(keys)
        log.info(f"API keys stored ({len(keys)} keys).")

    def store_config(self, config: dict):
        with self._lock:
            self._config = dict(config)
        log.info(f"Config stored ({len(config)} keys).")

    def has_fernet(self) -> bool:
        with self._lock:
            return self._fernet is not None

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a string with the Fernet key. Raises if key not loaded."""
        with self._lock:
            if self._fernet is None:
                raise RuntimeError("Fernet key not loaded — cannot encrypt")
            data = plaintext.encode() if isinstance(plaintext, str) else plaintext
            return self._fernet.encrypt(data)

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt Fernet ciphertext. Raises InvalidToken if tampered."""
        with self._lock:
            if self._fernet is None:
                raise RuntimeError("Fernet key not loaded — cannot decrypt")
            ct = ciphertext if isinstance(ciphertext, bytes) else ciphertext.encode()
            return self._fernet.decrypt(ct).decode()

    def wipe_secrets(self):
        """
        Atomically wipe all secrets from memory.
        Called by dead man's switch when OpenBao becomes unreachable.
        """
        with self._lock:
            self._fernet_key = None
            self._fernet = None
            self._api_keys.clear()
            self._config.clear()
            self._token = None
            self._token_expires_at = 0.0
            self._loaded_at = None
            self._wipe_count += 1
        log.warning(
            f"💀 DEAD MAN'S SWITCH — wiped all secrets from memory "
            f"(wipe #{self._wipe_count})"
        )

    def has_secrets(self) -> bool:
        with self._lock:
            return self._fernet is not None

    def set_health(self, healthy: bool):
        with self._lock:
            self._openbao_healthy = healthy
            self._last_health_check = datetime.now(timezone.utc).isoformat()

    # ── Active sessions (RAM / tmpfs only) ───────────────────────────────────

    def store_active_session(self, session_id: str, data: str):
        """
        Store a session in tmpfs. This data NEVER touches the workspace volume.
        Lost on container restart — use /session/save for persistence.
        """
        with self._lock:
            self._active_sessions[session_id] = {
                "data": data,
                "stored_at": datetime.now(timezone.utc).isoformat(),
                "storage": "tmpfs-ram",
            }
        # Also write to the actual tmpfs path for dual-layer guarantee
        session_file = Path(SESSIONS_PATH) / f"active_{session_id}.json"
        try:
            session_file.parent.mkdir(parents=True, exist_ok=True)
            session_file.write_text(json.dumps({"data": data, "session_id": session_id}))
            log.info(f"Active session '{session_id}' stored in RAM (tmpfs).")
        except Exception as e:
            log.warning(f"Could not write active session to tmpfs path: {e}")

    def get_active_session(self, session_id: str) -> dict | None:
        with self._lock:
            return self._active_sessions.get(session_id)

    def delete_active_session(self, session_id: str) -> bool:
        with self._lock:
            existed = session_id in self._active_sessions
            self._active_sessions.pop(session_id, None)
        # Also remove from tmpfs
        session_file = Path(SESSIONS_PATH) / f"active_{session_id}.json"
        secure_delete(str(session_file))
        return existed

    def active_session_count(self) -> int:
        with self._lock:
            return len(self._active_sessions)

    def increment_saved(self):
        with self._lock:
            self._sessions_saved += 1

    def increment_loaded(self):
        with self._lock:
            self._sessions_loaded += 1

    def status_summary(self) -> dict:
        with self._lock:
            return {
                "fernet_loaded": self._fernet is not None,
                "api_keys_loaded": bool(self._api_keys),
                "config_loaded": bool(self._config),
                "api_key_names": list(self._api_keys.keys()),
                "loaded_at": self._loaded_at.isoformat() if self._loaded_at else None,
                "openbao_healthy": self._openbao_healthy,
                "last_health_check": self._last_health_check,
                "wipe_count": self._wipe_count,
                "active_session_count": len(self._active_sessions),
                "sessions_saved": self._sessions_saved,
                "sessions_loaded": self._sessions_loaded,
            }


# Global state
state = SecureState()


# ─────────────────────────────────────────────
# Secure Delete
# ─────────────────────────────────────────────

def secure_delete(filepath: str) -> bool:
    """
    Securely delete a file by overwriting it with zeros before unlinking.

    This is the software equivalent of a shred. Note: on SSDs/flash, the OS
    may not guarantee that zeroes overwrite the same physical cells — but this
    is the best we can do without hardware-level secure erase.

    For tmpfs (RAM), any write + unlink effectively destroys the data since
    there's no underlying persistent storage.

    Returns True if file was deleted, False if it didn't exist.
    """
    path = Path(filepath)
    if not path.exists():
        return False

    try:
        file_size = path.stat().st_size
        if file_size > 0:
            with open(str(path), "r+b") as f:
                # Pass 1: overwrite with zeros
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())

                # Pass 2: overwrite with ones
                f.seek(0)
                f.write(b'\xff' * file_size)
                f.flush()
                os.fsync(f.fileno())

                # Pass 3: overwrite with random-ish pattern
                f.seek(0)
                f.write(b'\xa5' * file_size)
                f.flush()
                os.fsync(f.fileno())

        path.unlink()
        log.info(f"Secure delete: {filepath} ({file_size} bytes, 3-pass overwrite)")
        return True
    except Exception as e:
        log.error(f"Secure delete failed for {filepath}: {e}")
        # Best effort: try regular unlink
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def shred_workspace():
    """
    Overwrite and delete all files in the workspace volume.
    Called from SIGTERM trap (dead man's switch on container stop).
    """
    workspace = Path(WORKSPACE_PATH)
    if not workspace.exists():
        return

    log.warning("🔥 AUTO-SHRED: Overwriting all workspace files...")
    count = 0
    for filepath in workspace.rglob("*"):
        if filepath.is_file():
            secure_delete(str(filepath))
            count += 1

    log.warning(f"🔥 AUTO-SHRED: {count} files shredded from workspace.")


# ─────────────────────────────────────────────
# SIGTERM / SIGINT Handler (auto-shred trap)
# ─────────────────────────────────────────────

def _shutdown_handler(signum, frame):
    """
    Trap SIGTERM and SIGINT.
    Before exiting, wipe in-memory secrets and shred workspace files.
    This ensures no plaintext data survives container stop.
    """
    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    log.warning(f"⚡ {sig_name} received — triggering auto-shred and shutdown...")

    # 1. Wipe in-memory secrets immediately
    state.wipe_secrets()

    # 2. Shred workspace files
    shred_workspace()

    # 3. Clean up active session tmpfs files
    sessions_dir = Path(SESSIONS_PATH)
    if sessions_dir.exists():
        for f in sessions_dir.glob("*.json"):
            secure_delete(str(f))
        log.info("Active session tmpfs files wiped.")

    log.warning("Shutdown complete. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGTERM, _shutdown_handler)
signal.signal(signal.SIGINT, _shutdown_handler)


# ─────────────────────────────────────────────
# Mount Info Helpers
# ─────────────────────────────────────────────

def get_mount_info() -> dict:
    """Parse /proc/mounts to check which paths are on tmpfs."""
    mounts = {}
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mounts[parts[1]] = {
                        "device": parts[0],
                        "fstype": parts[2],
                        "options": parts[3] if len(parts) > 3 else "",
                    }
    except Exception:
        pass

    result = {}
    for path in [SESSIONS_PATH, SECRETS_PATH, CACHE_PATH, WORKSPACE_PATH]:
        if path in mounts:
            result[path] = mounts[path]
        else:
            # Check parents
            p = Path(path)
            while p != p.parent:
                if str(p) in mounts:
                    result[path] = {**mounts[str(p)], "mounted_at_parent": str(p)}
                    break
                p = p.parent
            else:
                result[path] = {"fstype": "unknown", "device": "unknown"}

    return result


def is_tmpfs(path: str) -> bool:
    """Check if a path is on a tmpfs mount."""
    info = get_mount_info()
    entry = info.get(path, {})
    return entry.get("fstype") == "tmpfs"


# ─────────────────────────────────────────────
# OpenBao API Helpers
# ─────────────────────────────────────────────

def bao_get(path: str, token: str) -> dict:
    url = f"{BAO_ADDR}/v1/{path}"
    r = requests.get(url, headers={"X-Vault-Token": token}, timeout=5)
    r.raise_for_status()
    return r.json()


def bao_post(path: str, data: dict, token: str = None) -> dict:
    url = f"{BAO_ADDR}/v1/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    r = requests.post(url, json=data, headers=headers, timeout=5)
    r.raise_for_status()
    return r.json()


def check_openbao_health() -> bool:
    try:
        r = requests.get(f"{BAO_ADDR}/v1/sys/health", timeout=3)
        return r.status_code in (200, 429)
    except Exception:
        return False


# ─────────────────────────────────────────────
# AppRole Authentication
# ─────────────────────────────────────────────

def read_approle_creds() -> tuple[str, str]:
    role_id   = Path(APPROLE_CREDS_PATH, "role_id").read_text().strip()
    secret_id = Path(APPROLE_CREDS_PATH, "secret_id").read_text().strip()
    return role_id, secret_id


def authenticate_approle() -> str:
    """Authenticate via AppRole and return a short-lived token."""
    log.info("Authenticating via AppRole...")
    role_id, secret_id = read_approle_creds()

    resp = bao_post("auth/approle/login", {"role_id": role_id, "secret_id": secret_id})
    token = resp["auth"]["client_token"]
    ttl   = resp["auth"]["lease_duration"]
    policies = resp["auth"]["policies"]

    log.info(f"AppRole auth OK. Policies: {policies}. Token TTL: {ttl}s")
    state.set_token(token, ttl)
    return token


def renew_token(token: str) -> bool:
    try:
        resp = bao_post("auth/token/renew-self", {}, token=token)
        state.set_token(token, resp["auth"]["lease_duration"])
        log.info("Token renewed.")
        return True
    except Exception as e:
        log.error(f"Token renewal failed: {e}")
        return False


# ─────────────────────────────────────────────
# Secrets Loading
# ─────────────────────────────────────────────

def fetch_all_secrets(token: str):
    """
    Fetch Fernet key + API keys + config from OpenBao.
    All data stays in RAM — nothing written to disk.

    The Fernet key at kv/openclaw/encryption is the most critical:
    it's used to encrypt/decrypt all session data written to the workspace volume.
    """
    # 1. Fernet encryption key (crown jewel)
    resp = bao_get("kv/data/openclaw/encryption", token)
    fernet_key = resp["data"]["data"]["fernet_key"]
    state.store_fernet_key(fernet_key)
    log.info("✓ Fernet encryption key loaded from OpenBao")

    # 2. API keys
    resp = bao_get("kv/data/openclaw/api-keys", token)
    state.store_api_keys(resp["data"]["data"])
    log.info("✓ API keys loaded from OpenBao")

    # 3. Config
    resp = bao_get("kv/data/openclaw/config", token)
    state.store_config(resp["data"]["data"])
    log.info("✓ Config loaded from OpenBao")

    # Write a non-sensitive manifest to the secrets tmpfs path
    _write_secrets_manifest()


def _write_secrets_manifest():
    """Write a non-sensitive manifest to /openclaw/secrets (tmpfs)."""
    try:
        os.makedirs(SECRETS_PATH, exist_ok=True)
        manifest = {
            "loaded_at": datetime.now(timezone.utc).isoformat(),
            "secrets_loaded": ["fernet_key", "api-keys", "config"],
            "note": "Actual secret values are in-memory only — not in this file",
            "storage": "tmpfs (RAM only)"
        }
        manifest_path = Path(SECRETS_PATH) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        log.info(f"Secrets manifest written to {manifest_path} (tmpfs)")
    except Exception as e:
        log.warning(f"Could not write secrets manifest: {e}")


# ─────────────────────────────────────────────
# Session Storage — Workspace (encrypted)
# ─────────────────────────────────────────────

def workspace_save(session_id: str, data: str) -> str:
    """
    Encrypt data with Fernet key (from OpenBao) and save to workspace volume.

    Security guarantee: the workspace volume contains ONLY ciphertext.
    The Fernet key is never written to the volume — it lives in RAM only.
    Without the key, the ciphertext is opaque.

    Returns the path where the encrypted file was saved.
    """
    if not state.has_fernet():
        raise RuntimeError("Fernet key not available — cannot save session")

    workspace = Path(WORKSPACE_PATH)
    workspace.mkdir(parents=True, exist_ok=True)

    # Encrypt
    ciphertext = state.encrypt(data)

    # Save ciphertext to workspace
    session_file = workspace / f"session_{session_id}.enc"
    session_file.write_bytes(ciphertext)

    state.increment_saved()
    log.info(
        f"Session '{session_id}' encrypted and saved to workspace "
        f"({len(ciphertext)} bytes ciphertext)"
    )
    return str(session_file)


def workspace_load(session_id: str) -> str:
    """
    Load and decrypt a session from the workspace volume.

    Raises FileNotFoundError if session doesn't exist.
    Raises cryptography.fernet.InvalidToken if ciphertext is tampered.
    """
    if not state.has_fernet():
        raise RuntimeError("Fernet key not available — cannot decrypt session")

    session_file = Path(WORKSPACE_PATH) / f"session_{session_id}.enc"
    if not session_file.exists():
        raise FileNotFoundError(f"Session '{session_id}' not found in workspace")

    ciphertext = session_file.read_bytes()
    plaintext  = state.decrypt(ciphertext)

    state.increment_loaded()
    log.info(f"Session '{session_id}' decrypted from workspace ({len(ciphertext)} bytes)")
    return plaintext


def workspace_delete(session_id: str) -> bool:
    """
    Securely delete a session from the workspace volume.
    Overwrites with zeros/ones/pattern before unlinking.
    """
    session_file = Path(WORKSPACE_PATH) / f"session_{session_id}.enc"
    deleted = secure_delete(str(session_file))
    if deleted:
        log.info(f"Session '{session_id}' securely deleted from workspace.")
    return deleted


def workspace_session_count() -> int:
    """Count encrypted session files in the workspace."""
    workspace = Path(WORKSPACE_PATH)
    if not workspace.exists():
        return 0
    return len(list(workspace.glob("session_*.enc")))


# ─────────────────────────────────────────────
# Dead Man's Switch
# ─────────────────────────────────────────────

def dead_mans_switch():
    """
    Background thread: check OpenBao health every HEARTBEAT_INTERVAL seconds.
    If OpenBao is unreachable for 3 consecutive checks, wipe all secrets.
    If OpenBao comes back, re-authenticate and re-fetch secrets.
    """
    log.info(f"Dead man's switch started. Interval: {HEARTBEAT_INTERVAL}s")
    consecutive_failures = 0
    MAX_FAILURES = 3

    while True:
        time.sleep(HEARTBEAT_INTERVAL)

        healthy = check_openbao_health()
        state.set_health(healthy)

        if healthy:
            consecutive_failures = 0

            if not state.has_secrets():
                log.info("OpenBao back online — re-fetching secrets...")
                try:
                    token = authenticate_approle()
                    fetch_all_secrets(token)
                    log.info("Secrets re-fetched after recovery.")
                except Exception as e:
                    log.error(f"Re-fetch failed: {e}")
            elif state.is_token_expired():
                token = state.get_token()
                if token:
                    log.info("Token near expiry — renewing...")
                    if not renew_token(token):
                        try:
                            token = authenticate_approle()
                            fetch_all_secrets(token)
                        except Exception as e:
                            log.error(f"Re-auth after token expiry failed: {e}")
        else:
            consecutive_failures += 1
            log.warning(
                f"OpenBao health check failed "
                f"({consecutive_failures}/{MAX_FAILURES})"
            )
            if consecutive_failures >= MAX_FAILURES:
                log.error("OpenBao unreachable — triggering dead man's switch!")
                state.wipe_secrets()
                consecutive_failures = 0


# ─────────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────────

@app.route("/health")
def health():
    """
    Health check. Returns 200 if Fernet key is loaded and sessions work.
    Never exposes key material.
    """
    if not state.has_fernet():
        return jsonify({
            "status": "unhealthy",
            "reason": "Fernet key not loaded (OpenBao unreachable or startup failed)",
            "encryption": False,
        }), 503

    return jsonify({
        "status": "healthy",
        "encryption": True,
        "fernet_key_source": "openbao (not hardcoded)",
        "sessions": {
            "active_count":    state.active_session_count(),
            "workspace_count": workspace_session_count(),
        },
        "storage": {
            "sessions_tmpfs":  is_tmpfs(SESSIONS_PATH),
            "secrets_tmpfs":   is_tmpfs(SECRETS_PATH),
            "cache_tmpfs":     is_tmpfs(CACHE_PATH),
        }
    }), 200


@app.route("/status")
def status():
    """Detailed status — mounts, encryption, session counts. No key material."""
    summary = state.status_summary()
    mount_info = get_mount_info()

    # Verify each expected tmpfs mount
    mount_checks = {}
    for path in [SESSIONS_PATH, SECRETS_PATH, CACHE_PATH]:
        info = mount_info.get(path, {})
        mount_checks[path] = {
            "fstype":   info.get("fstype", "unknown"),
            "is_tmpfs": info.get("fstype") == "tmpfs",
            "device":   info.get("device", "unknown"),
        }

    workspace_info = mount_info.get(WORKSPACE_PATH, {})

    return jsonify({
        "app":       "openclaw-secure-agent",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "openbao": {
            "address":           BAO_ADDR,
            "reachable":         check_openbao_health(),
            "last_health_check": summary["last_health_check"],
            "healthy":           summary["openbao_healthy"],
        },
        "encryption": {
            "fernet_key_loaded": summary["fernet_loaded"],
            "fernet_key_source": "openbao-approle" if summary["fernet_loaded"] else "not-loaded",
            "api_keys_loaded":   summary["api_keys_loaded"],
            "api_key_names":     summary["api_key_names"],  # names only, no values
        },
        "sessions": {
            "active_count":    summary["active_session_count"],
            "workspace_count": workspace_session_count(),
            "sessions_saved":  summary["sessions_saved"],
            "sessions_loaded": summary["sessions_loaded"],
        },
        "mounts": {
            "tmpfs_mounts": mount_checks,
            "workspace": {
                "path":     WORKSPACE_PATH,
                "fstype":   workspace_info.get("fstype", "unknown"),
                "device":   workspace_info.get("device", "unknown"),
                "note":     "Named volume — app-level Fernet encryption applied",
            },
        },
        "dead_mans_switch": {
            "heartbeat_interval_s": HEARTBEAT_INTERVAL,
            "wipe_count":           summary["wipe_count"],
            "description":          "Wipes Fernet key + secrets if OpenBao unreachable for 3 checks",
        },
        "security": {
            "user": os.environ.get("USER", "unknown"),
            "uid":  os.getuid(),
            "gid":  os.getgid(),
            "shred_on_exit":  True,
            "no_disk_secrets": True,
        },
    }), 200


@app.route("/session/save", methods=["POST"])
def session_save():
    """
    Save a session to the encrypted workspace volume.

    Request body: {"session_id": "...", "data": "..."}

    The data is encrypted with the Fernet key fetched from OpenBao
    before any bytes hit the workspace volume. The volume never
    contains plaintext.
    """
    if not state.has_fernet():
        return jsonify({"error": "Encryption not available — OpenBao unreachable"}), 503

    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    session_id = body.get("session_id", "").strip()
    data       = body.get("data", "")

    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    if not data:
        return jsonify({"error": "data is required"}), 400

    # Validate session_id (alphanumeric + hyphens only to prevent path traversal)
    import re
    if not re.match(r'^[a-zA-Z0-9_\-]{1,128}$', session_id):
        return jsonify({"error": "session_id must be alphanumeric (hyphens/underscores ok), max 128 chars"}), 400

    try:
        filepath = workspace_save(session_id, data)
        return jsonify({
            "status":     "saved",
            "session_id": session_id,
            "storage":    "workspace (encrypted)",
            "encrypted":  True,
            "key_source": "openbao",
            "note":       "Data encrypted with Fernet before disk write",
        }), 200
    except Exception as e:
        log.error(f"Session save failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/session/load/<session_id>")
def session_load(session_id: str):
    """
    Load and decrypt a session from the workspace volume.

    Returns the plaintext data. The Fernet key is used to decrypt
    the ciphertext read from the volume.
    """
    if not state.has_fernet():
        return jsonify({"error": "Decryption not available — OpenBao unreachable"}), 503

    import re
    if not re.match(r'^[a-zA-Z0-9_\-]{1,128}$', session_id):
        return jsonify({"error": "Invalid session_id"}), 400

    try:
        data = workspace_load(session_id)
        return jsonify({
            "status":     "loaded",
            "session_id": session_id,
            "data":       data,
            "source":     "workspace (decrypted)",
        }), 200
    except FileNotFoundError:
        return jsonify({"error": f"Session '{session_id}' not found"}), 404
    except InvalidToken:
        return jsonify({"error": "Decryption failed — data tampered or wrong key"}), 422
    except Exception as e:
        log.error(f"Session load failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/session/active", methods=["POST"])
def session_active_store():
    """
    Store an active session in RAM (tmpfs) only.

    This data is never written to the workspace volume.
    It exists only in:
      - Python process memory (dict)
      - tmpfs filesystem (/openclaw/sessions — RAM mapped, not disk)

    Lost on container restart. Use /session/save for persistence.
    """
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    session_id = body.get("session_id", "").strip()
    data       = body.get("data", "")

    if not session_id:
        return jsonify({"error": "session_id is required"}), 400

    import re
    if not re.match(r'^[a-zA-Z0-9_\-]{1,128}$', session_id):
        return jsonify({"error": "Invalid session_id"}), 400

    state.store_active_session(session_id, data)
    return jsonify({
        "status":     "stored",
        "session_id": session_id,
        "storage":    "tmpfs-ram (not persisted)",
        "encrypted":  False,
        "note":       "Use /session/save for encrypted persistence across restarts",
    }), 200


@app.route("/session/active/<session_id>")
def session_active_get(session_id: str):
    """Retrieve an active session from RAM."""
    import re
    if not re.match(r'^[a-zA-Z0-9_\-]{1,128}$', session_id):
        return jsonify({"error": "Invalid session_id"}), 400

    session = state.get_active_session(session_id)
    if session is None:
        return jsonify({"error": f"Active session '{session_id}' not found (may have been wiped)"}), 404

    return jsonify({
        "status":     "found",
        "session_id": session_id,
        "data":       session["data"],
        "stored_at":  session["stored_at"],
        "storage":    "tmpfs-ram",
    }), 200


@app.route("/session/<session_id>", methods=["DELETE"])
def session_delete(session_id: str):
    """
    Securely delete a session (both workspace and active).

    Workspace file: 3-pass overwrite (zeros, ones, pattern) + unlink.
    Active session: removed from memory dict + tmpfs file wiped.
    """
    import re
    if not re.match(r'^[a-zA-Z0-9_\-]{1,128}$', session_id):
        return jsonify({"error": "Invalid session_id"}), 400

    workspace_deleted = workspace_delete(session_id)
    active_deleted    = state.delete_active_session(session_id)

    if not workspace_deleted and not active_deleted:
        return jsonify({"error": f"Session '{session_id}' not found"}), 404

    return jsonify({
        "status":             "deleted",
        "session_id":         session_id,
        "workspace_shredded": workspace_deleted,
        "active_wiped":       active_deleted,
        "method":             "3-pass overwrite (zeros, ones, 0xa5) + unlink",
    }), 200


@app.route("/")
def index():
    return jsonify({
        "app": "OpenClaw Secure Agent Simulator",
        "version": "1.0.0",
        "endpoints": {
            "GET  /health":               "Health check (encryption + mount status)",
            "GET  /status":               "Detailed status (no key material exposed)",
            "POST /session/save":         "Encrypt + save session to workspace volume",
            "GET  /session/load/<id>":    "Decrypt + return session from workspace",
            "POST /session/active":       "Store active session in RAM (tmpfs) only",
            "GET  /session/active/<id>":  "Retrieve active session from RAM",
            "DELETE /session/<id>":       "Secure delete (3-pass shred)",
        },
        "security": {
            "encryption": "Fernet (from OpenBao)",
            "key_storage": "RAM only (never written to disk)",
            "session_storage": "tmpfs (RAM) for active, encrypted volume for persistent",
            "dead_mans_switch": "Enabled",
            "auto_shred": "SIGTERM/SIGINT triggers workspace shred",
        },
    })


# ─────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────

def startup():
    log.info("=" * 60)
    log.info("  OpenClaw Secure Agent Starting")
    log.info("=" * 60)
    log.info(f"OpenBao address:    {BAO_ADDR}")
    log.info(f"AppRole creds path: {APPROLE_CREDS_PATH}")
    log.info(f"Heartbeat interval: {HEARTBEAT_INTERVAL}s")
    log.info(f"Running as UID:     {os.getuid()}")

    # Ensure directories exist
    for path in [SESSIONS_PATH, WORKSPACE_PATH, SECRETS_PATH, CACHE_PATH]:
        try:
            os.makedirs(path, exist_ok=True)
            log.info(f"Directory ready: {path}")
        except Exception as e:
            log.warning(f"Could not create {path}: {e}")

    # Log mount types
    mount_info = get_mount_info()
    for path in [SESSIONS_PATH, SECRETS_PATH, CACHE_PATH]:
        fstype = mount_info.get(path, {}).get("fstype", "unknown")
        flag = "✓ tmpfs" if fstype == "tmpfs" else f"⚠ {fstype} (expected tmpfs!)"
        log.info(f"Mount {path}: {flag}")

    workspace_fstype = mount_info.get(WORKSPACE_PATH, {}).get("fstype", "unknown")
    log.info(f"Mount {WORKSPACE_PATH}: {workspace_fstype} (encrypted volume)")

    # Wait for OpenBao
    log.info("Waiting for OpenBao...")
    for attempt in range(30):
        if check_openbao_health():
            state.set_health(True)
            log.info("OpenBao is reachable!")
            break
        log.info(f"  Attempt {attempt + 1}/30 — retrying in 2s...")
        time.sleep(2)
    else:
        log.error("OpenBao not reachable after 30 attempts.")

    # Authenticate and fetch secrets
    try:
        token = authenticate_approle()
        fetch_all_secrets(token)
        log.info("All secrets loaded! Fernet key active.")
    except Exception as e:
        log.error(f"Startup secrets fetch failed: {e}")
        log.warning("Will retry via dead man's switch recovery loop.")

    # Start dead man's switch
    dms = threading.Thread(target=dead_mans_switch, daemon=True, name="dead-mans-switch")
    dms.start()
    log.info("Dead man's switch thread started.")

    log.info("=" * 60)
    log.info("  OpenClaw Secure Agent ready on :8300")
    log.info("  GET /health  GET /status  POST /session/save  etc.")
    log.info("=" * 60)


if __name__ == "__main__":
    startup()
    app.run(host="0.0.0.0", port=8300, debug=False, threaded=True)
