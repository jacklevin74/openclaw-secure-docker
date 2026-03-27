/**
 * SecureState — Thread-safe* in-memory state store
 * ==================================================
 * (*Node.js is single-threaded, but we maintain the same API contract
 * as the Python version for structural parity. The lock semantics are
 * implicit in the event loop — no concurrent mutations possible.)
 *
 * The Fernet key is the crown jewel — it lives only in RAM (fetched from
 * OpenBao at startup, never written to any file). All workspace writes
 * are encrypted with this key before hitting the volume.
 */

import { fernetEncrypt, fernetDecrypt } from "./crypto.js";
import type { ActiveSessionEntry, StatusSummary } from "./types.js";

export class SecureState {
  // Secrets (from OpenBao)
  private fernetKey: string | null = null; // raw Fernet key (base64url string)
  private apiKeys: Record<string, string> = {};
  private config: Record<string, string> = {};

  // Token lifecycle
  private token: string | null = null;
  private tokenExpiresAt = 0;

  // Active sessions (tmpfs / RAM only — never persist to disk)
  private activeSessions: Map<string, ActiveSessionEntry> = new Map();

  // Stats
  private loadedAt: Date | null = null;
  private openbaoHealthy = false;
  private lastHealthCheck: string | null = null;
  private wipeCount = 0;
  private sessionsSaved = 0;
  private sessionsLoaded = 0;

  // ── Token management ────────────────────────────────────────────────────

  setToken(tokenValue: string, ttlSeconds: number): void {
    this.token = tokenValue;
    this.tokenExpiresAt = Date.now() / 1000 + ttlSeconds - 60;
    console.log(`${new Date().toISOString()} [INFO] Token stored. TTL ~${ttlSeconds}s.`);
  }

  getToken(): string | null {
    return this.token;
  }

  isTokenExpired(): boolean {
    return Date.now() / 1000 >= this.tokenExpiresAt;
  }

  // ── Secrets management ──────────────────────────────────────────────────

  storeFernetKey(keyB64: string): void {
    this.fernetKey = keyB64;
    this.loadedAt = new Date();
    console.log(`${new Date().toISOString()} [INFO] Fernet encryption key loaded into memory.`);
  }

  storeApiKeys(keys: Record<string, string>): void {
    this.apiKeys = { ...keys };
    console.log(`${new Date().toISOString()} [INFO] API keys stored (${Object.keys(keys).length} keys).`);
  }

  storeConfig(cfg: Record<string, string>): void {
    this.config = { ...cfg };
    console.log(`${new Date().toISOString()} [INFO] Config stored (${Object.keys(cfg).length} keys).`);
  }

  hasFernet(): boolean {
    return this.fernetKey !== null;
  }

  encrypt(plaintext: string): string {
    if (this.fernetKey === null) {
      throw new Error("Fernet key not loaded — cannot encrypt");
    }
    return fernetEncrypt(plaintext, this.fernetKey);
  }

  decrypt(ciphertext: string): string {
    if (this.fernetKey === null) {
      throw new Error("Fernet key not loaded — cannot decrypt");
    }
    return fernetDecrypt(ciphertext, this.fernetKey);
  }

  /**
   * Atomically wipe all secrets from memory.
   * Called by dead man's switch when OpenBao becomes unreachable.
   */
  wipeSecrets(): void {
    this.fernetKey = null;
    this.apiKeys = {};
    this.config = {};
    this.token = null;
    this.tokenExpiresAt = 0;
    this.loadedAt = null;
    this.wipeCount++;
    console.warn(
      `${new Date().toISOString()} [WARNING] 💀 DEAD MAN'S SWITCH — wiped all secrets from memory (wipe #${this.wipeCount})`
    );
  }

  hasSecrets(): boolean {
    return this.fernetKey !== null;
  }

  setHealth(healthy: boolean): void {
    this.openbaoHealthy = healthy;
    this.lastHealthCheck = new Date().toISOString();
  }

  // ── Active sessions (RAM / tmpfs only) ──────────────────────────────────

  storeActiveSession(sessionId: string, data: string): void {
    this.activeSessions.set(sessionId, {
      data,
      stored_at: new Date().toISOString(),
      storage: "tmpfs-ram",
    });
  }

  getActiveSession(sessionId: string): ActiveSessionEntry | undefined {
    return this.activeSessions.get(sessionId);
  }

  deleteActiveSession(sessionId: string): boolean {
    const existed = this.activeSessions.has(sessionId);
    this.activeSessions.delete(sessionId);
    return existed;
  }

  activeSessionCount(): number {
    return this.activeSessions.size;
  }

  incrementSaved(): void {
    this.sessionsSaved++;
  }

  incrementLoaded(): void {
    this.sessionsLoaded++;
  }

  statusSummary(): StatusSummary {
    return {
      fernet_loaded: this.fernetKey !== null,
      api_keys_loaded: Object.keys(this.apiKeys).length > 0,
      config_loaded: Object.keys(this.config).length > 0,
      api_key_names: Object.keys(this.apiKeys),
      loaded_at: this.loadedAt ? this.loadedAt.toISOString() : null,
      openbao_healthy: this.openbaoHealthy,
      last_health_check: this.lastHealthCheck,
      wipe_count: this.wipeCount,
      active_session_count: this.activeSessions.size,
      sessions_saved: this.sessionsSaved,
      sessions_loaded: this.sessionsLoaded,
    };
  }
}
