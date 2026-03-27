/**
 * OpenBao API Helpers
 * ====================
 * HTTP wrappers for OpenBao (Vault-compatible) API:
 *   - Health checks
 *   - GET / POST with X-Vault-Token header
 *   - AppRole authentication
 *   - Token renewal
 */

import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type {
  OpenBaoAuthResponse,
  OpenBaoKVResponse,
  OpenBaoTokenRenewResponse,
} from "./types.js";
import type { SecureState } from "./state.js";

// ── Low-level API helpers ────────────────────────────────────────────────────

export async function baoGet(baoAddr: string, path: string, token: string): Promise<OpenBaoKVResponse> {
  const url = `${baoAddr}/v1/${path}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "X-Vault-Token": token },
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`OpenBao GET ${path} failed: HTTP ${res.status}`);
    }

    return (await res.json()) as OpenBaoKVResponse;
  } finally {
    clearTimeout(timeout);
  }
}

export async function baoPost(
  baoAddr: string,
  path: string,
  data: Record<string, string>,
  token?: string
): Promise<Record<string, unknown>> {
  const url = `${baoAddr}/v1/${path}`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers["X-Vault-Token"] = token;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(data),
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`OpenBao POST ${path} failed: HTTP ${res.status}`);
    }

    return (await res.json()) as Record<string, unknown>;
  } finally {
    clearTimeout(timeout);
  }
}

export async function checkOpenBaoHealth(baoAddr: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(`${baoAddr}/v1/sys/health`, {
      signal: controller.signal,
    });

    clearTimeout(timeout);
    return res.status === 200 || res.status === 429;
  } catch {
    return false;
  }
}

// ── AppRole Authentication ───────────────────────────────────────────────────

function readAppRoleCreds(credsPath: string): { roleId: string; secretId: string } {
  const roleId = readFileSync(join(credsPath, "role_id"), "utf8").trim();
  const secretId = readFileSync(join(credsPath, "secret_id"), "utf8").trim();
  return { roleId, secretId };
}

export async function authenticateAppRole(
  baoAddr: string,
  credsPath: string,
  state: SecureState
): Promise<string> {
  console.log(`${new Date().toISOString()} [INFO] Authenticating via AppRole...`);
  const { roleId, secretId } = readAppRoleCreds(credsPath);

  const resp = (await baoPost(baoAddr, "auth/approle/login", {
    role_id: roleId,
    secret_id: secretId,
  })) as unknown as OpenBaoAuthResponse;

  const token = resp.auth.client_token;
  const ttl = resp.auth.lease_duration;
  const policies = resp.auth.policies;

  console.log(
    `${new Date().toISOString()} [INFO] AppRole auth OK. Policies: ${JSON.stringify(policies)}. Token TTL: ${ttl}s`
  );
  state.setToken(token, ttl);
  return token;
}

export async function renewToken(
  baoAddr: string,
  token: string,
  state: SecureState
): Promise<boolean> {
  try {
    const resp = (await baoPost(baoAddr, "auth/token/renew-self", {}, token)) as unknown as OpenBaoTokenRenewResponse;
    state.setToken(token, resp.auth.lease_duration);
    console.log(`${new Date().toISOString()} [INFO] Token renewed.`);
    return true;
  } catch (e) {
    console.error(`${new Date().toISOString()} [ERROR] Token renewal failed: ${e}`);
    return false;
  }
}

// ── Secrets Loading ──────────────────────────────────────────────────────────

export async function fetchAllSecrets(
  baoAddr: string,
  token: string,
  state: SecureState,
  secretsPath: string
): Promise<void> {
  // 1. Fernet encryption key (crown jewel)
  const encResp = await baoGet(baoAddr, "kv/data/openclaw/encryption", token);
  const fernetKey = encResp.data.data.fernet_key;
  state.storeFernetKey(fernetKey);
  console.log(`${new Date().toISOString()} [INFO] ✓ Fernet encryption key loaded from OpenBao`);

  // 2. API keys
  const apiResp = await baoGet(baoAddr, "kv/data/openclaw/api-keys", token);
  state.storeApiKeys(apiResp.data.data);
  console.log(`${new Date().toISOString()} [INFO] ✓ API keys loaded from OpenBao`);

  // 3. Config
  const cfgResp = await baoGet(baoAddr, "kv/data/openclaw/config", token);
  state.storeConfig(cfgResp.data.data);
  console.log(`${new Date().toISOString()} [INFO] ✓ Config loaded from OpenBao`);

  // Write a non-sensitive manifest to the secrets tmpfs path
  writeSecretsManifest(secretsPath);
}

function writeSecretsManifest(secretsPath: string): void {
  try {
    mkdirSync(secretsPath, { recursive: true });
    const manifest = {
      loaded_at: new Date().toISOString(),
      secrets_loaded: ["fernet_key", "api-keys", "config"],
      note: "Actual secret values are in-memory only — not in this file",
      storage: "tmpfs (RAM only)",
    };
    writeFileSync(join(secretsPath, "manifest.json"), JSON.stringify(manifest, null, 2));
    console.log(`${new Date().toISOString()} [INFO] Secrets manifest written to ${secretsPath}/manifest.json (tmpfs)`);
  } catch (e) {
    console.warn(`${new Date().toISOString()} [WARNING] Could not write secrets manifest: ${e}`);
  }
}
