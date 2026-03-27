/**
 * OpenClaw Secure Agent Simulator — TypeScript/Express
 * =====================================================
 * Demonstrates production-grade secrets and session management:
 *
 *   Architecture:
 *     /openclaw/sessions/   — tmpfs (RAM) — active conversations
 *     /openclaw/workspace/  — encrypted named volume — persistent memory
 *     /openclaw/secrets/    — tmpfs (RAM) — fetched API keys
 *     /openclaw/cache/      — tmpfs (RAM) — model cache
 *
 *   Security layers:
 *     1. Fernet encryption key fetched from OpenBao at startup (not hardcoded)
 *     2. Active sessions stored in tmpfs — never touch disk
 *     3. Long-term saves encrypted with Fernet before writing to workspace volume
 *     4. Dead man's switch — wipes in-memory secrets if OpenBao unreachable
 *     5. Auto-shred trap — overwrites workspace files on SIGTERM/SIGINT
 *     6. Non-root user + read-only root filesystem
 *     7. Secure delete (overwrite + unlink) via DELETE /session/<id>
 */

import express from "express";
import { mkdirSync, readdirSync } from "node:fs";
import { SecureState } from "./state.js";
import { createRouter } from "./routes.js";
import { checkOpenBaoHealth, authenticateAppRole, fetchAllSecrets } from "./openbao.js";
import { startDeadMansSwitch } from "./deadman.js";
import { shredWorkspace, secureDelete } from "./storage.js";
import { getMountInfo } from "./mounts.js";
import type { AppConfig } from "./types.js";

// ─────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────

const config: AppConfig = {
  baoAddr: process.env.BAO_ADDR ?? "http://localhost:8200",
  approlCredsPath: process.env.APPROLE_CREDS_PATH ?? "/approle-creds",
  heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL ?? "30", 10),
  sessionsPath: "/openclaw/sessions",
  workspacePath: "/openclaw/workspace",
  secretsPath: "/openclaw/secrets",
  cachePath: "/openclaw/cache",
};

// ─────────────────────────────────────────────
// Global State
// ─────────────────────────────────────────────

const state = new SecureState();

// ─────────────────────────────────────────────
// SIGTERM / SIGINT Handler (auto-shred trap)
// ─────────────────────────────────────────────

function shutdownHandler(signal: string): void {
  console.warn(
    `${new Date().toISOString()} [WARNING] ⚡ ${signal} received — triggering auto-shred and shutdown...`
  );

  // 1. Wipe in-memory secrets immediately
  state.wipeSecrets();

  // 2. Shred workspace files
  shredWorkspace(config.workspacePath);

  // 3. Clean up active session tmpfs files
  try {
    const entries = readdirSync(config.sessionsPath);
    for (const entry of entries) {
      if (entry.endsWith(".json")) {
        secureDelete(`${config.sessionsPath}/${entry}`);
      }
    }
    console.log(`${new Date().toISOString()} [INFO] Active session tmpfs files wiped.`);
  } catch {
    // Sessions path may not exist
  }

  console.warn(`${new Date().toISOString()} [WARNING] Shutdown complete. Exiting.`);
  process.exit(0);
}

process.on("SIGTERM", () => shutdownHandler("SIGTERM"));
process.on("SIGINT", () => shutdownHandler("SIGINT"));

// ─────────────────────────────────────────────
// Express App
// ─────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(createRouter(state, config));

// ─────────────────────────────────────────────
// Startup
// ─────────────────────────────────────────────

async function startup(): Promise<void> {
  const log = (msg: string) =>
    console.log(`${new Date().toISOString()} [INFO] ${msg}`);
  const warn = (msg: string) =>
    console.warn(`${new Date().toISOString()} [WARNING] ${msg}`);

  log("=" .repeat(60));
  log("  OpenClaw Secure Agent Starting");
  log("=" .repeat(60));
  log(`OpenBao address:    ${config.baoAddr}`);
  log(`AppRole creds path: ${config.approlCredsPath}`);
  log(`Heartbeat interval: ${config.heartbeatInterval}s`);
  log(`Running as UID:     ${process.getuid ? process.getuid() : "unknown"}`);

  // Ensure directories exist
  for (const path of [config.sessionsPath, config.workspacePath, config.secretsPath, config.cachePath]) {
    try {
      mkdirSync(path, { recursive: true });
      log(`Directory ready: ${path}`);
    } catch (e) {
      warn(`Could not create ${path}: ${e}`);
    }
  }

  // Log mount types
  const mountInfo = getMountInfo();
  for (const path of [config.sessionsPath, config.secretsPath, config.cachePath]) {
    const fstype = mountInfo[path]?.fstype ?? "unknown";
    const flag = fstype === "tmpfs" ? "✓ tmpfs" : `⚠ ${fstype} (expected tmpfs!)`;
    log(`Mount ${path}: ${flag}`);
  }

  const workspaceFstype = mountInfo[config.workspacePath]?.fstype ?? "unknown";
  log(`Mount ${config.workspacePath}: ${workspaceFstype} (encrypted volume)`);

  // Wait for OpenBao
  log("Waiting for OpenBao...");
  let baoReady = false;
  for (let attempt = 1; attempt <= 30; attempt++) {
    if (await checkOpenBaoHealth(config.baoAddr)) {
      state.setHealth(true);
      log("OpenBao is reachable!");
      baoReady = true;
      break;
    }
    log(`  Attempt ${attempt}/30 — retrying in 2s...`);
    await sleep(2000);
  }
  if (!baoReady) {
    console.error(`${new Date().toISOString()} [ERROR] OpenBao not reachable after 30 attempts.`);
  }

  // Authenticate and fetch secrets
  try {
    const token = await authenticateAppRole(config.baoAddr, config.approlCredsPath, state);
    await fetchAllSecrets(config.baoAddr, token, state, config.secretsPath);
    log("All secrets loaded! Fernet key active.");
  } catch (e) {
    console.error(`${new Date().toISOString()} [ERROR] Startup secrets fetch failed: ${e}`);
    warn("Will retry via dead man's switch recovery loop.");
  }

  // Start dead man's switch
  startDeadMansSwitch(state, config.baoAddr, config.approlCredsPath, config.secretsPath, config.heartbeatInterval);
  log("Dead man's switch thread started.");

  // Start Express
  app.listen(8300, "0.0.0.0", () => {
    log("=" .repeat(60));
    log("  OpenClaw Secure Agent ready on :8300");
    log("  GET /health  GET /status  POST /session/save  etc.");
    log("=" .repeat(60));
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─────────────────────────────────────────────
// Launch
// ─────────────────────────────────────────────

startup().catch((e) => {
  console.error(`${new Date().toISOString()} [FATAL] Startup failed: ${e}`);
  process.exit(1);
});
