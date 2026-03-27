/**
 * Express Route Handlers
 * =======================
 * All HTTP endpoints for the OpenClaw Secure Agent Simulator.
 * Mirrors the Python/Flask routes exactly for API contract parity.
 */

import { Router } from "express";
import type { Request, Response } from "express";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { SecureState } from "./state.js";
import { getMountInfo, isTmpfs } from "./mounts.js";
import { checkOpenBaoHealth } from "./openbao.js";
import {
  workspaceSave,
  workspaceLoad,
  workspaceDelete,
  workspaceSessionCount,
  secureDelete,
} from "./storage.js";
import type { AppConfig } from "./types.js";

const SESSION_ID_REGEX = /^[a-zA-Z0-9_\-]{1,128}$/;

export function createRouter(state: SecureState, config: AppConfig): Router {
  const router = Router();

  // ── GET /health ─────────────────────────────────────────────────────────

  router.get("/health", (_req: Request, res: Response): void => {
    if (!state.hasFernet()) {
      res.status(503).json({
        status: "unhealthy",
        reason: "Fernet key not loaded (OpenBao unreachable or startup failed)",
        encryption: false,
      });
      return;
    }

    res.json({
      status: "healthy",
      encryption: true,
      fernet_key_source: "openbao (not hardcoded)",
      sessions: {
        active_count: state.activeSessionCount(),
        workspace_count: workspaceSessionCount(config.workspacePath),
      },
      storage: {
        sessions_tmpfs: isTmpfs(config.sessionsPath),
        secrets_tmpfs: isTmpfs(config.secretsPath),
        cache_tmpfs: isTmpfs(config.cachePath),
      },
    });
  });

  // ── GET /status ─────────────────────────────────────────────────────────

  router.get("/status", async (_req: Request, res: Response): Promise<void> => {
    const summary = state.statusSummary();
    const mountInfo = getMountInfo();

    // Verify each expected tmpfs mount
    const mountChecks: Record<string, { fstype: string; is_tmpfs: boolean; device: string }> = {};
    for (const path of [config.sessionsPath, config.secretsPath, config.cachePath]) {
      const info = mountInfo[path] ?? { fstype: "unknown", device: "unknown" };
      mountChecks[path] = {
        fstype: info.fstype,
        is_tmpfs: info.fstype === "tmpfs",
        device: info.device,
      };
    }

    const workspaceInfo = mountInfo[config.workspacePath] ?? { fstype: "unknown", device: "unknown" };

    const baoHealthy = await checkOpenBaoHealth(config.baoAddr);

    res.json({
      app: "openclaw-secure-agent",
      timestamp: new Date().toISOString(),
      openbao: {
        address: config.baoAddr,
        reachable: baoHealthy,
        last_health_check: summary.last_health_check,
        healthy: summary.openbao_healthy,
      },
      encryption: {
        fernet_key_loaded: summary.fernet_loaded,
        fernet_key_source: summary.fernet_loaded ? "openbao-approle" : "not-loaded",
        api_keys_loaded: summary.api_keys_loaded,
        api_key_names: summary.api_key_names, // names only, no values
      },
      sessions: {
        active_count: summary.active_session_count,
        workspace_count: workspaceSessionCount(config.workspacePath),
        sessions_saved: summary.sessions_saved,
        sessions_loaded: summary.sessions_loaded,
      },
      mounts: {
        tmpfs_mounts: mountChecks,
        workspace: {
          path: config.workspacePath,
          fstype: workspaceInfo.fstype,
          device: workspaceInfo.device,
          note: "Named volume — app-level Fernet encryption applied",
        },
      },
      dead_mans_switch: {
        heartbeat_interval_s: config.heartbeatInterval,
        wipe_count: summary.wipe_count,
        description: "Wipes Fernet key + secrets if OpenBao unreachable for 3 checks",
      },
      security: {
        user: process.env.USER ?? "unknown",
        uid: process.getuid ? process.getuid() : -1,
        gid: process.getgid ? process.getgid() : -1,
        shred_on_exit: true,
        no_disk_secrets: true,
      },
    });
  });

  // ── POST /session/save ──────────────────────────────────────────────────

  router.post("/session/save", (req: Request, res: Response): void => {
    if (!state.hasFernet()) {
      res.status(503).json({ error: "Encryption not available — OpenBao unreachable" });
      return;
    }

    const body = req.body as Record<string, unknown> | undefined;
    if (!body || typeof body !== "object") {
      res.status(400).json({ error: "Invalid JSON body" });
      return;
    }

    const sessionId = typeof body.session_id === "string" ? body.session_id.trim() : "";
    const data = typeof body.data === "string" ? body.data : "";

    if (!sessionId) {
      res.status(400).json({ error: "session_id is required" });
      return;
    }
    if (!data) {
      res.status(400).json({ error: "data is required" });
      return;
    }

    // Validate session_id (alphanumeric + hyphens only to prevent path traversal)
    if (!SESSION_ID_REGEX.test(sessionId)) {
      res.status(400).json({
        error: "session_id must be alphanumeric (hyphens/underscores ok), max 128 chars",
      });
      return;
    }

    try {
      workspaceSave(config.workspacePath, sessionId, data, state);
      res.json({
        status: "saved",
        session_id: sessionId,
        storage: "workspace (encrypted)",
        encrypted: true,
        key_source: "openbao",
        note: "Data encrypted with Fernet before disk write",
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`${new Date().toISOString()} [ERROR] Session save failed: ${msg}`);
      res.status(500).json({ error: msg });
    }
  });

  // ── GET /session/load/:session_id ───────────────────────────────────────

  router.get("/session/load/:session_id", (req: Request, res: Response): void => {
    if (!state.hasFernet()) {
      res.status(503).json({ error: "Decryption not available — OpenBao unreachable" });
      return;
    }

    const sessionId = String(req.params.session_id);
    if (!SESSION_ID_REGEX.test(sessionId)) {
      res.status(400).json({ error: "Invalid session_id" });
      return;
    }

    try {
      const data = workspaceLoad(config.workspacePath, sessionId, state);
      res.json({
        status: "loaded",
        session_id: sessionId,
        data,
        source: "workspace (decrypted)",
      });
    } catch (e) {
      if (e instanceof Error) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT" || e.message.includes("not found")) {
          res.status(404).json({ error: `Session '${sessionId}' not found` });
          return;
        }
        if (e.message.includes("HMAC verification failed") || e.message.includes("tampered")) {
          res.status(422).json({ error: "Decryption failed — data tampered or wrong key" });
          return;
        }
      }
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`${new Date().toISOString()} [ERROR] Session load failed: ${msg}`);
      res.status(500).json({ error: msg });
    }
  });

  // ── POST /session/active ────────────────────────────────────────────────

  router.post("/session/active", (req: Request, res: Response): void => {
    const body = req.body as Record<string, unknown> | undefined;
    if (!body || typeof body !== "object") {
      res.status(400).json({ error: "Invalid JSON body" });
      return;
    }

    const sessionId = typeof body.session_id === "string" ? body.session_id.trim() : "";
    const data = typeof body.data === "string" ? body.data : "";

    if (!sessionId) {
      res.status(400).json({ error: "session_id is required" });
      return;
    }

    if (!SESSION_ID_REGEX.test(sessionId)) {
      res.status(400).json({ error: "Invalid session_id" });
      return;
    }

    // Store in state (in-memory)
    state.storeActiveSession(sessionId, data);

    // Also write to the actual tmpfs path for dual-layer guarantee
    try {
      mkdirSync(config.sessionsPath, { recursive: true });
      const sessionFile = join(config.sessionsPath, `active_${sessionId}.json`);
      writeFileSync(sessionFile, JSON.stringify({ data, session_id: sessionId }));
      console.log(
        `${new Date().toISOString()} [INFO] Active session '${sessionId}' stored in RAM (tmpfs).`
      );
    } catch (e) {
      console.warn(
        `${new Date().toISOString()} [WARNING] Could not write active session to tmpfs path: ${e}`
      );
    }

    res.json({
      status: "stored",
      session_id: sessionId,
      storage: "tmpfs-ram (not persisted)",
      encrypted: false,
      note: "Use /session/save for encrypted persistence across restarts",
    });
  });

  // ── GET /session/active/:session_id ─────────────────────────────────────

  router.get("/session/active/:session_id", (req: Request, res: Response): void => {
    const sessionId = String(req.params.session_id);
    if (!SESSION_ID_REGEX.test(sessionId)) {
      res.status(400).json({ error: "Invalid session_id" });
      return;
    }

    const session = state.getActiveSession(sessionId);
    if (!session) {
      res.status(404).json({
        error: `Active session '${sessionId}' not found (may have been wiped)`,
      });
      return;
    }

    res.json({
      status: "found",
      session_id: sessionId,
      data: session.data,
      stored_at: session.stored_at,
      storage: "tmpfs-ram",
    });
  });

  // ── DELETE /session/:session_id ─────────────────────────────────────────

  router.delete("/session/:session_id", (req: Request, res: Response): void => {
    const sessionId = String(req.params.session_id);
    if (!SESSION_ID_REGEX.test(sessionId)) {
      res.status(400).json({ error: "Invalid session_id" });
      return;
    }

    const workspaceDeleted = workspaceDelete(config.workspacePath, sessionId);

    // Also remove from memory dict + tmpfs file
    const activeDeleted = state.deleteActiveSession(sessionId);
    const tmpfsFile = join(config.sessionsPath, `active_${sessionId}.json`);
    secureDelete(tmpfsFile);

    if (!workspaceDeleted && !activeDeleted) {
      res.status(404).json({ error: `Session '${sessionId}' not found` });
      return;
    }

    res.json({
      status: "deleted",
      session_id: sessionId,
      workspace_shredded: workspaceDeleted,
      active_wiped: activeDeleted,
      method: "3-pass overwrite (zeros, ones, 0xa5) + unlink",
    });
  });

  // ── GET / ───────────────────────────────────────────────────────────────

  router.get("/", (_req: Request, res: Response): void => {
    res.json({
      app: "OpenClaw Secure Agent Simulator",
      version: "1.0.0",
      endpoints: {
        "GET  /health": "Health check (encryption + mount status)",
        "GET  /status": "Detailed status (no key material exposed)",
        "POST /session/save": "Encrypt + save session to workspace volume",
        "GET  /session/load/<id>": "Decrypt + return session from workspace",
        "POST /session/active": "Store active session in RAM (tmpfs) only",
        "GET  /session/active/<id>": "Retrieve active session from RAM",
        "DELETE /session/<id>": "Secure delete (3-pass shred)",
      },
      security: {
        encryption: "Fernet (from OpenBao)",
        key_storage: "RAM only (never written to disk)",
        session_storage: "tmpfs (RAM) for active, encrypted volume for persistent",
        dead_mans_switch: "Enabled",
        auto_shred: "SIGTERM/SIGINT triggers workspace shred",
      },
    });
  });

  return router;
}
