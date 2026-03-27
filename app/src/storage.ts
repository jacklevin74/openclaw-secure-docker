/**
 * Workspace Storage — Encrypted Session Persistence
 * ===================================================
 * Handles saving, loading, and secure deletion of encrypted sessions
 * on the workspace volume.
 *
 * Security guarantees:
 *   - The workspace volume contains ONLY ciphertext
 *   - The Fernet key is never written to the volume — it lives in RAM only
 *   - Secure delete: 3-pass overwrite (zeros, ones, 0xa5 pattern) + unlink
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  statSync,
  openSync,
  writeSync,
  fsyncSync,
  closeSync,
  readdirSync,
} from "node:fs";
import { join } from "node:path";
import type { SecureState } from "./state.js";

// ── Secure Delete ────────────────────────────────────────────────────────────

/**
 * Securely delete a file by overwriting it with zeros before unlinking.
 *
 * This is the software equivalent of a shred. Note: on SSDs/flash, the OS
 * may not guarantee that zeroes overwrite the same physical cells — but this
 * is the best we can do without hardware-level secure erase.
 *
 * For tmpfs (RAM), any write + unlink effectively destroys the data since
 * there's no underlying persistent storage.
 *
 * Returns true if file was deleted, false if it didn't exist.
 */
export function secureDelete(filepath: string): boolean {
  if (!existsSync(filepath)) {
    return false;
  }

  try {
    const fileSize = statSync(filepath).size;

    if (fileSize > 0) {
      const fd = openSync(filepath, "r+");
      try {
        // Pass 1: overwrite with zeros
        const zeros = Buffer.alloc(fileSize, 0x00);
        writeSync(fd, zeros, 0, fileSize, 0);
        fsyncSync(fd);

        // Pass 2: overwrite with ones
        const ones = Buffer.alloc(fileSize, 0xff);
        writeSync(fd, ones, 0, fileSize, 0);
        fsyncSync(fd);

        // Pass 3: overwrite with random-ish pattern
        const pattern = Buffer.alloc(fileSize, 0xa5);
        writeSync(fd, pattern, 0, fileSize, 0);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    }

    unlinkSync(filepath);
    console.log(
      `${new Date().toISOString()} [INFO] Secure delete: ${filepath} (${fileSize} bytes, 3-pass overwrite)`
    );
    return true;
  } catch (e) {
    console.error(`${new Date().toISOString()} [ERROR] Secure delete failed for ${filepath}: ${e}`);
    // Best effort: try regular unlink
    try {
      unlinkSync(filepath);
    } catch {
      // Ignore
    }
    return false;
  }
}

/**
 * Overwrite and delete all files in the workspace volume.
 * Called from SIGTERM trap (dead man's switch on container stop).
 */
export function shredWorkspace(workspacePath: string): void {
  if (!existsSync(workspacePath)) {
    return;
  }

  console.warn(`${new Date().toISOString()} [WARNING] 🔥 AUTO-SHRED: Overwriting all workspace files...`);
  let count = 0;

  function shredRecursive(dir: string): void {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          shredRecursive(fullPath);
        } else if (entry.isFile()) {
          secureDelete(fullPath);
          count++;
        }
      }
    } catch {
      // Ignore errors during shred
    }
  }

  shredRecursive(workspacePath);
  console.warn(`${new Date().toISOString()} [WARNING] 🔥 AUTO-SHRED: ${count} files shredded from workspace.`);
}

// ── Workspace Session Storage ────────────────────────────────────────────────

/**
 * Encrypt data with Fernet key (from OpenBao) and save to workspace volume.
 *
 * Security guarantee: the workspace volume contains ONLY ciphertext.
 * The Fernet key is never written to the volume — it lives in RAM only.
 * Without the key, the ciphertext is opaque.
 *
 * Returns the path where the encrypted file was saved.
 */
export function workspaceSave(
  workspacePath: string,
  sessionId: string,
  data: string,
  state: SecureState
): string {
  if (!state.hasFernet()) {
    throw new Error("Fernet key not available — cannot save session");
  }

  mkdirSync(workspacePath, { recursive: true });

  // Encrypt
  const ciphertext = state.encrypt(data);

  // Save ciphertext to workspace
  const sessionFile = join(workspacePath, `session_${sessionId}.enc`);
  writeFileSync(sessionFile, ciphertext, "utf8");

  state.incrementSaved();
  console.log(
    `${new Date().toISOString()} [INFO] Session '${sessionId}' encrypted and saved to workspace (${ciphertext.length} bytes ciphertext)`
  );
  return sessionFile;
}

/**
 * Load and decrypt a session from the workspace volume.
 *
 * Throws Error if session doesn't exist.
 * Throws Error if ciphertext is tampered (HMAC verification fails).
 */
export function workspaceLoad(
  workspacePath: string,
  sessionId: string,
  state: SecureState
): string {
  if (!state.hasFernet()) {
    throw new Error("Fernet key not available — cannot decrypt session");
  }

  const sessionFile = join(workspacePath, `session_${sessionId}.enc`);
  if (!existsSync(sessionFile)) {
    const err = new Error(`Session '${sessionId}' not found in workspace`);
    (err as NodeJS.ErrnoException).code = "ENOENT";
    throw err;
  }

  const ciphertext = readFileSync(sessionFile, "utf8");
  const plaintext = state.decrypt(ciphertext);

  state.incrementLoaded();
  console.log(
    `${new Date().toISOString()} [INFO] Session '${sessionId}' decrypted from workspace (${ciphertext.length} bytes)`
  );
  return plaintext;
}

/**
 * Securely delete a session from the workspace volume.
 * Overwrites with zeros/ones/pattern before unlinking.
 */
export function workspaceDelete(workspacePath: string, sessionId: string): boolean {
  const sessionFile = join(workspacePath, `session_${sessionId}.enc`);
  const deleted = secureDelete(sessionFile);
  if (deleted) {
    console.log(`${new Date().toISOString()} [INFO] Session '${sessionId}' securely deleted from workspace.`);
  }
  return deleted;
}

/**
 * Count encrypted session files in the workspace.
 */
export function workspaceSessionCount(workspacePath: string): number {
  if (!existsSync(workspacePath)) {
    return 0;
  }
  try {
    const entries = readdirSync(workspacePath);
    return entries.filter((f) => f.startsWith("session_") && f.endsWith(".enc")).length;
  } catch {
    return 0;
  }
}
