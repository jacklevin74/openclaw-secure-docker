/**
 * Mount Info Helpers
 * ===================
 * Parses /proc/mounts to check which paths are on tmpfs.
 * Used for health/status reporting to verify RAM-backed storage.
 */

import { readFileSync } from "node:fs";
import type { MountInfo, MountEntry } from "./types.js";

// Mount paths
const MOUNT_PATHS = [
  "/openclaw/sessions",
  "/openclaw/workspace",
  "/openclaw/secrets",
  "/openclaw/cache",
];

/**
 * Parse /proc/mounts to check which paths are on tmpfs.
 */
export function getMountInfo(): MountInfo {
  const mounts: Record<string, MountEntry> = {};

  try {
    const content = readFileSync("/proc/mounts", "utf8");
    for (const line of content.split("\n")) {
      const parts = line.split(/\s+/);
      if (parts.length >= 3) {
        mounts[parts[1]] = {
          device: parts[0],
          fstype: parts[2],
          options: parts.length > 3 ? parts[3] : "",
        };
      }
    }
  } catch {
    // /proc/mounts may not be readable outside Linux containers
  }

  const result: MountInfo = {};

  for (const path of MOUNT_PATHS) {
    if (mounts[path]) {
      result[path] = mounts[path];
    } else {
      // Check parent directories
      let found = false;
      const segments = path.split("/");
      for (let i = segments.length - 1; i >= 1; i--) {
        const parent = segments.slice(0, i).join("/") || "/";
        if (mounts[parent]) {
          result[path] = { ...mounts[parent], mounted_at_parent: parent };
          found = true;
          break;
        }
      }
      if (!found) {
        result[path] = { fstype: "unknown", device: "unknown", options: "" };
      }
    }
  }

  return result;
}

/**
 * Check if a path is on a tmpfs mount.
 */
export function isTmpfs(path: string): boolean {
  const info = getMountInfo();
  const entry = info[path];
  return entry?.fstype === "tmpfs";
}
