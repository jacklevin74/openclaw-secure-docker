/**
 * TypeScript interfaces for OpenClaw Secure Agent Simulator
 */

// ── Mount & Storage ──────────────────────────────────────────────────────────

export interface MountEntry {
  device: string;
  fstype: string;
  options: string;
  mounted_at_parent?: string;
}

export interface MountInfo {
  [path: string]: MountEntry;
}

// ── Sessions ─────────────────────────────────────────────────────────────────

export interface ActiveSessionEntry {
  data: string;
  stored_at: string;
  storage: string;
}

export interface ActiveSessionFile {
  data: string;
  session_id: string;
}

// ── State ────────────────────────────────────────────────────────────────────

export interface StatusSummary {
  fernet_loaded: boolean;
  api_keys_loaded: boolean;
  config_loaded: boolean;
  api_key_names: string[];
  loaded_at: string | null;
  openbao_healthy: boolean;
  last_health_check: string | null;
  wipe_count: number;
  active_session_count: number;
  sessions_saved: number;
  sessions_loaded: number;
}

// ── OpenBao ──────────────────────────────────────────────────────────────────

export interface OpenBaoAuthResponse {
  auth: {
    client_token: string;
    lease_duration: number;
    policies: string[];
  };
}

export interface OpenBaoKVResponse {
  data: {
    data: Record<string, string>;
  };
}

export interface OpenBaoTokenRenewResponse {
  auth: {
    lease_duration: number;
  };
}

// ── API Request/Response ─────────────────────────────────────────────────────

export interface SessionSaveRequest {
  session_id: string;
  data: string;
}

export interface SessionSaveResponse {
  status: string;
  session_id: string;
  storage: string;
  encrypted: boolean;
  key_source: string;
  note: string;
}

export interface SessionLoadResponse {
  status: string;
  session_id: string;
  data: string;
  source: string;
}

export interface SessionActiveStoreResponse {
  status: string;
  session_id: string;
  storage: string;
  encrypted: boolean;
  note: string;
}

export interface SessionActiveGetResponse {
  status: string;
  session_id: string;
  data: string;
  stored_at: string;
  storage: string;
}

export interface SessionDeleteResponse {
  status: string;
  session_id: string;
  workspace_shredded: boolean;
  active_wiped: boolean;
  method: string;
}

export interface HealthResponse {
  status: string;
  reason?: string;
  encryption: boolean;
  fernet_key_source?: string;
  sessions?: {
    active_count: number;
    workspace_count: number;
  };
  storage?: {
    sessions_tmpfs: boolean;
    secrets_tmpfs: boolean;
    cache_tmpfs: boolean;
  };
}

export interface ErrorResponse {
  error: string;
}

export interface IndexResponse {
  app: string;
  version: string;
  endpoints: Record<string, string>;
  security: Record<string, string>;
}

// ── Config ───────────────────────────────────────────────────────────────────

export interface AppConfig {
  baoAddr: string;
  approlCredsPath: string;
  heartbeatInterval: number;
  sessionsPath: string;
  workspacePath: string;
  secretsPath: string;
  cachePath: string;
}
