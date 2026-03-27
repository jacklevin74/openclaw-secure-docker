/**
 * Dead Man's Switch
 * ==================
 * Background loop: checks OpenBao health every HEARTBEAT_INTERVAL seconds.
 * If OpenBao is unreachable for 3 consecutive checks, wipes all secrets.
 * If OpenBao comes back, re-authenticates and re-fetches secrets.
 */

import type { SecureState } from "./state.js";
import { checkOpenBaoHealth, authenticateAppRole, renewToken, fetchAllSecrets } from "./openbao.js";

const MAX_FAILURES = 3;

export function startDeadMansSwitch(
  state: SecureState,
  baoAddr: string,
  credsPath: string,
  secretsPath: string,
  heartbeatInterval: number
): NodeJS.Timeout {
  console.log(
    `${new Date().toISOString()} [INFO] Dead man's switch started. Interval: ${heartbeatInterval}s`
  );

  let consecutiveFailures = 0;

  const intervalId = setInterval(async () => {
    try {
      const healthy = await checkOpenBaoHealth(baoAddr);
      state.setHealth(healthy);

      if (healthy) {
        consecutiveFailures = 0;

        if (!state.hasSecrets()) {
          console.log(`${new Date().toISOString()} [INFO] OpenBao back online — re-fetching secrets...`);
          try {
            const token = await authenticateAppRole(baoAddr, credsPath, state);
            await fetchAllSecrets(baoAddr, token, state, secretsPath);
            console.log(`${new Date().toISOString()} [INFO] Secrets re-fetched after recovery.`);
          } catch (e) {
            console.error(`${new Date().toISOString()} [ERROR] Re-fetch failed: ${e}`);
          }
        } else if (state.isTokenExpired()) {
          const token = state.getToken();
          if (token) {
            console.log(`${new Date().toISOString()} [INFO] Token near expiry — renewing...`);
            const renewed = await renewToken(baoAddr, token, state);
            if (!renewed) {
              try {
                const newToken = await authenticateAppRole(baoAddr, credsPath, state);
                await fetchAllSecrets(baoAddr, newToken, state, secretsPath);
              } catch (e) {
                console.error(`${new Date().toISOString()} [ERROR] Re-auth after token expiry failed: ${e}`);
              }
            }
          }
        }
      } else {
        consecutiveFailures++;
        console.warn(
          `${new Date().toISOString()} [WARNING] OpenBao health check failed (${consecutiveFailures}/${MAX_FAILURES})`
        );
        if (consecutiveFailures >= MAX_FAILURES) {
          console.error(
            `${new Date().toISOString()} [ERROR] OpenBao unreachable — triggering dead man's switch!`
          );
          state.wipeSecrets();
          consecutiveFailures = 0;
        }
      }
    } catch (e) {
      console.error(`${new Date().toISOString()} [ERROR] Dead man's switch iteration error: ${e}`);
    }
  }, heartbeatInterval * 1000);

  // Allow the Node.js process to exit even if the interval is still running
  intervalId.unref();

  return intervalId;
}
