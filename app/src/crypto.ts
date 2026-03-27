/**
 * Fernet Encryption/Decryption
 * ============================
 * Implements the Fernet specification (https://github.com/kr/fernet-spec)
 * using Node.js built-in crypto module.
 *
 * Fernet key format: URL-safe base64 of 32 random bytes
 *   - First 16 bytes: HMAC-SHA256 signing key
 *   - Last 16 bytes: AES-128-CBC encryption key
 *
 * Fernet token format (all concatenated, then base64url-encoded):
 *   Version (1 byte) || Timestamp (8 bytes, big-endian) || IV (16 bytes) ||
 *   Ciphertext (variable, PKCS7-padded AES-128-CBC) || HMAC (32 bytes)
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

const FERNET_VERSION = 0x80;

/**
 * Decode a URL-safe base64 string to a Buffer.
 */
function urlSafeBase64Decode(encoded: string): Buffer {
  // Replace URL-safe chars with standard base64 chars
  const standard = encoded.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(standard, "base64");
}

/**
 * Encode a Buffer to URL-safe base64 string.
 */
function urlSafeBase64Encode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Parse a Fernet key (URL-safe base64 of 32 bytes) into signing and encryption keys.
 */
function parseFernetKey(keyB64: string): { signingKey: Buffer; encryptionKey: Buffer } {
  const keyBytes = urlSafeBase64Decode(keyB64);
  if (keyBytes.length !== 32) {
    throw new Error(`Invalid Fernet key length: expected 32 bytes, got ${keyBytes.length}`);
  }
  return {
    signingKey: keyBytes.subarray(0, 16),
    encryptionKey: keyBytes.subarray(16, 32),
  };
}

/**
 * Encrypt plaintext using a Fernet key.
 * Returns a Fernet token (URL-safe base64 string).
 */
export function fernetEncrypt(plaintext: string, keyB64: string): string {
  const { signingKey, encryptionKey } = parseFernetKey(keyB64);

  // Generate IV (16 random bytes)
  const iv = randomBytes(16);

  // Current timestamp as 8-byte big-endian
  const timestamp = BigInt(Math.floor(Date.now() / 1000));
  const timestampBuf = Buffer.alloc(8);
  timestampBuf.writeBigUInt64BE(timestamp);

  // Encrypt with AES-128-CBC (PKCS7 padding is default in Node.js)
  const cipher = createCipheriv("aes-128-cbc", encryptionKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  // Assemble the token payload (everything except the HMAC)
  const versionBuf = Buffer.from([FERNET_VERSION]);
  const payload = Buffer.concat([versionBuf, timestampBuf, iv, ciphertext]);

  // HMAC-SHA256 over the payload
  const hmac = createHmac("sha256", signingKey).update(payload).digest();

  // Final token: payload + HMAC, base64url-encoded
  const token = Buffer.concat([payload, hmac]);
  return urlSafeBase64Encode(token);
}

/**
 * Decrypt a Fernet token using a Fernet key.
 * Returns the plaintext string.
 * Throws on invalid token, bad HMAC, or decryption failure.
 */
export function fernetDecrypt(tokenB64: string, keyB64: string): string {
  const { signingKey, encryptionKey } = parseFernetKey(keyB64);

  const tokenBytes = urlSafeBase64Decode(tokenB64);

  // Minimum token size: 1 (version) + 8 (timestamp) + 16 (IV) + 16 (min ciphertext) + 32 (HMAC) = 73
  if (tokenBytes.length < 73) {
    throw new Error("Invalid Fernet token: too short");
  }

  // Extract components
  const version = tokenBytes[0];
  if (version !== FERNET_VERSION) {
    throw new Error(`Invalid Fernet version: expected 0x${FERNET_VERSION.toString(16)}, got 0x${version.toString(16)}`);
  }

  // Payload = everything except the last 32 bytes (HMAC)
  const payload = tokenBytes.subarray(0, tokenBytes.length - 32);
  const hmacReceived = tokenBytes.subarray(tokenBytes.length - 32);

  // Verify HMAC
  const hmacComputed = createHmac("sha256", signingKey).update(payload).digest();
  if (!hmacComputed.equals(hmacReceived)) {
    throw new Error("Invalid Fernet token: HMAC verification failed (data tampered or wrong key)");
  }

  // Extract IV and ciphertext from payload
  // payload: version (1) + timestamp (8) + iv (16) + ciphertext (rest)
  const iv = payload.subarray(9, 25);
  const ciphertext = payload.subarray(25);

  // Decrypt with AES-128-CBC
  const decipher = createDecipheriv("aes-128-cbc", encryptionKey, iv);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString("utf8");
}
