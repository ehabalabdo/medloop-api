import logger from "../utils/logger.js";
/**
 * AES-256-GCM encryption helpers for column-level PII protection.
 *
 * Format: "enc:" + base64(12-byte IV || ciphertext || 16-byte GCM tag)
 *
 * - Pass-through behavior when ENCRYPTION_KEY is not set, so the same code
 *   works in dev without secrets and in prod with secrets.
 * - decrypt() is tolerant: if the value is not "enc:"-prefixed, it returns
 *   the value as-is (supports gradual migration of existing plaintext rows).
 * - blindIndex() produces an HMAC-SHA256 hex digest suitable for searching
 *   on encrypted columns (e.g. login by email/username).
 *
 * Key requirement: ENCRYPTION_KEY must be 32 bytes (64 hex chars).
 *   Generate with:  node -e "logger.info(require('crypto').randomBytes(32).toString('hex'))"
 */

import crypto from "crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;
const PREFIX = "enc:";

let cachedKey = null;
function getKey() {
  if (cachedKey) return cachedKey;
  const hex = process.env.ENCRYPTION_KEY;
  if (!hex) return null;
  if (hex.length !== 64) {
    throw new Error("ENCRYPTION_KEY must be 64 hex chars (32 bytes)");
  }
  cachedKey = Buffer.from(hex, "hex");
  return cachedKey;
}

export function isEncryptionEnabled() {
  return !!getKey();
}

/**
 * Encrypt a string. Returns null/undefined unchanged so callers can safely
 * pipe arbitrary column values without null-checks. If encryption is not
 * configured, the plaintext is returned as-is.
 */
export function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return plaintext;
  const key = getKey();
  if (!key) return plaintext;
  const text = typeof plaintext === "string" ? plaintext : String(plaintext);
  // Don't double-encrypt
  if (text.startsWith(PREFIX)) return text;

  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, ct, tag]).toString("base64");
}

/**
 * Decrypt a value previously produced by encrypt(). If the value is not
 * "enc:"-prefixed, it is returned unchanged (legacy plaintext row).
 * Returns null/undefined unchanged.
 */
export function decrypt(value) {
  if (value === null || value === undefined) return value;
  if (typeof value !== "string") return value;
  if (!value.startsWith(PREFIX)) return value;
  const key = getKey();
  if (!key) {
    // Encryption disabled â€” cannot decrypt. Return marker so it's obvious in logs.
    return "[encrypted]";
  }
  try {
    const buf = Buffer.from(value.slice(PREFIX.length), "base64");
    if (buf.length < IV_LEN + TAG_LEN) return value;
    const iv = buf.subarray(0, IV_LEN);
    const tag = buf.subarray(buf.length - TAG_LEN);
    const ct = buf.subarray(IV_LEN, buf.length - TAG_LEN);
    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch (err) {
    logger.error("[crypto] decrypt failed:", err.message);
    return "[decrypt-error]";
  }
}

/**
 * Generate a deterministic search index for an encrypted column.
 * HMAC-SHA256(key, normalized_value).hex
 *
 * Use case: store users.email_idx = blindIndex(email) so login can do
 *   WHERE email_idx = $1
 * even though email itself is encrypted (and therefore non-searchable).
 *
 * Normalization: trim + lowercase. For phone numbers normalize digits-only
 * BEFORE calling this function.
 */
export function blindIndex(value) {
  if (value === null || value === undefined || value === "") return null;
  const key = getKey();
  if (!key) return null;
  const normalized = String(value).trim().toLowerCase();
  return crypto.createHmac("sha256", key).update(normalized).digest("hex");
}

/**
 * Helper to safely decrypt every value in an object (shallow). Useful when
 * mapping a DB row to the API response shape.
 */
export function decryptFields(row, fields) {
  if (!row) return row;
  const out = { ...row };
  for (const f of fields) {
    if (out[f] !== undefined) out[f] = decrypt(out[f]);
  }
  return out;
}
