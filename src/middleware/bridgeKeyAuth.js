/**
 * Bridge-key auth middleware: protects endpoints called by the on-prem
 * Bridge Agent (clinic LAN device that pushes lab results).
 *
 * Auth model: shared HMAC-style secret in header `X-Bridge-Key`.
 *   - Stored per-client in `clients.bridge_key_hash` (SHA-256 hex of secret)
 *   - Bridge agent sends raw secret; we hash and compare in constant time
 *   - Sets req.user = { client_id, type: 'bridge' } so downstream handlers
 *     work with the same tenant model as JWT users.
 *
 * Required header: X-Bridge-Key
 * Optional header: X-Client-Id (numeric, narrows the lookup; we still verify hash)
 */

import crypto from "crypto";
import pool from "../db.js";

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

export async function bridgeKeyAuth(req, res, next) {
  const key = req.headers["x-bridge-key"];
  if (!key || typeof key !== "string" || key.length < 32) {
    return res.status(401).json({ error: "missing_bridge_key" });
  }
  const hash = crypto.createHash("sha256").update(key).digest("hex");

  const clientIdHint = parseInt(req.headers["x-client-id"], 10);

  try {
    let row;
    if (Number.isFinite(clientIdHint)) {
      const r = await pool.query(
        "SELECT id, bridge_key_hash FROM clients WHERE id=$1 AND is_active=TRUE LIMIT 1",
        [clientIdHint]
      );
      row = r.rows[0];
    } else {
      // Fallback: full scan (small table). Constant-time-compares each.
      const r = await pool.query(
        "SELECT id, bridge_key_hash FROM clients WHERE bridge_key_hash IS NOT NULL AND is_active=TRUE"
      );
      row = r.rows.find((c) => timingSafeEqualHex(c.bridge_key_hash, hash));
    }

    if (!row || !row.bridge_key_hash || !timingSafeEqualHex(row.bridge_key_hash, hash)) {
      return res.status(403).json({ error: "invalid_bridge_key" });
    }

    req.user = { client_id: row.id, type: "bridge" };
    return next();
  } catch (err) {
    // table missing (pre-migration) — fail closed
    console.error("[bridgeKeyAuth] DB error:", err.message);
    return res.status(503).json({ error: "bridge_auth_unavailable" });
  }
}
