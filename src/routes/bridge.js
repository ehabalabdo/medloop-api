/**
 * Bridge Agent endpoints — auth via X-Bridge-Key (per-client shared secret),
 * NOT via JWT. These are called by the on-prem Bridge Agent that pushes
 * lab device results into MedLoop.
 *
 * Mounted at: /bridge
 *
 * Endpoints:
 *   POST /bridge/device-results        — single result
 *   POST /bridge/device-results/batch  — array of results
 *   POST /bridge/heartbeat             — bridge health ping
 *
 * Tenancy: req.user.client_id is set by bridgeKeyAuth from the matched key,
 * never trusted from the request body.
 */

import express from "express";
import pool from "../db.js";
import { bridgeKeyAuth } from "../middleware/bridgeKeyAuth.js";
import rateLimit from "express-rate-limit";

const router = express.Router();

// Per-IP rate limit on bridge endpoints — devices are bursty but not extreme.
// 600 results/min should comfortably cover even a busy clinic lab.
const bridgeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "rate_limited" },
});

router.use(bridgeLimiter);
router.use(bridgeKeyAuth);

// Optional IP allowlist (comma-separated CIDR/IPs in clients.bridge_allowed_ips)
async function checkAllowedIp(req, res, next) {
  try {
    const r = await pool.query(
      "SELECT bridge_allowed_ips FROM clients WHERE id=$1",
      [req.user.client_id]
    );
    const list = r.rows[0]?.bridge_allowed_ips;
    if (!list) return next(); // no allowlist configured — accept
    const allowed = list.split(",").map(s => s.trim()).filter(Boolean);
    if (allowed.includes(req.ip)) return next();
    return res.status(403).json({ error: "ip_not_allowed" });
  } catch {
    return next(); // fail-open if column missing pre-migration
  }
}
router.use(checkAllowedIp);

function sanitizeStr(s, max = 256) {
  if (s === null || s === undefined) return null;
  const t = String(s).replace(/[\u0000-\u001F\u007F]/g, "").trim();
  return t.length > max ? t.slice(0, max) : (t || null);
}

async function insertResult(clientId, body) {
  const devId = body.deviceId || body.device_id;
  const identifier = sanitizeStr(body.patientIdentifier || body.patient_identifier, 128);
  const tCode = sanitizeStr(body.testCode || body.test_code, 64);
  const tName = sanitizeStr(body.testName || body.test_name, 128);
  const value = sanitizeStr(body.value, 256);
  const unit = sanitizeStr(body.unit, 32);
  const refRange = sanitizeStr(body.referenceRange || body.reference_range, 64);
  const abnormal = !!(body.isAbnormal ?? body.is_abnormal);
  const rawMsg = sanitizeStr(body.rawMessage || body.raw_message, 8192);

  if (!devId || !identifier || !tCode || !value) {
    const e = new Error("deviceId, patientIdentifier, testCode, value required");
    e.status = 400;
    throw e;
  }

  // Verify device belongs to this tenant — prevents stolen key on one
  // tenant from posting results that get attributed to another's device.
  const dev = await pool.query(
    "SELECT id FROM devices WHERE id=$1::uuid AND client_id=$2 LIMIT 1",
    [devId, clientId]
  );
  if (dev.rows.length === 0) {
    const e = new Error("device_not_found_for_tenant");
    e.status = 403;
    throw e;
  }

  // Auto-match
  let matchedPatientId = null;
  let status = "pending";
  const numericId = parseInt(identifier, 10);
  if (Number.isFinite(numericId)) {
    const m = await pool.query(
      "SELECT id FROM patients WHERE id=$1 AND client_id=$2 LIMIT 1",
      [numericId, clientId]
    );
    if (m.rows.length > 0) { matchedPatientId = m.rows[0].id; status = "matched"; }
  }

  const { rows } = await pool.query(
    `INSERT INTO device_results (
      client_id, device_id, patient_identifier, test_code, test_name,
      value, unit, reference_range, is_abnormal, raw_message,
      status, matched_patient_id, matched_at, matched_by
    ) VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
    RETURNING id`,
    [
      clientId, devId, identifier, tCode, tName,
      value, unit, refRange, abnormal, rawMsg,
      status, matchedPatientId,
      matchedPatientId ? new Date().toISOString() : null,
      matchedPatientId ? "bridge-auto" : null,
    ]
  );
  return { id: rows[0].id, status, matchedPatientId };
}

router.post("/device-results", async (req, res) => {
  try {
    const out = await insertResult(req.user.client_id, req.body || {});
    res.status(201).json(out);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.post("/device-results/batch", async (req, res) => {
  const arr = Array.isArray(req.body?.results) ? req.body.results : (Array.isArray(req.body) ? req.body : null);
  if (!arr) return res.status(400).json({ error: "expected_array" });
  if (arr.length > 100) return res.status(413).json({ error: "batch_too_large" });
  const results = [];
  for (const item of arr) {
    try {
      results.push(await insertResult(req.user.client_id, item));
    } catch (err) {
      results.push({ error: err.message });
    }
  }
  res.json({ results });
});

router.post("/heartbeat", async (req, res) => {
  try {
    await pool.query(
      "UPDATE clients SET bridge_last_seen=now() WHERE id=$1",
      [req.user.client_id]
    ).catch(() => {}); // column may not exist; ignore
    res.json({ ok: true, ts: Date.now() });
  } catch {
    res.json({ ok: true, ts: Date.now() });
  }
});

export default router;
