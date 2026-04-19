/**
 * Audit logging middleware for state-changing requests.
 *
 * Records: who (user_id, role, client_id), what (method+path), when, from where (ip),
 * and outcome (HTTP status). Bodies are NOT logged to avoid PII leakage.
 *
 * Table: audit_log (created by migration 003)
 *
 * The middleware is best-effort: a failed insert never blocks the user request.
 */

import pool from "../db.js";

const SKIP_PATHS = [
  "/health",
  "/",
  "/auth/refresh", // noisy, contains no state change
];

const SKIP_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function auditLog(req, res, next) {
  // Skip read-only and noisy endpoints
  if (SKIP_METHODS.has(req.method)) return next();
  if (SKIP_PATHS.some((p) => req.path === p)) return next();

  const start = Date.now();

  res.on("finish", () => {
    // Defer the insert so it never blocks the response
    setImmediate(async () => {
      try {
        const u = req.user || {};
        await pool.query(
          `INSERT INTO audit_log
            (user_id, user_type, client_id, method, path, status_code, ip, user_agent, duration_ms)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            u.id || u.user_id || u.patient_id || u.employee_id || null,
            u.type || u.role || null,
            u.client_id || null,
            req.method,
            req.originalUrl?.split("?")[0]?.slice(0, 256) || req.path,
            res.statusCode,
            req.ip,
            (req.headers["user-agent"] || "").slice(0, 256),
            Date.now() - start,
          ]
        );
      } catch (err) {
        // table may not exist yet (pre-migration). Don't spam logs.
        if (err.code !== "42P01") {
          console.error("[audit] insert failed:", err.message);
        }
      }
    });
  });

  next();
}
