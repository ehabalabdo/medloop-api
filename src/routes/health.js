/**
 * Liveness/readiness endpoints for monitoring (Render, uptime checkers).
 *
 *  GET /healthz   -> liveness: process is up. Cheap, no DB hit.
 *  GET /readyz    -> readiness: DB reachable. Used by orchestrators
 *                    to decide whether to route traffic.
 *
 * Both return JSON; readyz returns 503 if the DB ping fails so external
 * monitors can alert without false positives from cold starts.
 */
import express from "express";
import pool from "../db.js";
import logger from "../utils/logger.js";

const router = express.Router();

const startedAt = Date.now();

router.get("/healthz", (_req, res) => {
  res.json({
    status: "ok",
    uptime_s: Math.round((Date.now() - startedAt) / 1000),
  });
});

router.get("/readyz", async (_req, res) => {
  const t0 = Date.now();
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "ready",
      db_ms: Date.now() - t0,
      uptime_s: Math.round((Date.now() - startedAt) / 1000),
    });
  } catch (err) {
    logger.error({ err }, "readiness check failed");
    res.status(503).json({ status: "degraded", error: "db_unreachable" });
  }
});

export default router;
