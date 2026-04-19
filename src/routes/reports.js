import express from "express";
import pool from "../db.js";
import { auth } from "../middleware/auth.js";

const router = express.Router();
router.use(auth);

// Ø¶ØºØ· Ø§Ù„Ø£Ø·Ø¨Ø§Ø¡ (Ø¹Ø¯Ø¯ Ø§Ù„Ù…ÙˆØ§Ø¹ÙŠØ¯ Ø¨Ø§Ù„Ø£Ø³Ø¨ÙˆØ¹)
router.get("/doctor-load", async (req, res) => {
  const { from, to } = req.query;
  const { client_id } = req.user;
  if (!client_id) return res.status(403).json({ error: "no_tenant" });
  const clinicId = req.query.clinic_id || null;

  const params = clinicId ? [client_id, from, to, clinicId] : [client_id, from, to];
  const clinicFilter = clinicId ? " AND a.clinic_id=$4" : "";

  const { rows } = await pool.query(
    `SELECT u.full_name AS doctor, COUNT(a.id) AS total
     FROM appointments a
     JOIN users u ON a.doctor_id = u.id AND u.client_id = a.client_id
     WHERE a.client_id=$1
       AND a.start_time BETWEEN $2 AND $3${clinicFilter}
     GROUP BY u.full_name
     ORDER BY total DESC`,
    params
  );

  res.json(rows);
});

// Ø§Ù„Ø¥Ù„ØºØ§Ø¡Ø§Øª (Cancelled / No-show)
router.get("/cancellations", async (req, res) => {
  const { from, to } = req.query;
  const { client_id } = req.user;
  if (!client_id) return res.status(403).json({ error: "no_tenant" });
  const clinicId = req.query.clinic_id || null;

  const params = clinicId ? [client_id, from, to, clinicId] : [client_id, from, to];
  const clinicFilter = clinicId ? " AND clinic_id=$4" : "";

  const { rows } = await pool.query(
    `SELECT status, COUNT(*) AS total
     FROM appointments
     WHERE client_id=$1
       AND status IN ('cancelled','no_show')
       AND start_time BETWEEN $2 AND $3${clinicFilter}
     GROUP BY status`,
    params
  );

  res.json(rows);
});

// Ø£ÙˆÙ‚Ø§Øª Ø§Ù„Ø°Ø±ÙˆØ© (Ø­Ø³Ø¨ Ø§Ù„Ø³Ø§Ø¹Ø©)
router.get("/peak-hours", async (req, res) => {
  const { from, to } = req.query;
  const { client_id } = req.user;
  if (!client_id) return res.status(403).json({ error: "no_tenant" });
  const clinicId = req.query.clinic_id || null;

  const params = clinicId ? [client_id, from, to, clinicId] : [client_id, from, to];
  const clinicFilter = clinicId ? " AND clinic_id=$4" : "";

  const { rows } = await pool.query(
    `SELECT EXTRACT(HOUR FROM start_time) AS hour, COUNT(*) AS total
     FROM appointments
     WHERE client_id=$1
       AND start_time BETWEEN $2 AND $3${clinicFilter}
     GROUP BY hour
     ORDER BY total DESC`,
    params
  );

  res.json(rows);
});

export default router;
