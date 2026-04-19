import express from "express";
import pool from "../db.js";
import { auth } from "../middleware/auth.js";

const router = express.Router();
router.use(auth);

// ضغط الأطباء (عدد المواعيد بالأسبوع)
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

// الإلغاءات (Cancelled / No-show)
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

// أوقات الذروة (حسب الساعة)
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
