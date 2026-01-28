import express from "express";
import pool from "../db.js";
import { auth } from "../middleware/auth.js";

const router = express.Router();
router.use(auth);

// ضغط الأطباء (عدد المواعيد بالأسبوع)
router.get("/doctor-load", async (req, res) => {
  const { from, to } = req.query;
  const { clinic_id } = req.user;

  const { rows } = await pool.query(
    `SELECT u.full_name AS doctor, COUNT(a.id) AS total
     FROM appointments a
     JOIN users u ON a.doctor_id = u.id
     WHERE a.clinic_id=$1
       AND a.start_time BETWEEN $2 AND $3
     GROUP BY u.full_name
     ORDER BY total DESC`,
    [clinic_id, from, to]
  );

  res.json(rows);
});

// الإلغاءات (Cancelled / No-show)
router.get("/cancellations", async (req, res) => {
  const { from, to } = req.query;
  const { clinic_id } = req.user;

  const { rows } = await pool.query(
    `SELECT status, COUNT(*) AS total
     FROM appointments
     WHERE clinic_id=$1
       AND status IN ('cancelled','no_show')
       AND start_time BETWEEN $2 AND $3
     GROUP BY status`,
    [clinic_id, from, to]
  );

  res.json(rows);
});

// أوقات الذروة (حسب الساعة)
router.get("/peak-hours", async (req, res) => {
  const { from, to } = req.query;
  const { clinic_id } = req.user;

  const { rows } = await pool.query(
    `SELECT EXTRACT(HOUR FROM start_time) AS hour, COUNT(*) AS total
     FROM appointments
     WHERE clinic_id=$1
       AND start_time BETWEEN $2 AND $3
     GROUP BY hour
     ORDER BY total DESC`,
    [clinic_id, from, to]
  );

  res.json(rows);
});

export default router;
