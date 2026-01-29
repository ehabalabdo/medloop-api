const express = require("express");
const pool = require("../db.js");
const { verifyToken } = require("../middleware/auth.js");
const { createAppointmentSchema } = require("../validation/appointment.js");

const router = express.Router();
router.use(verifyToken);

// مواعيد اليوم
router.get("/today", async (req, res) => {
  const { role, id, clinic_id } = req.user;

  if (role === "doctor") {
    const { rows } = await pool.query(
      `SELECT * FROM appointments
       WHERE doctor_id=$1 AND DATE(start_time)=CURRENT_DATE`,
      [id]
    );
    return res.json(rows);
  }

  if (role === "admin" || role === "receptionist") {
    const { rows } = await pool.query(
      `SELECT * FROM appointments
       WHERE clinic_id=$1 AND DATE(start_time)=CURRENT_DATE`,
      [clinic_id]
    );
    return res.json(rows);
  }

  res.status(403).json({ error: "Forbidden" });
});

// مواعيد أسبوع كامل
router.get("/week", async (req, res) => {
  const { role, id, clinic_id } = req.user;

  const q =
    role === "doctor"
      ? `SELECT * FROM appointments
       WHERE doctor_id=$1
       AND start_time BETWEEN CURRENT_DATE
       AND CURRENT_DATE + INTERVAL '7 days'
       ORDER BY start_time`
      : `SELECT * FROM appointments
       WHERE clinic_id=$1
       AND start_time BETWEEN CURRENT_DATE
       AND CURRENT_DATE + INTERVAL '7 days'
       ORDER BY start_time`;

  const params = role === "doctor" ? [id] : [clinic_id];
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

// مواعيد يوم معيّن
router.get("/day", async (req, res) => {
  const { date } = req.query;
  const { role, id, clinic_id } = req.user;

  if (!date) return res.status(400).json({ error: "date required" });

  const q =
    role === "doctor"
      ? `SELECT * FROM appointments
       WHERE doctor_id=$1 AND DATE(start_time)=$2
       ORDER BY start_time`
      : `SELECT * FROM appointments
       WHERE clinic_id=$1 AND DATE(start_time)=$2
       ORDER BY start_time`;

  const params = role === "doctor" ? [id, date] : [clinic_id, date];
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

// تغيير الحالة
router.put("/:id/status", async (req, res) => {
  const { role, id: userId } = req.user;
  const { status } = req.body;

  if (!["admin", "doctor"].includes(role)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  await pool.query(
    `UPDATE appointments
     SET status=$1, updated_by=$2
     WHERE id=$3`,
    [status, userId, req.params.id]
  );

  res.json({ success: true });
});

// إنشاء موعد
router.post("/", async (req, res) => {
  const { role, clinic_id, id: userId } = req.user;

  if (!["admin", "receptionist"].includes(role)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const parsed = createAppointmentSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json(parsed.error);
  }

  const { patient_id, doctor_id, start_time, end_time } = parsed.data;

  try {
    const { rows } = await pool.query(
      `INSERT INTO appointments
       (patient_id, doctor_id, clinic_id, start_time, end_time, status, updated_by)
       VALUES ($1,$2,$3,$4,$5,'scheduled',$6)
       RETURNING *`,
      [patient_id, doctor_id, clinic_id, start_time, end_time, userId]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    // تعارض مواعيد
    if (err.code === "23505" || err.message.includes("overlap")) {
      return res.status(409).json({ error: "Doctor already booked" });
    }
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
