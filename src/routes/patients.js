import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import pool from "../db.js";
import { verifyToken } from "../middleware/auth.js";

function makeUsername(phone) {
  const clean = String(phone || "").replace(/\D/g, "");
  return `p${clean}`;
}

function makePassword() {
  return crypto.randomBytes(6).toString("base64url");
}

const router = express.Router();


// جلب جميع المرضى


// Data Transfer Object (DTO) Mapper for Patient
function mapPatient(row) {
  return {
    id: row.id,
    name: row.full_name || row.name || "Unknown",
    phone: row.phone || "",
    age: row.age ?? null,
    gender: row.gender || "unknown",
    currentVisit: row.visit_id
      ? {
          id: row.visit_id,
          status: row.visit_status || "unknown",
          department: row.department_name || "General"
        }
      : null
  };
}

// GET /patients with strict API contract
router.get("/", verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.full_name, p.phone, p.age, p.gender,
             v.id as visit_id, v.status as visit_status,
             d.name as department_name
      FROM patients p
      LEFT JOIN visits v ON v.patient_id = p.id AND v.active = true
      LEFT JOIN departments d ON d.id = v.department_id
      ORDER BY p.id DESC
    `);
    const safePatients = rows.map(mapPatient);
    res.json(safePatients);
  } catch (error) {
    console.error("GET /patients error:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// إضافة مريض جديد (بسيط)
router.post("/", verifyToken, async (req, res) => {
  console.log("BODY:", req.body);
  const { full_name, phone, notes } = req.body;
  if (!full_name || !phone) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  try {
    const result = await pool.query(
      `INSERT INTO patients (full_name, phone, notes)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [full_name, phone, notes || null]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("INSERT ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
