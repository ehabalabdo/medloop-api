import express from "express";
import jwt from "jsonwebtoken";
import pool from "../db.js";
import bcrypt from "bcryptjs";

const router = express.Router();

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // 1) users
  const staff = await pool.query(
    "SELECT id, role, password_hash FROM users WHERE email=$1",
    [username]
  );

  if (staff.rows.length) {
    const user = staff.rows[0];
    // TEMP: Plain text password comparison for testing
    const ok = password === user.password_hash;
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role, type: "staff" },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    return res.json({ token, type: "staff", role: user.role });
  }

  // 2) patients
  const patient = await pool.query(
    "SELECT id, password_hash FROM patients WHERE username=$1 AND has_access=true",
    [username]
  );

  if (patient.rows.length) {
    const p = patient.rows[0];
    // TEMP: Plain text password comparison for testing
    const ok = password === p.password_hash;
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { patient_id: p.id, type: "patient" },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    return res.json({ token, type: "patient" });
  }

  res.status(401).json({ error: "Invalid credentials" });
});

router.post("/refresh", (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const newAccess = jwt.sign(decoded, process.env.JWT_SECRET, {
      expiresIn: "8h",
    });
    res.json({ token: newAccess });
  } catch {
    res.status(401).json({ error: "Invalid refresh token" });
  }
});

export default router;
