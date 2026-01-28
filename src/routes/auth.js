import express from "express";
import jwt from "jsonwebtoken";
import pool from "../db.js";
import bcrypt from "bcryptjs";

const router = express.Router();


router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // 1) users (staff)
  const staff = await pool.query(
    `SELECT id, email, password_hash, full_name, role, clinic_id FROM users WHERE email=$1`,
    [username]
  );

  if (staff.rows.length) {
    const user = staff.rows[0];
    // Check password securely using bcrypt
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    // Check if clinic is active (optional, but recommended)
    const clinicRes = await pool.query(
      `SELECT id, active FROM clinics WHERE id=$1`,
      [user.clinic_id]
    );
    if (!clinicRes.rows.length || clinicRes.rows[0].active === false) {
      return res.status(403).json({ error: "Clinic is not active" });
    }

    // Build JWT payload with clinicId and role
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        clinicId: user.clinic_id,
        type: "staff"
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    // Remove password_hash before sending user object
    const { password_hash, ...userWithoutPassword } = user;
    return res.json({
      token,
      user: userWithoutPassword
    });
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
