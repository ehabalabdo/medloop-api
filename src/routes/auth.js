const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("../db.js");
const bcrypt = require("bcryptjs");

const router = express.Router();




router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log("Login attempt for:", username);

    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [username]);
    const user = userRes.rows[0];

    if (!user) return res.status(401).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: "Wrong password" });

    // فحص العيادة - تأكد أن هذا الجدول موجود
    const clinicRes = await pool.query("SELECT active FROM clinics WHERE id = $1", [user.clinic_id]);
    if (clinicRes.rows.length === 0 || !clinicRes.rows[0].active) {
      return res.status(403).json({ error: "Clinic inactive or not found" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" });
    return res.json({ token, user: { email: user.email, fullName: user.full_name, role: user.role } });

  } catch (error) {
    console.error("Auth Error:", error);
    return res.status(500).json({ error: "Server Internal Error" });
  }
});

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

module.exports = router;
