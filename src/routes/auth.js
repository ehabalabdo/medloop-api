const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("../db.js");
const bcrypt = require("bcryptjs");

const router = express.Router();



router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("LOGIN_ATTEMPT:", username); // لوج بسيط جداً للتأكد من وصول الطلب

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [username]
    );
    const user = result.rows[0];

    if (!user) {
      console.log("USER_NOT_FOUND");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    console.log("PASSWORD_MATCH:", match);

    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    // فحص العيادة
    console.log("CLINIC_ID:", user.clinic_id);
    const clinicRes = await pool.query("SELECT active FROM clinics WHERE id=$1", [user.clinic_id]);
    
    if (!clinicRes.rows.length || !clinicRes.rows[0].active) {
       console.log("CLINIC_INACTIVE_OR_MISSING");
       return res.status(403).json({ error: "Clinic not active" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "8h" });
    res.json({ token, user: { email: user.email, role: user.role } });

  } catch (err) {
    console.error("AUTH_CRASH:", err);
    res.status(500).json({ error: "Server Error" });
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
