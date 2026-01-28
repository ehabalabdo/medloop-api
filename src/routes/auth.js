const express = require("express");
const jwt = require("jsonwebtoken");
const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("../db.js");
const bcrypt = require("bcryptjs");
const router = express.Router();

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log("LOGIN_TRY:", username);

    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [username]);
    const user = userRes.rows[0];

    if (!user) return res.status(401).json({ error: "No User" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Wrong Pass" });

    // فحص العيادة
    const clinicRes = await pool.query("SELECT active FROM clinics WHERE id = $1", [user.clinic_id]);
    if (!clinicRes.rows.length || !clinicRes.rows[0].active) {
      return res.status(403).json({ error: "Clinic Issue" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "8h" });
    return res.json({ token, user: { email: user.email, role: user.role } });

  } catch (err) {
    console.error("AUTH_ERROR:", err);
    return res.status(500).json({ error: "Server Error" });
  }
});

module.exports = router;

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
