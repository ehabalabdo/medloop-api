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
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [username]);
    const user = userRes.rows[0];

    if (!user) return res.status(401).json({ error: "Invalid" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "8h" });
    res.json({ token, user: { email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
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
