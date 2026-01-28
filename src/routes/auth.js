

const express = require("express");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg"); // استدعاء مباشر للمكتبة
const bcrypt = require("bcryptjs");
const router = express.Router();

// تعريف الاتصال مباشرة لضمان عدم ضياع الـ pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

router.post("/login", async (req, res) => {
  try {
    const identity = req.body.email || req.body.username;
    const { password } = req.body;

    if (!identity || !password) return res.status(400).json({ error: "Missing data" });

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [identity]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "8h" }
    );

    res.json({ token, user: { email: user.email, role: user.role } });

  } catch (err) {
    console.error("FINAL_AUTH_ERROR:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

module.exports = router;
