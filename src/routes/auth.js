
const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("../db.js");
const bcrypt = require("bcryptjs");
const router = express.Router();




router.post("/login", async (req, res) => {
  try {
    // قبول القيمة سواء كانت email أو username لضمان التوافق
    const identity = req.body.email || req.body.username;
    const password = req.body.password;

    if (!identity || !password) {
      return res.status(400).json({ error: "Missing data" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [identity]);
    const user = userRes.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // فحص ذكي للسر (Secret) لضمان عدم الانهيار
    const secret = process.env.JWT_SECRET || "fallback_secret_123";
    if (!process.env.JWT_SECRET) {
      console.warn("JWT_SECRET is missing! Using fallback secret. This is insecure for production.");
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      secret,
      { expiresIn: "8h" }
    );

    res.json({ token, user: { email: user.email, role: user.role } });

  } catch (err) {
    console.error("FINAL_AUTH_ERROR:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

module.exports = router;
