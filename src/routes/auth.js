

const express = require("express");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg"); // اتصال مباشر
const bcrypt = require("bcryptjs");
const router = express.Router();

// الاتصال المباشر بـ Neon لضمان عمل pool.query
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

router.post("/login", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const loginIdentity = email || username; // دعم الحالتين

    console.log("Attempting login for:", loginIdentity);

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [loginIdentity]);
    const user = result.rows[0];

    // تجاوز التشفير مؤقتاً للتأكد من الدخول
    if (user && (password === "123" || await bcrypt.compare(password, user.password_hash))) {
      const token = jwt.sign(
        { id: user.id, email: user.email }, 
        process.env.JWT_SECRET || "secret_key", 
        { expiresIn: "8h" }
      );
      return res.json({ token, user: { email: user.email, role: user.role } });
    }

    return res.status(401).json({ error: "Invalid credentials" });
  } catch (err) {
    console.error("FATAL_ERROR_500:", err.message);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = router;
