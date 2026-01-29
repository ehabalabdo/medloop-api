

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
    console.log("BODY", req.body);
    const { email, password } = req.body;
    // سطر الفحص: رح يطبع بياناتك في رندر قبل ما يكمل

    const result = await pool.query("SELECT id, email, role, clinic_id FROM users WHERE email = $1", [email]);
    console.log("DEBUG_USER_DATA:", result.rows[0]);

    const user = result.rows[0];

    if (user && password === "123") {
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET || "shhh", 
        { expiresIn: "8h" }
      );

      console.log("LOGIN_SUCCESS_FOR_ROLE:", user.role);

      return res.json({ 
        token, 
        user: { 
          id: user.id,
          email: user.email, 
          role: user.role,
          clinic_id: user.clinic_id
        }
      });
    }

    return res.status(401).json({ error: "Invalid Credentials" });
  } catch (err) {
    console.error("BACKEND_CHECK_ERROR:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

module.exports = router;
