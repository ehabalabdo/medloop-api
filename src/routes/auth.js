
const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("../db.js");
const bcrypt = require("bcryptjs");
const router = express.Router();



router.post("/login", async (req, res) => {
  try {
    // نأخذ القيمة سواء كانت مبعوثة باسم email أو username لضمان التوافق
    const loginValue = req.body.email || req.body.username;
    const { password } = req.body;

    if (!loginValue || !password) {
      return res.status(400).json({ error: "Missing email or password" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [loginValue]);
    
    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = userRes.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // إنشاء التوكن - تأكد من وجود JWT_SECRET في إعدادات Render
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role }, 
      process.env.JWT_SECRET, 
      { expiresIn: "8h" }
    );

    res.json({
      token,
      user: { email: user.email, fullName: user.full_name, role: user.role }
    });

  } catch (err) {
    // هذا السطر سيكتب سبب الخطأ الحقيقي في لوجز Render
    console.error("AUTH_ERROR:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

module.exports = router;
