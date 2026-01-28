
const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("../db.js");
const bcrypt = require("bcryptjs");
const router = express.Router();


router.post("/login", async (req, res) => {
  try {
    // يقبل أي اسم متغير (email أو username أو غيره)
    const loginIdentity = req.body.email || req.body.username || req.body.user || req.body.login || req.body.identity;
    const { password } = req.body;

    if (!loginIdentity || !password) {
      return res.status(400).json({ error: "يرجى إدخال البريد الإلكتروني أو اسم المستخدم وكلمة المرور" });
    }

    // جرب البحث بالبريد الإلكتروني أولاً
    let userRes = await pool.query("SELECT * FROM users WHERE email = $1", [loginIdentity]);
    // إذا لم يوجد، جرب البحث باسم المستخدم
    if (userRes.rows.length === 0) {
      userRes = await pool.query("SELECT * FROM users WHERE username = $1", [loginIdentity]);
    }

    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: "المستخدم غير موجود" });
    }

    const user = userRes.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: "كلمة المرور غير صحيحة" });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "8h" });
    return res.json({ token, user: { email: user.email, fullName: user.full_name, role: user.role } });
  } catch (err) {
    console.error("AUTH_FATAL_ERROR:", err.message);
    return res.status(500).json({ error: "خطأ داخلي في السيرفر" });
  }
});

module.exports = router;
