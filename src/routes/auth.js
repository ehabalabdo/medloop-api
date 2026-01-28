
const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("../db.js");
const bcrypt = require("bcryptjs");
const router = express.Router();

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [username]);
    
    if (userRes.rows.length === 0) return res.status(401).json({ error: "Invalid" });
    const user = userRes.rows[0];

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: "Invalid" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "8h" });
    return res.json({ token, user: { email: user.email } });
  } catch (err) {
    return res.status(500).json({ error: "Server Error" });
  }
});

module.exports = router;
