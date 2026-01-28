import express from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import pool from "../db.js";

function makeUsername(phone) {
  const clean = String(phone || "").replace(/\D/g, "");
  return `p${clean}`;
}

function makePassword() {
  return crypto.randomBytes(6).toString("base64url");
}

const router = express.Router();

// إنشاء مريض جديد مع حساب تلقائي
router.post("/", async (req, res) => {
  const { role } = req.user;
  if (!["admin", "receptionist"].includes(role)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { full_name, phone, notes } = req.body;
  if (!full_name || !phone) {
    return res.status(400).json({ error: "full_name and phone required" });
  }

  let username = makeUsername(phone);
  let password = makePassword();
  let password_hash = await bcrypt.hash(password, 10);

  try {
    const { rows } = await pool.query(
      `INSERT INTO patients (full_name, phone, notes, username, password_hash, has_access)
       VALUES ($1,$2,$3,$4,$5,true)
       RETURNING id, full_name, phone, username`,
      [full_name, phone, notes || null, username, password_hash]
    );
    res.status(201).json({
      patient: rows[0],
      credentials: { username, password }
    });
  } catch (err) {
    // لو username مكرر (نفس الرقم)
    if (err.code === "23505") {
      // أضف 4 أرقام عشوائية
      username = username + '-' + Math.floor(1000 + Math.random() * 9000);
      password = makePassword();
      password_hash = await bcrypt.hash(password, 10);
      const { rows } = await pool.query(
        `INSERT INTO patients (full_name, phone, notes, username, password_hash, has_access)
         VALUES ($1,$2,$3,$4,$5,true)
         RETURNING id, full_name, phone, username`,
        [full_name, phone, notes || null, username, password_hash]
      );
      return res.status(201).json({
        patient: rows[0],
        credentials: { username, password }
      });
    }
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
