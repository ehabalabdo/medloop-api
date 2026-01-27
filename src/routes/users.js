import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import pool from "../db.js";

function makeDoctorUsername(name) {
  return "dr_" + name.toLowerCase().replace(/\s+/g, "");
}

function makePassword() {
  return crypto.randomBytes(6).toString("base64url");
}

const router = express.Router();

// إضافة دكتور جديد مع حساب تلقائي
router.post("/doctors", async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { full_name, email } = req.body;
  if (!full_name) {
    return res.status(400).json({ error: "full_name required" });
  }

  let username = makeDoctorUsername(full_name);
  let password = makePassword();
  let password_hash = await bcrypt.hash(password, 10);

  try {
    const { rows } = await pool.query(
      `INSERT INTO users (full_name, email, role, username, password_hash)
       VALUES ($1,$2,'doctor',$3,$4)
       RETURNING id, full_name, username`,
      [full_name, email || null, username, password_hash]
    );
    res.status(201).json({
      doctor: rows[0],
      credentials: { username, password }
    });
  } catch (err) {
    if (err.code === "23505") {
      // أضف 4 أرقام عشوائية إذا كان الاسم مكرر
      username = username + '-' + Math.floor(1000 + Math.random() * 9000);
      password = makePassword();
      password_hash = await bcrypt.hash(password, 10);
      const { rows } = await pool.query(
        `INSERT INTO users (full_name, email, role, username, password_hash)
         VALUES ($1,$2,'doctor',$3,$4)
         RETURNING id, full_name, username`,
        [full_name, email || null, username, password_hash]
      );
      return res.status(201).json({
        doctor: rows[0],
        credentials: { username, password }
      });
    }
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
