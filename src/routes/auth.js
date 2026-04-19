import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import pool from "../db.js";

const router = express.Router();

/**
 * POST /auth/login
 * Accepts { username, password, client_id? }
 * Checks users table then patients table
 * Returns JWT with user info
 */
router.post("/login", async (req, res) => {
  try {
    const { username, password, client_id } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "username and password required" });
    }

    // 1) Check users table (staff: admin, doctor, receptionist, etc.)
    const staffQuery = client_id
      ? `SELECT id, full_name, email, password, role, clinic_id, clinic_ids, client_id, is_active
         FROM users
         WHERE (full_name=$1 OR email=$1)
           AND client_id=$2
         LIMIT 1`
      : `SELECT id, full_name, email, password, role, clinic_id, clinic_ids, client_id, is_active
         FROM users
         WHERE (full_name=$1 OR email=$1)
         LIMIT 1`;

    const staffParams = client_id ? [username, client_id] : [username];
    const staff = await pool.query(staffQuery, staffParams);

    if (staff.rows.length) {
      const user = staff.rows[0];

      if (user.is_active === false) {
        return res.status(403).json({ error: "Account is deactivated" });
      }

      // Support both bcrypt-hashed and plaintext passwords (migration period)
      let passwordValid = false;
      if (user.password && user.password.startsWith("$2")) {
        passwordValid = await bcrypt.compare(password, user.password);
      } else {
        passwordValid = password === user.password;
      }

      if (!passwordValid) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Parse clinic_ids
      let clinicIds = [];
      try {
        clinicIds = typeof user.clinic_ids === "string"
          ? JSON.parse(user.clinic_ids)
          : user.clinic_ids || [];
      } catch { clinicIds = []; }

      const token = jwt.sign(
        {
          id: user.id,
          role: user.role,
          type: "staff",
          client_id: user.client_id,
          clinic_id: user.clinic_id,
        },
        process.env.JWT_SECRET,
        { expiresIn: "8h" }
      );

      return res.json({
        token,
        type: "staff",
        user: {
          uid: String(user.id),
          name: user.full_name,
          email: user.email,
          role: user.role,
          clinicIds,
          clientId: user.client_id,
          isActive: user.is_active !== false,
        },
      });
    }

    // 2) Check patients table
    const patientQuery = client_id
      ? `SELECT id, full_name, phone, email, username, password, has_access, client_id,
                date_of_birth, gender, age, medical_profile, current_visit, history
         FROM patients
         WHERE (username=$1 OR phone=$1 OR full_name=$1 OR email=$1)
           AND has_access=true
           AND client_id=$2
         LIMIT 1`
      : `SELECT id, full_name, phone, email, username, password, has_access, client_id,
                date_of_birth, gender, age, medical_profile, current_visit, history
         FROM patients
         WHERE (username=$1 OR phone=$1 OR full_name=$1 OR email=$1)
           AND has_access=true
         LIMIT 1`;

    const patientParams = client_id ? [username, client_id] : [username];
    const patient = await pool.query(patientQuery, patientParams);

    if (patient.rows.length) {
      const p = patient.rows[0];

      // Support both bcrypt-hashed and plaintext passwords
      let passwordValid = false;
      if (p.password && p.password.startsWith("$2")) {
        passwordValid = await bcrypt.compare(password, p.password);
      } else {
        passwordValid = password === p.password;
      }

      if (!passwordValid) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign(
        {
          patient_id: p.id,
          type: "patient",
          client_id: p.client_id,
        },
        process.env.JWT_SECRET,
        { expiresIn: "8h" }
      );

      return res.json({
        token,
        type: "patient",
        patient: {
          id: String(p.id),
          name: p.full_name,
          phone: p.phone,
          email: p.email,
          username: p.username,
          clientId: p.client_id,
        },
      });
    }

    res.status(401).json({ error: "Invalid credentials" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /auth/super-admin/login
 * For platform super admin login. Uses bcrypt-hashed passwords stored in
 * super_admins.password_hash. Falls back to legacy plaintext "password"
 * column ONLY if the row has not been migrated yet (auto-upgrades on success).
 */
router.post("/super-admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "username and password required" });
    }

    // Detect whether the legacy plaintext "password" column still exists,
    // so this works on freshly migrated and not-yet-migrated databases.
    const colInfo = await pool.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name='super_admins'
         AND column_name IN ('password','password_hash','is_active')`
    );
    const cols = new Set(colInfo.rows.map((r) => r.column_name));
    const hasHash      = cols.has("password_hash");
    const hasLegacy    = cols.has("password");
    const hasIsActive  = cols.has("is_active");

    const selectCols = [
      "id",
      "username",
      "name",
      hasHash ? "password_hash" : null,
      hasLegacy ? "password" : null,
      hasIsActive ? "is_active" : null,
    ].filter(Boolean).join(", ");

    const { rows } = await pool.query(
      `SELECT ${selectCols} FROM super_admins WHERE username=$1 LIMIT 1`,
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const admin = rows[0];

    if (hasIsActive && admin.is_active === false) {
      return res.status(403).json({ error: "Account is deactivated" });
    }

    let valid = false;
    let upgradeFromPlaintext = false;
    if (admin.password_hash && admin.password_hash.startsWith("$2")) {
      valid = await bcrypt.compare(password, admin.password_hash);
      console.log("[super-admin/login] bcrypt compare for", username,
        "hash_prefix=", admin.password_hash.slice(0,7),
        "pwd_len=", password.length, "result=", valid);
    } else if (admin.password) {
      // Legacy plaintext fallback — auto-upgrade to bcrypt on successful login.
      valid = password === admin.password;
      upgradeFromPlaintext = valid;
    }

    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (upgradeFromPlaintext && hasHash) {
      try {
        const newHash = await bcrypt.hash(password, 12);
        await pool.query(
          "UPDATE super_admins SET password_hash=$1, updated_at=NOW() WHERE id=$2",
          [newHash, admin.id]
        );
      } catch (e) {
        console.error("Failed to upgrade super_admin password to bcrypt:", e);
      }
    }

    if (hasIsActive) {
      pool.query(
        "UPDATE super_admins SET last_login_at=NOW() WHERE id=$1",
        [admin.id]
      ).catch(() => {});
    }

    const token = jwt.sign(
      { id: admin.id, type: "super_admin", role: "super_admin" },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    return res.json({
      token,
      type: "super_admin",
      admin: { id: admin.id, username: admin.username, name: admin.name },
    });
  } catch (err) {
    console.error("Super admin login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /auth/hr-login
 * HR Employee login (separate from staff login)
 */
router.post("/hr-login", async (req, res) => {
  try {
    const { username, password, client_id } = req.body;
    if (!username || !password || !client_id) {
      return res.status(400).json({ error: "username, password, client_id required" });
    }

    const result = await pool.query(
      `SELECT id, client_id, full_name, username, password, status
       FROM hr_employees
       WHERE (username=$1 OR email=$1) AND client_id=$2
       LIMIT 1`,
      [username, client_id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const emp = result.rows[0];
    if (emp.status !== "active") {
      return res.status(403).json({ error: "Account is deactivated" });
    }

    // bcrypt check (with plaintext fallback for migration)
    let passwordValid = false;
    if (emp.password && emp.password.startsWith("$2")) {
      passwordValid = await bcrypt.compare(password, emp.password);
    } else {
      passwordValid = password === emp.password;
    }
    if (!passwordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        id: emp.id,
        hr_employee_id: emp.id,
        role: "employee",
        type: "hr_employee",
        client_id: emp.client_id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    return res.json({
      token,
      type: "hr_employee",
      employee: {
        id: emp.id,
        fullName: emp.full_name,
        username: emp.username,
        clientId: emp.client_id,
      },
    });
  } catch (err) {
    console.error("HR login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /auth/refresh
 * Refresh an expired JWT access token
 */
router.post("/refresh", (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // Remove iat/exp from old token before re-signing
    const { iat, exp, ...payload } = decoded;
    const newAccess = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "8h",
    });
    res.json({ token: newAccess });
  } catch {
    res.status(401).json({ error: "Invalid refresh token" });
  }
});

export default router;
