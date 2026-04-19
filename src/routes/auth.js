import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import pool from "../db.js";
import { decrypt, blindIndex } from "../utils/crypto.js";
import { isLocked, recordFailedLogin, recordSuccessfulLogin, LOCKOUT_CONFIG } from "../utils/lockout.js";
import logger from "../utils/logger.js";
import { validateBody, z } from "../utils/zod-validate.js";

const router = express.Router();

// Shared schemas — bound payload sizes to defeat oversized-string DoS attempts.
const LoginSchema = z.object({
  username: z.string().trim().min(1).max(255),
  password: z.string().min(1).max(500),
  client_id: z.union([z.string().min(1).max(64), z.number().int().positive()]),
});

const SuperAdminLoginSchema = z.object({
  username: z.string().trim().min(1).max(255),
  password: z.string().min(1).max(500),
});

const HrLoginSchema = LoginSchema;

/**
 * POST /auth/login
 * Accepts { username, password, client_id? }
 * Checks users table then patients table
 * Returns JWT with user info
 */
router.post("/login", validateBody(LoginSchema), async (req, res) => {
  try {
    const { username, password, client_id } = req.validBody;

    // SECURITY: client_id is mandatory to prevent cross-tenant account
    // enumeration / hijacking. Frontend must always resolve tenant via slug
    // before invoking login.
    if (!client_id) {
      return res.status(400).json({ error: "client_id required" });
    }

    // 1) Check users table (staff: admin, doctor, receptionist, etc.)
    const staffQuery = `SELECT id, full_name, email, password, role, clinic_id, clinic_ids, client_id, is_active,
            failed_login_count, locked_until
         FROM users
         WHERE (full_name=$1 OR email=$1)
           AND client_id=$2
         LIMIT 1`;
    const staffParams = [username, client_id];
    const staff = await pool.query(staffQuery, staffParams);

    if (staff.rows.length) {
      const user = staff.rows[0];

      if (user.is_active === false) {
        return res.status(403).json({ error: "Account is deactivated" });
      }

      if (isLocked(user)) {
        return res.status(423).json({ error: `Account locked. Try again in ${LOCKOUT_CONFIG.LOCK_MINUTES} minutes.` });
      }

      // Support both bcrypt-hashed and plaintext passwords (migration period)
      let passwordValid = false;
      if (user.password && user.password.startsWith("$2")) {
        passwordValid = await bcrypt.compare(password, user.password);
      } else {
        passwordValid = password === user.password;
      }

      if (!passwordValid) {
        await recordFailedLogin("users", user.id).catch(() => {});
        return res.status(401).json({ error: "Invalid credentials" });
      }

      await recordSuccessfulLogin("users", user.id).catch(() => {});

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

    // Patient login: search by blind indexes first (encrypted columns are not directly searchable),
    // then fall back to plaintext columns for legacy rows that haven't been migrated yet.
    const usernameIdx = blindIndex(username);
    const phoneIdx = blindIndex(String(username).replace(/\D/g, ""));

    const patientQuery = `SELECT id, full_name, phone, email, username, password, has_access, client_id,
                date_of_birth, gender, age, medical_profile, current_visit, history,
                failed_login_count, locked_until
         FROM patients
         WHERE (
              ($3::char(64) IS NOT NULL AND username_idx=$3)
           OR ($4::char(64) IS NOT NULL AND phone_idx=$4)
           OR username=$1
           OR phone=$1
           OR full_name=$1
           OR email=$1
         )
           AND has_access=true
           AND client_id=$2
         LIMIT 1`;
    const patientParams = [username, client_id, usernameIdx, phoneIdx];
    const patient = await pool.query(patientQuery, patientParams);

    if (patient.rows.length) {
      const p = patient.rows[0];

      if (isLocked(p)) {
        return res.status(423).json({ error: `Account locked. Try again in ${LOCKOUT_CONFIG.LOCK_MINUTES} minutes.` });
      }

      // Support both bcrypt-hashed and plaintext passwords
      let passwordValid = false;
      if (p.password && p.password.startsWith("$2")) {
        passwordValid = await bcrypt.compare(password, p.password);
      } else {
        passwordValid = password === p.password;
      }

      if (!passwordValid) {
        await recordFailedLogin("patients", p.id).catch(() => {});
        return res.status(401).json({ error: "Invalid credentials" });
      }

      await recordSuccessfulLogin("patients", p.id).catch(() => {});

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
          name: decrypt(p.full_name),
          phone: decrypt(p.phone),
          email: decrypt(p.email),
          username: p.username,
          clientId: p.client_id,
        },
      });
    }

    res.status(401).json({ error: "Invalid credentials" });
  } catch (err) {
    logger.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /auth/super-admin/login
 * For platform super admin login. Uses bcrypt-hashed passwords stored in
 * super_admins.password_hash. Falls back to legacy plaintext "password"
 * column ONLY if the row has not been migrated yet (auto-upgrades on success).
 */
router.post("/super-admin/login", validateBody(SuperAdminLoginSchema), async (req, res) => {
  try {
    const { username, password } = req.validBody;

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

    if (isLocked(admin)) {
      return res.status(423).json({ error: `Account locked. Try again in ${LOCKOUT_CONFIG.LOCK_MINUTES} minutes.` });
    }

    let valid = false;
    let upgradeFromPlaintext = false;
    if (admin.password_hash && admin.password_hash.startsWith("$2")) {
      valid = await bcrypt.compare(password, admin.password_hash);
    } else if (admin.password) {
      // Legacy plaintext fallback â€” auto-upgrade to bcrypt on successful login.
      valid = password === admin.password;
      upgradeFromPlaintext = valid;
    }

    if (!valid) {
      await recordFailedLogin("super_admins", admin.id).catch(() => {});
      return res.status(401).json({ error: "Invalid credentials" });
    }

    await recordSuccessfulLogin("super_admins", admin.id).catch(() => {});

    if (upgradeFromPlaintext && hasHash) {
      try {
        const newHash = await bcrypt.hash(password, 12);
        await pool.query(
          "UPDATE super_admins SET password_hash=$1, updated_at=NOW() WHERE id=$2",
          [newHash, admin.id]
        );
      } catch (e) {
        logger.error("Failed to upgrade super_admin password to bcrypt:", e);
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
    logger.error("Super admin login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /auth/hr-login
 * HR Employee login (separate from staff login)
 */
router.post("/hr-login", validateBody(HrLoginSchema), async (req, res) => {
  try {
    const { username, password, client_id } = req.validBody;

    const emailIdx = blindIndex(username);
    const result = await pool.query(
      `SELECT id, client_id, full_name, username, password, status,
              failed_login_count, locked_until
       FROM hr_employees
       WHERE (
            username=$1
         OR email=$1
         OR ($3::char(64) IS NOT NULL AND email_idx=$3)
       ) AND client_id=$2
       LIMIT 1`,
      [username, client_id, emailIdx]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const emp = result.rows[0];
    if (emp.status !== "active") {
      return res.status(403).json({ error: "Account is deactivated" });
    }

    if (isLocked(emp)) {
      return res.status(423).json({ error: `Account locked. Try again in ${LOCKOUT_CONFIG.LOCK_MINUTES} minutes.` });
    }

    // bcrypt check (with plaintext fallback for migration)
    let passwordValid = false;
    if (emp.password && emp.password.startsWith("$2")) {
      passwordValid = await bcrypt.compare(password, emp.password);
    } else {
      passwordValid = password === emp.password;
    }
    if (!passwordValid) {
      await recordFailedLogin("hr_employees", emp.id).catch(() => {});
      return res.status(401).json({ error: "Invalid credentials" });
    }

    await recordSuccessfulLogin("hr_employees", emp.id).catch(() => {});

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
        fullName: decrypt(emp.full_name),
        username: emp.username,
        clientId: emp.client_id,
      },
    });
  } catch (err) {
    logger.error("HR login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /auth/refresh
 * Refresh an expired JWT access token
 */
/**
 * POST /auth/migrate-encryption
 * Super-admin only. Re-encrypts plaintext PII rows and back-fills blind
 * indexes. Idempotent: rows already prefixed with `enc:` are skipped.
 * Safe to re-run after toggling ENCRYPTION_KEY.
 */
router.post("/migrate-encryption", async (req, res) => {
  try {
    // Authn via JWT (super-admin)
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    let decoded;
    try { decoded = jwt.verify(token, process.env.JWT_SECRET); }
    catch { return res.status(401).json({ error: "Invalid token" }); }
    if (decoded.role !== "super_admin" && decoded.type !== "super_admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { encrypt } = await import("../utils/crypto.js");
    const stats = { patients: 0, hr_employees: 0, appointments: 0, invoices: 0 };
    const normPhone = (p) => (p ? String(p).replace(/\D/g, "") : null);

    // patients ---------------------------------------------------------
    {
      const { rows } = await pool.query(
        `SELECT id, full_name, phone, email, notes, username FROM patients`
      );
      for (const r of rows) {
        const sets = [];
        const params = [];
        let idx = 1;
        const enc = (col, v) => {
          if (v == null) return;
          if (typeof v === "string" && v.startsWith("enc:")) return;
          sets.push(`${col}=$${idx++}`);
          params.push(encrypt(v));
        };
        enc("full_name", r.full_name);
        enc("phone", r.phone);
        enc("email", r.email);
        enc("notes", r.notes);
        // blind indexes
        if (r.phone) { sets.push(`phone_idx=$${idx++}`); params.push(blindIndex(normPhone(r.phone))); }
        if (r.username) { sets.push(`username_idx=$${idx++}`); params.push(blindIndex(r.username)); }
        if (sets.length) {
          params.push(r.id);
          await pool.query(`UPDATE patients SET ${sets.join(", ")} WHERE id=$${idx}`, params);
          stats.patients++;
        }
      }
    }

    // hr_employees -----------------------------------------------------
    {
      const { rows } = await pool.query(
        `SELECT id, full_name, phone, email FROM hr_employees`
      );
      for (const r of rows) {
        const sets = [];
        const params = [];
        let idx = 1;
        const enc = (col, v) => {
          if (v == null) return;
          if (typeof v === "string" && v.startsWith("enc:")) return;
          sets.push(`${col}=$${idx++}`);
          params.push(encrypt(v));
        };
        enc("full_name", r.full_name);
        enc("phone", r.phone);
        enc("email", r.email);
        if (r.email) { sets.push(`email_idx=$${idx++}`); params.push(blindIndex(r.email)); }
        if (r.phone) { sets.push(`phone_idx=$${idx++}`); params.push(blindIndex(normPhone(r.phone))); }
        if (sets.length) {
          params.push(r.id);
          await pool.query(`UPDATE hr_employees SET ${sets.join(", ")} WHERE id=$${idx}`, params);
          stats.hr_employees++;
        }
      }
    }

    // appointments -----------------------------------------------------
    {
      const { rows } = await pool.query(
        `SELECT id, patient_name, reason FROM appointments`
      );
      for (const r of rows) {
        const sets = [];
        const params = [];
        let idx = 1;
        const enc = (col, v) => {
          if (v == null) return;
          if (typeof v === "string" && v.startsWith("enc:")) return;
          sets.push(`${col}=$${idx++}`);
          params.push(encrypt(v));
        };
        enc("patient_name", r.patient_name);
        enc("reason", r.reason);
        if (sets.length) {
          params.push(r.id);
          await pool.query(`UPDATE appointments SET ${sets.join(", ")} WHERE id=$${idx}`, params);
          stats.appointments++;
        }
      }
    }

    // invoices ---------------------------------------------------------
    {
      const { rows } = await pool.query(
        `SELECT id, patient_name FROM invoices`
      );
      for (const r of rows) {
        if (!r.patient_name || (typeof r.patient_name === "string" && r.patient_name.startsWith("enc:"))) continue;
        await pool.query(
          `UPDATE invoices SET patient_name=$1 WHERE id=$2`,
          [encrypt(r.patient_name), r.id]
        );
        stats.invoices++;
      }
    }

    return res.json({ ok: true, migrated: stats });
  } catch (err) {
    logger.error("POST /auth/migrate-encryption error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /auth/migrate-passwords
 * Super-admin only. Bcrypt-hashes any remaining plaintext passwords in
 * users / hr_employees / patients. Idempotent: rows already prefixed with
 * `$2` (bcrypt hash) are skipped. Safe to re-run.
 */
router.post("/migrate-passwords", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    let decoded;
    try { decoded = jwt.verify(token, process.env.JWT_SECRET); }
    catch { return res.status(401).json({ error: "Invalid token" }); }
    if (decoded.role !== "super_admin" && decoded.type !== "super_admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    const stats = { users: 0, hr_employees: 0, patients: 0 };
    for (const table of ["users", "hr_employees", "patients"]) {
      const { rows } = await pool.query(
        `SELECT id, password FROM ${table}
         WHERE password IS NOT NULL AND password NOT LIKE '$2%'`
      );
      for (const r of rows) {
        const hash = await bcrypt.hash(r.password, 12);
        await pool.query(`UPDATE ${table} SET password=$1 WHERE id=$2`, [hash, r.id]);
        stats[table]++;
      }
    }
    return res.json({ ok: true, hashed: stats });
  } catch (err) {
    logger.error("POST /auth/migrate-passwords error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

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
