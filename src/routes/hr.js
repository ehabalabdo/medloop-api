import express from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import pool from "../db.js";
import { auth } from "../middleware/auth.js";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const router = express.Router();
router.use(auth);

// ============================================================
//  CONSTANTS / HELPERS
// ============================================================

/** Relying-party config for WebAuthn (must match the HTTPS origin) */
const RP_NAME = "MED LOOP HR";
const RP_ID_PROD = "med.loopjo.com";
const RP_ORIGIN_PROD = "https://med.loopjo.com";
const RP_ID_DEV = "localhost";
const RP_ORIGIN_DEV = "http://localhost:3000";

function rpConfig() {
  const isProd = process.env.NODE_ENV === "production" ||
    !process.env.NODE_ENV; // default to prod on Render
  return {
    rpID: isProd ? RP_ID_PROD : RP_ID_DEV,
    rpName: RP_NAME,
    origin: isProd ? RP_ORIGIN_PROD : RP_ORIGIN_DEV,
  };
}

/** Haversine distance between two lat/lng pairs -> metres */
function haversineMetres(lat1, lng1, lat2, lng2) {
  const R = 6_371_000; // Earth radius in metres
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function requireAdmin(req, res) {
  if (req.user.role !== "admin" && req.user.type !== "hr_employee") {
    res.status(403).json({ error: "Admin access required" });
    return false;
  }
  // hr_employee can never reach admin routes via normal auth; double-check
  if (req.user.type === "hr_employee") {
    res.status(403).json({ error: "Admin access required" });
    return false;
  }
  return true;
}

function requireHrEmployee(req, res) {
  if (req.user.type !== "hr_employee") {
    res.status(403).json({ error: "HR employee access required" });
    return false;
  }
  return true;
}

// ============================================================
//  1. CLINIC LOCATION  (admin)
// ============================================================

/**
 * PATCH /hr/clinic/location
 * Body: { clinic_id, latitude, longitude, allowed_radius_meters }
 */
router.patch("/clinic/location", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { client_id } = req.user;
    const { clinic_id, latitude, longitude, allowed_radius_meters } = req.body;
    if (latitude == null || longitude == null) {
      return res.status(400).json({ error: "latitude and longitude required" });
    }
    const radius = allowed_radius_meters ?? 100;

    // If clinic_id provided, update that clinic; otherwise update first clinic of client
    let query, params;
    if (clinic_id) {
      query = `UPDATE clinics SET latitude=$1, longitude=$2, allowed_radius_meters=$3,
               location_updated_at=NOW() WHERE id=$4 AND client_id=$5 RETURNING *`;
      params = [latitude, longitude, radius, clinic_id, client_id];
    } else {
      query = `UPDATE clinics SET latitude=$1, longitude=$2, allowed_radius_meters=$3,
               location_updated_at=NOW() WHERE client_id=$4 AND id=(SELECT id FROM clinics WHERE client_id=$4 ORDER BY id LIMIT 1)
               RETURNING *`;
      params = [latitude, longitude, radius, client_id];
    }

    const { rows } = await pool.query(query, params);
    if (!rows.length) return res.status(404).json({ error: "Clinic not found" });
    res.json({
      clinic_id: rows[0].id,
      latitude: rows[0].latitude,
      longitude: rows[0].longitude,
      allowed_radius_meters: rows[0].allowed_radius_meters,
    });
  } catch (err) {
    console.error("PATCH /hr/clinic/location error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /hr/clinic/location
 * Returns location of the client's clinics
 */
router.get("/clinic/location", async (req, res) => {
  try {
    const { client_id } = req.user;
    const { rows } = await pool.query(
      `SELECT id, name, latitude, longitude, allowed_radius_meters
       FROM clinics WHERE client_id=$1 ORDER BY id`,
      [client_id]
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /hr/clinic/location error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================================
//  2. EMPLOYEES CRUD  (admin)
// ============================================================

/** GET /hr/employees */
router.get("/employees", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { client_id } = req.user;
    const { rows } = await pool.query(
      `SELECT e.*,
              (SELECT COUNT(*) FROM hr_biometric_credentials bc WHERE bc.employee_id=e.id) AS bio_count,
              s.work_days, s.start_time, s.end_time, s.grace_minutes, s.overtime_enabled
       FROM hr_employees e
       LEFT JOIN LATERAL (
         SELECT * FROM hr_work_schedules ws
         WHERE ws.employee_id=e.id AND ws.effective_from <= CURRENT_DATE
           AND (ws.effective_to IS NULL OR ws.effective_to >= CURRENT_DATE)
         ORDER BY ws.effective_from DESC LIMIT 1
       ) s ON true
       WHERE e.client_id=$1
       ORDER BY e.created_at DESC`,
      [client_id]
    );
    res.json(
      rows.map((r) => ({
        id: r.id,
        clientId: r.client_id,
        fullName: r.full_name,
        username: r.username,
        phone: r.phone,
        email: r.email,
        status: r.status,
        bioRegistered: Number(r.bio_count) > 0,
        schedule: r.work_days
          ? {
              workDays: r.work_days,
              startTime: r.start_time,
              endTime: r.end_time,
              graceMinutes: r.grace_minutes,
              overtimeEnabled: r.overtime_enabled,
            }
          : null,
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      }))
    );
  } catch (err) {
    console.error("GET /hr/employees error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/** POST /hr/employees */
router.post("/employees", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { client_id } = req.user;
    const {
      full_name,
      username,
      password,
      phone,
      email,
      work_days,
      start_time,
      end_time,
      grace_minutes,
      overtime_enabled,
    } = req.body;

    if (!full_name || !username || !password) {
      return res
        .status(400)
        .json({ error: "full_name, username, password required" });
    }

    // Check uniqueness
    const dup = await pool.query(
      `SELECT id FROM hr_employees WHERE client_id=$1 AND username=$2`,
      [client_id, username]
    );
    if (dup.rows.length) {
      return res
        .status(409)
        .json({ error: "Username already exists for this client" });
    }

    const hash = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO hr_employees (client_id, full_name, username, password, phone, email)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [client_id, full_name, username, hash, phone || null, email || null]
    );

    const empId = rows[0].id;

    // Create initial schedule
    await pool.query(
      `INSERT INTO hr_work_schedules
         (client_id, employee_id, work_days, start_time, end_time, grace_minutes, overtime_enabled)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        client_id,
        empId,
        JSON.stringify(work_days || [1, 2, 3, 4, 5]),
        start_time || "09:00",
        end_time || "17:00",
        grace_minutes ?? 10,
        overtime_enabled !== false,
      ]
    );

    res.status(201).json({ id: empId, username: rows[0].username });
  } catch (err) {
    console.error("POST /hr/employees error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/** PUT /hr/employees/:id */
router.put("/employees/:id", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { client_id } = req.user;
    const { id } = req.params;
    const { full_name, phone, email, status, work_days, start_time, end_time, grace_minutes, overtime_enabled } =
      req.body;

    // Update employee row
    const { rows } = await pool.query(
      `UPDATE hr_employees SET
         full_name=COALESCE($1, full_name),
         phone=COALESCE($2, phone),
         email=COALESCE($3, email),
         status=COALESCE($4, status),
         updated_at=NOW()
       WHERE id=$5 AND client_id=$6 RETURNING *`,
      [full_name, phone, email, status, id, client_id]
    );
    if (!rows.length) return res.status(404).json({ error: "Employee not found" });

    // Update schedule if schedule fields provided
    if (work_days || start_time || end_time || grace_minutes != null || overtime_enabled != null) {
      // Close old schedule
      await pool.query(
        `UPDATE hr_work_schedules SET effective_to=CURRENT_DATE
         WHERE employee_id=$1 AND client_id=$2 AND effective_to IS NULL`,
        [id, client_id]
      );
      // Insert new schedule
      await pool.query(
        `INSERT INTO hr_work_schedules
           (client_id, employee_id, work_days, start_time, end_time, grace_minutes, overtime_enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [
          client_id,
          id,
          JSON.stringify(work_days || [1, 2, 3, 4, 5]),
          start_time || "09:00",
          end_time || "17:00",
          grace_minutes ?? 10,
          overtime_enabled !== false,
        ]
      );
    }

    res.json({ message: "Updated" });
  } catch (err) {
    console.error("PUT /hr/employees/:id error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/** DELETE /hr/employees/:id  (soft deactivate) */
router.delete("/employees/:id", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { client_id } = req.user;
    const { id } = req.params;
    const { rows } = await pool.query(
      `UPDATE hr_employees SET status='inactive', updated_at=NOW()
       WHERE id=$1 AND client_id=$2 RETURNING id`,
      [id, client_id]
    );
    if (!rows.length) return res.status(404).json({ error: "Employee not found" });
    res.json({ message: "Deactivated" });
  } catch (err) {
    console.error("DELETE /hr/employees/:id error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/** POST /hr/employees/:id/reset-password */
router.post("/employees/:id/reset-password", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { client_id } = req.user;
    const { id } = req.params;
    const { password } = req.body;
    const newPass = password || crypto.randomBytes(6).toString("base64url");
    const hash = await bcrypt.hash(newPass, 10);
    const { rows } = await pool.query(
      `UPDATE hr_employees SET password=$1, updated_at=NOW()
       WHERE id=$2 AND client_id=$3 RETURNING id`,
      [hash, id, client_id]
    );
    if (!rows.length) return res.status(404).json({ error: "Employee not found" });
    res.json({ password: newPass }); // Return plaintext one-time so admin can share
  } catch (err) {
    console.error("POST /hr/employees/:id/reset-password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================================
//  3. EMPLOYEE SELF  (hr_employee)
// ============================================================

/** GET /hr/me */
router.get("/me", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  try {
    const { hr_employee_id, client_id } = req.user;

    const emp = await pool.query(
      `SELECT * FROM hr_employees WHERE id=$1 AND client_id=$2`,
      [hr_employee_id, client_id]
    );
    if (!emp.rows.length) return res.status(404).json({ error: "Not found" });
    const e = emp.rows[0];

    // Current schedule
    const sched = await pool.query(
      `SELECT * FROM hr_work_schedules
       WHERE employee_id=$1 AND client_id=$2
         AND effective_from <= CURRENT_DATE
         AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
       ORDER BY effective_from DESC LIMIT 1`,
      [hr_employee_id, client_id]
    );

    // Biometric count
    const bio = await pool.query(
      `SELECT COUNT(*) AS cnt FROM hr_biometric_credentials
       WHERE employee_id=$1 AND client_id=$2`,
      [hr_employee_id, client_id]
    );

    // Today attendance
    const today = await pool.query(
      `SELECT * FROM hr_attendance
       WHERE employee_id=$1 AND client_id=$2 AND work_date=CURRENT_DATE`,
      [hr_employee_id, client_id]
    );

    res.json({
      id: e.id,
      fullName: e.full_name,
      username: e.username,
      phone: e.phone,
      email: e.email,
      status: e.status,
      bioRegistered: Number(bio.rows[0].cnt) > 0,
      bioCount: Number(bio.rows[0].cnt),
      schedule: sched.rows[0]
        ? {
            workDays: sched.rows[0].work_days,
            startTime: sched.rows[0].start_time,
            endTime: sched.rows[0].end_time,
            graceMinutes: sched.rows[0].grace_minutes,
            overtimeEnabled: sched.rows[0].overtime_enabled,
          }
        : null,
      todayAttendance: today.rows[0]
        ? {
            checkIn: today.rows[0].check_in,
            checkOut: today.rows[0].check_out,
            totalMinutes: today.rows[0].total_minutes,
            lateMinutes: today.rows[0].late_minutes,
            overtimeMinutes: today.rows[0].overtime_minutes,
            status: today.rows[0].status,
          }
        : null,
    });
  } catch (err) {
    console.error("GET /hr/me error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================================
//  4. WEBAUTHN  REGISTER  (hr_employee)
// ============================================================

/** POST /hr/webauthn/register/options */
router.post("/webauthn/register/options", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  try {
    const { hr_employee_id, client_id } = req.user;
    const { rpID, rpName } = rpConfig();

    const emp = await pool.query(
      `SELECT id, full_name, username FROM hr_employees WHERE id=$1 AND client_id=$2`,
      [hr_employee_id, client_id]
    );
    if (!emp.rows.length) return res.status(404).json({ error: "Not found" });
    const e = emp.rows[0];

    // Existing credentials to exclude
    const existing = await pool.query(
      `SELECT credential_id FROM hr_biometric_credentials WHERE employee_id=$1`,
      [hr_employee_id]
    );

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: new TextEncoder().encode(String(e.id)),
      userName: e.username,
      userDisplayName: e.full_name,
      excludeCredentials: existing.rows.map((r) => ({
        id: r.credential_id,
        type: "public-key",
      })),
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "discouraged",
      },
      attestationType: "none",
    });

    // Store challenge
    await pool.query(
      `DELETE FROM hr_webauthn_challenges WHERE employee_id=$1 AND type='register'`,
      [hr_employee_id]
    );
    await pool.query(
      `INSERT INTO hr_webauthn_challenges (employee_id, challenge, type)
       VALUES ($1, $2, 'register')`,
      [hr_employee_id, options.challenge]
    );

    res.json(options);
  } catch (err) {
    console.error("POST /hr/webauthn/register/options error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/** POST /hr/webauthn/register/verify */
router.post("/webauthn/register/verify", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  try {
    const { hr_employee_id, client_id } = req.user;
    const { rpID, origin } = rpConfig();

    // Retrieve stored challenge
    const ch = await pool.query(
      `SELECT challenge FROM hr_webauthn_challenges
       WHERE employee_id=$1 AND type='register' AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [hr_employee_id]
    );
    if (!ch.rows.length) return res.status(400).json({ error: "Challenge expired" });

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: ch.rows[0].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "Verification failed" });
    }

    const { credential, credentialDeviceType } = verification.registrationInfo;

    await pool.query(
      `INSERT INTO hr_biometric_credentials
         (client_id, employee_id, credential_id, public_key, counter, transports, device_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        client_id,
        hr_employee_id,
        Buffer.from(credential.id).toString("base64url"),
        Buffer.from(credential.publicKey).toString("base64url"),
        credential.counter,
        JSON.stringify(req.body.response?.transports || []),
        req.body.deviceName || credentialDeviceType || "Unknown",
      ]
    );

    // Cleanup challenge
    await pool.query(
      `DELETE FROM hr_webauthn_challenges WHERE employee_id=$1 AND type='register'`,
      [hr_employee_id]
    );

    res.json({ verified: true });
  } catch (err) {
    console.error("POST /hr/webauthn/register/verify error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================================
//  5. WEBAUTHN  AUTHENTICATE  (hr_employee)
// ============================================================

/** POST /hr/webauthn/authenticate/options */
router.post("/webauthn/authenticate/options", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  try {
    const { hr_employee_id } = req.user;
    const { rpID } = rpConfig();

    const creds = await pool.query(
      `SELECT credential_id, transports FROM hr_biometric_credentials WHERE employee_id=$1`,
      [hr_employee_id]
    );
    if (!creds.rows.length) {
      return res.status(400).json({ error: "No biometric registered", code: "NO_BIOMETRIC" });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: creds.rows.map((r) => ({
        id: r.credential_id,
        type: "public-key",
        transports: r.transports || ["internal"],
      })),
      userVerification: "required",
    });

    await pool.query(
      `DELETE FROM hr_webauthn_challenges WHERE employee_id=$1 AND type='authenticate'`,
      [hr_employee_id]
    );
    await pool.query(
      `INSERT INTO hr_webauthn_challenges (employee_id, challenge, type)
       VALUES ($1, $2, 'authenticate')`,
      [hr_employee_id, options.challenge]
    );

    res.json(options);
  } catch (err) {
    console.error("POST /hr/webauthn/authenticate/options error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/** POST /hr/webauthn/authenticate/verify */
router.post("/webauthn/authenticate/verify", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  try {
    const { hr_employee_id } = req.user;
    const { rpID, origin } = rpConfig();

    const ch = await pool.query(
      `SELECT challenge FROM hr_webauthn_challenges
       WHERE employee_id=$1 AND type='authenticate' AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [hr_employee_id]
    );
    if (!ch.rows.length) return res.status(400).json({ error: "Challenge expired" });

    // Find credential
    const credIdFromBody = req.body.id; // base64url credential id
    const cred = await pool.query(
      `SELECT * FROM hr_biometric_credentials
       WHERE employee_id=$1 AND credential_id=$2`,
      [hr_employee_id, credIdFromBody]
    );
    if (!cred.rows.length) return res.status(400).json({ error: "Credential not found" });

    const storedCred = cred.rows[0];

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: ch.rows[0].challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: storedCred.credential_id,
        publicKey: Buffer.from(storedCred.public_key, "base64url"),
        counter: Number(storedCred.counter),
        transports: storedCred.transports || [],
      },
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "Biometric verification failed" });
    }

    // Update counter
    await pool.query(
      `UPDATE hr_biometric_credentials SET counter=$1 WHERE id=$2`,
      [verification.authenticationInfo.newCounter, storedCred.id]
    );

    // Cleanup
    await pool.query(
      `DELETE FROM hr_webauthn_challenges WHERE employee_id=$1 AND type='authenticate'`,
      [hr_employee_id]
    );

    res.json({ verified: true });
  } catch (err) {
    console.error("POST /hr/webauthn/authenticate/verify error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================================
//  6. ATTENDANCE CHECK-IN / CHECK-OUT
// ============================================================

/**
 * Shared: validate geo-fence and return clinic location
 */
async function validateGeoFence(client_id, latitude, longitude) {
  // Get clinics with location configured
  const { rows } = await pool.query(
    `SELECT id, name, latitude, longitude, allowed_radius_meters
     FROM clinics WHERE client_id=$1 AND latitude IS NOT NULL AND longitude IS NOT NULL`,
    [client_id]
  );
  if (!rows.length) {
    return { ok: false, error: "NO_CLINIC_LOCATION", message: "No clinic location configured. Ask admin to set clinic location." };
  }

  // Check if inside ANY clinic radius
  for (const clinic of rows) {
    const dist = haversineMetres(latitude, longitude, clinic.latitude, clinic.longitude);
    if (dist <= clinic.allowed_radius_meters) {
      return { ok: true, clinic, distance: Math.round(dist) };
    }
  }

  // Outside all clinics
  const nearest = rows[0];
  const dist = haversineMetres(latitude, longitude, nearest.latitude, nearest.longitude);
  return {
    ok: false,
    error: "OUTSIDE_RANGE",
    message: `You are ${Math.round(dist)}m from ${nearest.name}. Max allowed: ${nearest.allowed_radius_meters}m.`,
    distance: Math.round(dist),
  };
}

/**
 * Get active schedule for employee on a given date
 */
async function getScheduleForDate(employeeId, clientId, date) {
  const { rows } = await pool.query(
    `SELECT * FROM hr_work_schedules
     WHERE employee_id=$1 AND client_id=$2
       AND effective_from <= $3
       AND (effective_to IS NULL OR effective_to >= $3)
     ORDER BY effective_from DESC LIMIT 1`,
    [employeeId, clientId, date]
  );
  return rows[0] || null;
}

/**
 * Compute attendance metrics after check-out
 */
function computeAttendance(checkIn, checkOut, schedule) {
  if (!checkIn || !checkOut || !schedule) return {};

  const ciDate = new Date(checkIn);
  const coDate = new Date(checkOut);

  // Parse schedule times (HH:MM) on the same day as check-in
  const [sh, sm] = schedule.start_time.split(":").map(Number);
  const [eh, em] = schedule.end_time.split(":").map(Number);

  const schedStart = new Date(ciDate);
  schedStart.setHours(sh, sm, 0, 0);
  const schedEnd = new Date(ciDate);
  schedEnd.setHours(eh, em, 0, 0);

  const totalMinutes = Math.max(0, Math.round((coDate - ciDate) / 60000));

  // Late = minutes after start + grace
  const lateMs = ciDate - schedStart;
  const lateRaw = Math.round(lateMs / 60000);
  const lateMinutes = Math.max(0, lateRaw - (schedule.grace_minutes || 0));

  // Early leave
  const earlyLeaveMs = schedEnd - coDate;
  const earlyLeaveMinutes = earlyLeaveMs > 0 ? Math.round(earlyLeaveMs / 60000) : 0;

  // Overtime
  const overtimeMs = coDate - schedEnd;
  const overtimeMinutes = schedule.overtime_enabled && overtimeMs > 0 ? Math.round(overtimeMs / 60000) : 0;

  let status = "normal";
  if (lateMinutes > 0) status = "late";

  return { totalMinutes, lateMinutes, earlyLeaveMinutes, overtimeMinutes, status };
}

/** POST /hr/attendance/check-in */
router.post("/attendance/check-in", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  try {
    const { hr_employee_id, client_id } = req.user;
    const { latitude, longitude, device_info } = req.body;

    if (latitude == null || longitude == null) {
      return res.status(400).json({ error: "GPS_REQUIRED", message: "Location is required for check-in" });
    }

    // Geo-fence check
    const geo = await validateGeoFence(client_id, latitude, longitude);
    if (!geo.ok) {
      return res.status(400).json({ error: geo.error, message: geo.message, distance: geo.distance });
    }

    // Check biometric registered
    const bio = await pool.query(
      `SELECT COUNT(*) AS cnt FROM hr_biometric_credentials WHERE employee_id=$1`,
      [hr_employee_id]
    );
    if (Number(bio.rows[0].cnt) === 0) {
      return res.status(400).json({ error: "NO_BIOMETRIC", message: "Register biometrics first" });
    }

    // Check if already checked in today
    const existing = await pool.query(
      `SELECT * FROM hr_attendance
       WHERE employee_id=$1 AND client_id=$2 AND work_date=CURRENT_DATE`,
      [hr_employee_id, client_id]
    );

    if (existing.rows.length && existing.rows[0].check_in) {
      return res.status(409).json({ error: "ALREADY_CHECKED_IN", message: "Already checked in today" });
    }

    const now = new Date();
    const todayStr = now.toISOString().slice(0, 10);

    // Get schedule to determine weekday status
    const schedule = await getScheduleForDate(hr_employee_id, client_id, todayStr);
    const dayOfWeek = now.getDay() === 0 ? 7 : now.getDay(); // Convert Sun=0 to 7
    const isWorkDay = schedule && schedule.work_days && schedule.work_days.includes(dayOfWeek);

    const initialStatus = isWorkDay === false ? "weekend" : "incomplete";

    if (existing.rows.length) {
      // Row exists but no check_in (shouldn't happen normally, but handle)
      await pool.query(
        `UPDATE hr_attendance SET check_in=$1, check_in_lat=$2, check_in_lng=$3,
         device_info=$4, status=$5, updated_at=NOW()
         WHERE id=$6`,
        [now, latitude, longitude, device_info, initialStatus, existing.rows[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO hr_attendance
           (client_id, employee_id, work_date, check_in, check_in_lat, check_in_lng, device_info, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [client_id, hr_employee_id, todayStr, now, latitude, longitude, device_info, initialStatus]
      );
    }

    res.json({ message: "Checked in", time: now.toISOString(), clinicName: geo.clinic.name });
  } catch (err) {
    console.error("POST /hr/attendance/check-in error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/** POST /hr/attendance/check-out */
router.post("/attendance/check-out", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  try {
    const { hr_employee_id, client_id } = req.user;
    const { latitude, longitude, device_info } = req.body;

    if (latitude == null || longitude == null) {
      return res.status(400).json({ error: "GPS_REQUIRED", message: "Location is required for check-out" });
    }

    // Geo-fence check
    const geo = await validateGeoFence(client_id, latitude, longitude);
    if (!geo.ok) {
      return res.status(400).json({ error: geo.error, message: geo.message, distance: geo.distance });
    }

    // Must have checked in today
    const existing = await pool.query(
      `SELECT * FROM hr_attendance
       WHERE employee_id=$1 AND client_id=$2 AND work_date=CURRENT_DATE`,
      [hr_employee_id, client_id]
    );
    if (!existing.rows.length || !existing.rows[0].check_in) {
      return res.status(400).json({ error: "NOT_CHECKED_IN", message: "Must check in first" });
    }
    if (existing.rows[0].check_out) {
      return res.status(409).json({ error: "ALREADY_CHECKED_OUT", message: "Already checked out today" });
    }

    const now = new Date();
    const todayStr = now.toISOString().slice(0, 10);
    const schedule = await getScheduleForDate(hr_employee_id, client_id, todayStr);
    const metrics = computeAttendance(existing.rows[0].check_in, now, schedule);

    await pool.query(
      `UPDATE hr_attendance SET
         check_out=$1, check_out_lat=$2, check_out_lng=$3,
         total_minutes=$4, late_minutes=$5, early_leave_minutes=$6, overtime_minutes=$7,
         status=$8, updated_at=NOW()
       WHERE id=$9`,
      [
        now,
        latitude,
        longitude,
        metrics.totalMinutes || 0,
        metrics.lateMinutes || 0,
        metrics.earlyLeaveMinutes || 0,
        metrics.overtimeMinutes || 0,
        metrics.status || "normal",
        existing.rows[0].id,
      ]
    );

    res.json({
      message: "Checked out",
      time: now.toISOString(),
      totalMinutes: metrics.totalMinutes,
      lateMinutes: metrics.lateMinutes,
      overtimeMinutes: metrics.overtimeMinutes,
    });
  } catch (err) {
    console.error("POST /hr/attendance/check-out error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================================
//  7. ATTENDANCE LIST  (admin)
// ============================================================

/** GET /hr/attendance?from=&to=&employee_id=&status= */
router.get("/attendance", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const { client_id } = req.user;
    const { from, to, employee_id, status } = req.query;

    let query = `SELECT a.*, e.full_name AS employee_name
                 FROM hr_attendance a
                 JOIN hr_employees e ON e.id = a.employee_id
                 WHERE a.client_id=$1`;
    const params = [client_id];
    let idx = 2;

    if (from) { query += ` AND a.work_date >= $${idx}`; params.push(from); idx++; }
    if (to) { query += ` AND a.work_date <= $${idx}`; params.push(to); idx++; }
    if (employee_id) { query += ` AND a.employee_id = $${idx}`; params.push(employee_id); idx++; }
    if (status) { query += ` AND a.status = $${idx}`; params.push(status); idx++; }

    query += " ORDER BY a.work_date DESC, e.full_name";

    const { rows } = await pool.query(query, params);
    res.json(
      rows.map((r) => ({
        id: r.id,
        employeeId: r.employee_id,
        employeeName: r.employee_name,
        workDate: r.work_date,
        checkIn: r.check_in,
        checkOut: r.check_out,
        totalMinutes: r.total_minutes,
        lateMinutes: r.late_minutes,
        earlyLeaveMinutes: r.early_leave_minutes,
        overtimeMinutes: r.overtime_minutes,
        status: r.status,
      }))
    );
  } catch (err) {
    console.error("GET /hr/attendance error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ============================================================
//  8. REPORTS
// ============================================================

/**
 * GET /hr/reports/monthly?employee_id=&month=YYYY-MM
 * Admin: any employee; hr_employee: self only
 */
router.get("/reports/monthly", async (req, res) => {
  try {
    const { client_id, role, type, hr_employee_id } = req.user;
    let { employee_id, month } = req.query;

    // Self-only for hr_employee
    if (type === "hr_employee") {
      employee_id = hr_employee_id;
    } else if (role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    if (!employee_id || !month) {
      return res.status(400).json({ error: "employee_id and month (YYYY-MM) required" });
    }

    const startDate = `${month}-01`;
    // End of month
    const [y, m] = month.split("-").map(Number);
    const endDate = new Date(y, m, 0).toISOString().slice(0, 10); // last day

    const { rows } = await pool.query(
      `SELECT * FROM hr_attendance
       WHERE client_id=$1 AND employee_id=$2 AND work_date BETWEEN $3 AND $4
       ORDER BY work_date`,
      [client_id, employee_id, startDate, endDate]
    );

    const summary = {
      daysPresent: 0,
      totalWorkMinutes: 0,
      totalLateMinutes: 0,
      totalOvertimeMinutes: 0,
      totalEarlyLeaveMinutes: 0,
    };

    const days = rows.map((r) => {
      if (r.check_in) summary.daysPresent++;
      summary.totalWorkMinutes += r.total_minutes || 0;
      summary.totalLateMinutes += r.late_minutes || 0;
      summary.totalOvertimeMinutes += r.overtime_minutes || 0;
      summary.totalEarlyLeaveMinutes += r.early_leave_minutes || 0;

      return {
        workDate: r.work_date,
        checkIn: r.check_in,
        checkOut: r.check_out,
        totalMinutes: r.total_minutes,
        lateMinutes: r.late_minutes,
        earlyLeaveMinutes: r.early_leave_minutes,
        overtimeMinutes: r.overtime_minutes,
        status: r.status,
      };
    });

    res.json({ month, employeeId: Number(employee_id), summary, days });
  } catch (err) {
    console.error("GET /hr/reports/monthly error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /hr/reports/my-monthly?month=YYYY-MM
 * Shortcut for employee to get own report
 */
router.get("/reports/my-monthly", async (req, res) => {
  if (!requireHrEmployee(req, res)) return;
  req.query.employee_id = req.user.hr_employee_id;
  req.user.type = "hr_employee"; // ensure self-only logic
  // Delegate to /reports/monthly handler logic
  try {
    const { client_id, hr_employee_id } = req.user;
    const { month } = req.query;
    if (!month) return res.status(400).json({ error: "month (YYYY-MM) required" });

    const startDate = `${month}-01`;
    const [y, m] = month.split("-").map(Number);
    const endDate = new Date(y, m, 0).toISOString().slice(0, 10);

    const { rows } = await pool.query(
      `SELECT * FROM hr_attendance
       WHERE client_id=$1 AND employee_id=$2 AND work_date BETWEEN $3 AND $4
       ORDER BY work_date`,
      [client_id, hr_employee_id, startDate, endDate]
    );

    const summary = { daysPresent: 0, totalWorkMinutes: 0, totalLateMinutes: 0, totalOvertimeMinutes: 0, totalEarlyLeaveMinutes: 0 };
    const days = rows.map((r) => {
      if (r.check_in) summary.daysPresent++;
      summary.totalWorkMinutes += r.total_minutes || 0;
      summary.totalLateMinutes += r.late_minutes || 0;
      summary.totalOvertimeMinutes += r.overtime_minutes || 0;
      summary.totalEarlyLeaveMinutes += r.early_leave_minutes || 0;
      return {
        workDate: r.work_date, checkIn: r.check_in, checkOut: r.check_out,
        totalMinutes: r.total_minutes, lateMinutes: r.late_minutes,
        earlyLeaveMinutes: r.early_leave_minutes, overtimeMinutes: r.overtime_minutes,
        status: r.status,
      };
    });

    res.json({ month, employeeId: hr_employee_id, summary, days });
  } catch (err) {
    console.error("GET /hr/reports/my-monthly error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
