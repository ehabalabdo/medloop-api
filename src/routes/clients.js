import express from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import pool from "../db.js";
import { auth } from "../middleware/auth.js";

const router = express.Router();

/**
 * All client routes require super_admin auth (except getBySlug which is public for tenant resolution)
 */

/**
 * GET /clients/by-slug/:slug
 * Public — used by frontend to resolve tenant from URL
 */
router.get("/by-slug/:slug", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM clients WHERE slug=$1 LIMIT 1",
      [req.params.slug]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }
    res.json(mapClientRow(rows[0]));
  } catch (err) {
    console.error("GET /clients/by-slug error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// All routes below require super_admin auth
router.use(auth);

function requireSuperAdmin(req, res, next) {
  if (req.user.type !== "super_admin" && req.user.role !== "super_admin") {
    return res.status(403).json({ error: "Super admin access required" });
  }
  next();
}

/**
 * GET /clients
 * List all clients (super_admin only)
 */
router.get("/", requireSuperAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM clients ORDER BY created_at DESC"
    );
    res.json(rows.map(mapClientRow));
  } catch (err) {
    console.error("GET /clients error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /clients/:id
 * GET /clients/audit-log (super_admin only)
 * Query: client_id, user_id, method, status, since, until, limit (max 500), offset
 * Returns recent audit entries (metadata only, never bodies).
 * Defined BEFORE /:id to avoid route collision.
 */
router.get("/audit-log", requireSuperAdmin, async (req, res) => {
  try {
    const {
      client_id, user_id, method, status,
      since, until, limit, offset,
    } = req.query;

    const lim = Math.min(parseInt(limit, 10) || 100, 500);
    const off = Math.max(parseInt(offset, 10) || 0, 0);

    const where = [];
    const params = [];
    const push = (cond, val) => { params.push(val); where.push(cond.replace("$$", `$${params.length}`)); };

    if (client_id) push("client_id = $$", client_id);
    if (user_id) push("user_id = $$", user_id);
    if (method) push("method = $$", String(method).toUpperCase());
    if (status) push("status_code = $$", parseInt(status, 10));
    if (since) push("created_at >= $$", since);
    if (until) push("created_at <= $$", until);

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    params.push(lim, off);

    const { rows } = await pool.query(
      `SELECT id, user_id, user_type, client_id, method, path, status_code,
              ip, user_agent, duration_ms, created_at
         FROM audit_log
         ${whereSql}
         ORDER BY created_at DESC
         LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    res.json({ entries: rows, limit: lim, offset: off });
  } catch (err) {
    console.error("GET /clients/audit-log error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /clients/security-alerts (super_admin only)
 * Suspicious patterns from audit_log over the last 24h:
 *   - IPs with >= 10 4xx/5xx responses
 *   - users with >= 5 401/403 responses
 *   - currently locked accounts
 * Defined BEFORE /:id to avoid route collision.
 */
router.get("/security-alerts", requireSuperAdmin, async (req, res) => {
  try {
    const [ipAbuse, userAbuse, locked] = await Promise.all([
      pool.query(
        `SELECT ip, COUNT(*) AS count
           FROM audit_log
          WHERE created_at >= NOW() - INTERVAL '24 hours'
            AND status_code >= 400
          GROUP BY ip
         HAVING COUNT(*) >= 10
          ORDER BY count DESC
          LIMIT 50`
      ),
      pool.query(
        `SELECT user_id, user_type, client_id, COUNT(*) AS count
           FROM audit_log
          WHERE created_at >= NOW() - INTERVAL '24 hours'
            AND status_code IN (401, 403)
            AND user_id IS NOT NULL
          GROUP BY user_id, user_type, client_id
         HAVING COUNT(*) >= 5
          ORDER BY count DESC
          LIMIT 50`
      ),
      pool.query(
        `SELECT 'users' AS source, id, failed_login_count, locked_until FROM users WHERE locked_until > NOW()
         UNION ALL
         SELECT 'hr_employees', id, failed_login_count, locked_until FROM hr_employees WHERE locked_until > NOW()
         UNION ALL
         SELECT 'patients', id, failed_login_count, locked_until FROM patients WHERE locked_until > NOW()
         UNION ALL
         SELECT 'super_admins', id, failed_login_count, locked_until FROM super_admins WHERE locked_until > NOW()
         LIMIT 100`
      ),
    ]);

    res.json({
      window: "24h",
      generated_at: new Date().toISOString(),
      ip_abuse: ipAbuse.rows,
      user_abuse: userAbuse.rows,
      locked_accounts: locked.rows,
      summary: {
        ip_abuse_count: ipAbuse.rows.length,
        user_abuse_count: userAbuse.rows.length,
        locked_count: locked.rows.length,
      },
    });
  } catch (err) {
    console.error("GET /clients/security-alerts error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Get a single client by ID (super_admin only)
 */
router.get("/:id", requireSuperAdmin, async (req, res) => {
  try {
    const idNum = parseInt(req.params.id, 10);
    if (!Number.isFinite(idNum)) return res.status(400).json({ error: "Invalid client id" });
    const { rows } = await pool.query(
      "SELECT * FROM clients WHERE id=$1 LIMIT 1",
      [idNum]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }
    res.json(mapClientRow(rows[0]));
  } catch (err) {
    console.error("GET /clients/:id error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /clients
 * Create a new client (super_admin only)
 */
router.post("/", requireSuperAdmin, async (req, res) => {
  try {
    const { name, slug, phone, email, address, trialDays } = req.body;
    if (!name || !slug) {
      return res.status(400).json({ error: "name and slug required" });
    }

    const days = trialDays || 30;
    const { rows } = await pool.query(
      `INSERT INTO clients (name, slug, phone, email, address, status, trial_ends_at, created_at, updated_at, is_active)
       VALUES ($1, $2, $3, $4, $5, 'trial', NOW() + ($6 || ' days')::interval, NOW(), NOW(), true)
       RETURNING *`,
      [name, slug, phone || "", email || "", address || "", String(days)]
    );

    res.status(201).json(mapClientRow(rows[0]));
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Slug already exists" });
    }
    console.error("POST /clients error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /clients/:id/owner
 * Create the admin user for a client (super_admin only)
 */
router.post("/:id/owner", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "name, email, and password required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users (full_name, email, password, role, client_id, created_at, updated_at, created_by, updated_by, is_active, is_archived)
       VALUES ($1, $2, $3, 'admin', $4, NOW(), NOW(), 'super_admin', 'super_admin', true, false)
       RETURNING id`,
      [name, email, hashedPassword, clientId]
    );

    const userId = rows[0].id;
    await pool.query("UPDATE clients SET owner_user_id=$1 WHERE id=$2", [
      userId,
      clientId,
    ]);

    res.status(201).json({ userId });
  } catch (err) {
    console.error("POST /clients/:id/owner error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * PUT /clients/:id/extend-trial
 * Extend trial period by N days (super_admin only)
 */
router.put("/:id/extend-trial", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    const { days } = req.body;
    if (!days || days <= 0) {
      return res.status(400).json({ error: "days required (positive number)" });
    }

    await pool.query(
      `UPDATE clients
       SET trial_ends_at = COALESCE(
             CASE WHEN trial_ends_at > NOW() THEN trial_ends_at ELSE NOW() END,
             NOW()
           ) + ($1 || ' days')::interval,
           updated_at = NOW()
       WHERE id = $2`,
      [String(days), clientId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("PUT extend-trial error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * PUT /clients/:id/trial-end-date
 * Set trial end date directly (super_admin only)
 */
router.put("/:id/trial-end-date", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    const { endDate } = req.body;
    if (!endDate) {
      return res.status(400).json({ error: "endDate required" });
    }

    await pool.query(
      `UPDATE clients SET trial_ends_at=$1::timestamptz, updated_at=NOW() WHERE id=$2`,
      [endDate, clientId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("PUT trial-end-date error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * PUT /clients/:id/extend-subscription
 * Activate/extend subscription by N days (super_admin only)
 */
router.put(
  "/:id/extend-subscription",
  requireSuperAdmin,
  async (req, res) => {
    try {
      const clientId = parseInt(req.params.id);
      const { days } = req.body;
      if (!days || days <= 0) {
        return res
          .status(400)
          .json({ error: "days required (positive number)" });
      }

      await pool.query(
        `UPDATE clients
       SET status = 'active',
           subscription_ends_at = COALESCE(
             CASE WHEN subscription_ends_at > NOW() THEN subscription_ends_at ELSE NOW() END,
             NOW()
           ) + ($1 || ' days')::interval,
           updated_at = NOW()
       WHERE id = $2`,
        [String(days), clientId]
      );

      res.json({ success: true });
    } catch (err) {
      console.error("PUT extend-subscription error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

/**
 * PUT /clients/:id/suspend
 * Suspend a client (super_admin only)
 */
router.put("/:id/suspend", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    await pool.query(
      "UPDATE clients SET status='suspended', updated_at=NOW() WHERE id=$1",
      [clientId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("PUT suspend error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * PUT /clients/:id/activate
 * Reactivate a client (super_admin only)
 */
router.put("/:id/activate", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    await pool.query(
      "UPDATE clients SET status='active', updated_at=NOW() WHERE id=$1",
      [clientId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("PUT activate error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * PUT /clients/:id/features
 * Update enabled features (super_admin only)
 */
router.put("/:id/features", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    const { features } = req.body;
    if (!features) {
      return res.status(400).json({ error: "features object required" });
    }

    await pool.query(
      "UPDATE clients SET enabled_features=$1::jsonb, updated_at=NOW() WHERE id=$2",
      [JSON.stringify(features), clientId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("PUT features error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * PATCH /clients/:id
 * Update client info (super_admin only)
 */
router.patch("/:id", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    const { name, phone, email, address, logoUrl } = req.body;

    const sets = ["updated_at=NOW()"];
    const params = [];
    let idx = 1;

    if (name !== undefined) {
      sets.push(`name=$${idx++}`);
      params.push(name);
    }
    if (phone !== undefined) {
      sets.push(`phone=$${idx++}`);
      params.push(phone);
    }
    if (email !== undefined) {
      sets.push(`email=$${idx++}`);
      params.push(email);
    }
    if (address !== undefined) {
      sets.push(`address=$${idx++}`);
      params.push(address);
    }
    if (logoUrl !== undefined) {
      sets.push(`logo_url=$${idx++}`);
      params.push(logoUrl);
    }

    params.push(clientId);
    await pool.query(
      `UPDATE clients SET ${sets.join(", ")} WHERE id=$${idx}`,
      params
    );

    res.json({ success: true });
  } catch (err) {
    console.error("PATCH /clients/:id error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /clients/:id/stats
 * Get stats for a client (super_admin only)
 */
router.get("/:id/stats", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);

    const [patients, users, appointments] = await Promise.all([
      pool.query(
        "SELECT COUNT(*)::int as count FROM patients WHERE client_id=$1",
        [clientId]
      ),
      pool.query(
        "SELECT COUNT(*)::int as count FROM users WHERE client_id=$1",
        [clientId]
      ),
      pool.query(
        "SELECT COUNT(*)::int as count FROM appointments WHERE client_id=$1",
        [clientId]
      ),
    ]);

    res.json({
      patientsCount: patients.rows[0]?.count || 0,
      usersCount: users.rows[0]?.count || 0,
      appointmentsCount: appointments.rows[0]?.count || 0,
    });
  } catch (err) {
    console.error("GET /clients/:id/stats error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * DELETE /clients/:id
 * Delete a client and all related data (super_admin only)
 */
router.delete("/:id", requireSuperAdmin, async (req, res) => {
  const client = pool.connect ? await pool.connect() : null;
  try {
    const clientId = parseInt(req.params.id);

    // Delete in dependency order
    if (client) {
      await client.query("BEGIN");
      await client.query("DELETE FROM device_results WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM device_api_keys WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM devices WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM invoices WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM appointments WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM patients WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM users WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM clinics WHERE client_id=$1", [clientId]);
      await client.query("DELETE FROM clients WHERE id=$1", [clientId]);
      await client.query("COMMIT");
    } else {
      // Fallback: sequential deletes without transaction
      for (const table of [
        "device_results", "device_api_keys", "devices",
        "invoices", "appointments", "patients", "users", "clinics",
      ]) {
        try {
          await pool.query(`DELETE FROM ${table} WHERE client_id=$1`, [clientId]);
        } catch (e) {
          // Table may not exist, skip
        }
      }
      await pool.query("DELETE FROM clients WHERE id=$1", [clientId]);
    }

    res.json({ success: true });
  } catch (err) {
    if (client) {
      try { await client.query("ROLLBACK"); } catch {}
    }
    console.error("DELETE /clients/:id error:", err);
    res.status(500).json({ error: "Server error" });
  } finally {
    if (client) client.release();
  }
});

/** Map a DB row to frontend-compatible Client shape */
function mapClientRow(row) {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    logoUrl: row.logo_url || "",
    phone: row.phone || "",
    email: row.email || "",
    address: row.address || "",
    status: row.status,
    trialEndsAt: row.trial_ends_at,
    subscriptionEndsAt: row.subscription_ends_at,
    ownerUserId: row.owner_user_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    isActive: row.is_active,
    enabledFeatures: row.enabled_features || {
      dental_lab: false,
      implant_company: false,
      academy: false,
      device_results: false,
    },
  };
}

/**
 * POST /clients/:id/bridge-key/rotate
 * Super-admin only. Generates a new bridge agent secret, stores SHA-256 hash
 * in clients.bridge_key_hash, returns the raw secret ONCE.
 */
router.post("/:id/bridge-key/rotate", requireSuperAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);
    if (!clientId) return res.status(400).json({ error: "Invalid client id" });

    const secret = crypto.randomBytes(32).toString("hex");
    const hash = crypto.createHash("sha256").update(secret).digest("hex");

    const { rowCount } = await pool.query(
      `UPDATE clients SET bridge_key_hash=$1 WHERE id=$2`,
      [hash, clientId]
    );
    if (!rowCount) return res.status(404).json({ error: "Client not found" });

    return res.json({
      ok: true,
      bridge_key: secret,
      warning: "Store this key now. It will not be shown again.",
    });
  } catch (err) {
    console.error("POST /clients/:id/bridge-key/rotate error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
