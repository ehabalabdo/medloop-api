import pool from "../db.js";

const MAX_FAILS = 5;
const LOCK_MINUTES = 15;

/**
 * Account-lockout helpers. After MAX_FAILS consecutive failed password
 * attempts, the account row is locked for LOCK_MINUTES. Successful login
 * resets the counter.
 *
 * `table` must be one of: users, hr_employees, super_admins, patients
 * `idCol` is the primary-key column name (usually "id")
 */
function safeTable(t) {
  const allowed = new Set(["users", "hr_employees", "super_admins", "patients"]);
  if (!allowed.has(t)) throw new Error(`Invalid lockout table: ${t}`);
  return t;
}

export function isLocked(row) {
  if (!row || !row.locked_until) return false;
  return new Date(row.locked_until).getTime() > Date.now();
}

export async function recordFailedLogin(table, id) {
  const t = safeTable(table);
  await pool.query(
    `UPDATE ${t}
       SET failed_login_count = failed_login_count + 1,
           locked_until = CASE
             WHEN failed_login_count + 1 >= $2
             THEN NOW() + ($3 || ' minutes')::interval
             ELSE locked_until
           END
     WHERE id = $1`,
    [id, MAX_FAILS, String(LOCK_MINUTES)]
  );
}

export async function recordSuccessfulLogin(table, id) {
  const t = safeTable(table);
  await pool.query(
    `UPDATE ${t}
        SET failed_login_count = 0,
            locked_until = NULL
      WHERE id = $1`,
    [id]
  );
}

export const LOCKOUT_CONFIG = { MAX_FAILS, LOCK_MINUTES };
