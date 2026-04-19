/**
 * Create or update a Super Admin account (bcrypt-hashed).
 *
 * Usage (PowerShell):
 *   $env:DATABASE_URL="postgres://..."
 *   $env:SA_USERNAME="ehab"
 *   $env:SA_NAME="Ehab Alabdo"
 *   $env:SA_PASSWORD="your-strong-password"
 *   node scripts/create-super-admin.js
 *
 * Reads credentials from env vars only (never hard-coded).
 * Safe to re-run: updates the password if the username already exists.
 */
import "dotenv/config";
import bcrypt from "bcrypt";
import pg from "pg";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL;
const SA_USERNAME  = process.env.SA_USERNAME;
const SA_NAME      = process.env.SA_NAME;
const SA_PASSWORD  = process.env.SA_PASSWORD;

if (!DATABASE_URL) {
  console.error("[ERROR] DATABASE_URL is required");
  process.exit(1);
}
if (!SA_USERNAME || !SA_NAME || !SA_PASSWORD) {
  console.error("[ERROR] SA_USERNAME, SA_NAME, and SA_PASSWORD env vars are required");
  process.exit(1);
}
if (SA_PASSWORD.length < 12) {
  console.error("[ERROR] SA_PASSWORD must be at least 12 characters");
  process.exit(1);
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const migrationPath = path.join(__dirname, "super_admins.sql");
const migrationSql  = fs.readFileSync(migrationPath, "utf8");

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function main() {
  console.log("[1/4] Ensuring super_admins table exists...");
  await pool.query(migrationSql);

  console.log("[2/4] Hashing password (bcrypt rounds=12)...");
  const hash = await bcrypt.hash(SA_PASSWORD, 12);

  console.log(`[3/4] Upserting super admin "${SA_USERNAME}"...`);
  const { rows } = await pool.query(
    `INSERT INTO super_admins (username, name, password_hash, is_active, created_at, updated_at)
     VALUES ($1, $2, $3, TRUE, NOW(), NOW())
     ON CONFLICT (username) DO UPDATE
       SET name          = EXCLUDED.name,
           password_hash = EXCLUDED.password_hash,
           is_active     = TRUE,
           updated_at    = NOW()
     RETURNING id, username, name, is_active, created_at`,
    [SA_USERNAME, SA_NAME, hash]
  );

  console.log("[4/4] Done.");
  console.log(rows[0]);
  await pool.end();
}

main().catch((err) => {
  console.error("[FATAL]", err);
  pool.end().finally(() => process.exit(1));
});
