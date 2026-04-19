-- Migration 002: Bind WebAuthn bioToken to issuance IP and (optional) location
-- Run on Neon production:  psql "$DATABASE_URL" -f scripts/migrations/002_biotoken_binding.sql
-- Idempotent.

ALTER TABLE hr_webauthn_challenges
  ADD COLUMN IF NOT EXISTS issue_ip        INET,
  ADD COLUMN IF NOT EXISTS issue_latitude  NUMERIC(10,7),
  ADD COLUMN IF NOT EXISTS issue_longitude NUMERIC(10,7),
  ADD COLUMN IF NOT EXISTS issue_user_agent TEXT;

CREATE INDEX IF NOT EXISTS hr_webauthn_challenges_employee_type_idx
  ON hr_webauthn_challenges (employee_id, type, expires_at);
