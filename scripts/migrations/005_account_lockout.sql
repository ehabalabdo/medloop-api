-- Migration 005: Account lockout columns
-- Adds failed_login_count + locked_until to all login tables. After
-- N consecutive failures the account is locked for a cooldown window.
-- Mitigates credential-stuffing past the IP-based rateLimit floor.

ALTER TABLE users           ADD COLUMN IF NOT EXISTS failed_login_count INT NOT NULL DEFAULT 0;
ALTER TABLE users           ADD COLUMN IF NOT EXISTS locked_until       TIMESTAMPTZ;
ALTER TABLE hr_employees    ADD COLUMN IF NOT EXISTS failed_login_count INT NOT NULL DEFAULT 0;
ALTER TABLE hr_employees    ADD COLUMN IF NOT EXISTS locked_until       TIMESTAMPTZ;
ALTER TABLE super_admins    ADD COLUMN IF NOT EXISTS failed_login_count INT NOT NULL DEFAULT 0;
ALTER TABLE super_admins    ADD COLUMN IF NOT EXISTS locked_until       TIMESTAMPTZ;
ALTER TABLE patients        ADD COLUMN IF NOT EXISTS failed_login_count INT NOT NULL DEFAULT 0;
ALTER TABLE patients        ADD COLUMN IF NOT EXISTS locked_until       TIMESTAMPTZ;
