-- Migration 004: Expand PII columns to TEXT to accommodate AES-256-GCM ciphertext
-- (the encrypted form is "enc:" + base64(IV||CT||TAG) which can exceed varchar(20/255)).
-- Idempotent. Run on Neon production.

ALTER TABLE patients ALTER COLUMN full_name TYPE TEXT;
ALTER TABLE patients ALTER COLUMN phone     TYPE TEXT;
ALTER TABLE patients ALTER COLUMN email     TYPE TEXT;
ALTER TABLE patients ALTER COLUMN notes     TYPE TEXT;

-- date_of_birth stays DATE (we do NOT encrypt it; protected by app-level RBAC).
-- If you ever need encrypted DOB, add a separate dob_enc TEXT column.

-- HR employees PII columns (encrypted via Phase 2 rollout)
ALTER TABLE hr_employees ALTER COLUMN full_name TYPE TEXT;
ALTER TABLE hr_employees ALTER COLUMN phone     TYPE TEXT;
ALTER TABLE hr_employees ALTER COLUMN email     TYPE TEXT;
