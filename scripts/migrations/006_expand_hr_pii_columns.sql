-- 006: Expand hr_employees varchar columns to TEXT for encryption.
-- Migration 004 expanded patients/appointments/invoices but missed hr_employees.
-- Without this, encrypting a 10-digit phone overflows the varchar(50) cap
-- because the ciphertext is "enc:" + base64(IV+CT+TAG) ~= 56 chars.

ALTER TABLE hr_employees ALTER COLUMN phone TYPE TEXT;
ALTER TABLE hr_employees ALTER COLUMN email TYPE TEXT;
ALTER TABLE hr_employees ALTER COLUMN full_name TYPE TEXT;
