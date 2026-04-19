-- Super Admins table
-- Stores platform-level administrators who can manage all client tenants.
CREATE TABLE IF NOT EXISTS super_admins (
  id            SERIAL PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- If the table already existed from an older deploy with a plaintext "password"
-- column, migrate it to the new hashed column structure.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'super_admins' AND column_name = 'password'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'super_admins' AND column_name = 'password_hash'
  ) THEN
    ALTER TABLE super_admins RENAME COLUMN password TO password_hash;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'super_admins' AND column_name = 'is_active'
  ) THEN
    ALTER TABLE super_admins ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'super_admins' AND column_name = 'last_login_at'
  ) THEN
    ALTER TABLE super_admins ADD COLUMN last_login_at TIMESTAMPTZ;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS super_admins_username_idx ON super_admins (username);
