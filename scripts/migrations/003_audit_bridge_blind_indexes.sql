-- Migration 003: Audit log + bridge agent shared key
-- Idempotent. Run on Neon production.

CREATE TABLE IF NOT EXISTS audit_log (
  id            BIGSERIAL PRIMARY KEY,
  ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id       INTEGER,
  user_type     VARCHAR(32),
  client_id     INTEGER,
  method        VARCHAR(8)  NOT NULL,
  path          VARCHAR(256) NOT NULL,
  status_code   INTEGER,
  ip            INET,
  user_agent    VARCHAR(256),
  duration_ms   INTEGER
);

CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_client_user_idx ON audit_log (client_id, user_id, ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_path_idx ON audit_log (path, ts DESC);

-- Bridge Agent: per-client shared secret (SHA-256 hex)
ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS bridge_key_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS bridge_key_created_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS bridge_allowed_ips TEXT,         -- comma-separated CIDR list
  ADD COLUMN IF NOT EXISTS bridge_last_seen TIMESTAMPTZ;

-- Blind indexes for encrypted searchable columns (Phase 2 foundation)
ALTER TABLE patients
  ADD COLUMN IF NOT EXISTS phone_idx CHAR(64),
  ADD COLUMN IF NOT EXISTS username_idx CHAR(64);

CREATE INDEX IF NOT EXISTS patients_phone_idx_idx ON patients (phone_idx) WHERE phone_idx IS NOT NULL;
CREATE INDEX IF NOT EXISTS patients_username_idx_idx ON patients (username_idx) WHERE username_idx IS NOT NULL;

ALTER TABLE hr_employees
  ADD COLUMN IF NOT EXISTS email_idx CHAR(64),
  ADD COLUMN IF NOT EXISTS phone_idx CHAR(64);

CREATE INDEX IF NOT EXISTS hr_employees_email_idx_idx ON hr_employees (email_idx) WHERE email_idx IS NOT NULL;
