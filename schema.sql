-- AccountMatrix Schema (Cloudflare D1 / SQLite)
-- Run: wrangler d1 execute account_matrix_db --file=./schema.sql --remote

CREATE TABLE IF NOT EXISTS matrix_accounts (
  id             TEXT PRIMARY KEY,
  service        TEXT NOT NULL,
  tag            TEXT,
  address        TEXT NOT NULL,
  username       TEXT,
  password       TEXT,
  totp_secret    TEXT,
  api_key        TEXT,
  recovery_codes TEXT,
  opsec_note     TEXT,
  status         TEXT NOT NULL DEFAULT 'active',  -- active | trial | cooldown | burned
  expires_at     INTEGER,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_matrix_created ON matrix_accounts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_matrix_status  ON matrix_accounts(status);
CREATE INDEX IF NOT EXISTS idx_matrix_address ON matrix_accounts(address);

CREATE TABLE IF NOT EXISTS matrix_settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
