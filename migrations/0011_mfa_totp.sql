PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS mfa_totp_factors (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  secret_base32 TEXT NOT NULL,
  issuer TEXT NOT NULL,
  account_name TEXT NOT NULL,
  verified_at TEXT,
  disabled_at TEXT,
  last_used_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_totp_factors_user_id ON mfa_totp_factors(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_totp_factors_active ON mfa_totp_factors(user_id, verified_at, disabled_at);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL UNIQUE,
  used_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id, used_at);

CREATE TABLE IF NOT EXISTS mfa_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('sign_in')),
  metadata_json TEXT,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id, purpose, created_at);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at, used_at);
