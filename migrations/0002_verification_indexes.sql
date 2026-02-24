CREATE INDEX IF NOT EXISTS idx_verification_codes_code_hash ON verification_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON verification_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_revoked ON sessions(user_id, revoked_at);
