PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS session_risk_events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  reason TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_risk_events_user_id ON session_risk_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_session_risk_events_score ON session_risk_events(risk_score, created_at);
