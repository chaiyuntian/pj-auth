PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organization_invitations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  invited_by_user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  accepted_by_user_id TEXT,
  accepted_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (invited_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (accepted_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org_id
  ON organization_invitations(organization_id, created_at);

CREATE INDEX IF NOT EXISTS idx_org_invitations_email
  ON organization_invitations(email, created_at);

CREATE INDEX IF NOT EXISTS idx_org_invitations_pending
  ON organization_invitations(organization_id, email, expires_at, accepted_at, revoked_at);
