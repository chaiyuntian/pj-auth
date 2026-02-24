PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organization_policies (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'role', 'team', 'service_account')),
  subject_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  action TEXT NOT NULL,
  effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
  condition_json TEXT,
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (organization_id, subject_type, subject_id, resource, action),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_org_policies_org_id ON organization_policies(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_policies_subject ON organization_policies(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_org_policies_resource_action ON organization_policies(resource, action);
