PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS saml_connections (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  idp_entity_id TEXT NOT NULL,
  sso_url TEXT NOT NULL,
  x509_cert_pem TEXT NOT NULL,
  sp_entity_id TEXT NOT NULL,
  acs_url TEXT NOT NULL,
  default_role TEXT NOT NULL CHECK (default_role IN ('owner', 'admin', 'member')) DEFAULT 'member',
  attribute_mapping_json TEXT,
  require_signed_assertions INTEGER NOT NULL DEFAULT 1,
  allow_idp_initiated INTEGER NOT NULL DEFAULT 1,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (organization_id, slug),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_saml_connections_org_id ON saml_connections(organization_id);
CREATE INDEX IF NOT EXISTS idx_saml_connections_active ON saml_connections(organization_id, is_active);

CREATE TABLE IF NOT EXISTS saml_auth_states (
  id TEXT PRIMARY KEY,
  saml_connection_id TEXT NOT NULL,
  redirect_to TEXT,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (saml_connection_id) REFERENCES saml_connections(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_saml_auth_states_connection ON saml_auth_states(saml_connection_id);
CREATE INDEX IF NOT EXISTS idx_saml_auth_states_expires ON saml_auth_states(expires_at, used_at);

CREATE TABLE IF NOT EXISTS domain_routes (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE,
  connection_type TEXT NOT NULL CHECK (connection_type IN ('password', 'google', 'saml')),
  connection_id TEXT,
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (organization_id, domain),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_domain_routes_org_id ON domain_routes(organization_id);

CREATE TABLE IF NOT EXISTS retention_policies (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('audit_logs', 'webhook_deliveries', 'scim_tokens', 'saml_auth_states', 'export_jobs')),
  retention_days INTEGER NOT NULL CHECK (retention_days > 0 AND retention_days <= 3650),
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (organization_id, target_type),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_retention_policies_org_id ON retention_policies(organization_id);

CREATE TABLE IF NOT EXISTS organization_kms_keys (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  alias TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  algorithm TEXT NOT NULL DEFAULT 'aes-256-gcm',
  encrypted_key_material TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  rotated_at TEXT,
  UNIQUE (organization_id, alias),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_org_kms_keys_org_id ON organization_kms_keys(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_kms_keys_active ON organization_kms_keys(organization_id, is_active);

CREATE TABLE IF NOT EXISTS export_jobs (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('audit_logs', 'members', 'policies', 'service_accounts', 'webhooks', 'scim_tokens', 'all')),
  status TEXT NOT NULL CHECK (status IN ('queued', 'completed', 'failed')),
  filters_json TEXT,
  result_json TEXT,
  result_encrypted INTEGER NOT NULL DEFAULT 0,
  kms_key_id TEXT,
  error_message TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (kms_key_id) REFERENCES organization_kms_keys(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_export_jobs_org_id ON export_jobs(organization_id);
CREATE INDEX IF NOT EXISTS idx_export_jobs_status ON export_jobs(status, created_at);
