import { nowIso } from "./time";

export type SamlConnectionRow = {
  id: string;
  organization_id: string;
  slug: string;
  name: string;
  idp_entity_id: string;
  sso_url: string;
  x509_cert_pem: string;
  sp_entity_id: string;
  acs_url: string;
  default_role: "owner" | "admin" | "member";
  attribute_mapping_json: string | null;
  require_signed_assertions: number;
  allow_idp_initiated: number;
  is_active: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
};

export type SamlAuthStateRow = {
  id: string;
  saml_connection_id: string;
  redirect_to: string | null;
  expires_at: string;
  used_at: string | null;
  created_at: string;
};

export type DomainRouteConnectionType = "password" | "google" | "saml";

export type DomainRouteRow = {
  id: string;
  organization_id: string;
  domain: string;
  connection_type: DomainRouteConnectionType;
  connection_id: string | null;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
};

export type RetentionPolicyTargetType =
  | "audit_logs"
  | "webhook_deliveries"
  | "scim_tokens"
  | "saml_auth_states"
  | "export_jobs";

export type RetentionPolicyRow = {
  id: string;
  organization_id: string;
  target_type: RetentionPolicyTargetType;
  retention_days: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
};

export type OrganizationKmsKeyRow = {
  id: string;
  organization_id: string;
  alias: string;
  version: number;
  algorithm: string;
  encrypted_key_material: string;
  is_active: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
  rotated_at: string | null;
};

export type ExportJobTargetType =
  | "audit_logs"
  | "members"
  | "policies"
  | "service_accounts"
  | "webhooks"
  | "scim_tokens"
  | "all";

export type ExportJobStatus = "queued" | "completed" | "failed";

export type ExportJobRow = {
  id: string;
  organization_id: string;
  requested_by_user_id: string;
  target_type: ExportJobTargetType;
  status: ExportJobStatus;
  filters_json: string | null;
  result_json: string | null;
  result_encrypted: number;
  kms_key_id: string | null;
  error_message: string | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
};

const normalizeDomain = (value: string): string =>
  value
    .trim()
    .toLowerCase()
    .replace(/^\.+/, "")
    .replace(/\.+$/, "");

export const createSamlConnection = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    slug: string;
    name: string;
    idpEntityId: string;
    ssoUrl: string;
    x509CertPem: string;
    spEntityId: string;
    acsUrl: string;
    defaultRole: "owner" | "admin" | "member";
    attributeMappingJson?: string | null;
    requireSignedAssertions: boolean;
    allowIdpInitiated: boolean;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO saml_connections (
        id,
        organization_id,
        slug,
        name,
        idp_entity_id,
        sso_url,
        x509_cert_pem,
        sp_entity_id,
        acs_url,
        default_role,
        attribute_mapping_json,
        require_signed_assertions,
        allow_idp_initiated,
        is_active,
        created_by_user_id,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`
    )
    .bind(
      params.id,
      params.organizationId,
      params.slug.trim().toLowerCase(),
      params.name.trim(),
      params.idpEntityId.trim(),
      params.ssoUrl.trim(),
      params.x509CertPem.trim(),
      params.spEntityId.trim(),
      params.acsUrl.trim(),
      params.defaultRole,
      params.attributeMappingJson ?? null,
      params.requireSignedAssertions ? 1 : 0,
      params.allowIdpInitiated ? 1 : 0,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const listSamlConnectionsForOrganization = async (
  db: D1Database,
  organizationId: string
): Promise<SamlConnectionRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              slug,
              name,
              idp_entity_id,
              sso_url,
              x509_cert_pem,
              sp_entity_id,
              acs_url,
              default_role,
              attribute_mapping_json,
              require_signed_assertions,
              allow_idp_initiated,
              is_active,
              created_by_user_id,
              created_at,
              updated_at
       FROM saml_connections
       WHERE organization_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(organizationId)
    .all<SamlConnectionRow>();
  return result.results ?? [];
};

export const findSamlConnectionByIdInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    connectionId: string;
  }
): Promise<SamlConnectionRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              slug,
              name,
              idp_entity_id,
              sso_url,
              x509_cert_pem,
              sp_entity_id,
              acs_url,
              default_role,
              attribute_mapping_json,
              require_signed_assertions,
              allow_idp_initiated,
              is_active,
              created_by_user_id,
              created_at,
              updated_at
       FROM saml_connections
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.connectionId, params.organizationId)
    .first<SamlConnectionRow>();

export const findActiveSamlConnectionBySlug = async (
  db: D1Database,
  slug: string
): Promise<SamlConnectionRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              slug,
              name,
              idp_entity_id,
              sso_url,
              x509_cert_pem,
              sp_entity_id,
              acs_url,
              default_role,
              attribute_mapping_json,
              require_signed_assertions,
              allow_idp_initiated,
              is_active,
              created_by_user_id,
              created_at,
              updated_at
       FROM saml_connections
       WHERE slug = ? AND is_active = 1`
    )
    .bind(slug.trim().toLowerCase())
    .first<SamlConnectionRow>();

export const updateSamlConnection = async (
  db: D1Database,
  params: {
    organizationId: string;
    connectionId: string;
    name?: string;
    idpEntityId?: string;
    ssoUrl?: string;
    x509CertPem?: string;
    spEntityId?: string;
    acsUrl?: string;
    defaultRole?: "owner" | "admin" | "member";
    attributeMappingJson?: string | null;
    requireSignedAssertions?: boolean;
    allowIdpInitiated?: boolean;
    isActive?: boolean;
  }
): Promise<SamlConnectionRow | null> => {
  const existing = await findSamlConnectionByIdInOrganization(db, {
    organizationId: params.organizationId,
    connectionId: params.connectionId
  });
  if (!existing) {
    return null;
  }

  const now = nowIso();
  await db
    .prepare(
      `UPDATE saml_connections
       SET name = ?,
           idp_entity_id = ?,
           sso_url = ?,
           x509_cert_pem = ?,
           sp_entity_id = ?,
           acs_url = ?,
           default_role = ?,
           attribute_mapping_json = ?,
           require_signed_assertions = ?,
           allow_idp_initiated = ?,
           is_active = ?,
           updated_at = ?
       WHERE id = ? AND organization_id = ?`
    )
    .bind(
      params.name?.trim() ?? existing.name,
      params.idpEntityId?.trim() ?? existing.idp_entity_id,
      params.ssoUrl?.trim() ?? existing.sso_url,
      params.x509CertPem?.trim() ?? existing.x509_cert_pem,
      params.spEntityId?.trim() ?? existing.sp_entity_id,
      params.acsUrl?.trim() ?? existing.acs_url,
      params.defaultRole ?? existing.default_role,
      params.attributeMappingJson === undefined ? existing.attribute_mapping_json : params.attributeMappingJson,
      params.requireSignedAssertions === undefined
        ? existing.require_signed_assertions
        : params.requireSignedAssertions
          ? 1
          : 0,
      params.allowIdpInitiated === undefined ? existing.allow_idp_initiated : params.allowIdpInitiated ? 1 : 0,
      params.isActive === undefined ? existing.is_active : params.isActive ? 1 : 0,
      now,
      params.connectionId,
      params.organizationId
    )
    .run();

  return findSamlConnectionByIdInOrganization(db, {
    organizationId: params.organizationId,
    connectionId: params.connectionId
  });
};

export const disableSamlConnection = async (
  db: D1Database,
  params: {
    organizationId: string;
    connectionId: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE saml_connections
       SET is_active = 0, updated_at = ?
       WHERE id = ? AND organization_id = ? AND is_active = 1`
    )
    .bind(now, params.connectionId, params.organizationId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const createSamlAuthState = async (
  db: D1Database,
  params: {
    id: string;
    samlConnectionId: string;
    redirectTo?: string | null;
    expiresAt: string;
  }
): Promise<void> => {
  await db
    .prepare(
      `INSERT INTO saml_auth_states (id, saml_connection_id, redirect_to, expires_at, used_at, created_at)
       VALUES (?, ?, ?, ?, NULL, ?)`
    )
    .bind(params.id, params.samlConnectionId, params.redirectTo ?? null, params.expiresAt, nowIso())
    .run();
};

export const consumeSamlAuthStateById = async (
  db: D1Database,
  stateId: string
): Promise<SamlAuthStateRow | null> => {
  const state = await db
    .prepare(
      `SELECT id, saml_connection_id, redirect_to, expires_at, used_at, created_at
       FROM saml_auth_states
       WHERE id = ?`
    )
    .bind(stateId)
    .first<SamlAuthStateRow>();

  if (!state || state.used_at || Date.parse(state.expires_at) <= Date.now()) {
    return null;
  }

  await db.prepare(`UPDATE saml_auth_states SET used_at = ? WHERE id = ?`).bind(nowIso(), stateId).run();
  return state;
};

export const createDomainRoute = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    domain: string;
    connectionType: DomainRouteConnectionType;
    connectionId?: string | null;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO domain_routes (
        id,
        organization_id,
        domain,
        connection_type,
        connection_id,
        created_by_user_id,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      params.id,
      params.organizationId,
      normalizeDomain(params.domain),
      params.connectionType,
      params.connectionId ?? null,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const listDomainRoutesForOrganization = async (
  db: D1Database,
  organizationId: string
): Promise<DomainRouteRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              domain,
              connection_type,
              connection_id,
              created_by_user_id,
              created_at,
              updated_at
       FROM domain_routes
       WHERE organization_id = ?
       ORDER BY lower(domain) ASC`
    )
    .bind(organizationId)
    .all<DomainRouteRow>();
  return result.results ?? [];
};

export const findDomainRouteByDomain = async (
  db: D1Database,
  domain: string
): Promise<DomainRouteRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              domain,
              connection_type,
              connection_id,
              created_by_user_id,
              created_at,
              updated_at
       FROM domain_routes
       WHERE domain = ?`
    )
    .bind(normalizeDomain(domain))
    .first<DomainRouteRow>();

export const deleteDomainRouteByIdInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    routeId: string;
  }
): Promise<boolean> => {
  const result = await db
    .prepare(
      `DELETE FROM domain_routes
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.routeId, params.organizationId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const upsertRetentionPolicy = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    targetType: RetentionPolicyTargetType;
    retentionDays: number;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO retention_policies (
        id,
        organization_id,
        target_type,
        retention_days,
        created_by_user_id,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (organization_id, target_type) DO UPDATE SET
        retention_days = excluded.retention_days,
        created_by_user_id = excluded.created_by_user_id,
        updated_at = excluded.updated_at`
    )
    .bind(
      params.id,
      params.organizationId,
      params.targetType,
      params.retentionDays,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const listRetentionPoliciesForOrganization = async (
  db: D1Database,
  organizationId: string
): Promise<RetentionPolicyRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              target_type,
              retention_days,
              created_by_user_id,
              created_at,
              updated_at
       FROM retention_policies
       WHERE organization_id = ?
       ORDER BY target_type ASC`
    )
    .bind(organizationId)
    .all<RetentionPolicyRow>();
  return result.results ?? [];
};

export const createExportJob = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    requestedByUserId: string;
    targetType: ExportJobTargetType;
    filtersJson?: string | null;
    kmsKeyId?: string | null;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO export_jobs (
        id,
        organization_id,
        requested_by_user_id,
        target_type,
        status,
        filters_json,
        result_json,
        result_encrypted,
        kms_key_id,
        error_message,
        expires_at,
        created_at,
        updated_at,
        completed_at
      ) VALUES (?, ?, ?, ?, 'queued', ?, NULL, 0, ?, NULL, NULL, ?, ?, NULL)`
    )
    .bind(
      params.id,
      params.organizationId,
      params.requestedByUserId,
      params.targetType,
      params.filtersJson ?? null,
      params.kmsKeyId ?? null,
      now,
      now
    )
    .run();
};

export const markExportJobCompleted = async (
  db: D1Database,
  params: {
    jobId: string;
    organizationId: string;
    resultJson: string;
    resultEncrypted: boolean;
    expiresAt?: string | null;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE export_jobs
       SET status = 'completed',
           result_json = ?,
           result_encrypted = ?,
           error_message = NULL,
           expires_at = ?,
           completed_at = ?,
           updated_at = ?
       WHERE id = ? AND organization_id = ?`
    )
    .bind(
      params.resultJson,
      params.resultEncrypted ? 1 : 0,
      params.expiresAt ?? null,
      now,
      now,
      params.jobId,
      params.organizationId
    )
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const markExportJobFailed = async (
  db: D1Database,
  params: {
    jobId: string;
    organizationId: string;
    errorMessage: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE export_jobs
       SET status = 'failed',
           error_message = ?,
           updated_at = ?,
           completed_at = ?
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.errorMessage.slice(0, 2000), now, now, params.jobId, params.organizationId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const listExportJobsForOrganization = async (
  db: D1Database,
  organizationId: string,
  limit = 100
): Promise<ExportJobRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              requested_by_user_id,
              target_type,
              status,
              filters_json,
              result_json,
              result_encrypted,
              kms_key_id,
              error_message,
              expires_at,
              created_at,
              updated_at,
              completed_at
       FROM export_jobs
       WHERE organization_id = ?
       ORDER BY datetime(created_at) DESC
       LIMIT ?`
    )
    .bind(organizationId, limit)
    .all<ExportJobRow>();
  return result.results ?? [];
};

export const findExportJobByIdInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    jobId: string;
  }
): Promise<ExportJobRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              requested_by_user_id,
              target_type,
              status,
              filters_json,
              result_json,
              result_encrypted,
              kms_key_id,
              error_message,
              expires_at,
              created_at,
              updated_at,
              completed_at
       FROM export_jobs
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.jobId, params.organizationId)
    .first<ExportJobRow>();

export const createOrganizationKmsKey = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    alias: string;
    algorithm: string;
    encryptedKeyMaterial: string;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO organization_kms_keys (
        id,
        organization_id,
        alias,
        version,
        algorithm,
        encrypted_key_material,
        is_active,
        created_by_user_id,
        created_at,
        updated_at,
        rotated_at
      ) VALUES (?, ?, ?, 1, ?, ?, 1, ?, ?, ?, NULL)`
    )
    .bind(
      params.id,
      params.organizationId,
      params.alias.trim(),
      params.algorithm.trim(),
      params.encryptedKeyMaterial,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const listOrganizationKmsKeys = async (
  db: D1Database,
  organizationId: string
): Promise<OrganizationKmsKeyRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              alias,
              version,
              algorithm,
              encrypted_key_material,
              is_active,
              created_by_user_id,
              created_at,
              updated_at,
              rotated_at
       FROM organization_kms_keys
       WHERE organization_id = ?
       ORDER BY lower(alias) ASC`
    )
    .bind(organizationId)
    .all<OrganizationKmsKeyRow>();
  return result.results ?? [];
};

export const findActiveOrganizationKmsKeyByIdInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    keyId: string;
  }
): Promise<OrganizationKmsKeyRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              alias,
              version,
              algorithm,
              encrypted_key_material,
              is_active,
              created_by_user_id,
              created_at,
              updated_at,
              rotated_at
       FROM organization_kms_keys
       WHERE id = ? AND organization_id = ? AND is_active = 1`
    )
    .bind(params.keyId, params.organizationId)
    .first<OrganizationKmsKeyRow>();

export const rotateOrganizationKmsKey = async (
  db: D1Database,
  params: {
    organizationId: string;
    keyId: string;
    encryptedKeyMaterial: string;
  }
): Promise<OrganizationKmsKeyRow | null> => {
  const existing = await findActiveOrganizationKmsKeyByIdInOrganization(db, {
    organizationId: params.organizationId,
    keyId: params.keyId
  });
  if (!existing) {
    return null;
  }

  const now = nowIso();
  await db
    .prepare(
      `UPDATE organization_kms_keys
       SET encrypted_key_material = ?,
           version = version + 1,
           rotated_at = ?,
           updated_at = ?
       WHERE id = ? AND organization_id = ? AND is_active = 1`
    )
    .bind(params.encryptedKeyMaterial, now, now, params.keyId, params.organizationId)
    .run();

  return findActiveOrganizationKmsKeyByIdInOrganization(db, {
    organizationId: params.organizationId,
    keyId: params.keyId
  });
};

export const deactivateOrganizationKmsKey = async (
  db: D1Database,
  params: {
    organizationId: string;
    keyId: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE organization_kms_keys
       SET is_active = 0,
           updated_at = ?
       WHERE id = ? AND organization_id = ? AND is_active = 1`
    )
    .bind(now, params.keyId, params.organizationId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};
