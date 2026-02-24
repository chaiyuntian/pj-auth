import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { requireAuth } from "../middleware/require-auth";
import {
  createDomainRoute,
  createExportJob,
  createOrganizationKmsKey,
  createSamlConnection,
  deactivateOrganizationKmsKey,
  deleteDomainRouteByIdInOrganization,
  findActiveOrganizationKmsKeyByIdInOrganization,
  findExportJobByIdInOrganization,
  findSamlConnectionByIdInOrganization,
  listDomainRoutesForOrganization,
  listExportJobsForOrganization,
  listOrganizationKmsKeys,
  listRetentionPoliciesForOrganization,
  listSamlConnectionsForOrganization,
  markExportJobCompleted,
  markExportJobFailed,
  rotateOrganizationKmsKey,
  upsertRetentionPolicy,
  updateSamlConnection,
  disableSamlConnection,
  type DomainRouteConnectionType,
  type ExportJobTargetType,
  type RetentionPolicyTargetType
} from "../lib/enterprise-db";
import {
  findOrganizationById,
  findOrganizationMembership,
  listAuditLogs,
  listOrganizationMembers,
  listOrganizationPolicies,
  listScimTokensForOrganization,
  listServiceAccountsForOrganization,
  listWebhookDeliveriesForEndpoint,
  listWebhookEndpointsForOrganization,
  writeAuditLog,
  type OrganizationMembershipRow,
  type OrganizationRow
} from "../lib/db";
import { evaluateOrganizationPermission } from "../lib/policy";
import { addSecondsToIso } from "../lib/time";
import { readJsonBody } from "../lib/request";
import {
  decryptManagedKeyMaterial,
  decryptWithManagedKey,
  encryptManagedKeyMaterial,
  encryptWithManagedKey,
  generateRandomDataKeyMaterial
} from "../lib/kms";
import { getAppUrl } from "../lib/config";

const createSamlConnectionSchema = z.object({
  name: z.string().min(2).max(120),
  slug: z
    .string()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    .optional(),
  idpEntityId: z.string().min(3).max(1000),
  ssoUrl: z.string().url().max(1000),
  x509CertPem: z.string().min(20).max(20000),
  spEntityId: z.string().min(3).max(1000).optional(),
  acsUrl: z.string().url().max(1000).optional(),
  defaultRole: z.enum(["owner", "admin", "member"]).optional(),
  attributeMapping: z
    .object({
      email: z.string().min(1).max(200).optional(),
      fullName: z.string().min(1).max(200).optional(),
      firstName: z.string().min(1).max(200).optional(),
      lastName: z.string().min(1).max(200).optional()
    })
    .optional(),
  requireSignedAssertions: z.boolean().optional(),
  allowIdpInitiated: z.boolean().optional()
});

const updateSamlConnectionSchema = createSamlConnectionSchema.partial();

const createDomainRouteSchema = z.object({
  domain: z
    .string()
    .min(3)
    .max(255)
    .regex(/^[a-z0-9.-]+$/),
  connectionType: z.enum(["password", "google", "saml"]),
  connectionId: z.string().uuid().optional()
});

const upsertRetentionPoliciesSchema = z.object({
  policies: z
    .array(
      z.object({
        targetType: z.enum(["audit_logs", "webhook_deliveries", "scim_tokens", "saml_auth_states", "export_jobs"]),
        retentionDays: z.number().int().positive().max(3650)
      })
    )
    .min(1)
    .max(20)
});

const runPruneSchema = z.object({
  dryRun: z.boolean().optional()
});

const createExportJobSchema = z.object({
  targetType: z.enum(["audit_logs", "members", "policies", "service_accounts", "webhooks", "scim_tokens", "all"]),
  filters: z.record(z.string(), z.unknown()).optional(),
  kmsKeyId: z.string().uuid().optional()
});

const createKmsKeySchema = z.object({
  alias: z
    .string()
    .min(2)
    .max(80)
    .regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/)
});

const kmsEncryptSchema = z.object({
  plaintext: z.string().min(1).max(100000)
});

const kmsDecryptSchema = z.object({
  ciphertext: z.string().min(3).max(200000)
});

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

const slugify = (value: string, fallback: string): string => {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "")
    .slice(0, 64);
  return normalized || fallback;
};

const formatSamlConnection = (connection: {
  id: string;
  slug: string;
  name: string;
  idp_entity_id: string;
  sso_url: string;
  sp_entity_id: string;
  acs_url: string;
  default_role: string;
  attribute_mapping_json: string | null;
  require_signed_assertions: number;
  allow_idp_initiated: number;
  is_active: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
}) => ({
  id: connection.id,
  slug: connection.slug,
  name: connection.name,
  idpEntityId: connection.idp_entity_id,
  ssoUrl: connection.sso_url,
  spEntityId: connection.sp_entity_id,
  acsUrl: connection.acs_url,
  defaultRole: connection.default_role,
  attributeMapping: (() => {
    if (!connection.attribute_mapping_json) {
      return null;
    }
    try {
      return JSON.parse(connection.attribute_mapping_json);
    } catch {
      return null;
    }
  })(),
  requireSignedAssertions: Boolean(connection.require_signed_assertions),
  allowIdpInitiated: Boolean(connection.allow_idp_initiated),
  isActive: Boolean(connection.is_active),
  createdByUserId: connection.created_by_user_id,
  createdAt: connection.created_at,
  updatedAt: connection.updated_at
});

const formatDomainRoute = (route: {
  id: string;
  domain: string;
  connection_type: string;
  connection_id: string | null;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
}) => ({
  id: route.id,
  domain: route.domain,
  connectionType: route.connection_type,
  connectionId: route.connection_id,
  createdByUserId: route.created_by_user_id,
  createdAt: route.created_at,
  updatedAt: route.updated_at
});

const formatRetentionPolicy = (policy: {
  id: string;
  target_type: string;
  retention_days: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
}) => ({
  id: policy.id,
  targetType: policy.target_type,
  retentionDays: policy.retention_days,
  createdByUserId: policy.created_by_user_id,
  createdAt: policy.created_at,
  updatedAt: policy.updated_at
});

const formatExportJob = (job: {
  id: string;
  target_type: string;
  status: string;
  filters_json: string | null;
  result_encrypted: number;
  kms_key_id: string | null;
  error_message: string | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}) => ({
  id: job.id,
  targetType: job.target_type,
  status: job.status,
  filters: (() => {
    if (!job.filters_json) {
      return null;
    }
    try {
      return JSON.parse(job.filters_json);
    } catch {
      return null;
    }
  })(),
  resultEncrypted: Boolean(job.result_encrypted),
  kmsKeyId: job.kms_key_id,
  errorMessage: job.error_message,
  expiresAt: job.expires_at,
  createdAt: job.created_at,
  updatedAt: job.updated_at,
  completedAt: job.completed_at
});

const formatKmsKey = (key: {
  id: string;
  alias: string;
  version: number;
  algorithm: string;
  is_active: number;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
  rotated_at: string | null;
}) => ({
  id: key.id,
  alias: key.alias,
  version: key.version,
  algorithm: key.algorithm,
  isActive: Boolean(key.is_active),
  createdByUserId: key.created_by_user_id,
  createdAt: key.created_at,
  updatedAt: key.updated_at,
  rotatedAt: key.rotated_at
});

const loadOrganizationAccess = async (params: {
  db: D1Database;
  organizationId: string;
  userId: string;
}): Promise<{ organization: OrganizationRow; membership: OrganizationMembershipRow } | null> => {
  const organization = await findOrganizationById(params.db, params.organizationId);
  if (!organization) {
    return null;
  }
  const membership = await findOrganizationMembership(params.db, params.organizationId, params.userId);
  if (!membership) {
    return null;
  }
  return {
    organization,
    membership
  };
};

const hasOrganizationPermission = async (params: {
  db: D1Database;
  organizationId: string;
  membership: OrganizationMembershipRow;
  resource: string;
  action: string;
}): Promise<boolean> => {
  const evaluation = await evaluateOrganizationPermission({
    db: params.db,
    organizationId: params.organizationId,
    userId: params.membership.user_id,
    role: params.membership.role,
    permission: {
      resource: params.resource,
      action: params.action
    }
  });
  return evaluation.allowed;
};

const requireOrgPermission = async (params: {
  db: D1Database;
  organizationId: string;
  membership: OrganizationMembershipRow;
  resource: string;
  action: string;
}): Promise<{ ok: true } | { ok: false; response: Response }> => {
  const allowed = await hasOrganizationPermission(params);
  if (allowed) {
    return { ok: true };
  }
  return {
    ok: false,
    response: new Response(
      JSON.stringify({
        error: {
          code: "FORBIDDEN",
          message: `You do not have permission to ${params.action} ${params.resource}`
        }
      }),
      {
        status: 403,
        headers: {
          "content-type": "application/json"
        }
      }
    )
  };
};

const findAvailableSamlSlug = async (db: D1Database, desiredSlug: string): Promise<string> => {
  let candidate = desiredSlug;
  let suffix = 2;
  while (
    await db
      .prepare(`SELECT id FROM saml_connections WHERE slug = ?`)
      .bind(candidate)
      .first<{ id: string }>()
  ) {
    candidate = `${desiredSlug}-${suffix}`;
    suffix += 1;
  }
  return candidate;
};

const listOrgScopedAuditLogs = async (db: D1Database, organizationId: string, limit: number) => {
  const logs = await listAuditLogs(db, { limit });
  return logs.filter((entry) => {
    if (!entry.metadata_json) {
      return false;
    }
    return entry.metadata_json.includes(`\\\"organizationId\\\":\\\"${organizationId}\\\"`);
  });
};

const countAndDelete = async (params: {
  db: D1Database;
  countSql: string;
  deleteSql: string;
  binds: unknown[];
  dryRun: boolean;
}): Promise<number> => {
  const countRow = await params.db.prepare(params.countSql).bind(...params.binds).first<{ count: number }>();
  const count = countRow?.count ?? 0;
  if (!params.dryRun && count > 0) {
    await params.db.prepare(params.deleteSql).bind(...params.binds).run();
  }
  return count;
};

const runRetentionPrune = async (params: {
  db: D1Database;
  organizationId: string;
  targetType: RetentionPolicyTargetType;
  cutoffIso: string;
  dryRun: boolean;
}): Promise<number> => {
  const binds = [params.organizationId, params.cutoffIso];
  switch (params.targetType) {
    case "audit_logs":
      return countAndDelete({
        db: params.db,
        countSql:
          "SELECT COUNT(*) AS count FROM audit_logs WHERE instr(COALESCE(metadata_json, ''), '\\\"organizationId\\\":\\\"' || ? || '\\\"') > 0 AND datetime(created_at) < datetime(?)",
        deleteSql:
          "DELETE FROM audit_logs WHERE instr(COALESCE(metadata_json, ''), '\\\"organizationId\\\":\\\"' || ? || '\\\"') > 0 AND datetime(created_at) < datetime(?)",
        binds,
        dryRun: params.dryRun
      });
    case "webhook_deliveries":
      return countAndDelete({
        db: params.db,
        countSql:
          "SELECT COUNT(*) AS count FROM webhook_deliveries WHERE endpoint_id IN (SELECT id FROM webhook_endpoints WHERE organization_id = ?) AND datetime(created_at) < datetime(?)",
        deleteSql:
          "DELETE FROM webhook_deliveries WHERE endpoint_id IN (SELECT id FROM webhook_endpoints WHERE organization_id = ?) AND datetime(created_at) < datetime(?)",
        binds,
        dryRun: params.dryRun
      });
    case "scim_tokens":
      return countAndDelete({
        db: params.db,
        countSql:
          "SELECT COUNT(*) AS count FROM scim_tokens WHERE organization_id = ? AND revoked_at IS NOT NULL AND datetime(updated_at) < datetime(?)",
        deleteSql:
          "DELETE FROM scim_tokens WHERE organization_id = ? AND revoked_at IS NOT NULL AND datetime(updated_at) < datetime(?)",
        binds,
        dryRun: params.dryRun
      });
    case "saml_auth_states":
      return countAndDelete({
        db: params.db,
        countSql:
          "SELECT COUNT(*) AS count FROM saml_auth_states WHERE saml_connection_id IN (SELECT id FROM saml_connections WHERE organization_id = ?) AND datetime(created_at) < datetime(?)",
        deleteSql:
          "DELETE FROM saml_auth_states WHERE saml_connection_id IN (SELECT id FROM saml_connections WHERE organization_id = ?) AND datetime(created_at) < datetime(?)",
        binds,
        dryRun: params.dryRun
      });
    case "export_jobs":
      return countAndDelete({
        db: params.db,
        countSql:
          "SELECT COUNT(*) AS count FROM export_jobs WHERE organization_id = ? AND datetime(created_at) < datetime(?)",
        deleteSql:
          "DELETE FROM export_jobs WHERE organization_id = ? AND datetime(created_at) < datetime(?)",
        binds,
        dryRun: params.dryRun
      });
    default:
      return 0;
  }
};

const buildExportPayload = async (params: {
  db: D1Database;
  organizationId: string;
  targetType: ExportJobTargetType;
  filters: Record<string, unknown>;
}) => {
  const include = (name: ExportJobTargetType): boolean => params.targetType === "all" || params.targetType === name;
  const output: Record<string, unknown> = {
    organizationId: params.organizationId,
    targetType: params.targetType,
    filters: params.filters,
    generatedAt: new Date().toISOString()
  };

  if (include("members")) {
    output.members = await listOrganizationMembers(params.db, params.organizationId);
  }
  if (include("policies")) {
    output.policies = await listOrganizationPolicies(params.db, params.organizationId);
  }
  if (include("service_accounts")) {
    output.serviceAccounts = await listServiceAccountsForOrganization(params.db, params.organizationId);
  }
  if (include("scim_tokens")) {
    output.scimTokens = (await listScimTokensForOrganization(params.db, params.organizationId)).map((item) => ({
      id: item.id,
      name: item.name,
      tokenPrefix: item.token_prefix,
      revokedAt: item.revoked_at,
      lastUsedAt: item.last_used_at,
      createdAt: item.created_at,
      updatedAt: item.updated_at
    }));
  }
  if (include("webhooks")) {
    const endpoints = await listWebhookEndpointsForOrganization(params.db, params.organizationId);
    const limitDeliveriesRaw = Number(params.filters.limitDeliveriesPerWebhook ?? 10);
    const limitDeliveries = Number.isFinite(limitDeliveriesRaw)
      ? Math.max(1, Math.min(Math.floor(limitDeliveriesRaw), 100))
      : 10;
    output.webhooks = await Promise.all(
      endpoints.map(async (endpoint) => ({
        endpoint,
        deliveries: await listWebhookDeliveriesForEndpoint(params.db, endpoint.id, limitDeliveries)
      }))
    );
  }
  if (include("audit_logs")) {
    const limitRaw = Number(params.filters.auditLogLimit ?? 1000);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(Math.floor(limitRaw), 5000)) : 1000;
    output.auditLogs = await listOrgScopedAuditLogs(params.db, params.organizationId, limit);
  }

  output.samlConnections = await listSamlConnectionsForOrganization(params.db, params.organizationId);
  output.domainRoutes = await listDomainRoutesForOrganization(params.db, params.organizationId);
  output.retentionPolicies = await listRetentionPoliciesForOrganization(params.db, params.organizationId);
  output.kmsKeys = (await listOrganizationKmsKeys(params.db, params.organizationId)).map((item) => ({
    id: item.id,
    alias: item.alias,
    version: item.version,
    algorithm: item.algorithm,
    isActive: Boolean(item.is_active),
    createdAt: item.created_at,
    updatedAt: item.updated_at,
    rotatedAt: item.rotated_at
  }));

  return output;
};

export const orgEnterpriseRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

orgEnterpriseRoutes.use("/*", requireAuth);

orgEnterpriseRoutes.get("/:orgId/enterprise/diagnostics", async (context) => {
  const organizationId = context.req.param("orgId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "enterprise",
    action: "read"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const [
    samlConnections,
    domainRoutes,
    retentionPolicies,
    exportJobs,
    kmsKeys,
    scimTokens,
    webhookEndpoints,
    serviceAccounts,
    auditLogs
  ] = await Promise.all([
    listSamlConnectionsForOrganization(context.env.DB, organizationId),
    listDomainRoutesForOrganization(context.env.DB, organizationId),
    listRetentionPoliciesForOrganization(context.env.DB, organizationId),
    listExportJobsForOrganization(context.env.DB, organizationId, 50),
    listOrganizationKmsKeys(context.env.DB, organizationId),
    listScimTokensForOrganization(context.env.DB, organizationId),
    listWebhookEndpointsForOrganization(context.env.DB, organizationId),
    listServiceAccountsForOrganization(context.env.DB, organizationId),
    listOrgScopedAuditLogs(context.env.DB, organizationId, 100)
  ]);

  return context.json({
    organization: {
      id: access.organization.id,
      slug: access.organization.slug,
      name: access.organization.name,
      myRole: access.membership.role
    },
    diagnostics: {
      samlConnections: {
        total: samlConnections.length,
        active: samlConnections.filter((item) => item.is_active).length
      },
      domainRoutes: {
        total: domainRoutes.length,
        byType: domainRoutes.reduce<Record<string, number>>((acc, item) => {
          acc[item.connection_type] = (acc[item.connection_type] ?? 0) + 1;
          return acc;
        }, {})
      },
      retentionPolicies: retentionPolicies.length,
      exportJobs: {
        total: exportJobs.length,
        queued: exportJobs.filter((item) => item.status === "queued").length,
        failed: exportJobs.filter((item) => item.status === "failed").length
      },
      kmsKeys: {
        total: kmsKeys.length,
        active: kmsKeys.filter((item) => item.is_active).length
      },
      scimTokens: {
        total: scimTokens.length,
        active: scimTokens.filter((item) => !item.revoked_at).length
      },
      webhooks: {
        total: webhookEndpoints.length,
        active: webhookEndpoints.filter((item) => item.is_active).length
      },
      serviceAccounts: {
        total: serviceAccounts.length,
        active: serviceAccounts.filter((item) => !item.disabled_at).length
      },
      recentAuditEventCount: auditLogs.length
    }
  });
});

orgEnterpriseRoutes.get("/:orgId/saml/connections", async (context) => {
  const organizationId = context.req.param("orgId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "saml",
    action: "read"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const connections = await listSamlConnectionsForOrganization(context.env.DB, organizationId);
  return context.json({
    organization: {
      id: access.organization.id,
      slug: access.organization.slug,
      name: access.organization.name
    },
    connections: connections.map((item) => formatSamlConnection(item))
  });
});

orgEnterpriseRoutes.post("/:orgId/saml/connections", async (context) => {
  const organizationId = context.req.param("orgId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "saml",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createSamlConnectionSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const desiredSlug = parsed.data.slug?.toLowerCase() || slugify(parsed.data.name, "saml");
  const slug = await findAvailableSamlSlug(context.env.DB, desiredSlug);
  const baseUrl = getAppUrl(context.env, context.req.raw);
  const spEntityId = parsed.data.spEntityId?.trim() || `${baseUrl}/v1/saml/${encodeURIComponent(slug)}/metadata`;
  const acsUrl = parsed.data.acsUrl?.trim() || `${baseUrl}/v1/saml/${encodeURIComponent(slug)}/acs`;
  const connectionId = crypto.randomUUID();

  await createSamlConnection(context.env.DB, {
    id: connectionId,
    organizationId,
    slug,
    name: parsed.data.name,
    idpEntityId: parsed.data.idpEntityId,
    ssoUrl: parsed.data.ssoUrl,
    x509CertPem: parsed.data.x509CertPem,
    spEntityId,
    acsUrl,
    defaultRole: parsed.data.defaultRole ?? "member",
    attributeMappingJson: parsed.data.attributeMapping ? JSON.stringify(parsed.data.attributeMapping) : null,
    requireSignedAssertions: parsed.data.requireSignedAssertions ?? true,
    allowIdpInitiated: parsed.data.allowIdpInitiated ?? true,
    createdByUserId: currentUserId
  });

  const connection = await findSamlConnectionByIdInOrganization(context.env.DB, {
    organizationId,
    connectionId
  });
  if (!connection) {
    return context.json(
      {
        error: {
          code: "SAML_CONNECTION_CREATION_FAILED",
          message: "SAML connection was created but cannot be loaded"
        }
      },
      500
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.saml_connection_created",
    metadataJson: JSON.stringify({
      organizationId,
      samlConnectionId: connection.id,
      samlConnectionSlug: connection.slug
    })
  });

  return context.json(
    {
      connection: formatSamlConnection(connection)
    },
    201
  );
});

orgEnterpriseRoutes.patch("/:orgId/saml/connections/:connectionId", async (context) => {
  const organizationId = context.req.param("orgId");
  const connectionId = context.req.param("connectionId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "saml",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = updateSamlConnectionSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const connection = await updateSamlConnection(context.env.DB, {
    organizationId,
    connectionId,
    name: parsed.data.name,
    idpEntityId: parsed.data.idpEntityId,
    ssoUrl: parsed.data.ssoUrl,
    x509CertPem: parsed.data.x509CertPem,
    spEntityId: parsed.data.spEntityId,
    acsUrl: parsed.data.acsUrl,
    defaultRole: parsed.data.defaultRole,
    attributeMappingJson: parsed.data.attributeMapping ? JSON.stringify(parsed.data.attributeMapping) : undefined,
    requireSignedAssertions: parsed.data.requireSignedAssertions,
    allowIdpInitiated: parsed.data.allowIdpInitiated
  });
  if (!connection) {
    return context.json(
      {
        error: {
          code: "SAML_CONNECTION_NOT_FOUND",
          message: "SAML connection was not found"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.saml_connection_updated",
    metadataJson: JSON.stringify({
      organizationId,
      samlConnectionId: connection.id,
      samlConnectionSlug: connection.slug
    })
  });

  return context.json({
    connection: formatSamlConnection(connection)
  });
});

orgEnterpriseRoutes.post("/:orgId/saml/connections/:connectionId/disable", async (context) => {
  const organizationId = context.req.param("orgId");
  const connectionId = context.req.param("connectionId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "saml",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const disabled = await disableSamlConnection(context.env.DB, {
    organizationId,
    connectionId
  });
  if (!disabled) {
    return context.json(
      {
        error: {
          code: "SAML_CONNECTION_NOT_FOUND",
          message: "SAML connection was not found or already disabled"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.saml_connection_disabled",
    metadataJson: JSON.stringify({
      organizationId,
      samlConnectionId: connectionId
    })
  });

  return context.json({
    ok: true,
    connectionId
  });
});

orgEnterpriseRoutes.get("/:orgId/domain-routes", async (context) => {
  const organizationId = context.req.param("orgId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "domains",
    action: "read"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const routes = await listDomainRoutesForOrganization(context.env.DB, organizationId);
  return context.json({
    organization: {
      id: access.organization.id,
      slug: access.organization.slug,
      name: access.organization.name
    },
    routes: routes.map((route) => formatDomainRoute(route))
  });
});

orgEnterpriseRoutes.post("/:orgId/domain-routes", async (context) => {
  const organizationId = context.req.param("orgId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "domains",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createDomainRouteSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  if (parsed.data.connectionType === "saml") {
    if (!parsed.data.connectionId) {
      return context.json(
        {
          error: {
            code: "SAML_CONNECTION_REQUIRED",
            message: "connectionId is required when connectionType is 'saml'"
          }
        },
        400
      );
    }
    const connection = await findSamlConnectionByIdInOrganization(context.env.DB, {
      organizationId,
      connectionId: parsed.data.connectionId
    });
    if (!connection) {
      return context.json(
        {
          error: {
            code: "SAML_CONNECTION_NOT_FOUND",
            message: "SAML connection does not exist in this organization"
          }
        },
        404
      );
    }
  }

  const routeId = crypto.randomUUID();
  try {
    await createDomainRoute(context.env.DB, {
      id: routeId,
      organizationId,
      domain: parsed.data.domain,
      connectionType: parsed.data.connectionType as DomainRouteConnectionType,
      connectionId: parsed.data.connectionType === "saml" ? parsed.data.connectionId ?? null : null,
      createdByUserId: currentUserId
    });
  } catch {
    return context.json(
      {
        error: {
          code: "DOMAIN_ROUTE_CONFLICT",
          message: "Domain route already exists"
        }
      },
      409
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.domain_route_created",
    metadataJson: JSON.stringify({
      organizationId,
      domainRouteId: routeId,
      domain: parsed.data.domain.toLowerCase(),
      connectionType: parsed.data.connectionType,
      connectionId: parsed.data.connectionId ?? null
    })
  });

  const route = (await listDomainRoutesForOrganization(context.env.DB, organizationId)).find((item) => item.id === routeId);
  if (!route) {
    return context.json(
      {
        error: {
          code: "DOMAIN_ROUTE_WRITE_FAILED",
          message: "Domain route was created but cannot be loaded"
        }
      },
      500
    );
  }

  return context.json(
    {
      route: formatDomainRoute(route)
    },
    201
  );
});

orgEnterpriseRoutes.delete("/:orgId/domain-routes/:routeId", async (context) => {
  const organizationId = context.req.param("orgId");
  const routeId = context.req.param("routeId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "domains",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const removed = await deleteDomainRouteByIdInOrganization(context.env.DB, {
    organizationId,
    routeId
  });
  if (!removed) {
    return context.json(
      {
        error: {
          code: "DOMAIN_ROUTE_NOT_FOUND",
          message: "Domain route does not exist"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.domain_route_removed",
    metadataJson: JSON.stringify({
      organizationId,
      domainRouteId: routeId
    })
  });

  return context.json({
    ok: true,
    routeId
  });
});

orgEnterpriseRoutes.get("/:orgId/compliance/retention", async (context) => {
  const organizationId = context.req.param("orgId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "compliance",
    action: "read"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const policies = await listRetentionPoliciesForOrganization(context.env.DB, organizationId);
  return context.json({
    organization: {
      id: access.organization.id,
      slug: access.organization.slug,
      name: access.organization.name
    },
    retentionPolicies: policies.map((item) => formatRetentionPolicy(item))
  });
});

orgEnterpriseRoutes.put("/:orgId/compliance/retention", async (context) => {
  const organizationId = context.req.param("orgId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "compliance",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = upsertRetentionPoliciesSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  for (const policy of parsed.data.policies) {
    await upsertRetentionPolicy(context.env.DB, {
      id: crypto.randomUUID(),
      organizationId,
      targetType: policy.targetType as RetentionPolicyTargetType,
      retentionDays: policy.retentionDays,
      createdByUserId: currentUserId
    });
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.retention_policies_upserted",
    metadataJson: JSON.stringify({
      organizationId,
      policyCount: parsed.data.policies.length
    })
  });

  const policies = await listRetentionPoliciesForOrganization(context.env.DB, organizationId);
  return context.json({
    retentionPolicies: policies.map((item) => formatRetentionPolicy(item))
  });
});

orgEnterpriseRoutes.post("/:orgId/compliance/prune", async (context) => {
  const organizationId = context.req.param("orgId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "compliance",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = runPruneSchema.safeParse(payload ?? {});
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const policies = await listRetentionPoliciesForOrganization(context.env.DB, organizationId);
  const dryRun = Boolean(parsed.data.dryRun);
  const result: Record<string, number> = {};
  for (const policy of policies) {
    const cutoff = new Date(Date.now() - policy.retention_days * 24 * 60 * 60 * 1000).toISOString();
    try {
      result[policy.target_type] = await runRetentionPrune({
        db: context.env.DB,
        organizationId,
        targetType: policy.target_type,
        cutoffIso: cutoff,
        dryRun
      });
    } catch (error) {
      return context.json(
        {
          error: {
            code: "RETENTION_PRUNE_FAILED",
            message: error instanceof Error ? error.message : "Retention prune failed unexpectedly",
            targetType: policy.target_type
          }
        },
        500
      );
    }
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.retention_prune_executed",
    metadataJson: JSON.stringify({
      organizationId,
      dryRun,
      affected: result
    })
  });

  return context.json({
    dryRun,
    affected: result
  });
});

orgEnterpriseRoutes.get("/:orgId/compliance/exports", async (context) => {
  const organizationId = context.req.param("orgId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "compliance",
    action: "read"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const limitRaw = Number.parseInt(context.req.query("limit") ?? "100", 10);
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(limitRaw, 500)) : 100;
  const jobs = await listExportJobsForOrganization(context.env.DB, organizationId, limit);
  return context.json({
    jobs: jobs.map((job) => formatExportJob(job))
  });
});

orgEnterpriseRoutes.get("/:orgId/compliance/exports/:jobId", async (context) => {
  const organizationId = context.req.param("orgId");
  const jobId = context.req.param("jobId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "compliance",
    action: "read"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const job = await findExportJobByIdInOrganization(context.env.DB, {
    organizationId,
    jobId
  });
  if (!job) {
    return context.json(
      {
        error: {
          code: "EXPORT_JOB_NOT_FOUND",
          message: "Export job does not exist"
        }
      },
      404
    );
  }

  const includeResult = context.req.query("includeResult") === "true";
  return context.json({
    job: formatExportJob(job),
    result: includeResult
      ? (() => {
          if (!job.result_json) {
            return null;
          }
          try {
            return JSON.parse(job.result_json);
          } catch {
            return { raw: job.result_json };
          }
        })()
      : undefined
  });
});

orgEnterpriseRoutes.post("/:orgId/compliance/exports", async (context) => {
  const organizationId = context.req.param("orgId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "compliance",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createExportJobSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  let kmsKey = null;
  if (parsed.data.kmsKeyId) {
    kmsKey = await findActiveOrganizationKmsKeyByIdInOrganization(context.env.DB, {
      organizationId,
      keyId: parsed.data.kmsKeyId
    });
    if (!kmsKey) {
      return context.json(
        {
          error: {
            code: "KMS_KEY_NOT_FOUND",
            message: "KMS key does not exist or is inactive"
          }
        },
        404
      );
    }
  }

  const exportJobId = crypto.randomUUID();
  await createExportJob(context.env.DB, {
    id: exportJobId,
    organizationId,
    requestedByUserId: currentUserId,
    targetType: parsed.data.targetType as ExportJobTargetType,
    filtersJson: parsed.data.filters ? JSON.stringify(parsed.data.filters) : null,
    kmsKeyId: kmsKey?.id ?? null
  });

  try {
    const payloadData = await buildExportPayload({
      db: context.env.DB,
      organizationId,
      targetType: parsed.data.targetType as ExportJobTargetType,
      filters: parsed.data.filters ?? {}
    });

    let resultJson = JSON.stringify(payloadData);
    let resultEncrypted = false;
    if (kmsKey) {
      const keyMaterial = await decryptManagedKeyMaterial({
        env: context.env,
        encryptedKeyMaterial: kmsKey.encrypted_key_material
      });
      const ciphertext = await encryptWithManagedKey({
        keyMaterial,
        plaintext: resultJson
      });
      resultJson = JSON.stringify({
        algorithm: kmsKey.algorithm,
        keyId: kmsKey.id,
        keyAlias: kmsKey.alias,
        keyVersion: kmsKey.version,
        ciphertext
      });
      resultEncrypted = true;
    }

    await markExportJobCompleted(context.env.DB, {
      jobId: exportJobId,
      organizationId,
      resultJson,
      resultEncrypted,
      expiresAt: addSecondsToIso(24 * 60 * 60)
    });
  } catch (error) {
    await markExportJobFailed(context.env.DB, {
      jobId: exportJobId,
      organizationId,
      errorMessage: error instanceof Error ? error.message : "Failed to generate export"
    });
  }

  const job = await findExportJobByIdInOrganization(context.env.DB, {
    organizationId,
    jobId: exportJobId
  });
  if (!job) {
    return context.json(
      {
        error: {
          code: "EXPORT_JOB_NOT_FOUND",
          message: "Export job cannot be loaded"
        }
      },
      500
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.export_job_created",
    metadataJson: JSON.stringify({
      organizationId,
      exportJobId: job.id,
      targetType: job.target_type,
      status: job.status,
      encrypted: Boolean(job.result_encrypted)
    })
  });

  return context.json(
    {
      job: formatExportJob(job)
    },
    201
  );
});

orgEnterpriseRoutes.get("/:orgId/kms/keys", async (context) => {
  const organizationId = context.req.param("orgId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "kms",
    action: "read"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const keys = await listOrganizationKmsKeys(context.env.DB, organizationId);
  return context.json({
    keys: keys.map((item) => formatKmsKey(item))
  });
});

orgEnterpriseRoutes.post("/:orgId/kms/keys", async (context) => {
  const organizationId = context.req.param("orgId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "kms",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createKmsKeySchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const keyMaterial = generateRandomDataKeyMaterial();
  const encryptedKeyMaterial = await encryptManagedKeyMaterial({
    env: context.env,
    keyMaterial
  });

  const keyId = crypto.randomUUID();
  try {
    await createOrganizationKmsKey(context.env.DB, {
      id: keyId,
      organizationId,
      alias: parsed.data.alias,
      algorithm: "aes-256-gcm",
      encryptedKeyMaterial,
      createdByUserId: currentUserId
    });
  } catch {
    return context.json(
      {
        error: {
          code: "KMS_KEY_ALIAS_CONFLICT",
          message: "KMS key alias already exists"
        }
      },
      409
    );
  }

  const key = await findActiveOrganizationKmsKeyByIdInOrganization(context.env.DB, {
    organizationId,
    keyId
  });
  if (!key) {
    return context.json(
      {
        error: {
          code: "KMS_KEY_WRITE_FAILED",
          message: "KMS key was created but cannot be loaded"
        }
      },
      500
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.kms_key_created",
    metadataJson: JSON.stringify({
      organizationId,
      kmsKeyId: key.id,
      alias: key.alias
    })
  });

  return context.json(
    {
      key: formatKmsKey(key)
    },
    201
  );
});

orgEnterpriseRoutes.post("/:orgId/kms/keys/:keyId/rotate", async (context) => {
  const organizationId = context.req.param("orgId");
  const keyId = context.req.param("keyId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "kms",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const keyMaterial = generateRandomDataKeyMaterial();
  const encryptedKeyMaterial = await encryptManagedKeyMaterial({
    env: context.env,
    keyMaterial
  });

  const key = await rotateOrganizationKmsKey(context.env.DB, {
    organizationId,
    keyId,
    encryptedKeyMaterial
  });
  if (!key) {
    return context.json(
      {
        error: {
          code: "KMS_KEY_NOT_FOUND",
          message: "KMS key does not exist or is inactive"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.kms_key_rotated",
    metadataJson: JSON.stringify({
      organizationId,
      kmsKeyId: key.id,
      version: key.version
    })
  });

  return context.json({
    key: formatKmsKey(key)
  });
});

orgEnterpriseRoutes.post("/:orgId/kms/keys/:keyId/disable", async (context) => {
  const organizationId = context.req.param("orgId");
  const keyId = context.req.param("keyId");
  const currentUserId = context.get("authUserId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "kms",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const disabled = await deactivateOrganizationKmsKey(context.env.DB, {
    organizationId,
    keyId
  });
  if (!disabled) {
    return context.json(
      {
        error: {
          code: "KMS_KEY_NOT_FOUND",
          message: "KMS key does not exist or is already inactive"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.kms_key_disabled",
    metadataJson: JSON.stringify({
      organizationId,
      kmsKeyId: keyId
    })
  });

  return context.json({
    ok: true,
    keyId
  });
});

orgEnterpriseRoutes.post("/:orgId/kms/keys/:keyId/encrypt", async (context) => {
  const organizationId = context.req.param("orgId");
  const keyId = context.req.param("keyId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "kms",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const key = await findActiveOrganizationKmsKeyByIdInOrganization(context.env.DB, {
    organizationId,
    keyId
  });
  if (!key) {
    return context.json(
      {
        error: {
          code: "KMS_KEY_NOT_FOUND",
          message: "KMS key does not exist or is inactive"
        }
      },
      404
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = kmsEncryptSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const keyMaterial = await decryptManagedKeyMaterial({
    env: context.env,
    encryptedKeyMaterial: key.encrypted_key_material
  });
  const ciphertext = await encryptWithManagedKey({
    keyMaterial,
    plaintext: parsed.data.plaintext
  });

  return context.json({
    key: {
      id: key.id,
      alias: key.alias,
      version: key.version,
      algorithm: key.algorithm
    },
    ciphertext
  });
});

orgEnterpriseRoutes.post("/:orgId/kms/keys/:keyId/decrypt", async (context) => {
  const organizationId = context.req.param("orgId");
  const keyId = context.req.param("keyId");
  const access = await loadOrganizationAccess({
    db: context.env.DB,
    organizationId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_NOT_FOUND_OR_FORBIDDEN",
          message: "Organization does not exist or you do not have access"
        }
      },
      404
    );
  }

  const permission = await requireOrgPermission({
    db: context.env.DB,
    organizationId,
    membership: access.membership,
    resource: "kms",
    action: "manage"
  });
  if (!permission.ok) {
    return permission.response;
  }

  const key = await findActiveOrganizationKmsKeyByIdInOrganization(context.env.DB, {
    organizationId,
    keyId
  });
  if (!key) {
    return context.json(
      {
        error: {
          code: "KMS_KEY_NOT_FOUND",
          message: "KMS key does not exist or is inactive"
        }
      },
      404
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = kmsDecryptSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const keyMaterial = await decryptManagedKeyMaterial({
    env: context.env,
    encryptedKeyMaterial: key.encrypted_key_material
  });
  let plaintext: string;
  try {
    plaintext = await decryptWithManagedKey({
      keyMaterial,
      ciphertext: parsed.data.ciphertext
    });
  } catch {
    return context.json(
      {
        error: {
          code: "KMS_DECRYPT_FAILED",
          message: "Ciphertext cannot be decrypted with this key"
        }
      },
      400
    );
  }

  return context.json({
    key: {
      id: key.id,
      alias: key.alias,
      version: key.version,
      algorithm: key.algorithm
    },
    plaintext
  });
});
