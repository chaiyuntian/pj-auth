import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { requireAuth } from "../middleware/require-auth";
import {
  countOrganizationMembers,
  countOrganizationOwners,
  countOrganizationTeams,
  createApiKey,
  createOrganizationWithOwner,
  createServiceAccount,
  createWebhookEndpoint,
  createTeam,
  disableServiceAccount,
  findOrganizationById,
  findOrganizationBySlug,
  findOrganizationMembership,
  findServiceAccountByIdInOrganization,
  findTeamByIdInOrganization,
  findTeamBySlugInOrganization,
  findTeamMembership,
  findWebhookEndpointByIdInOrganization,
  findUserByEmail,
  listOrganizationMembers,
  listOrganizationPolicies,
  listOrganizationsForUser,
  listServiceAccountApiKeys,
  listServiceAccountsForOrganization,
  listTeamMembers,
  listTeamsForUserInOrganization,
  listWebhookDeliveriesForEndpoint,
  listWebhookEndpointsForOrganization,
  removeOrganizationMembership,
  removeOrganizationPolicy,
  revokeServiceAccountApiKey,
  removeTeamMembership,
  type OrganizationMembershipRow,
  type OrganizationRole,
  type OrganizationPolicySubjectType,
  type OrganizationRow,
  type TeamRole,
  upsertOrganizationMembership,
  upsertTeamMembership,
  updateWebhookEndpoint,
  upsertOrganizationPolicy,
  writeAuditLog
} from "../lib/db";
import { readJsonBody } from "../lib/request";
import { publicUser } from "../lib/http";
import { randomToken } from "../lib/encoding";
import { addSecondsToIso } from "../lib/time";
import { sha256Hex } from "../lib/crypto";
import { emitOrganizationWebhookEvent } from "../lib/webhooks";
import { evaluateOrganizationPermission } from "../lib/policy";

const organizationRoleSchema = z.enum(["owner", "admin", "member"]);
const teamRoleSchema = z.enum(["maintainer", "member"]);

const createOrganizationSchema = z.object({
  name: z.string().min(2).max(120),
  slug: z
    .string()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    .optional()
});

const upsertOrganizationMemberSchema = z.object({
  email: z.string().email().min(3).max(320),
  role: organizationRoleSchema.optional()
});

const updateOrganizationMemberRoleSchema = z.object({
  role: organizationRoleSchema
});

const createTeamSchema = z.object({
  name: z.string().min(2).max(120),
  slug: z
    .string()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    .optional()
});

const upsertTeamMemberSchema = z.object({
  email: z.string().email().min(3).max(320),
  role: teamRoleSchema.optional()
});

const updateTeamMemberRoleSchema = z.object({
  role: teamRoleSchema
});

const createServiceAccountSchema = z.object({
  name: z.string().min(2).max(120),
  description: z.string().max(500).optional()
});

const createServiceAccountApiKeySchema = z.object({
  name: z.string().min(2).max(120),
  scopes: z.array(z.string().min(1).max(120)).max(50).optional(),
  expiresInDays: z.number().int().positive().max(3650).optional()
});

const webhookEventNameSchema = z.string().min(2).max(120);

const createWebhookSchema = z.object({
  url: z.string().url().max(1000),
  eventTypes: z.array(webhookEventNameSchema).max(100).optional()
});

const updateWebhookSchema = z.object({
  url: z.string().url().max(1000).optional(),
  eventTypes: z.array(webhookEventNameSchema).max(100).optional(),
  isActive: z.boolean().optional(),
  rotateSigningSecret: z.boolean().optional()
});

const policySubjectTypeSchema = z.enum(["user", "role", "team", "service_account"]);
const policyEffectSchema = z.enum(["allow", "deny"]);
const policySubjectIdSchema = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[a-zA-Z0-9._:-]+$/);
const policyResourceSchema = z
  .string()
  .min(1)
  .max(80)
  .regex(/^[a-zA-Z0-9_*.-]+$/);
const policyActionSchema = z
  .string()
  .min(1)
  .max(80)
  .regex(/^[a-zA-Z0-9_*.-]+$/);

const createPolicySchema = z.object({
  subjectType: policySubjectTypeSchema,
  subjectId: policySubjectIdSchema,
  resource: policyResourceSchema,
  action: policyActionSchema,
  effect: policyEffectSchema,
  condition: z.record(z.string(), z.unknown()).optional()
});

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

const isOrganizationOwner = (role: OrganizationRole): boolean => role === "owner";

const slugify = (rawValue: string, fallback: string): string => {
  const normalized = rawValue
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "")
    .slice(0, 64);
  return normalized || fallback;
};

const parseScopesJson = (rawScopes: string | null): string[] => {
  if (!rawScopes) {
    return [];
  }
  try {
    const parsed = JSON.parse(rawScopes);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.filter((value): value is string => typeof value === "string");
  } catch {
    return [];
  }
};

const normalizeEventTypes = (eventTypes: string[] | undefined): string[] => {
  if (!eventTypes || eventTypes.length === 0) {
    return ["*"];
  }
  return Array.from(new Set(eventTypes.map((eventType) => eventType.trim()).filter(Boolean)));
};

const findAvailableOrganizationSlug = async (
  db: D1Database,
  desiredSlug: string
): Promise<string> => {
  let candidate = desiredSlug;
  let suffix = 2;
  while (await findOrganizationBySlug(db, candidate)) {
    candidate = `${desiredSlug}-${suffix}`;
    suffix += 1;
  }
  return candidate;
};

const findAvailableTeamSlug = async (
  db: D1Database,
  organizationId: string,
  desiredSlug: string
): Promise<string> => {
  let candidate = desiredSlug;
  let suffix = 2;
  while (await findTeamBySlugInOrganization(db, { organizationId, slug: candidate })) {
    candidate = `${desiredSlug}-${suffix}`;
    suffix += 1;
  }
  return candidate;
};

const formatOrganization = (organization: OrganizationRow) => ({
  id: organization.id,
  slug: organization.slug,
  name: organization.name,
  createdAt: organization.created_at,
  updatedAt: organization.updated_at
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

const formatPolicy = (policy: {
  id: string;
  subject_type: OrganizationPolicySubjectType;
  subject_id: string;
  resource: string;
  action: string;
  effect: "allow" | "deny";
  condition_json: string | null;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
}) => {
  let condition: Record<string, unknown> | null = null;
  if (policy.condition_json) {
    try {
      const parsed = JSON.parse(policy.condition_json);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        condition = parsed as Record<string, unknown>;
      }
    } catch {
      condition = null;
    }
  }
  return {
    id: policy.id,
    subjectType: policy.subject_type,
    subjectId: policy.subject_id,
    resource: policy.resource,
    action: policy.action,
    effect: policy.effect,
    condition,
    createdByUserId: policy.created_by_user_id,
    createdAt: policy.created_at,
    updatedAt: policy.updated_at
  };
};

const emitOrgWebhookSafely = async (params: {
  env: EnvBindings;
  organizationId: string;
  eventType: string;
  payload: Record<string, unknown>;
}): Promise<void> => {
  try {
    await emitOrganizationWebhookEvent({
      env: params.env,
      organizationId: params.organizationId,
      eventType: params.eventType,
      payload: params.payload
    });
  } catch (error) {
    console.error(
      `[webhook] emit_failed org=${params.organizationId} event=${params.eventType} error=${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
};

export const orgRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

orgRoutes.use("/*", requireAuth);

orgRoutes.get("", async (context) => {
  const userId = context.get("authUserId");
  const organizations = await listOrganizationsForUser(context.env.DB, userId);
  return context.json({
    organizations: organizations.map((organization) => ({
      id: organization.id,
      slug: organization.slug,
      name: organization.name,
      role: organization.membership_role,
      joinedAt: organization.membership_created_at,
      createdAt: organization.created_at,
      updatedAt: organization.updated_at
    }))
  });
});

orgRoutes.post("", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = createOrganizationSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const desiredSlug = parsed.data.slug?.toLowerCase() || slugify(parsed.data.name, "org");
  const slug = await findAvailableOrganizationSlug(context.env.DB, desiredSlug);
  const organizationId = crypto.randomUUID();
  const userId = context.get("authUserId");

  await createOrganizationWithOwner(context.env.DB, {
    id: organizationId,
    slug,
    name: parsed.data.name.trim(),
    ownerUserId: userId
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "org.created",
    metadataJson: JSON.stringify({ organizationId, slug })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.created",
    payload: {
      organizationId,
      slug,
      createdByUserId: userId
    }
  });

  const organization = await findOrganizationById(context.env.DB, organizationId);
  const membership = await findOrganizationMembership(context.env.DB, organizationId, userId);
  if (!organization || !membership) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_CREATION_FAILED",
          message: "Organization was created but cannot be loaded"
        }
      },
      500
    );
  }

  return context.json(
    {
      organization: formatOrganization(organization),
      membership: {
        role: membership.role,
        joinedAt: membership.created_at
      }
    },
    201
  );
});

orgRoutes.get("/:orgId", async (context) => {
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

  const [memberCount, teamCount] = await Promise.all([
    countOrganizationMembers(context.env.DB, organizationId),
    countOrganizationTeams(context.env.DB, organizationId)
  ]);

  return context.json({
    organization: formatOrganization(access.organization),
    membership: {
      role: access.membership.role,
      joinedAt: access.membership.created_at
    },
    stats: {
      members: memberCount,
      teams: teamCount
    }
  });
});

orgRoutes.get("/:orgId/members", async (context) => {
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

  const members = await listOrganizationMembers(context.env.DB, organizationId);
  return context.json({
    organization: formatOrganization(access.organization),
    members: members.map((member) => ({
      user: publicUser({
        id: member.user_id,
        email: member.email,
        full_name: member.full_name,
        image_url: member.image_url,
        email_verified: member.email_verified,
        created_at: member.user_created_at,
        updated_at: member.user_updated_at,
        password_hash: null,
        password_salt: null
      }),
      role: member.role,
      joinedAt: member.created_at
    }))
  });
});

orgRoutes.post("/:orgId/members", async (context) => {
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "members",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can manage members"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = upsertOrganizationMemberSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const role = parsed.data.role ?? "member";
  if (role === "owner" && !isOrganizationOwner(access.membership.role)) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only owners can grant owner role"
        }
      },
      403
    );
  }

  const user = await findUserByEmail(context.env.DB, parsed.data.email);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "User does not exist. User must sign up before being added."
        }
      },
      404
    );
  }

  await upsertOrganizationMembership(context.env.DB, {
    organizationId,
    userId: user.id,
    role
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "org.member_upserted",
    metadataJson: JSON.stringify({
      organizationId,
      userId: user.id,
      role
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.member.upserted",
    payload: {
      userId: user.id,
      role,
      changedByUserId: context.get("authUserId")
    }
  });

  const membership = await findOrganizationMembership(context.env.DB, organizationId, user.id);
  if (!membership) {
    return context.json(
      {
        error: {
          code: "MEMBERSHIP_WRITE_FAILED",
          message: "Membership write completed but cannot be loaded"
        }
      },
      500
    );
  }

  return context.json({
    user: publicUser(user),
    membership: {
      role: membership.role,
      joinedAt: membership.created_at
    }
  });
});

orgRoutes.patch("/:orgId/members/:userId", async (context) => {
  const organizationId = context.req.param("orgId");
  const targetUserId = context.req.param("userId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "members",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can update member roles"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = updateOrganizationMemberRoleSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  if (parsed.data.role === "owner" && !isOrganizationOwner(access.membership.role)) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only owners can grant owner role"
        }
      },
      403
    );
  }

  const membership = await findOrganizationMembership(context.env.DB, organizationId, targetUserId);
  if (!membership) {
    return context.json(
      {
        error: {
          code: "MEMBERSHIP_NOT_FOUND",
          message: "Target user is not a member of this organization"
        }
      },
      404
    );
  }

  if (membership.role === "owner" && parsed.data.role !== "owner") {
    const owners = await countOrganizationOwners(context.env.DB, organizationId);
    if (owners <= 1) {
      return context.json(
        {
          error: {
            code: "LAST_OWNER_CONSTRAINT",
            message: "Organization must keep at least one owner"
          }
        },
        409
      );
    }
  }

  await upsertOrganizationMembership(context.env.DB, {
    organizationId,
    userId: targetUserId,
    role: parsed.data.role
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "org.member_role_updated",
    metadataJson: JSON.stringify({
      organizationId,
      userId: targetUserId,
      role: parsed.data.role
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.member.role_updated",
    payload: {
      userId: targetUserId,
      role: parsed.data.role,
      changedByUserId: context.get("authUserId")
    }
  });

  return context.json({
    ok: true,
    userId: targetUserId,
    role: parsed.data.role
  });
});

orgRoutes.delete("/:orgId/members/:userId", async (context) => {
  const organizationId = context.req.param("orgId");
  const targetUserId = context.req.param("userId");
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

  const isSelf = targetUserId === currentUserId;
  if (
    !isSelf &&
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "members",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can remove other members"
        }
      },
      403
    );
  }

  const targetMembership = await findOrganizationMembership(context.env.DB, organizationId, targetUserId);
  if (!targetMembership) {
    return context.json(
      {
        error: {
          code: "MEMBERSHIP_NOT_FOUND",
          message: "Target user is not a member of this organization"
        }
      },
      404
    );
  }

  if (targetMembership.role === "owner") {
    const owners = await countOrganizationOwners(context.env.DB, organizationId);
    if (owners <= 1) {
      return context.json(
        {
          error: {
            code: "LAST_OWNER_CONSTRAINT",
            message: "Organization must keep at least one owner"
          }
        },
        409
      );
    }
  }

  const removed = await removeOrganizationMembership(context.env.DB, {
    organizationId,
    userId: targetUserId
  });
  if (!removed) {
    return context.json(
      {
        error: {
          code: "MEMBERSHIP_NOT_FOUND",
          message: "Target user is not a member of this organization"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.member_removed",
    metadataJson: JSON.stringify({
      organizationId,
      userId: targetUserId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.member.removed",
    payload: {
      userId: targetUserId,
      removedByUserId: currentUserId
    }
  });

  return context.json({
    ok: true,
    userId: targetUserId
  });
});

orgRoutes.get("/:orgId/service-accounts", async (context) => {
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

  const accounts = await listServiceAccountsForOrganization(context.env.DB, organizationId);
  return context.json({
    organization: formatOrganization(access.organization),
    serviceAccounts: accounts.map((account) => ({
      id: account.id,
      name: account.name,
      description: account.description,
      disabledAt: account.disabled_at,
      createdByUserId: account.created_by_user_id,
      createdAt: account.created_at,
      updatedAt: account.updated_at
    }))
  });
});

orgRoutes.post("/:orgId/service-accounts", async (context) => {
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "service_accounts",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can create service accounts"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createServiceAccountSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const serviceAccountId = crypto.randomUUID();
  await createServiceAccount(context.env.DB, {
    id: serviceAccountId,
    organizationId,
    name: parsed.data.name.trim(),
    description: parsed.data.description?.trim() ?? null,
    createdByUserId: currentUserId
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.service_account_created",
    metadataJson: JSON.stringify({
      organizationId,
      serviceAccountId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.service_account.created",
    payload: {
      serviceAccountId,
      createdByUserId: currentUserId
    }
  });

  const serviceAccount = await findServiceAccountByIdInOrganization(context.env.DB, {
    organizationId,
    serviceAccountId
  });
  if (!serviceAccount) {
    return context.json(
      {
        error: {
          code: "SERVICE_ACCOUNT_CREATION_FAILED",
          message: "Service account was created but cannot be loaded"
        }
      },
      500
    );
  }

  return context.json(
    {
      serviceAccount: {
        id: serviceAccount.id,
        name: serviceAccount.name,
        description: serviceAccount.description,
        disabledAt: serviceAccount.disabled_at,
        createdByUserId: serviceAccount.created_by_user_id,
        createdAt: serviceAccount.created_at,
        updatedAt: serviceAccount.updated_at
      }
    },
    201
  );
});

orgRoutes.post("/:orgId/service-accounts/:serviceAccountId/disable", async (context) => {
  const organizationId = context.req.param("orgId");
  const serviceAccountId = context.req.param("serviceAccountId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "service_accounts",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can disable service accounts"
        }
      },
      403
    );
  }

  const disabled = await disableServiceAccount(context.env.DB, {
    organizationId,
    serviceAccountId
  });
  if (!disabled) {
    return context.json(
      {
        error: {
          code: "SERVICE_ACCOUNT_NOT_FOUND",
          message: "Service account was not found or already disabled"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.service_account_disabled",
    metadataJson: JSON.stringify({
      organizationId,
      serviceAccountId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.service_account.disabled",
    payload: {
      serviceAccountId,
      disabledByUserId: currentUserId
    }
  });

  return context.json({
    ok: true,
    serviceAccountId
  });
});

orgRoutes.get("/:orgId/service-accounts/:serviceAccountId/api-keys", async (context) => {
  const organizationId = context.req.param("orgId");
  const serviceAccountId = context.req.param("serviceAccountId");
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

  const serviceAccount = await findServiceAccountByIdInOrganization(context.env.DB, {
    organizationId,
    serviceAccountId
  });
  if (!serviceAccount) {
    return context.json(
      {
        error: {
          code: "SERVICE_ACCOUNT_NOT_FOUND",
          message: "Service account does not exist in this organization"
        }
      },
      404
    );
  }

  const keys = await listServiceAccountApiKeys(context.env.DB, serviceAccountId);
  return context.json({
    serviceAccount: {
      id: serviceAccount.id,
      name: serviceAccount.name,
      disabledAt: serviceAccount.disabled_at
    },
    apiKeys: keys.map((key) => ({
      id: key.id,
      name: key.name,
      keyPrefix: key.key_prefix,
      scopes: parseScopesJson(key.scopes_json),
      expiresAt: key.expires_at,
      lastUsedAt: key.last_used_at,
      revokedAt: key.revoked_at,
      createdAt: key.created_at
    }))
  });
});

orgRoutes.post("/:orgId/service-accounts/:serviceAccountId/api-keys", async (context) => {
  const organizationId = context.req.param("orgId");
  const serviceAccountId = context.req.param("serviceAccountId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "service_accounts",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can create service account keys"
        }
      },
      403
    );
  }

  const serviceAccount = await findServiceAccountByIdInOrganization(context.env.DB, {
    organizationId,
    serviceAccountId
  });
  if (!serviceAccount || serviceAccount.disabled_at) {
    return context.json(
      {
        error: {
          code: "SERVICE_ACCOUNT_NOT_FOUND",
          message: "Service account is missing or disabled"
        }
      },
      404
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createServiceAccountApiKeySchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const secret = `pjk_${randomToken(40)}`;
  const keyHash = await sha256Hex(secret);
  const keyPrefix = secret.slice(0, 16);
  const scopes = parsed.data.scopes ?? [];
  const expiresAt = parsed.data.expiresInDays
    ? addSecondsToIso(parsed.data.expiresInDays * 24 * 60 * 60)
    : null;
  const apiKeyId = crypto.randomUUID();

  await createApiKey(context.env.DB, {
    id: apiKeyId,
    ownerType: "service_account",
    serviceAccountId,
    name: parsed.data.name,
    keyPrefix,
    keyHash,
    scopesJson: JSON.stringify(scopes),
    expiresAt
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.service_account_api_key_created",
    metadataJson: JSON.stringify({
      organizationId,
      serviceAccountId,
      apiKeyId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.service_account_api_key.created",
    payload: {
      serviceAccountId,
      apiKeyId,
      createdByUserId: currentUserId
    }
  });

  return context.json(
    {
      apiKey: {
        id: apiKeyId,
        name: parsed.data.name,
        keyPrefix,
        scopes,
        expiresAt
      },
      secret
    },
    201
  );
});

orgRoutes.post("/:orgId/service-accounts/:serviceAccountId/api-keys/:apiKeyId/revoke", async (context) => {
  const organizationId = context.req.param("orgId");
  const serviceAccountId = context.req.param("serviceAccountId");
  const apiKeyId = context.req.param("apiKeyId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "service_accounts",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can revoke service account keys"
        }
      },
      403
    );
  }

  const serviceAccount = await findServiceAccountByIdInOrganization(context.env.DB, {
    organizationId,
    serviceAccountId
  });
  if (!serviceAccount) {
    return context.json(
      {
        error: {
          code: "SERVICE_ACCOUNT_NOT_FOUND",
          message: "Service account does not exist in this organization"
        }
      },
      404
    );
  }

  const revoked = await revokeServiceAccountApiKey(context.env.DB, {
    serviceAccountId,
    apiKeyId
  });
  if (!revoked) {
    return context.json(
      {
        error: {
          code: "API_KEY_NOT_FOUND",
          message: "API key was not found or already revoked"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.service_account_api_key_revoked",
    metadataJson: JSON.stringify({
      organizationId,
      serviceAccountId,
      apiKeyId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.service_account_api_key.revoked",
    payload: {
      serviceAccountId,
      apiKeyId,
      revokedByUserId: currentUserId
    }
  });

  return context.json({
    ok: true,
    apiKeyId
  });
});

orgRoutes.get("/:orgId/webhooks", async (context) => {
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

  const endpoints = await listWebhookEndpointsForOrganization(context.env.DB, organizationId);
  return context.json({
    organization: formatOrganization(access.organization),
    webhooks: endpoints.map((endpoint) => ({
      id: endpoint.id,
      url: endpoint.url,
      eventTypes: normalizeEventTypes(
        (() => {
          try {
            return endpoint.event_types_json ? (JSON.parse(endpoint.event_types_json) as string[]) : ["*"];
          } catch {
            return ["*"];
          }
        })()
      ),
      isActive: Boolean(endpoint.is_active),
      createdByUserId: endpoint.created_by_user_id,
      lastDeliveryAt: endpoint.last_delivery_at,
      createdAt: endpoint.created_at,
      updatedAt: endpoint.updated_at
    }))
  });
});

orgRoutes.post("/:orgId/webhooks", async (context) => {
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "webhooks",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can manage webhooks"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createWebhookSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const webhookId = crypto.randomUUID();
  const signingSecret = `whsec_${randomToken(40)}`;
  const eventTypes = normalizeEventTypes(parsed.data.eventTypes);
  await createWebhookEndpoint(context.env.DB, {
    id: webhookId,
    organizationId,
    url: parsed.data.url,
    signingSecret,
    eventTypesJson: JSON.stringify(eventTypes),
    createdByUserId: currentUserId
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.webhook_created",
    metadataJson: JSON.stringify({
      organizationId,
      webhookId,
      url: parsed.data.url
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.webhook.created",
    payload: {
      webhookId,
      url: parsed.data.url,
      createdByUserId: currentUserId
    }
  });

  return context.json(
    {
      webhook: {
        id: webhookId,
        url: parsed.data.url,
        eventTypes,
        isActive: true
      },
      signingSecret
    },
    201
  );
});

orgRoutes.patch("/:orgId/webhooks/:webhookId", async (context) => {
  const organizationId = context.req.param("orgId");
  const webhookId = context.req.param("webhookId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "webhooks",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can manage webhooks"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = updateWebhookSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const existing = await findWebhookEndpointByIdInOrganization(context.env.DB, {
    organizationId,
    webhookId
  });
  if (!existing) {
    return context.json(
      {
        error: {
          code: "WEBHOOK_NOT_FOUND",
          message: "Webhook endpoint was not found"
        }
      },
      404
    );
  }

  const nextSecret = parsed.data.rotateSigningSecret ? `whsec_${randomToken(40)}` : undefined;
  const nextEventTypes = parsed.data.eventTypes ? normalizeEventTypes(parsed.data.eventTypes) : undefined;
  const updated = await updateWebhookEndpoint(context.env.DB, {
    organizationId,
    webhookId,
    url: parsed.data.url,
    eventTypesJson: nextEventTypes ? JSON.stringify(nextEventTypes) : undefined,
    signingSecret: nextSecret,
    isActive: parsed.data.isActive
  });
  if (!updated) {
    return context.json(
      {
        error: {
          code: "WEBHOOK_NOT_FOUND",
          message: "Webhook endpoint was not found"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.webhook_updated",
    metadataJson: JSON.stringify({
      organizationId,
      webhookId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.webhook.updated",
    payload: {
      webhookId,
      updatedByUserId: currentUserId
    }
  });

  const reloaded = await findWebhookEndpointByIdInOrganization(context.env.DB, {
    organizationId,
    webhookId
  });
  if (!reloaded) {
    return context.json(
      {
        error: {
          code: "WEBHOOK_NOT_FOUND",
          message: "Webhook endpoint was not found"
        }
      },
      404
    );
  }

  return context.json({
    webhook: {
      id: reloaded.id,
      url: reloaded.url,
      eventTypes: normalizeEventTypes(
        (() => {
          try {
            return reloaded.event_types_json ? (JSON.parse(reloaded.event_types_json) as string[]) : ["*"];
          } catch {
            return ["*"];
          }
        })()
      ),
      isActive: Boolean(reloaded.is_active),
      lastDeliveryAt: reloaded.last_delivery_at,
      updatedAt: reloaded.updated_at
    },
    ...(nextSecret ? { signingSecret: nextSecret } : {})
  });
});

orgRoutes.get("/:orgId/webhooks/:webhookId/deliveries", async (context) => {
  const organizationId = context.req.param("orgId");
  const webhookId = context.req.param("webhookId");
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

  const endpoint = await findWebhookEndpointByIdInOrganization(context.env.DB, {
    organizationId,
    webhookId
  });
  if (!endpoint) {
    return context.json(
      {
        error: {
          code: "WEBHOOK_NOT_FOUND",
          message: "Webhook endpoint was not found"
        }
      },
      404
    );
  }

  const deliveries = await listWebhookDeliveriesForEndpoint(context.env.DB, webhookId, 100);
  return context.json({
    webhook: {
      id: endpoint.id,
      url: endpoint.url
    },
    deliveries: deliveries.map((delivery) => ({
      id: delivery.id,
      eventType: delivery.event_type,
      status: delivery.status,
      statusCode: delivery.status_code,
      attemptCount: delivery.attempt_count,
      nextAttemptAt: delivery.next_attempt_at,
      lastError: delivery.last_error,
      createdAt: delivery.created_at,
      updatedAt: delivery.updated_at
    }))
  });
});

orgRoutes.post("/:orgId/webhooks/:webhookId/test", async (context) => {
  const organizationId = context.req.param("orgId");
  const webhookId = context.req.param("webhookId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "webhooks",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can send webhook tests"
        }
      },
      403
    );
  }

  const endpoint = await findWebhookEndpointByIdInOrganization(context.env.DB, {
    organizationId,
    webhookId
  });
  if (!endpoint) {
    return context.json(
      {
        error: {
          code: "WEBHOOK_NOT_FOUND",
          message: "Webhook endpoint was not found"
        }
      },
      404
    );
  }

  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.webhook.test",
    payload: {
      webhookId,
      triggeredByUserId: currentUserId
    }
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.webhook_test_sent",
    metadataJson: JSON.stringify({
      organizationId,
      webhookId
    })
  });

  return context.json({
    ok: true,
    webhookId
  });
});

orgRoutes.get("/:orgId/policies", async (context) => {
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

  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "policies",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "You do not have permission to view organization policies"
        }
      },
      403
    );
  }

  const policies = await listOrganizationPolicies(context.env.DB, organizationId);
  return context.json({
    organization: formatOrganization(access.organization),
    policies: policies.map((policy) => formatPolicy(policy))
  });
});

orgRoutes.post("/:orgId/policies", async (context) => {
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

  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "policies",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "You do not have permission to manage organization policies"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createPolicySchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  if (
    parsed.data.subjectType === "role" &&
    !["owner", "admin", "member"].includes(parsed.data.subjectId.toLowerCase())
  ) {
    return context.json(
      {
        error: {
          code: "INVALID_ROLE_SUBJECT",
          message: "Role subjectId must be one of owner/admin/member"
        }
      },
      400
    );
  }

  const normalizedSubjectId =
    parsed.data.subjectType === "role" ? parsed.data.subjectId.toLowerCase() : parsed.data.subjectId;
  const normalizedResource = parsed.data.resource.toLowerCase();
  const normalizedAction = parsed.data.action.toLowerCase();

  await upsertOrganizationPolicy(context.env.DB, {
    id: crypto.randomUUID(),
    organizationId,
    subjectType: parsed.data.subjectType,
    subjectId: normalizedSubjectId,
    resource: normalizedResource,
    action: normalizedAction,
    effect: parsed.data.effect,
    conditionJson: parsed.data.condition ? JSON.stringify(parsed.data.condition) : null,
    createdByUserId: currentUserId
  });

  const updatedPolicies = await listOrganizationPolicies(context.env.DB, organizationId);
  const policy =
    updatedPolicies.find(
      (item) =>
        item.subject_type === parsed.data.subjectType &&
        item.subject_id === normalizedSubjectId &&
        item.resource === normalizedResource &&
        item.action === normalizedAction
    ) ?? null;
  if (!policy) {
    return context.json(
      {
        error: {
          code: "POLICY_WRITE_FAILED",
          message: "Policy write completed but policy cannot be loaded"
        }
      },
      500
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.policy_upserted",
    metadataJson: JSON.stringify({
      organizationId,
      policyId: policy.id,
      subjectType: policy.subject_type,
      subjectId: policy.subject_id,
      resource: policy.resource,
      action: policy.action,
      effect: policy.effect
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.policy.upserted",
    payload: {
      policyId: policy.id,
      subjectType: policy.subject_type,
      subjectId: policy.subject_id,
      resource: policy.resource,
      action: policy.action,
      effect: policy.effect,
      changedByUserId: currentUserId
    }
  });

  return context.json(
    {
      policy: formatPolicy(policy)
    },
    201
  );
});

orgRoutes.delete("/:orgId/policies/:policyId", async (context) => {
  const organizationId = context.req.param("orgId");
  const policyId = context.req.param("policyId");
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

  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "policies",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "You do not have permission to manage organization policies"
        }
      },
      403
    );
  }

  const removed = await removeOrganizationPolicy(context.env.DB, {
    organizationId,
    policyId
  });
  if (!removed) {
    return context.json(
      {
        error: {
          code: "POLICY_NOT_FOUND",
          message: "Policy was not found"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.policy_removed",
    metadataJson: JSON.stringify({
      organizationId,
      policyId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.policy.removed",
    payload: {
      policyId,
      removedByUserId: currentUserId
    }
  });

  return context.json({
    ok: true,
    policyId
  });
});

orgRoutes.get("/:orgId/teams", async (context) => {
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

  const teams = await listTeamsForUserInOrganization(context.env.DB, {
    organizationId,
    userId: context.get("authUserId")
  });
  return context.json({
    organization: formatOrganization(access.organization),
    teams: teams.map((team) => ({
      id: team.id,
      slug: team.slug,
      name: team.name,
      myRole: team.my_role,
      createdAt: team.created_at,
      updatedAt: team.updated_at
    }))
  });
});

orgRoutes.post("/:orgId/teams", async (context) => {
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "teams",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can create teams"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = createTeamSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const desiredSlug = parsed.data.slug?.toLowerCase() || slugify(parsed.data.name, "team");
  const slug = await findAvailableTeamSlug(context.env.DB, organizationId, desiredSlug);
  const teamId = crypto.randomUUID();
  const creatorUserId = context.get("authUserId");

  await createTeam(context.env.DB, {
    id: teamId,
    organizationId,
    slug,
    name: parsed.data.name.trim()
  });
  await upsertTeamMembership(context.env.DB, {
    teamId,
    userId: creatorUserId,
    role: "maintainer"
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: creatorUserId,
    eventType: "org.team_created",
    metadataJson: JSON.stringify({
      organizationId,
      teamId,
      slug
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.team.created",
    payload: {
      teamId,
      slug,
      createdByUserId: creatorUserId
    }
  });

  const team = await findTeamByIdInOrganization(context.env.DB, { organizationId, teamId });
  if (!team) {
    return context.json(
      {
        error: {
          code: "TEAM_CREATION_FAILED",
          message: "Team was created but cannot be loaded"
        }
      },
      500
    );
  }

  return context.json(
    {
      team: {
        id: team.id,
        slug: team.slug,
        name: team.name,
        createdAt: team.created_at,
        updatedAt: team.updated_at
      }
    },
    201
  );
});

orgRoutes.get("/:orgId/teams/:teamId/members", async (context) => {
  const organizationId = context.req.param("orgId");
  const teamId = context.req.param("teamId");
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

  const team = await findTeamByIdInOrganization(context.env.DB, { organizationId, teamId });
  if (!team) {
    return context.json(
      {
        error: {
          code: "TEAM_NOT_FOUND",
          message: "Team does not exist in this organization"
        }
      },
      404
    );
  }

  const members = await listTeamMembers(context.env.DB, teamId);
  return context.json({
    team: {
      id: team.id,
      slug: team.slug,
      name: team.name,
      createdAt: team.created_at,
      updatedAt: team.updated_at
    },
    members: members.map((member) => ({
      user: publicUser({
        id: member.user_id,
        email: member.email,
        full_name: member.full_name,
        image_url: member.image_url,
        email_verified: member.email_verified,
        created_at: member.user_created_at,
        updated_at: member.user_updated_at,
        password_hash: null,
        password_salt: null
      }),
      role: member.role,
      joinedAt: member.created_at
    }))
  });
});

orgRoutes.post("/:orgId/teams/:teamId/members", async (context) => {
  const organizationId = context.req.param("orgId");
  const teamId = context.req.param("teamId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "teams",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can manage team members"
        }
      },
      403
    );
  }

  const team = await findTeamByIdInOrganization(context.env.DB, { organizationId, teamId });
  if (!team) {
    return context.json(
      {
        error: {
          code: "TEAM_NOT_FOUND",
          message: "Team does not exist in this organization"
        }
      },
      404
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = upsertTeamMemberSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const user = await findUserByEmail(context.env.DB, parsed.data.email);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "User does not exist. User must sign up before being added."
        }
      },
      404
    );
  }

  const orgMembership = await findOrganizationMembership(context.env.DB, organizationId, user.id);
  if (!orgMembership) {
    return context.json(
      {
        error: {
          code: "ORGANIZATION_MEMBERSHIP_REQUIRED",
          message: "User must be an organization member before joining a team"
        }
      },
      409
    );
  }

  const role = parsed.data.role ?? "member";
  await upsertTeamMembership(context.env.DB, {
    teamId,
    userId: user.id,
    role
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.team_member_upserted",
    metadataJson: JSON.stringify({
      organizationId,
      teamId,
      userId: user.id,
      role
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.team_member.upserted",
    payload: {
      teamId,
      userId: user.id,
      role,
      changedByUserId: currentUserId
    }
  });

  const membership = await findTeamMembership(context.env.DB, { teamId, userId: user.id });
  if (!membership) {
    return context.json(
      {
        error: {
          code: "TEAM_MEMBERSHIP_WRITE_FAILED",
          message: "Team membership write completed but cannot be loaded"
        }
      },
      500
    );
  }

  return context.json({
    user: publicUser(user),
    membership: {
      role: membership.role,
      joinedAt: membership.created_at
    }
  });
});

orgRoutes.patch("/:orgId/teams/:teamId/members/:userId", async (context) => {
  const organizationId = context.req.param("orgId");
  const teamId = context.req.param("teamId");
  const targetUserId = context.req.param("userId");
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
  if (
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "teams",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can update team member roles"
        }
      },
      403
    );
  }

  const team = await findTeamByIdInOrganization(context.env.DB, { organizationId, teamId });
  if (!team) {
    return context.json(
      {
        error: {
          code: "TEAM_NOT_FOUND",
          message: "Team does not exist in this organization"
        }
      },
      404
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = updateTeamMemberRoleSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const membership = await findTeamMembership(context.env.DB, { teamId, userId: targetUserId });
  if (!membership) {
    return context.json(
      {
        error: {
          code: "TEAM_MEMBERSHIP_NOT_FOUND",
          message: "Target user is not a member of this team"
        }
      },
      404
    );
  }

  await upsertTeamMembership(context.env.DB, {
    teamId,
    userId: targetUserId,
    role: parsed.data.role
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.team_member_role_updated",
    metadataJson: JSON.stringify({
      organizationId,
      teamId,
      userId: targetUserId,
      role: parsed.data.role
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.team_member.role_updated",
    payload: {
      teamId,
      userId: targetUserId,
      role: parsed.data.role,
      changedByUserId: currentUserId
    }
  });

  return context.json({
    ok: true,
    userId: targetUserId,
    role: parsed.data.role
  });
});

orgRoutes.delete("/:orgId/teams/:teamId/members/:userId", async (context) => {
  const organizationId = context.req.param("orgId");
  const teamId = context.req.param("teamId");
  const targetUserId = context.req.param("userId");
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

  const team = await findTeamByIdInOrganization(context.env.DB, { organizationId, teamId });
  if (!team) {
    return context.json(
      {
        error: {
          code: "TEAM_NOT_FOUND",
          message: "Team does not exist in this organization"
        }
      },
      404
    );
  }

  const isSelf = targetUserId === currentUserId;
  if (
    !isSelf &&
    !(await hasOrganizationPermission({
      db: context.env.DB,
      organizationId,
      membership: access.membership,
      resource: "teams",
      action: "manage"
    }))
  ) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only organization owners/admins can remove other team members"
        }
      },
      403
    );
  }

  const removed = await removeTeamMembership(context.env.DB, {
    teamId,
    userId: targetUserId
  });
  if (!removed) {
    return context.json(
      {
        error: {
          code: "TEAM_MEMBERSHIP_NOT_FOUND",
          message: "Target user is not a member of this team"
        }
      },
      404
    );
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "org.team_member_removed",
    metadataJson: JSON.stringify({
      organizationId,
      teamId,
      userId: targetUserId
    })
  });
  await emitOrgWebhookSafely({
    env: context.env,
    organizationId,
    eventType: "org.team_member.removed",
    payload: {
      teamId,
      userId: targetUserId,
      removedByUserId: currentUserId
    }
  });

  return context.json({
    ok: true,
    userId: targetUserId
  });
});
