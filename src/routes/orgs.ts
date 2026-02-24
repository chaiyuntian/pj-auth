import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { requireAuth } from "../middleware/require-auth";
import {
  countOrganizationMembers,
  countOrganizationOwners,
  countOrganizationTeams,
  createOrganizationWithOwner,
  createTeam,
  findOrganizationById,
  findOrganizationBySlug,
  findOrganizationMembership,
  findTeamByIdInOrganization,
  findTeamBySlugInOrganization,
  findTeamMembership,
  findUserByEmail,
  listOrganizationMembers,
  listOrganizationsForUser,
  listTeamMembers,
  listTeamsForUserInOrganization,
  removeOrganizationMembership,
  removeTeamMembership,
  type OrganizationMembershipRow,
  type OrganizationRole,
  type OrganizationRow,
  type TeamRole,
  upsertOrganizationMembership,
  upsertTeamMembership,
  writeAuditLog
} from "../lib/db";
import { readJsonBody } from "../lib/request";
import { publicUser } from "../lib/http";

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

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

const canManageOrganization = (role: OrganizationRole): boolean => role === "owner" || role === "admin";
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
  if (!canManageOrganization(access.membership.role)) {
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
  if (!canManageOrganization(access.membership.role)) {
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
  if (!isSelf && !canManageOrganization(access.membership.role)) {
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

  return context.json({
    ok: true,
    userId: targetUserId
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
  if (!canManageOrganization(access.membership.role)) {
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
  if (!canManageOrganization(access.membership.role)) {
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
  if (!canManageOrganization(access.membership.role)) {
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
  if (!isSelf && !canManageOrganization(access.membership.role)) {
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

  return context.json({
    ok: true,
    userId: targetUserId
  });
});
