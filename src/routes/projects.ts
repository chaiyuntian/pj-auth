import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import {
  createProjectWithOwner,
  findProjectById,
  findProjectBySlug,
  findProjectMembership,
  getProjectGoogleProviderConfig,
  listProjectsForUser,
  upsertProjectGoogleProvider,
  writeAuditLog,
  type ProjectMembershipRow,
  type ProjectRole,
  type ProjectRow
} from "../lib/db";
import { readJsonBody } from "../lib/request";
import { requireAuth } from "../middleware/require-auth";

const createProjectSchema = z.object({
  name: z.string().min(2).max(120),
  slug: z
    .string()
    .min(2)
    .max(64)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    .optional(),
  authDomain: z
    .string()
    .min(3)
    .max(255)
    .regex(/^[a-z0-9.-]+$/),
  branding: z.record(z.string(), z.unknown()).optional()
});

const upsertProjectGoogleProviderSchema = z.object({
  enabled: z.boolean().optional(),
  clientId: z.string().min(3).max(300).optional(),
  clientSecret: z.string().min(8).max(600).optional(),
  redirectUri: z.string().url().max(500).optional(),
  scope: z.string().min(3).max(600).optional()
});

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

const isProjectManager = (role: ProjectRole): boolean => role === "owner" || role === "admin";

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

const findAvailableProjectSlug = async (db: D1Database, desiredSlug: string): Promise<string> => {
  let candidate = desiredSlug;
  let suffix = 2;
  while (await findProjectBySlug(db, candidate)) {
    candidate = `${desiredSlug}-${suffix}`;
    suffix += 1;
  }
  return candidate;
};

const formatProject = (project: ProjectRow) => ({
  id: project.id,
  slug: project.slug,
  name: project.name,
  authDomain: project.auth_domain,
  branding: (() => {
    if (!project.branding_json) {
      return null;
    }
    try {
      return JSON.parse(project.branding_json);
    } catch {
      return null;
    }
  })(),
  createdByUserId: project.created_by_user_id,
  createdAt: project.created_at,
  updatedAt: project.updated_at
});

const loadProjectAccess = async (params: {
  db: D1Database;
  projectId: string;
  userId: string;
}): Promise<{ project: ProjectRow; membership: ProjectMembershipRow } | null> => {
  const project = await findProjectById(params.db, params.projectId);
  if (!project) {
    return null;
  }
  const membership = await findProjectMembership(params.db, {
    projectId: params.projectId,
    userId: params.userId
  });
  if (!membership) {
    return null;
  }
  return {
    project,
    membership
  };
};

export const projectRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

projectRoutes.use("/*", requireAuth);

projectRoutes.get("/", async (context) => {
  const projects = await listProjectsForUser(context.env.DB, context.get("authUserId"));
  return context.json({
    projects: projects.map((project) => ({
      ...formatProject(project),
      membership: {
        role: project.membership_role,
        joinedAt: project.membership_created_at
      }
    }))
  });
});

projectRoutes.post("/", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = createProjectSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const authDomain = parsed.data.authDomain.toLowerCase();
  const desiredSlug = parsed.data.slug?.toLowerCase() || slugify(parsed.data.name, "project");
  const slug = await findAvailableProjectSlug(context.env.DB, desiredSlug);
  const projectId = crypto.randomUUID();
  const ownerUserId = context.get("authUserId");

  await createProjectWithOwner(context.env.DB, {
    id: projectId,
    slug,
    name: parsed.data.name.trim(),
    authDomain,
    brandingJson: parsed.data.branding ? JSON.stringify(parsed.data.branding) : null,
    ownerUserId
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: ownerUserId,
    eventType: "project.created",
    metadataJson: JSON.stringify({
      projectId,
      slug,
      authDomain
    })
  });

  const project = await findProjectById(context.env.DB, projectId);
  const membership = await findProjectMembership(context.env.DB, {
    projectId,
    userId: ownerUserId
  });
  if (!project) {
    return context.json(
      {
        error: {
          code: "PROJECT_CREATION_FAILED",
          message: "Project was created but cannot be loaded"
        }
      },
      500
    );
  }

  return context.json(
    {
      project: formatProject(project),
      membership: {
        role: "owner",
        joinedAt: membership?.created_at ?? project.created_at
      }
    },
    201
  );
});

projectRoutes.get("/:projectId", async (context) => {
  const projectId = context.req.param("projectId");
  const access = await loadProjectAccess({
    db: context.env.DB,
    projectId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "PROJECT_NOT_FOUND_OR_FORBIDDEN",
          message: "Project does not exist or you do not have access"
        }
      },
      404
    );
  }
  return context.json({
    project: formatProject(access.project),
    membership: {
      role: access.membership.role,
      joinedAt: access.membership.created_at
    }
  });
});

projectRoutes.get("/:projectId/oauth/providers/google", async (context) => {
  const projectId = context.req.param("projectId");
  const access = await loadProjectAccess({
    db: context.env.DB,
    projectId,
    userId: context.get("authUserId")
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "PROJECT_NOT_FOUND_OR_FORBIDDEN",
          message: "Project does not exist or you do not have access"
        }
      },
      404
    );
  }

  const provider = await getProjectGoogleProviderConfig(context.env.DB, projectId);
  return context.json({
    project: {
      id: access.project.id,
      slug: access.project.slug,
      authDomain: access.project.auth_domain
    },
    provider: "google",
    enabled: Boolean(provider?.enabled),
    clientId: provider?.client_id ?? "",
    redirectUri: provider?.redirect_uri ?? "",
    scope: provider?.scope ?? "openid email profile",
    hasClientSecret: Boolean(provider?.client_secret)
  });
});

projectRoutes.put("/:projectId/oauth/providers/google", async (context) => {
  const projectId = context.req.param("projectId");
  const currentUserId = context.get("authUserId");
  const access = await loadProjectAccess({
    db: context.env.DB,
    projectId,
    userId: currentUserId
  });
  if (!access) {
    return context.json(
      {
        error: {
          code: "PROJECT_NOT_FOUND_OR_FORBIDDEN",
          message: "Project does not exist or you do not have access"
        }
      },
      404
    );
  }
  if (!isProjectManager(access.membership.role)) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Only project owners/admins can update project OAuth providers"
        }
      },
      403
    );
  }

  const payload = await readJsonBody(context.req.raw);
  const parsed = upsertProjectGoogleProviderSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const current = await getProjectGoogleProviderConfig(context.env.DB, projectId);
  const next = {
    enabled: parsed.data.enabled ?? Boolean(current?.enabled),
    clientId: parsed.data.clientId ?? current?.client_id ?? "",
    clientSecret: parsed.data.clientSecret ?? current?.client_secret ?? "",
    redirectUri: parsed.data.redirectUri ?? current?.redirect_uri ?? "",
    scope: parsed.data.scope ?? current?.scope ?? "openid email profile"
  };
  if (!next.clientId || !next.clientSecret || !next.redirectUri) {
    return context.json(
      {
        error: {
          code: "MISSING_PROVIDER_CONFIG",
          message: "clientId, clientSecret, and redirectUri are required"
        }
      },
      400
    );
  }

  await upsertProjectGoogleProvider(context.env.DB, {
    projectId,
    enabled: next.enabled,
    clientId: next.clientId,
    clientSecret: next.clientSecret,
    redirectUri: next.redirectUri,
    scope: next.scope
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: currentUserId,
    eventType: "project.google_provider_updated",
    metadataJson: JSON.stringify({
      projectId,
      enabled: next.enabled,
      redirectUri: next.redirectUri,
      scope: next.scope
    })
  });

  return context.json({
    project: {
      id: access.project.id,
      slug: access.project.slug,
      authDomain: access.project.auth_domain
    },
    provider: "google",
    enabled: next.enabled,
    clientId: next.clientId,
    redirectUri: next.redirectUri,
    scope: next.scope,
    hasClientSecret: true
  });
});
