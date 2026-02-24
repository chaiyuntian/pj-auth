import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { requireScimToken } from "../middleware/require-scim";
import {
  createUser,
  findOrganizationById,
  findOrganizationMembership,
  findUserByEmail,
  findUserById,
  listOrganizationMembers,
  removeOrganizationMembership,
  upsertOrganizationMembership,
  updateUserProfile,
  writeAuditLog
} from "../lib/db";
import { readJsonBody } from "../lib/request";

const scimUserCreateSchema = z.object({
  userName: z.string().email().min(3).max(320),
  active: z.boolean().optional(),
  displayName: z.string().min(1).max(200).optional(),
  name: z
    .object({
      formatted: z.string().min(1).max(200).optional()
    })
    .optional(),
  emails: z
    .array(
      z.object({
        value: z.string().email().min(3).max(320),
        primary: z.boolean().optional()
      })
    )
    .optional()
});

const scimPatchSchema = z.object({
  Operations: z
    .array(
      z.object({
        op: z.string().min(1),
        path: z.string().optional(),
        value: z.unknown().optional()
      })
    )
    .min(1)
});

const listResponse = (resources: unknown[], startIndex = 1, totalResults = resources.length) => ({
  schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  totalResults,
  startIndex,
  itemsPerPage: resources.length,
  Resources: resources
});

const parseScimFilterUserName = (raw: string | undefined): string | null => {
  if (!raw) {
    return null;
  }
  const match = raw.match(/^\s*userName\s+eq\s+"([^"]+)"\s*$/i);
  if (!match) {
    return null;
  }
  return match[1]?.trim().toLowerCase() ?? null;
};

const extractEmailFromCreatePayload = (payload: z.infer<typeof scimUserCreateSchema>): string => {
  const primaryEmail = payload.emails?.find((entry) => entry.primary)?.value;
  const firstEmail = payload.emails?.[0]?.value;
  return (payload.userName || primaryEmail || firstEmail || "").trim().toLowerCase();
};

const displayNameFromCreatePayload = (payload: z.infer<typeof scimUserCreateSchema>): string | null =>
  payload.displayName?.trim() || payload.name?.formatted?.trim() || null;

const toScimUser = (params: {
  user: {
    id: string;
    email: string;
    full_name: string | null;
    created_at: string;
    updated_at: string;
  };
  active: boolean;
}) => ({
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  id: params.user.id,
  userName: params.user.email,
  displayName: params.user.full_name,
  active: params.active,
  name: params.user.full_name ? { formatted: params.user.full_name } : undefined,
  emails: [{ value: params.user.email, primary: true }],
  meta: {
    resourceType: "User",
    created: params.user.created_at,
    lastModified: params.user.updated_at
  }
});

const applyScimPatch = (params: {
  operations: z.infer<typeof scimPatchSchema>["Operations"];
  currentDisplayName: string | null;
  currentlyActive: boolean;
}): { nextDisplayName: string | null; nextActive: boolean } => {
  let nextDisplayName = params.currentDisplayName;
  let nextActive = params.currentlyActive;

  for (const operation of params.operations) {
    const op = operation.op.trim().toLowerCase();
    const path = operation.path?.trim().toLowerCase() ?? "";
    const value = operation.value;
    if (!["add", "replace", "remove"].includes(op)) {
      continue;
    }

    if (path === "active" || (!path && typeof value === "object" && value !== null && "active" in value)) {
      const activeValue =
        typeof value === "boolean"
          ? value
          : typeof value === "object" && value !== null && "active" in value
            ? Boolean((value as Record<string, unknown>).active)
            : null;
      if (activeValue !== null) {
        nextActive = activeValue;
      }
    }

    if (path === "displayname" || path === "name.formatted" || (!path && typeof value === "string")) {
      if (typeof value === "string") {
        nextDisplayName = value.trim() || null;
      } else if (op === "remove") {
        nextDisplayName = null;
      }
    }
  }

  return {
    nextDisplayName,
    nextActive
  };
};

export const scimRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    scimTokenId: string;
    scimOrganizationId: string;
  };
}>();

scimRoutes.use("/*", requireScimToken);

scimRoutes.get("/v2/ServiceProviderConfig", (context) =>
  context.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        name: "OAuth Bearer Token",
        description: "Authentication Scheme using the Bearer Token Standard",
        type: "oauthbearertoken",
        primary: true
      }
    ]
  })
);

scimRoutes.get("/v2/Users", async (context) => {
  const organizationId = context.get("scimOrganizationId");
  const organization = await findOrganizationById(context.env.DB, organizationId);
  if (!organization) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "Organization for SCIM token was not found",
        status: "404"
      },
      404
    );
  }

  const filterEmail = parseScimFilterUserName(context.req.query("filter"));
  const members = await listOrganizationMembers(context.env.DB, organizationId);
  const filtered = filterEmail
    ? members.filter((member) => member.email.toLowerCase() === filterEmail)
    : members;
  return context.json(
    listResponse(
      filtered.map((member) =>
        toScimUser({
          user: {
            id: member.user_id,
            email: member.email,
            full_name: member.full_name,
            created_at: member.user_created_at,
            updated_at: member.user_updated_at
          },
          active: true
        })
      )
    )
  );
});

scimRoutes.post("/v2/Users", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = scimUserCreateSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "Request body validation failed",
        status: "400",
        errors: parsed.error.issues
      },
      400
    );
  }

  const organizationId = context.get("scimOrganizationId");
  const email = extractEmailFromCreatePayload(parsed.data);
  const displayName = displayNameFromCreatePayload(parsed.data);
  let user = await findUserByEmail(context.env.DB, email);
  if (!user) {
    const userId = crypto.randomUUID();
    await createUser(context.env.DB, {
      id: userId,
      email,
      fullName: displayName,
      emailVerified: true
    });
    user = await findUserById(context.env.DB, userId);
  } else if (displayName && user.full_name !== displayName) {
    await updateUserProfile(context.env.DB, {
      userId: user.id,
      fullName: displayName
    });
    user = await findUserById(context.env.DB, user.id);
  }

  if (!user) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User provisioning failed",
        status: "500"
      },
      500
    );
  }

  const active = parsed.data.active ?? true;
  if (active) {
    await upsertOrganizationMembership(context.env.DB, {
      organizationId,
      userId: user.id,
      role: "member"
    });
  } else {
    await removeOrganizationMembership(context.env.DB, {
      organizationId,
      userId: user.id
    });
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "scim",
    actorId: context.get("scimTokenId"),
    eventType: "scim.user_upserted",
    metadataJson: JSON.stringify({
      organizationId,
      userId: user.id,
      email,
      active
    })
  });

  const refreshedUser = await findUserById(context.env.DB, user.id);
  if (!refreshedUser) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User provisioning failed",
        status: "500"
      },
      500
    );
  }
  return context.json(
    toScimUser({
      user: refreshedUser,
      active
    }),
    201
  );
});

scimRoutes.get("/v2/Users/:userId", async (context) => {
  const organizationId = context.get("scimOrganizationId");
  const userId = context.req.param("userId");
  const user = await findUserById(context.env.DB, userId);
  if (!user) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User not found",
        status: "404"
      },
      404
    );
  }
  const membership = await findOrganizationMembership(context.env.DB, organizationId, userId);
  if (!membership) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User is not in this organization",
        status: "404"
      },
      404
    );
  }
  return context.json(
    toScimUser({
      user,
      active: true
    })
  );
});

scimRoutes.patch("/v2/Users/:userId", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = scimPatchSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "Request body validation failed",
        status: "400",
        errors: parsed.error.issues
      },
      400
    );
  }

  const organizationId = context.get("scimOrganizationId");
  const userId = context.req.param("userId");
  const user = await findUserById(context.env.DB, userId);
  if (!user) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User not found",
        status: "404"
      },
      404
    );
  }
  const currentMembership = await findOrganizationMembership(context.env.DB, organizationId, userId);
  const patch = applyScimPatch({
    operations: parsed.data.Operations,
    currentDisplayName: user.full_name,
    currentlyActive: Boolean(currentMembership)
  });

  await updateUserProfile(context.env.DB, {
    userId,
    fullName: patch.nextDisplayName
  });
  if (patch.nextActive) {
    await upsertOrganizationMembership(context.env.DB, {
      organizationId,
      userId,
      role: currentMembership?.role ?? "member"
    });
  } else if (currentMembership) {
    await removeOrganizationMembership(context.env.DB, {
      organizationId,
      userId
    });
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "scim",
    actorId: context.get("scimTokenId"),
    eventType: "scim.user_patched",
    metadataJson: JSON.stringify({
      organizationId,
      userId,
      active: patch.nextActive
    })
  });

  const updatedUser = await findUserById(context.env.DB, userId);
  if (!updatedUser) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User update failed",
        status: "500"
      },
      500
    );
  }
  return context.json(
    toScimUser({
      user: updatedUser,
      active: patch.nextActive
    })
  );
});

scimRoutes.delete("/v2/Users/:userId", async (context) => {
  const organizationId = context.get("scimOrganizationId");
  const userId = context.req.param("userId");
  await removeOrganizationMembership(context.env.DB, {
    organizationId,
    userId
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "scim",
    actorId: context.get("scimTokenId"),
    eventType: "scim.user_deleted",
    metadataJson: JSON.stringify({
      organizationId,
      userId
    })
  });
  return context.body(null, 204);
});
