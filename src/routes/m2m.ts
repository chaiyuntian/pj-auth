import { Hono } from "hono";
import type { EnvBindings } from "../types";
import { requireApiKey } from "../middleware/require-api-key";
import { findServiceAccountById, findUserById } from "../lib/db";
import { publicUser } from "../lib/http";

export const m2mRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    apiKeyId: string;
    apiPrincipalType: "user" | "service_account";
    apiPrincipalId: string;
    apiScopes: string[];
    apiServiceAccountId: string | null;
    apiOrganizationId: string | null;
  };
}>();

m2mRoutes.use("/*", requireApiKey);

m2mRoutes.get("/me", async (context) => {
  const principalType = context.get("apiPrincipalType");
  const principalId = context.get("apiPrincipalId");
  const scopes = context.get("apiScopes");

  if (principalType === "user") {
    const user = await findUserById(context.env.DB, principalId);
    if (!user) {
      return context.json(
        {
          error: {
            code: "PRINCIPAL_NOT_FOUND",
            message: "User principal no longer exists"
          }
        },
        404
      );
    }
    return context.json({
      principalType,
      apiKeyId: context.get("apiKeyId"),
      scopes,
      user: publicUser(user)
    });
  }

  const serviceAccount = await findServiceAccountById(context.env.DB, principalId);
  if (!serviceAccount || serviceAccount.disabled_at) {
    return context.json(
      {
        error: {
          code: "PRINCIPAL_NOT_FOUND",
          message: "Service account principal no longer exists"
        }
      },
      404
    );
  }
  return context.json({
    principalType,
    apiKeyId: context.get("apiKeyId"),
    scopes,
    serviceAccount: {
      id: serviceAccount.id,
      organizationId: serviceAccount.organization_id,
      name: serviceAccount.name,
      description: serviceAccount.description,
      createdAt: serviceAccount.created_at,
      updatedAt: serviceAccount.updated_at
    }
  });
});
