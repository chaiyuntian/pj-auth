import { createMiddleware } from "hono/factory";
import type { EnvBindings } from "../types";
import { parseBearerToken } from "../lib/auth";
import { sha256Hex } from "../lib/crypto";
import { findActiveApiKeyByHash, findServiceAccountById, touchApiKeyUsage } from "../lib/db";

const readApiKeyFromRequest = (request: Request): string | null => {
  const headerKey = request.headers.get("x-api-key")?.trim();
  if (headerKey) {
    return headerKey;
  }
  const bearer = parseBearerToken(request);
  if (bearer && bearer.startsWith("pjk_")) {
    return bearer;
  }
  return null;
};

const parseScopes = (rawScopes: string | null): string[] => {
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

export const requireApiKey = createMiddleware<{
  Bindings: EnvBindings;
  Variables: {
    apiKeyId: string;
    apiPrincipalType: "user" | "service_account";
    apiPrincipalId: string;
    apiScopes: string[];
    apiServiceAccountId: string | null;
    apiOrganizationId: string | null;
  };
}>(async (context, next) => {
  const apiKey = readApiKeyFromRequest(context.req.raw);
  if (!apiKey) {
    return context.json(
      {
        error: {
          code: "UNAUTHORIZED",
          message: "API key is required via x-api-key or Bearer token"
        }
      },
      401
    );
  }

  const keyHash = await sha256Hex(apiKey);
  const keyRow = await findActiveApiKeyByHash(context.env.DB, keyHash);
  if (!keyRow) {
    return context.json(
      {
        error: {
          code: "INVALID_API_KEY",
          message: "API key is invalid, revoked, or expired"
        }
      },
      401
    );
  }

  const scopes = parseScopes(keyRow.scopes_json);
  context.set("apiKeyId", keyRow.id);
  context.set("apiScopes", scopes);

  if (keyRow.owner_type === "user" && keyRow.owner_user_id) {
    context.set("apiPrincipalType", "user");
    context.set("apiPrincipalId", keyRow.owner_user_id);
    context.set("apiServiceAccountId", null);
    context.set("apiOrganizationId", null);
    await touchApiKeyUsage(context.env.DB, keyRow.id);
    await next();
    return;
  }

  if (keyRow.owner_type === "service_account" && keyRow.service_account_id) {
    const serviceAccount = await findServiceAccountById(context.env.DB, keyRow.service_account_id);
    if (!serviceAccount || serviceAccount.disabled_at) {
      return context.json(
        {
          error: {
            code: "INVALID_API_KEY",
            message: "Service account is disabled or missing"
          }
        },
        401
      );
    }
    context.set("apiPrincipalType", "service_account");
    context.set("apiPrincipalId", serviceAccount.id);
    context.set("apiServiceAccountId", serviceAccount.id);
    context.set("apiOrganizationId", serviceAccount.organization_id);
    await touchApiKeyUsage(context.env.DB, keyRow.id);
    await next();
    return;
  }

  return context.json(
    {
      error: {
        code: "INVALID_API_KEY",
        message: "API key owner is invalid"
      }
    },
    401
  );
});
