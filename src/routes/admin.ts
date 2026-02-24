import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { getGoogleProviderConfig, upsertGoogleProvider, writeAuditLog } from "../lib/db";
import { requireAdminApiKey } from "../middleware/require-admin";
import { readJsonBody } from "../lib/request";
import { getCorsOrigins, getEmailFromAddress } from "../lib/config";

const updateGoogleProviderSchema = z.object({
  enabled: z.boolean().optional(),
  clientId: z.string().min(3).max(300).optional(),
  clientSecret: z.string().min(8).max(600).optional(),
  redirectUri: z.string().url().max(500).optional(),
  scope: z.string().min(3).max(600).optional()
});

export const adminRoutes = new Hono<{ Bindings: EnvBindings }>();
adminRoutes.use("/*", requireAdminApiKey);

adminRoutes.get("/oauth/providers/google", async (context) => {
  const config = await getGoogleProviderConfig(context.env.DB, context.env);
  return context.json({
    provider: "google",
    enabled: config.enabled,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scope: config.scope,
    hasClientSecret: Boolean(config.clientSecret)
  });
});

adminRoutes.put("/oauth/providers/google", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = updateGoogleProviderSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(
      {
        error: {
          code: "INVALID_REQUEST",
          message: "Body validation failed",
          issues: parsed.error.issues
        }
      },
      400
    );
  }

  const current = await getGoogleProviderConfig(context.env.DB, context.env);
  const next = {
    enabled: parsed.data.enabled ?? current.enabled,
    clientId: parsed.data.clientId ?? current.clientId,
    clientSecret: parsed.data.clientSecret ?? current.clientSecret,
    redirectUri: parsed.data.redirectUri ?? current.redirectUri,
    scope: parsed.data.scope ?? current.scope
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

  await upsertGoogleProvider(context.env.DB, next);
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "admin",
    eventType: "admin.google_provider_updated",
    metadataJson: JSON.stringify({
      enabled: next.enabled,
      redirectUri: next.redirectUri,
      scope: next.scope
    })
  });

  return context.json({
    provider: "google",
    enabled: next.enabled,
    clientId: next.clientId,
    redirectUri: next.redirectUri,
    scope: next.scope,
    hasClientSecret: true
  });
});

adminRoutes.get("/stats", async (context) => {
  const users = await context.env.DB.prepare("SELECT COUNT(*) as count FROM users").first<{ count: number }>();
  const sessions = await context.env.DB.prepare("SELECT COUNT(*) as count FROM sessions WHERE revoked_at IS NULL").first<{
    count: number;
  }>();
  return context.json({
    users: users?.count ?? 0,
    activeSessions: sessions?.count ?? 0
  });
});

adminRoutes.get("/system/status", async (context) => {
  const google = await getGoogleProviderConfig(context.env.DB, context.env);
  const dbCheck = await context.env.DB.prepare("SELECT 1 as ok").first<{ ok: number }>().catch(() => null);

  return context.json({
    db: {
      healthy: dbCheck?.ok === 1
    },
    cors: {
      origins: getCorsOrigins(context.env)
    },
    oauth: {
      google: {
        enabled: google.enabled,
        hasClientId: Boolean(google.clientId),
        hasClientSecret: Boolean(google.clientSecret),
        hasRedirectUri: Boolean(google.redirectUri)
      }
    },
    email: {
      provider: context.env.RESEND_API_KEY ? "resend" : "log_only",
      hasApiKey: Boolean(context.env.RESEND_API_KEY),
      fromAddress: getEmailFromAddress(context.env),
      configured: Boolean(context.env.RESEND_API_KEY && getEmailFromAddress(context.env))
    }
  });
});
