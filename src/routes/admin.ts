import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { getGoogleProviderConfig, listAuditLogs, upsertGoogleProvider, writeAuditLog } from "../lib/db";
import { requireAdminApiKey } from "../middleware/require-admin";
import { readJsonBody } from "../lib/request";
import { getCorsOrigins, getEmailFromAddress, getTurnstileSettings } from "../lib/config";
import { retryDueWebhookDeliveries } from "../lib/webhooks";

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
  const organizations = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM organizations")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const teams = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM teams")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const projects = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM projects")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const passkeys = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM passkey_credentials WHERE revoked_at IS NULL")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const mfaTotp = await context.env.DB
    .prepare(
      "SELECT COUNT(*) as count FROM mfa_totp_factors WHERE verified_at IS NOT NULL AND disabled_at IS NULL"
    )
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const samlConnections = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM saml_connections WHERE is_active = 1")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const domainRoutes = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM domain_routes")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const retentionPolicies = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM retention_policies")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const exportJobs = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM export_jobs")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  const kmsKeys = await context.env.DB
    .prepare("SELECT COUNT(*) as count FROM organization_kms_keys WHERE is_active = 1")
    .first<{ count: number }>()
    .catch(() => ({ count: 0 }));
  return context.json({
    users: users?.count ?? 0,
    activeSessions: sessions?.count ?? 0,
    organizations: organizations?.count ?? 0,
    teams: teams?.count ?? 0,
    projects: projects?.count ?? 0,
    activePasskeys: passkeys?.count ?? 0,
    mfaTotpEnabledUsers: mfaTotp?.count ?? 0,
    activeSamlConnections: samlConnections?.count ?? 0,
    domainRoutes: domainRoutes?.count ?? 0,
    retentionPolicies: retentionPolicies?.count ?? 0,
    exportJobs: exportJobs?.count ?? 0,
    activeKmsKeys: kmsKeys?.count ?? 0
  });
});

adminRoutes.get("/system/status", async (context) => {
  const google = await getGoogleProviderConfig(context.env.DB, context.env);
  const dbCheck = await context.env.DB.prepare("SELECT 1 as ok").first<{ ok: number }>().catch(() => null);
  const turnstile = getTurnstileSettings(context.env);

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
    },
    turnstile: {
      enabled: turnstile.enabled,
      configured: Boolean(turnstile.secretKey)
    }
  });
});

adminRoutes.post("/webhooks/retry", async (context) => {
  const payload = (await readJsonBody<{ limit?: number }>(context.req.raw)) ?? {};
  const limit =
    typeof payload.limit === "number" && Number.isFinite(payload.limit) && payload.limit > 0
      ? Math.min(Math.floor(payload.limit), 200)
      : 50;

  const result = await retryDueWebhookDeliveries({
    env: context.env,
    limit
  });
  return context.json({
    ok: true,
    processed: result.processed
  });
});

adminRoutes.get("/audit-logs", async (context) => {
  const limitRaw = context.req.query("limit");
  const parsedLimit = limitRaw ? Number.parseInt(limitRaw, 10) : Number.NaN;
  const limit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 500) : 100;
  const actorType = context.req.query("actorType")?.trim();
  const eventType = context.req.query("eventType")?.trim();

  const logs = await listAuditLogs(context.env.DB, {
    limit,
    actorType: actorType || undefined,
    eventType: eventType || undefined
  });

  return context.json({
    logs: logs.map((log) => ({
      id: log.id,
      actorType: log.actor_type,
      actorId: log.actor_id,
      eventType: log.event_type,
      metadata: (() => {
        if (!log.metadata_json) {
          return null;
        }
        try {
          return JSON.parse(log.metadata_json);
        } catch {
          return {
            raw: log.metadata_json
          };
        }
      })(),
      createdAt: log.created_at
    }))
  });
});
