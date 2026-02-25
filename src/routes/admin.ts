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

type SamlSignatureAuditRow = {
  metadata_json: string | null;
  created_at: string;
};

type ParsedSamlSignatureAudit = {
  mode: string | null;
  attempted: boolean | null;
  verified: boolean | null;
  reason: string | null;
  signatureAlgorithm: string | null;
  canonicalizationAlgorithm: string | null;
  referenceCount: number | null;
  referenceDigestsValid: boolean | null;
  referenceValidationReason: string | null;
};

const parseSamlSignatureAudit = (metadataJson: string | null): ParsedSamlSignatureAudit | null => {
  if (!metadataJson) {
    return null;
  }
  try {
    const metadata = JSON.parse(metadataJson) as {
      xmlSignature?: {
        mode?: unknown;
        attempted?: unknown;
        verified?: unknown;
        reason?: unknown;
        signatureAlgorithm?: unknown;
        canonicalizationAlgorithm?: unknown;
        referenceCount?: unknown;
        referenceDigestsValid?: unknown;
        referenceValidationReason?: unknown;
      };
    };
    const xmlSignature = metadata?.xmlSignature;
    if (!xmlSignature || typeof xmlSignature !== "object") {
      return null;
    }
    return {
      mode: typeof xmlSignature.mode === "string" ? xmlSignature.mode : null,
      attempted: typeof xmlSignature.attempted === "boolean" ? xmlSignature.attempted : null,
      verified: typeof xmlSignature.verified === "boolean" ? xmlSignature.verified : null,
      reason: typeof xmlSignature.reason === "string" ? xmlSignature.reason : null,
      signatureAlgorithm:
        typeof xmlSignature.signatureAlgorithm === "string" ? xmlSignature.signatureAlgorithm : null,
      canonicalizationAlgorithm:
        typeof xmlSignature.canonicalizationAlgorithm === "string"
          ? xmlSignature.canonicalizationAlgorithm
          : null,
      referenceCount: typeof xmlSignature.referenceCount === "number" ? xmlSignature.referenceCount : null,
      referenceDigestsValid:
        typeof xmlSignature.referenceDigestsValid === "boolean" ? xmlSignature.referenceDigestsValid : null,
      referenceValidationReason:
        typeof xmlSignature.referenceValidationReason === "string"
          ? xmlSignature.referenceValidationReason
          : null
    };
  } catch {
    return null;
  }
};

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
    },
    saml: {
      xmlSignatureMode: (() => {
        const mode = context.env.SAML_XMLSIG_MODE?.trim().toLowerCase();
        if (mode === "off" || mode === "optional" || mode === "required") {
          return mode;
        }
        return "optional";
      })()
    }
  });
});

adminRoutes.get("/saml/signature-health", async (context) => {
  const windowHoursRaw = Number.parseInt(context.req.query("hours") ?? "24", 10);
  const windowHours = Number.isFinite(windowHoursRaw) ? Math.max(1, Math.min(windowHoursRaw, 24 * 30)) : 24;
  const limitRaw = Number.parseInt(context.req.query("limit") ?? "2000", 10);
  const limit = Number.isFinite(limitRaw) ? Math.max(100, Math.min(limitRaw, 10000)) : 2000;
  const sinceIso = new Date(Date.now() - windowHours * 60 * 60 * 1000).toISOString();

  const rows = await context.env.DB
    .prepare(
      `SELECT metadata_json, created_at
       FROM audit_logs
       WHERE event_type = 'auth.sign_in_saml'
         AND datetime(created_at) >= datetime(?)
       ORDER BY datetime(created_at) DESC
       LIMIT ?`
    )
    .bind(sinceIso, limit)
    .all<SamlSignatureAuditRow>();

  const items = rows.results ?? [];
  const modeCounts: Record<string, number> = {};
  const failureReasons: Record<string, number> = {};
  let withSignatureMetadata = 0;
  let verifiedCount = 0;
  let failedCount = 0;
  let referenceFailureCount = 0;
  let missingSignatureMetadata = 0;
  const samples: Array<{
    createdAt: string;
    mode: string | null;
    verified: boolean | null;
    reason: string | null;
    referenceDigestsValid: boolean | null;
    referenceValidationReason: string | null;
  }> = [];

  for (const item of items) {
    const parsed = parseSamlSignatureAudit(item.metadata_json);
    if (!parsed) {
      missingSignatureMetadata += 1;
      if (samples.length < 25) {
        samples.push({
          createdAt: item.created_at,
          mode: null,
          verified: null,
          reason: null,
          referenceDigestsValid: null,
          referenceValidationReason: null
        });
      }
      continue;
    }

    withSignatureMetadata += 1;
    const mode = parsed.mode ?? "unknown";
    modeCounts[mode] = (modeCounts[mode] ?? 0) + 1;
    if (parsed.verified) {
      verifiedCount += 1;
    } else {
      failedCount += 1;
      const reason = parsed.reason || "unknown";
      failureReasons[reason] = (failureReasons[reason] ?? 0) + 1;
      if (parsed.referenceDigestsValid === false || parsed.referenceValidationReason) {
        referenceFailureCount += 1;
      }
    }

    if (samples.length < 25) {
      samples.push({
        createdAt: item.created_at,
        mode: parsed.mode,
        verified: parsed.verified,
        reason: parsed.reason,
        referenceDigestsValid: parsed.referenceDigestsValid,
        referenceValidationReason: parsed.referenceValidationReason
      });
    }
  }

  const totalEvents = items.length;
  const canEnableRequired = totalEvents > 0 && failedCount === 0 && missingSignatureMetadata === 0;

  return context.json({
    windowHours,
    since: sinceIso,
    totalEvents,
    withSignatureMetadata,
    missingSignatureMetadata,
    verifiedCount,
    failedCount,
    referenceFailureCount,
    verificationRate: totalEvents > 0 ? Number((verifiedCount / totalEvents).toFixed(4)) : 0,
    modeCounts,
    failureReasons,
    recommendation: {
      canEnableRequired,
      message: canEnableRequired
        ? "No signature verification failures detected in selected window; SAML_XMLSIG_MODE=required is likely safe."
        : "Failures or missing signature metadata detected; keep optional mode and investigate failureReasons."
    },
    samples
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
