import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { requireAuth } from "../middleware/require-auth";
import {
  consumeMfaChallengeById,
  consumeRecoveryCodeHash,
  countRemainingRecoveryCodes,
  createTotpFactor,
  disableTotpFactorsForUser,
  findActiveVerifiedTotpFactorForUser,
  findTotpFactorByIdForUser,
  findUserById,
  replaceRecoveryCodes,
  revokeOtherUserSessions,
  touchTotpFactorUsage,
  verifyTotpFactor,
  writeAuditLog
} from "../lib/db";
import { readJsonBody } from "../lib/request";
import { buildTotpOtpauthUri, generateRecoveryCodes, generateTotpSecret, verifyTotpCode } from "../lib/mfa";
import { sha256Hex } from "../lib/crypto";
import { createSessionAndTokens, readRequestIp } from "../lib/auth";
import { setRefreshTokenCookie } from "../lib/cookies";
import { assessAndRecordSessionRisk } from "../lib/session-risk";
import { publicUser } from "../lib/http";

const totpSetupConfirmSchema = z.object({
  factorId: z.string().uuid(),
  code: z.string().min(6).max(12)
});

const totpDisableSchema = z.object({
  method: z.enum(["totp", "recovery_code"]).default("totp"),
  code: z.string().min(6).max(30)
});

const challengeVerifySchema = z.object({
  challengeId: z.string().uuid(),
  method: z.enum(["totp", "recovery_code"]).default("totp"),
  code: z.string().min(6).max(30)
});

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

const hashRecoveryCode = async (code: string): Promise<string> =>
  sha256Hex(`recovery:${code.trim().toUpperCase().replace(/[^A-Z0-9]/g, "")}`);

const issueRecoveryCodes = async (db: D1Database, userId: string): Promise<string[]> => {
  const recoveryCodes = generateRecoveryCodes(8);
  const hashes = await Promise.all(recoveryCodes.map((code) => hashRecoveryCode(code)));
  await replaceRecoveryCodes(db, {
    userId,
    codeHashes: hashes
  });
  return recoveryCodes;
};

const verifyTotpOrRecoveryCode = async (params: {
  db: D1Database;
  userId: string;
  factorId: string;
  method: "totp" | "recovery_code";
  code: string;
  secretBase32: string;
}): Promise<"totp" | "recovery_code" | null> => {
  if (params.method === "totp") {
    const verified = await verifyTotpCode({
      secretBase32: params.secretBase32,
      code: params.code
    });
    if (!verified) {
      return null;
    }
    await touchTotpFactorUsage(params.db, params.factorId);
    return "totp";
  }

  const codeHash = await hashRecoveryCode(params.code);
  const consumed = await consumeRecoveryCodeHash(params.db, {
    userId: params.userId,
    codeHash
  });
  if (!consumed) {
    return null;
  }
  return "recovery_code";
};

const formatSession = (session: { id: string; accessToken: string }) => ({
  id: session.id,
  accessToken: session.accessToken,
  tokenType: "Bearer"
});

export const mfaRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

mfaRoutes.get("/status", requireAuth, async (context) => {
  const userId = context.get("authUserId");
  const factor = await findActiveVerifiedTotpFactorForUser(context.env.DB, userId);
  const remainingRecoveryCodes = factor ? await countRemainingRecoveryCodes(context.env.DB, userId) : 0;
  return context.json({
    enabled: Boolean(factor),
    totp: factor
      ? {
          factorId: factor.id,
          issuer: factor.issuer,
          accountName: factor.account_name,
          verifiedAt: factor.verified_at,
          lastUsedAt: factor.last_used_at
        }
      : null,
    remainingRecoveryCodes
  });
});

mfaRoutes.post("/totp/setup/start", requireAuth, async (context) => {
  const userId = context.get("authUserId");
  const user = await findUserById(context.env.DB, userId);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "Authenticated user does not exist"
        }
      },
      404
    );
  }

  const issuer = "PajamaDot Auth";
  const accountName = user.email;
  const secretBase32 = generateTotpSecret(20);
  const factorId = crypto.randomUUID();
  await createTotpFactor(context.env.DB, {
    id: factorId,
    userId,
    secretBase32,
    issuer,
    accountName
  });

  const otpauthUri = buildTotpOtpauthUri({
    issuer,
    accountName,
    secretBase32,
    digits: 6,
    periodSeconds: 30
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.mfa_totp_setup_started",
    metadataJson: JSON.stringify({ factorId })
  });

  return context.json(
    {
      factorId,
      secretBase32,
      otpauthUri,
      issuer,
      accountName
    },
    201
  );
});

mfaRoutes.post("/totp/setup/confirm", requireAuth, async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = totpSetupConfirmSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const userId = context.get("authUserId");
  const factor = await findTotpFactorByIdForUser(context.env.DB, {
    factorId: parsed.data.factorId,
    userId
  });
  if (!factor || factor.disabled_at) {
    return context.json(
      {
        error: {
          code: "MFA_FACTOR_NOT_FOUND",
          message: "TOTP factor was not found"
        }
      },
      404
    );
  }

  const verified = await verifyTotpCode({
    secretBase32: factor.secret_base32,
    code: parsed.data.code
  });
  if (!verified) {
    return context.json(
      {
        error: {
          code: "MFA_CODE_INVALID",
          message: "TOTP code is invalid"
        }
      },
      400
    );
  }

  await verifyTotpFactor(context.env.DB, {
    factorId: factor.id,
    userId
  });
  await touchTotpFactorUsage(context.env.DB, factor.id);
  const recoveryCodes = await issueRecoveryCodes(context.env.DB, userId);
  const remainingRecoveryCodes = await countRemainingRecoveryCodes(context.env.DB, userId);

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.mfa_totp_enabled",
    metadataJson: JSON.stringify({
      factorId: factor.id,
      remainingRecoveryCodes
    })
  });

  return context.json({
    ok: true,
    mfa: {
      enabled: true,
      factorId: factor.id,
      remainingRecoveryCodes
    },
    recoveryCodes
  });
});

mfaRoutes.post("/recovery-codes/regenerate", requireAuth, async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = totpDisableSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const userId = context.get("authUserId");
  const factor = await findActiveVerifiedTotpFactorForUser(context.env.DB, userId);
  if (!factor) {
    return context.json(
      {
        error: {
          code: "MFA_NOT_ENABLED",
          message: "No active TOTP factor is enabled"
        }
      },
      400
    );
  }

  const method = await verifyTotpOrRecoveryCode({
    db: context.env.DB,
    userId,
    factorId: factor.id,
    method: parsed.data.method,
    code: parsed.data.code,
    secretBase32: factor.secret_base32
  });
  if (!method) {
    return context.json(
      {
        error: {
          code: "MFA_CODE_INVALID",
          message: "Verification code is invalid"
        }
      },
      400
    );
  }

  const recoveryCodes = await issueRecoveryCodes(context.env.DB, userId);
  const remainingRecoveryCodes = await countRemainingRecoveryCodes(context.env.DB, userId);
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.mfa_recovery_codes_regenerated",
    metadataJson: JSON.stringify({
      method,
      remainingRecoveryCodes
    })
  });

  return context.json({
    ok: true,
    method,
    remainingRecoveryCodes,
    recoveryCodes
  });
});

mfaRoutes.post("/totp/disable", requireAuth, async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = totpDisableSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const userId = context.get("authUserId");
  const factor = await findActiveVerifiedTotpFactorForUser(context.env.DB, userId);
  if (!factor) {
    return context.json(
      {
        error: {
          code: "MFA_NOT_ENABLED",
          message: "No active TOTP factor is enabled"
        }
      },
      400
    );
  }

  const method = await verifyTotpOrRecoveryCode({
    db: context.env.DB,
    userId,
    factorId: factor.id,
    method: parsed.data.method,
    code: parsed.data.code,
    secretBase32: factor.secret_base32
  });
  if (!method) {
    return context.json(
      {
        error: {
          code: "MFA_CODE_INVALID",
          message: "Verification code is invalid"
        }
      },
      400
    );
  }

  await disableTotpFactorsForUser(context.env.DB, { userId });
  await replaceRecoveryCodes(context.env.DB, {
    userId,
    codeHashes: []
  });
  const revokedCount = await revokeOtherUserSessions(context.env.DB, {
    userId,
    exceptSessionId: context.get("authSessionId")
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.mfa_totp_disabled",
    metadataJson: JSON.stringify({
      method,
      revokedCount
    })
  });

  return context.json({
    ok: true,
    method,
    revokedCount
  });
});

mfaRoutes.post("/challenge/verify", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = challengeVerifySchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const challenge = await consumeMfaChallengeById(context.env.DB, {
    challengeId: parsed.data.challengeId,
    purpose: "sign_in"
  });
  if (!challenge) {
    return context.json(
      {
        error: {
          code: "MFA_CHALLENGE_INVALID",
          message: "MFA challenge is invalid, expired, or already used"
        }
      },
      400
    );
  }

  const user = await findUserById(context.env.DB, challenge.user_id);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "Challenge user was not found"
        }
      },
      404
    );
  }

  const factor = await findActiveVerifiedTotpFactorForUser(context.env.DB, user.id);
  if (!factor) {
    return context.json(
      {
        error: {
          code: "MFA_NOT_ENABLED",
          message: "No active TOTP factor is enabled for this user"
        }
      },
      400
    );
  }

  const method = await verifyTotpOrRecoveryCode({
    db: context.env.DB,
    userId: user.id,
    factorId: factor.id,
    method: parsed.data.method,
    code: parsed.data.code,
    secretBase32: factor.secret_base32
  });
  if (!method) {
    return context.json(
      {
        error: {
          code: "MFA_CODE_INVALID",
          message: "Verification code is invalid"
        }
      },
      400
    );
  }

  const tokens = await createSessionAndTokens(context.env, {
    userId: user.id,
    userAgent: context.req.header("user-agent"),
    ipAddress: readRequestIp(context.req.raw)
  });
  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);
  const risk = await assessAndRecordSessionRisk({
    db: context.env.DB,
    userId: user.id,
    sessionId: tokens.sessionId,
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null,
    eventType: "auth.sign_in"
  });
  const remainingRecoveryCodes = await countRemainingRecoveryCodes(context.env.DB, user.id);

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: user.id,
    eventType: "auth.mfa_challenge_completed",
    metadataJson: JSON.stringify({
      challengeId: challenge.id,
      method,
      remainingRecoveryCodes
    })
  });

  return context.json({
    user: publicUser(user),
    session: formatSession({
      id: tokens.sessionId,
      accessToken: tokens.accessToken
    }),
    mfa: {
      method,
      remainingRecoveryCodes
    },
    sessionRisk: {
      score: risk.score,
      level: risk.level,
      reasons: risk.reasons,
      stepUpRecommended: risk.stepUpRecommended,
      autoRevokedOtherSessions: risk.autoRevokedOtherSessions,
      revokedCount: risk.revokedCount
    }
  });
});
