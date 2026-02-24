import { Hono } from "hono";
import type { Context } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { createPasswordHash, sha256Hex, verifyPasswordHash } from "../lib/crypto";
import {
  createSessionAndTokens,
  readRequestIp,
  refreshSessionTokens
} from "../lib/auth";
import { clearRefreshTokenCookie, readRefreshTokenCookie, setRefreshTokenCookie } from "../lib/cookies";
import {
  createUser,
  createVerificationCode,
  createApiKey,
  findUserByEmail,
  findUserById,
  invalidateVerificationCodes,
  listOrganizationsForUser,
  listLatestSessionRiskForUser,
  listSessionRiskEventsForUser,
  listUserApiKeys,
  listUserSessions,
  revokeAllUserSessions,
  revokeUserApiKey,
  revokeOtherUserSessions,
  revokeSession,
  revokeUserSession,
  updateUserEmailVerification,
  updateUserPassword,
  writeAuditLog,
  consumeVerificationCodeByHash
} from "../lib/db";
import { publicUser } from "../lib/http";
import { requireAuth } from "../middleware/require-auth";
import { readJsonBody } from "../lib/request";
import {
  getAppUrl,
  getEmailVerificationTtlSeconds,
  getPasswordResetTtlSeconds,
  shouldExposeTestTokens
} from "../lib/config";
import { addSecondsToIso, isIsoExpired } from "../lib/time";
import { randomToken } from "../lib/encoding";
import { sendTransactionalEmail } from "../lib/mailer";
import { assertTurnstileIfEnabled } from "../lib/turnstile";
import { assessAndRecordSessionRisk } from "../lib/session-risk";

const VERIFICATION_PURPOSE_EMAIL = "email_verify";
const VERIFICATION_PURPOSE_PASSWORD_RESET = "password_reset";

const signUpSchema = z.object({
  email: z.string().email().min(3).max(320),
  password: z.string().min(8).max(128),
  fullName: z.string().min(1).max(200).optional(),
  turnstileToken: z.string().min(10).optional()
});

const signInSchema = z.object({
  email: z.string().email().min(3).max(320),
  password: z.string().min(8).max(128),
  turnstileToken: z.string().min(10).optional()
});

const refreshSchema = z.object({
  refreshToken: z.string().min(20).optional()
});

const verificationConfirmSchema = z.object({
  token: z.string().min(16)
});

const passwordResetStartSchema = z.object({
  email: z.string().email().min(3).max(320),
  turnstileToken: z.string().min(10).optional()
});

const passwordResetConfirmSchema = z.object({
  token: z.string().min(16),
  newPassword: z.string().min(8).max(128)
});

const createPersonalApiKeySchema = z.object({
  name: z.string().min(2).max(120),
  scopes: z.array(z.string().min(1).max(120)).max(50).optional(),
  expiresInDays: z.number().int().positive().max(3650).optional()
});

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

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

const scoreToRiskLevel = (score: number): "low" | "medium" | "high" | "critical" => {
  if (score >= 80) {
    return "critical";
  }
  if (score >= 60) {
    return "high";
  }
  if (score >= 30) {
    return "medium";
  }
  return "low";
};

const parseRiskReason = (reason: string): { source: string; signals: string[] } => {
  const separator = reason.indexOf(":");
  if (separator === -1) {
    return { source: "unknown", signals: reason ? [reason] : [] };
  }
  const source = reason.slice(0, separator);
  const signalsRaw = reason.slice(separator + 1);
  const signals =
    signalsRaw && signalsRaw !== "baseline"
      ? signalsRaw
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean)
      : [];
  return { source, signals };
};

export const authRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

type AuthContext = Context<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>;

const issueVerificationToken = async (params: {
  context: AuthContext;
  userId: string;
  email: string;
  purpose: string;
  ttlSeconds: number;
  confirmationPath: string;
}): Promise<{ token: string; expiresAt: string; confirmationUrl: string }> => {
  const token = randomToken(32);
  const codeHash = await sha256Hex(token);
  const expiresAt = addSecondsToIso(params.ttlSeconds);

  await invalidateVerificationCodes(params.context.env.DB, {
    purpose: params.purpose,
    userId: params.userId
  });

  await createVerificationCode(params.context.env.DB, {
    id: crypto.randomUUID(),
    userId: params.userId,
    email: params.email,
    purpose: params.purpose,
    codeHash,
    expiresAt
  });

  const appUrl = getAppUrl(params.context.env, params.context.req.raw);
  const confirmationUrl = new URL(params.confirmationPath, appUrl);
  confirmationUrl.searchParams.set("token", token);

  return {
    token,
    expiresAt,
    confirmationUrl: confirmationUrl.toString()
  };
};

const formatSession = (session: { id: string; accessToken: string }) => ({
  id: session.id,
  accessToken: session.accessToken,
  tokenType: "Bearer"
});

const sendEmailVerificationMessage = async (params: {
  context: AuthContext;
  email: string;
  confirmationUrl: string;
}): Promise<{
  delivered: boolean;
  provider: "resend" | "log";
  messageId?: string;
  reason?: string;
}> =>
  sendTransactionalEmail({
    env: params.context.env,
    to: params.email,
    subject: "Verify your PajamaDot account",
    text: `Please verify your account by opening this link:\n${params.confirmationUrl}\n\nIf you did not request this, ignore this email.`,
    html: `<p>Please verify your account by clicking this link:</p><p><a href="${params.confirmationUrl}">${params.confirmationUrl}</a></p><p>If you did not request this, ignore this email.</p>`
  });

const sendPasswordResetMessage = async (params: {
  context: AuthContext;
  email: string;
  resetUrl: string;
}): Promise<{
  delivered: boolean;
  provider: "resend" | "log";
  messageId?: string;
  reason?: string;
}> =>
  sendTransactionalEmail({
    env: params.context.env,
    to: params.email,
    subject: "Reset your PajamaDot password",
    text: `You can reset your password by opening this link:\n${params.resetUrl}\n\nIf you did not request this, ignore this email.`,
    html: `<p>You can reset your password by clicking this link:</p><p><a href="${params.resetUrl}">${params.resetUrl}</a></p><p>If you did not request this, ignore this email.</p>`
  });

authRoutes.post("/sign-up", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = signUpSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const existingUser = await findUserByEmail(context.env.DB, parsed.data.email);
  if (existingUser) {
    return context.json(
      {
        error: {
          code: "EMAIL_IN_USE",
          message: "A user with this email already exists"
        }
      },
      409
    );
  }

  const turnstile = await assertTurnstileIfEnabled({
    env: context.env,
    request: context.req.raw,
    token: parsed.data.turnstileToken
  });
  if (!turnstile.ok) {
    return context.json(
      {
        error: {
          code: turnstile.code,
          message: turnstile.message,
          detail: turnstile.detail
        }
      },
      turnstile.code === "TURNSTILE_NOT_CONFIGURED" ? 500 : 400
    );
  }

  const userId = crypto.randomUUID();
  const password = await createPasswordHash(parsed.data.password);
  await createUser(context.env.DB, {
    id: userId,
    email: parsed.data.email,
    passwordHash: password.passwordHash,
    passwordSalt: password.passwordSalt,
    fullName: parsed.data.fullName ?? null,
    emailVerified: false
  });

  const tokens = await createSessionAndTokens(context.env, {
    userId,
    userAgent: context.req.header("user-agent"),
    ipAddress: readRequestIp(context.req.raw)
  });

  const user = await findUserById(context.env.DB, userId);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_CREATION_FAILED",
          message: "User was created but cannot be retrieved"
        }
      },
      500
    );
  }

  const verification = await issueVerificationToken({
    context,
    userId: user.id,
    email: user.email,
    purpose: VERIFICATION_PURPOSE_EMAIL,
    ttlSeconds: getEmailVerificationTtlSeconds(context.env),
    confirmationPath: "/v1/auth/email-verification/confirm"
  });
  const delivery = await sendEmailVerificationMessage({
    context,
    email: user.email,
    confirmationUrl: verification.confirmationUrl
  });

  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);
  const signUpRisk = await assessAndRecordSessionRisk({
    db: context.env.DB,
    userId: user.id,
    sessionId: tokens.sessionId,
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null,
    eventType: "auth.sign_up"
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.sign_up",
    metadataJson: JSON.stringify({ method: "password" })
  });

  console.log(
    `[email_verification] user=${user.id} email=${user.email} link=${verification.confirmationUrl} delivered=${delivery.delivered} provider=${delivery.provider}`
  );

  return context.json(
    {
      user: publicUser(user),
      session: formatSession({
        id: tokens.sessionId,
        accessToken: tokens.accessToken
      }),
      emailVerification: {
        required: true,
        expiresAt: verification.expiresAt,
        delivery: {
          delivered: delivery.delivered,
          provider: delivery.provider
        },
        ...(shouldExposeTestTokens(context.env)
          ? { testToken: verification.token, testConfirmationUrl: verification.confirmationUrl }
          : {})
      },
      sessionRisk: {
        score: signUpRisk.score,
        level: signUpRisk.level,
        reasons: signUpRisk.reasons,
        stepUpRecommended: signUpRisk.stepUpRecommended
      }
    },
    201
  );
});

authRoutes.post("/sign-in", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = signInSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const user = await findUserByEmail(context.env.DB, parsed.data.email);
  if (!user || !user.password_hash || !user.password_salt) {
    return context.json(
      {
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password"
        }
      },
      401
    );
  }

  const turnstile = await assertTurnstileIfEnabled({
    env: context.env,
    request: context.req.raw,
    token: parsed.data.turnstileToken
  });
  if (!turnstile.ok) {
    return context.json(
      {
        error: {
          code: turnstile.code,
          message: turnstile.message,
          detail: turnstile.detail
        }
      },
      turnstile.code === "TURNSTILE_NOT_CONFIGURED" ? 500 : 400
    );
  }

  const passwordMatch = await verifyPasswordHash({
    password: parsed.data.password,
    storedHash: user.password_hash,
    storedSalt: user.password_salt
  });

  if (!passwordMatch) {
    return context.json(
      {
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password"
        }
      },
      401
    );
  }

  const tokens = await createSessionAndTokens(context.env, {
    userId: user.id,
    userAgent: context.req.header("user-agent"),
    ipAddress: readRequestIp(context.req.raw)
  });

  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);
  const signInRisk = await assessAndRecordSessionRisk({
    db: context.env.DB,
    userId: user.id,
    sessionId: tokens.sessionId,
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null,
    eventType: "auth.sign_in"
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: user.id,
    eventType: "auth.sign_in",
    metadataJson: JSON.stringify({ method: "password" })
  });

  return context.json({
    user: publicUser(user),
    session: formatSession({
      id: tokens.sessionId,
      accessToken: tokens.accessToken
    }),
    sessionRisk: {
      score: signInRisk.score,
      level: signInRisk.level,
      reasons: signInRisk.reasons,
      stepUpRecommended: signInRisk.stepUpRecommended,
      autoRevokedOtherSessions: signInRisk.autoRevokedOtherSessions,
      revokedCount: signInRisk.revokedCount
    }
  });
});

authRoutes.post("/token/refresh", async (context) => {
  const payload = (await readJsonBody(context.req.raw)) ?? {};
  const parsed = refreshSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const refreshToken = parsed.data.refreshToken ?? readRefreshTokenCookie(context);
  if (!refreshToken) {
    return context.json(
      {
        error: {
          code: "MISSING_REFRESH_TOKEN",
          message: "Provide refreshToken in body or cookie"
        }
      },
      401
    );
  }

  const refreshed = await refreshSessionTokens(context.env, refreshToken).catch(() => null);
  if (!refreshed) {
    clearRefreshTokenCookie(context);
    return context.json(
      {
        error: {
          code: "INVALID_REFRESH_TOKEN",
          message: "Refresh token is invalid or expired"
        }
      },
      401
    );
  }

  const user = await findUserById(context.env.DB, refreshed.userId);
  if (!user) {
    clearRefreshTokenCookie(context);
    return context.json(
      {
        error: {
          code: "SESSION_USER_NOT_FOUND",
          message: "Session user no longer exists"
        }
      },
      401
    );
  }

  setRefreshTokenCookie(context, refreshed.refreshToken, refreshed.refreshTtlSeconds);
  const refreshRisk = await assessAndRecordSessionRisk({
    db: context.env.DB,
    userId: refreshed.userId,
    sessionId: refreshed.sessionId,
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null,
    eventType: "auth.refresh"
  });
  return context.json({
    user: publicUser(user),
    session: formatSession({
      id: refreshed.sessionId,
      accessToken: refreshed.accessToken
    }),
    sessionRisk: {
      score: refreshRisk.score,
      level: refreshRisk.level,
      reasons: refreshRisk.reasons,
      stepUpRecommended: refreshRisk.stepUpRecommended,
      autoRevokedOtherSessions: refreshRisk.autoRevokedOtherSessions,
      revokedCount: refreshRisk.revokedCount
    }
  });
});

authRoutes.post("/email-verification/start", requireAuth, async (context) => {
  const user = await findUserById(context.env.DB, context.get("authUserId"));
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

  if (user.email_verified) {
    return context.json({
      ok: true,
      alreadyVerified: true
    });
  }

  const verification = await issueVerificationToken({
    context,
    userId: user.id,
    email: user.email,
    purpose: VERIFICATION_PURPOSE_EMAIL,
    ttlSeconds: getEmailVerificationTtlSeconds(context.env),
    confirmationPath: "/v1/auth/email-verification/confirm"
  });
  const delivery = await sendEmailVerificationMessage({
    context,
    email: user.email,
    confirmationUrl: verification.confirmationUrl
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: user.id,
    eventType: "auth.email_verification_requested"
  });
  console.log(
    `[email_verification] user=${user.id} email=${user.email} link=${verification.confirmationUrl} delivered=${delivery.delivered} provider=${delivery.provider}`
  );

  return context.json({
    ok: true,
    expiresAt: verification.expiresAt,
    delivery: {
      delivered: delivery.delivered,
      provider: delivery.provider
    },
    ...(shouldExposeTestTokens(context.env)
      ? { testToken: verification.token, testConfirmationUrl: verification.confirmationUrl }
      : {})
  });
});

const confirmEmailVerification = async (
  context: AuthContext
) => {
  const payload = await readJsonBody<{ token?: string }>(context.req.raw);
  const token = payload?.token ?? context.req.query("token");
  const parsed = verificationConfirmSchema.safeParse({ token });
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const codeHash = await sha256Hex(parsed.data.token);
  const code = await consumeVerificationCodeByHash(context.env.DB, {
    purpose: VERIFICATION_PURPOSE_EMAIL,
    codeHash
  });

  if (!code) {
    return context.json(
      {
        error: {
          code: "INVALID_VERIFICATION_TOKEN",
          message: "Verification token is invalid, expired, or already used"
        }
      },
      400
    );
  }

  const user = (code.user_id ? await findUserById(context.env.DB, code.user_id) : null) ?? (await findUserByEmail(context.env.DB, code.email));
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "Verification token user was not found"
        }
      },
      404
    );
  }

  await updateUserEmailVerification(context.env.DB, {
    userId: user.id,
    emailVerified: true
  });
  await invalidateVerificationCodes(context.env.DB, {
    purpose: VERIFICATION_PURPOSE_EMAIL,
    userId: user.id
  });

  const updatedUser = await findUserById(context.env.DB, user.id);
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: user.id,
    eventType: "auth.email_verified"
  });

  return context.json({
    ok: true,
    user: updatedUser ? publicUser(updatedUser) : publicUser(user)
  });
};

authRoutes.post("/email-verification/confirm", confirmEmailVerification);
authRoutes.get("/email-verification/confirm", confirmEmailVerification);

authRoutes.post("/password-reset/start", async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = passwordResetStartSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const user = await findUserByEmail(context.env.DB, parsed.data.email);
  const turnstile = await assertTurnstileIfEnabled({
    env: context.env,
    request: context.req.raw,
    token: parsed.data.turnstileToken
  });
  if (!turnstile.ok) {
    return context.json(
      {
        error: {
          code: turnstile.code,
          message: turnstile.message,
          detail: turnstile.detail
        }
      },
      turnstile.code === "TURNSTILE_NOT_CONFIGURED" ? 500 : 400
    );
  }
  let testToken: string | undefined;
  let testConfirmationUrl: string | undefined;
  let expiresAt: string | undefined;
  let delivery: { delivered: boolean; provider: "resend" | "log" } | undefined;

  if (user) {
    const token = randomToken(32);
    const codeHash = await sha256Hex(token);
    const ttlSeconds = getPasswordResetTtlSeconds(context.env);
    expiresAt = addSecondsToIso(ttlSeconds);

    await invalidateVerificationCodes(context.env.DB, {
      purpose: VERIFICATION_PURPOSE_PASSWORD_RESET,
      userId: user.id
    });
    await createVerificationCode(context.env.DB, {
      id: crypto.randomUUID(),
      userId: user.id,
      email: user.email,
      purpose: VERIFICATION_PURPOSE_PASSWORD_RESET,
      codeHash,
      expiresAt
    });

    const appUrl = getAppUrl(context.env, context.req.raw);
    const resetUrl = new URL("/v1/auth/password-reset/confirm", appUrl);
    resetUrl.searchParams.set("token", token);
    testToken = token;
    testConfirmationUrl = resetUrl.toString();
    const sent = await sendPasswordResetMessage({
      context,
      email: user.email,
      resetUrl: resetUrl.toString()
    });
    delivery = {
      delivered: sent.delivered,
      provider: sent.provider
    };

    await writeAuditLog(context.env.DB, {
      id: crypto.randomUUID(),
      actorType: "user",
      actorId: user.id,
      eventType: "auth.password_reset_requested"
    });
    console.log(
      `[password_reset] user=${user.id} email=${user.email} link=${resetUrl.toString()} delivered=${sent.delivered} provider=${sent.provider}`
    );
  }

  return context.json({
    ok: true,
    message: "If an account exists for this email, password reset instructions were generated.",
    ...(delivery ? { delivery } : {}),
    ...(shouldExposeTestTokens(context.env) && testToken
      ? { testToken, testConfirmationUrl, expiresAt }
      : {})
  });
});

authRoutes.post("/password-reset/confirm", async (context) => {
  const bodyPayload = (await readJsonBody<{ token?: string; newPassword?: string }>(context.req.raw)) ?? {};
  const token = bodyPayload.token ?? context.req.query("token");
  const parsed = passwordResetConfirmSchema.safeParse({
    token,
    newPassword: bodyPayload.newPassword
  });
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const codeHash = await sha256Hex(parsed.data.token);
  const code = await consumeVerificationCodeByHash(context.env.DB, {
    purpose: VERIFICATION_PURPOSE_PASSWORD_RESET,
    codeHash
  });

  if (!code) {
    return context.json(
      {
        error: {
          code: "INVALID_PASSWORD_RESET_TOKEN",
          message: "Password reset token is invalid, expired, or already used"
        }
      },
      400
    );
  }

  const user = (code.user_id ? await findUserById(context.env.DB, code.user_id) : null) ?? (await findUserByEmail(context.env.DB, code.email));
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "Password reset user was not found"
        }
      },
      404
    );
  }

  const nextPassword = await createPasswordHash(parsed.data.newPassword);
  await updateUserPassword(context.env.DB, {
    userId: user.id,
    passwordHash: nextPassword.passwordHash,
    passwordSalt: nextPassword.passwordSalt
  });
  await revokeAllUserSessions(context.env.DB, {
    userId: user.id
  });

  const tokens = await createSessionAndTokens(context.env, {
    userId: user.id,
    userAgent: context.req.header("user-agent"),
    ipAddress: readRequestIp(context.req.raw)
  });
  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);
  const resetRisk = await assessAndRecordSessionRisk({
    db: context.env.DB,
    userId: user.id,
    sessionId: tokens.sessionId,
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null,
    eventType: "auth.sign_in"
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: user.id,
    eventType: "auth.password_reset_completed"
  });

  const updatedUser = await findUserById(context.env.DB, user.id);
  return context.json({
    ok: true,
    user: updatedUser ? publicUser(updatedUser) : publicUser(user),
    session: formatSession({
      id: tokens.sessionId,
      accessToken: tokens.accessToken
    }),
    sessionRisk: {
      score: resetRisk.score,
      level: resetRisk.level,
      reasons: resetRisk.reasons,
      stepUpRecommended: resetRisk.stepUpRecommended,
      autoRevokedOtherSessions: resetRisk.autoRevokedOtherSessions,
      revokedCount: resetRisk.revokedCount
    }
  });
});

authRoutes.get("/sessions", requireAuth, async (context) => {
  const userId = context.get("authUserId");
  const [sessions, latestRiskRows] = await Promise.all([
    listUserSessions(context.env.DB, userId),
    listLatestSessionRiskForUser(context.env.DB, userId)
  ]);
  const currentSessionId = context.get("authSessionId");
  const latestRiskBySession = new Map(latestRiskRows.map((row) => [row.session_id, row]));

  return context.json({
    sessions: sessions.map((session) => ({
      id: session.id,
      userAgent: session.user_agent,
      ipAddress: session.ip_address,
      expiresAt: session.expires_at,
      createdAt: session.created_at,
      lastActiveAt: session.last_active_at,
      revokedAt: session.revoked_at,
      isCurrent: session.id === currentSessionId,
      isActive: !session.revoked_at && !isIsoExpired(session.expires_at),
      risk: (() => {
        const latest = latestRiskBySession.get(session.id);
        if (!latest) {
          return null;
        }
        const parsed = parseRiskReason(latest.reason);
        return {
          score: latest.risk_score,
          level: scoreToRiskLevel(latest.risk_score),
          source: parsed.source,
          signals: parsed.signals,
          observedAt: latest.created_at
        };
      })()
    }))
  });
});

authRoutes.get("/sessions/risk-events", requireAuth, async (context) => {
  const limitRaw = context.req.query("limit");
  const parsedLimit = limitRaw ? Number.parseInt(limitRaw, 10) : Number.NaN;
  const limit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 200) : 100;
  const events = await listSessionRiskEventsForUser(context.env.DB, {
    userId: context.get("authUserId"),
    limit
  });
  return context.json({
    riskEvents: events.map((event) => {
      const parsed = parseRiskReason(event.reason);
      return {
        id: event.id,
        sessionId: event.session_id,
        score: event.risk_score,
        level: scoreToRiskLevel(event.risk_score),
        source: parsed.source,
        signals: parsed.signals,
        ipAddress: event.ip_address,
        userAgent: event.user_agent,
        createdAt: event.created_at
      };
    })
  });
});

authRoutes.get("/api-keys", requireAuth, async (context) => {
  const keys = await listUserApiKeys(context.env.DB, context.get("authUserId"));
  return context.json({
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

authRoutes.post("/api-keys", requireAuth, async (context) => {
  const payload = await readJsonBody(context.req.raw);
  const parsed = createPersonalApiKeySchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const secret = `pjk_${randomToken(40)}`;
  const keyHash = await sha256Hex(secret);
  const keyPrefix = secret.slice(0, 16);
  const expiresAt = parsed.data.expiresInDays
    ? addSecondsToIso(parsed.data.expiresInDays * 24 * 60 * 60)
    : null;
  const scopes = parsed.data.scopes ?? [];

  const apiKeyId = crypto.randomUUID();
  await createApiKey(context.env.DB, {
    id: apiKeyId,
    ownerType: "user",
    ownerUserId: context.get("authUserId"),
    name: parsed.data.name,
    keyPrefix,
    keyHash,
    scopesJson: JSON.stringify(scopes),
    expiresAt
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "auth.api_key_created",
    metadataJson: JSON.stringify({
      apiKeyId,
      name: parsed.data.name,
      keyPrefix
    })
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

authRoutes.post("/api-keys/:apiKeyId/revoke", requireAuth, async (context) => {
  const apiKeyId = context.req.param("apiKeyId");
  const revoked = await revokeUserApiKey(context.env.DB, {
    userId: context.get("authUserId"),
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
    actorId: context.get("authUserId"),
    eventType: "auth.api_key_revoked",
    metadataJson: JSON.stringify({ apiKeyId })
  });

  return context.json({
    ok: true,
    apiKeyId
  });
});

authRoutes.post("/sessions/:sessionId/revoke", requireAuth, async (context) => {
  const sessionId = context.req.param("sessionId");
  if (!sessionId) {
    return context.json(
      {
        error: {
          code: "INVALID_SESSION_ID",
          message: "sessionId path param is required"
        }
      },
      400
    );
  }

  const revoked = await revokeUserSession(context.env.DB, {
    userId: context.get("authUserId"),
    sessionId
  });
  if (!revoked) {
    return context.json(
      {
        error: {
          code: "SESSION_NOT_FOUND",
          message: "Session was not found or already revoked"
        }
      },
      404
    );
  }

  if (sessionId === context.get("authSessionId")) {
    clearRefreshTokenCookie(context);
  }

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "auth.session_revoked",
    metadataJson: JSON.stringify({ sessionId })
  });

  return context.json({
    ok: true,
    sessionId
  });
});

authRoutes.post("/sessions/revoke-others", requireAuth, async (context) => {
  const revokedCount = await revokeOtherUserSessions(context.env.DB, {
    userId: context.get("authUserId"),
    exceptSessionId: context.get("authSessionId")
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "auth.other_sessions_revoked",
    metadataJson: JSON.stringify({ revokedCount })
  });

  return context.json({
    ok: true,
    revokedCount
  });
});

authRoutes.post("/sessions/revoke-all", requireAuth, async (context) => {
  const revokedCount = await revokeAllUserSessions(context.env.DB, {
    userId: context.get("authUserId")
  });
  clearRefreshTokenCookie(context);

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "auth.all_sessions_revoked",
    metadataJson: JSON.stringify({ revokedCount })
  });

  return context.json({
    ok: true,
    revokedCount
  });
});

authRoutes.post("/sign-out", requireAuth, async (context) => {
  const sessionId = context.get("authSessionId");
  await revokeSession(context.env.DB, sessionId);
  clearRefreshTokenCookie(context);

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "auth.sign_out"
  });

  return context.json({ ok: true });
});

authRoutes.get("/me", requireAuth, async (context) => {
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
  const organizations = await listOrganizationsForUser(context.env.DB, userId);
  return context.json({
    user: publicUser(user),
    organizations: organizations.map((organization) => ({
      id: organization.id,
      slug: organization.slug,
      name: organization.name,
      role: organization.membership_role,
      joinedAt: organization.membership_created_at
    }))
  });
});
