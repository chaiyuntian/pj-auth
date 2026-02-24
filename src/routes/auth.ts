import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { createPasswordHash, verifyPasswordHash } from "../lib/crypto";
import { createSessionAndTokens, readRequestIp, refreshSessionTokens } from "../lib/auth";
import { clearRefreshTokenCookie, readRefreshTokenCookie, setRefreshTokenCookie } from "../lib/cookies";
import { createUser, findUserByEmail, findUserById, revokeSession, writeAuditLog } from "../lib/db";
import { publicUser } from "../lib/http";
import { requireAuth } from "../middleware/require-auth";

const signUpSchema = z.object({
  email: z.string().email().min(3).max(320),
  password: z.string().min(8).max(128),
  fullName: z.string().min(1).max(200).optional()
});

const signInSchema = z.object({
  email: z.string().email().min(3).max(320),
  password: z.string().min(8).max(128)
});

const refreshSchema = z.object({
  refreshToken: z.string().min(20).optional()
});

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

export const authRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

authRoutes.post("/sign-up", async (context) => {
  const payload = await context.req.json().catch(() => null);
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

  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.sign_up",
    metadataJson: JSON.stringify({ method: "password" })
  });

  return context.json(
    {
      user: publicUser(user),
      session: {
        id: tokens.sessionId,
        accessToken: tokens.accessToken,
        tokenType: "Bearer"
      }
    },
    201
  );
});

authRoutes.post("/sign-in", async (context) => {
  const payload = await context.req.json().catch(() => null);
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
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: user.id,
    eventType: "auth.sign_in",
    metadataJson: JSON.stringify({ method: "password" })
  });

  return context.json({
    user: publicUser(user),
    session: {
      id: tokens.sessionId,
      accessToken: tokens.accessToken,
      tokenType: "Bearer"
    }
  });
});

authRoutes.post("/token/refresh", async (context) => {
  const payload = await context.req.json().catch(() => ({}));
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
  return context.json({
    user: publicUser(user),
    session: {
      id: refreshed.sessionId,
      accessToken: refreshed.accessToken,
      tokenType: "Bearer"
    }
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
  return context.json({ user: publicUser(user) });
});
