import type { EnvBindings, SessionClaims } from "../types";
import { getAccessTokenTtlSeconds, getRefreshTokenTtlSeconds } from "./config";
import {
  createSession,
  findActiveSessionByRefreshTokenHash,
  findUserById,
  revokeSession,
  rotateSessionRefreshToken
} from "./db";
import { generateRefreshToken, sha256Hex } from "./crypto";
import { signAccessToken, verifyAccessToken } from "./jwt";
import { addSecondsToIso, isIsoExpired, unixNow } from "./time";

export class AuthError extends Error {
  public readonly status: number;
  public readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const createClaims = (userId: string, sessionId: string, ttlSeconds: number): SessionClaims => ({
  sub: userId,
  sid: sessionId,
  typ: "access",
  iat: unixNow(),
  exp: unixNow() + ttlSeconds
});

export const createSessionAndTokens = async (
  env: EnvBindings,
  params: {
    userId: string;
    userAgent?: string | null;
    ipAddress?: string | null;
  }
): Promise<{
  sessionId: string;
  accessToken: string;
  refreshToken: string;
  refreshTtlSeconds: number;
}> => {
  const refreshTtlSeconds = getRefreshTokenTtlSeconds(env);
  const accessTtlSeconds = getAccessTokenTtlSeconds(env);

  const sessionId = crypto.randomUUID();
  const refreshToken = generateRefreshToken();
  const refreshTokenHash = await sha256Hex(refreshToken);
  const sessionExpiry = addSecondsToIso(refreshTtlSeconds);

  await createSession(env.DB, {
    id: sessionId,
    userId: params.userId,
    refreshTokenHash,
    expiresAt: sessionExpiry,
    userAgent: params.userAgent ?? null,
    ipAddress: params.ipAddress ?? null
  });

  const accessToken = await signAccessToken(createClaims(params.userId, sessionId, accessTtlSeconds), env.JWT_SIGNING_KEY);

  return {
    sessionId,
    accessToken,
    refreshToken,
    refreshTtlSeconds
  };
};

export const refreshSessionTokens = async (
  env: EnvBindings,
  refreshToken: string
): Promise<{
  sessionId: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  refreshTtlSeconds: number;
}> => {
  const refreshTokenHash = await sha256Hex(refreshToken);
  const session = await findActiveSessionByRefreshTokenHash(env.DB, refreshTokenHash);

  if (!session || isIsoExpired(session.expires_at)) {
    throw new AuthError(401, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
  }

  const user = await findUserById(env.DB, session.user_id);
  if (!user) {
    await revokeSession(env.DB, session.id);
    throw new AuthError(401, "SESSION_USER_NOT_FOUND", "Session user no longer exists");
  }

  const newRefreshToken = generateRefreshToken();
  const newRefreshTokenHash = await sha256Hex(newRefreshToken);
  const refreshTtlSeconds = getRefreshTokenTtlSeconds(env);
  const newSessionExpiry = addSecondsToIso(refreshTtlSeconds);
  await rotateSessionRefreshToken(env.DB, {
    sessionId: session.id,
    refreshTokenHash: newRefreshTokenHash,
    expiresAt: newSessionExpiry
  });

  const accessTtlSeconds = getAccessTokenTtlSeconds(env);
  const accessToken = await signAccessToken(
    createClaims(user.id, session.id, accessTtlSeconds),
    env.JWT_SIGNING_KEY
  );

  return {
    sessionId: session.id,
    userId: user.id,
    accessToken,
    refreshToken: newRefreshToken,
    refreshTtlSeconds
  };
};

export const parseBearerToken = (request: Request): string | null => {
  const header = request.headers.get("authorization");
  if (!header) {
    return null;
  }
  const [scheme, value] = header.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !value) {
    return null;
  }
  return value.trim();
};

export const authenticateAccessToken = async (
  env: EnvBindings,
  bearerToken: string | null
): Promise<{ userId: string; sessionId: string } | null> => {
  if (!bearerToken) {
    return null;
  }

  const claims = await verifyAccessToken(bearerToken, env.JWT_SIGNING_KEY);
  if (!claims) {
    return null;
  }

  return {
    userId: claims.sub,
    sessionId: claims.sid
  };
};

export const readRequestIp = (request: Request): string | null =>
  request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || null;
