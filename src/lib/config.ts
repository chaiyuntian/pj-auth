import type { EnvBindings } from "../types";

const parsePositiveInt = (value: string | undefined, fallback: number): number => {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
};

export const getAccessTokenTtlSeconds = (env: EnvBindings): number =>
  parsePositiveInt(env.ACCESS_TOKEN_TTL_SECONDS, 15 * 60);

export const getRefreshTokenTtlSeconds = (env: EnvBindings): number =>
  parsePositiveInt(env.REFRESH_TOKEN_TTL_SECONDS, 30 * 24 * 60 * 60);

export const getCookieName = (env: EnvBindings): string => env.COOKIE_NAME?.trim() || "pj_auth_refresh";

export const getCookieDomain = (env: EnvBindings): string | null => {
  const value = env.COOKIE_DOMAIN?.trim();
  return value ? value : null;
};

export const getAppUrl = (env: EnvBindings, request: Request): string => {
  const configured = env.APP_URL?.trim();
  if (configured) {
    return configured.replace(/\/+$/, "");
  }
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
};

export const assertCriticalSecrets = (env: EnvBindings): void => {
  if (!env.JWT_SIGNING_KEY || env.JWT_SIGNING_KEY.length < 32) {
    throw new Error("JWT_SIGNING_KEY must be set and at least 32 characters long");
  }
  if (!env.ADMIN_API_KEY || env.ADMIN_API_KEY.length < 16) {
    throw new Error("ADMIN_API_KEY must be set and at least 16 characters long");
  }
};
