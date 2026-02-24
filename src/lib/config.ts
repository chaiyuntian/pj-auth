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

export const getEmailVerificationTtlSeconds = (env: EnvBindings): number =>
  parsePositiveInt(env.EMAIL_VERIFICATION_TTL_SECONDS, 15 * 60);

export const getPasswordResetTtlSeconds = (env: EnvBindings): number =>
  parsePositiveInt(env.PASSWORD_RESET_TTL_SECONDS, 15 * 60);

export const getCookieName = (env: EnvBindings): string => env.COOKIE_NAME?.trim() || "pj_auth_refresh";

export const getCookieDomain = (env: EnvBindings): string | null => {
  const value = env.COOKIE_DOMAIN?.trim();
  return value ? value : null;
};

export const shouldExposeTestTokens = (env: EnvBindings): boolean =>
  (env.EXPOSE_TEST_TOKENS?.trim().toLowerCase() ?? "") === "true";

export const getAppUrl = (env: EnvBindings, request: Request): string => {
  const configured = env.PUBLIC_AUTH_URL?.trim() || env.APP_URL?.trim();
  if (configured) {
    return configured.replace(/\/+$/, "");
  }
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
};

export const getCorsOrigins = (env: EnvBindings): string[] => {
  const configured = env.CORS_ORIGINS?.trim();
  if (!configured) {
    return ["*"];
  }
  return configured
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
};

export const getEmailFromAddress = (env: EnvBindings): string => env.EMAIL_FROM?.trim() || "";

export const getResendApiBaseUrl = (env: EnvBindings): string =>
  env.RESEND_API_BASE_URL?.trim().replace(/\/+$/, "") || "https://api.resend.com";

export const assertCriticalSecrets = (env: EnvBindings): void => {
  if (!env.JWT_SIGNING_KEY || env.JWT_SIGNING_KEY.length < 32) {
    throw new Error("JWT_SIGNING_KEY must be set and at least 32 characters long");
  }
  if (!env.ADMIN_API_KEY || env.ADMIN_API_KEY.length < 16) {
    throw new Error("ADMIN_API_KEY must be set and at least 16 characters long");
  }
};
