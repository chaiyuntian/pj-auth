export type EnvBindings = {
  DB: D1Database;
  APP_URL?: string;
  ACCESS_TOKEN_TTL_SECONDS?: string;
  REFRESH_TOKEN_TTL_SECONDS?: string;
  EMAIL_VERIFICATION_TTL_SECONDS?: string;
  PASSWORD_RESET_TTL_SECONDS?: string;
  COOKIE_NAME?: string;
  COOKIE_DOMAIN?: string;
  EXPOSE_TEST_TOKENS?: string;
  JWT_SIGNING_KEY: string;
  ADMIN_API_KEY: string;
  OAUTH_GOOGLE_CLIENT_ID?: string;
  OAUTH_GOOGLE_CLIENT_SECRET?: string;
  OAUTH_GOOGLE_REDIRECT_URI?: string;
  GOOGLE_DEFAULT_SCOPE?: string;
};

export type SessionClaims = {
  sub: string;
  sid: string;
  typ: "access";
  iat: number;
  exp: number;
};

export type AuthenticatedUser = {
  userId: string;
  sessionId: string;
};

export type GoogleProviderConfig = {
  provider: "google";
  enabled: boolean;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
};
