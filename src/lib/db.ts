import type { EnvBindings, GoogleProviderConfig } from "../types";
import { nowIso } from "./time";

export type UserRow = {
  id: string;
  email: string;
  password_hash: string | null;
  password_salt: string | null;
  full_name: string | null;
  image_url: string | null;
  email_verified: number;
  created_at: string;
  updated_at: string;
};

export type SessionRow = {
  id: string;
  user_id: string;
  refresh_token_hash: string;
  user_agent: string | null;
  ip_address: string | null;
  expires_at: string;
  last_active_at: string;
  revoked_at: string | null;
  created_at: string;
};

type OAuthProviderRow = {
  provider: string;
  enabled: number;
  client_id: string | null;
  client_secret: string | null;
  redirect_uri: string | null;
  scope: string | null;
  updated_at: string;
  created_at: string;
};

export type OAuthAccountRow = {
  id: string;
  user_id: string;
  provider: string;
  provider_user_id: string;
  provider_email: string | null;
  access_token: string | null;
  refresh_token: string | null;
  token_expires_at: string | null;
  created_at: string;
  updated_at: string;
};

type OAuthStateRow = {
  state: string;
  provider: string;
  redirect_to: string | null;
  expires_at: string;
  used_at: string | null;
  created_at: string;
};

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

export const findUserByEmail = async (db: D1Database, email: string): Promise<UserRow | null> =>
  db
    .prepare(
      `SELECT id, email, password_hash, password_salt, full_name, image_url, email_verified, created_at, updated_at
       FROM users
       WHERE email = ?`
    )
    .bind(normalizeEmail(email))
    .first<UserRow>();

export const findUserById = async (db: D1Database, userId: string): Promise<UserRow | null> =>
  db
    .prepare(
      `SELECT id, email, password_hash, password_salt, full_name, image_url, email_verified, created_at, updated_at
       FROM users
       WHERE id = ?`
    )
    .bind(userId)
    .first<UserRow>();

export const createUser = async (
  db: D1Database,
  params: {
    id: string;
    email: string;
    passwordHash?: string | null;
    passwordSalt?: string | null;
    fullName?: string | null;
    imageUrl?: string | null;
    emailVerified?: boolean;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO users (
        id, email, password_hash, password_salt, full_name, image_url, email_verified, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      params.id,
      normalizeEmail(params.email),
      params.passwordHash ?? null,
      params.passwordSalt ?? null,
      params.fullName ?? null,
      params.imageUrl ?? null,
      params.emailVerified ? 1 : 0,
      now,
      now
    )
    .run();
};

export const createSession = async (
  db: D1Database,
  params: {
    id: string;
    userId: string;
    refreshTokenHash: string;
    expiresAt: string;
    userAgent?: string | null;
    ipAddress?: string | null;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO sessions (
        id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, last_active_at, revoked_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`
    )
    .bind(
      params.id,
      params.userId,
      params.refreshTokenHash,
      params.userAgent ?? null,
      params.ipAddress ?? null,
      params.expiresAt,
      now,
      now
    )
    .run();
};

export const rotateSessionRefreshToken = async (
  db: D1Database,
  params: {
    sessionId: string;
    refreshTokenHash: string;
    expiresAt: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `UPDATE sessions
       SET refresh_token_hash = ?, expires_at = ?, last_active_at = ?
       WHERE id = ? AND revoked_at IS NULL`
    )
    .bind(params.refreshTokenHash, params.expiresAt, now, params.sessionId)
    .run();
};

export const findActiveSessionByRefreshTokenHash = async (
  db: D1Database,
  refreshTokenHash: string
): Promise<SessionRow | null> =>
  db
    .prepare(
      `SELECT id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, last_active_at, revoked_at, created_at
       FROM sessions
       WHERE refresh_token_hash = ? AND revoked_at IS NULL`
    )
    .bind(refreshTokenHash)
    .first<SessionRow>();

export const revokeSession = async (db: D1Database, sessionId: string): Promise<void> => {
  await db
    .prepare(`UPDATE sessions SET revoked_at = ?, last_active_at = ? WHERE id = ?`)
    .bind(nowIso(), nowIso(), sessionId)
    .run();
};

export const upsertGoogleProvider = async (
  db: D1Database,
  params: {
    enabled: boolean;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    scope: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO oauth_providers (
        provider, enabled, client_id, client_secret, redirect_uri, scope, updated_at, created_at
      ) VALUES ('google', ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(provider) DO UPDATE SET
        enabled = excluded.enabled,
        client_id = excluded.client_id,
        client_secret = excluded.client_secret,
        redirect_uri = excluded.redirect_uri,
        scope = excluded.scope,
        updated_at = excluded.updated_at`
    )
    .bind(params.enabled ? 1 : 0, params.clientId, params.clientSecret, params.redirectUri, params.scope, now, now)
    .run();
};

export const getGoogleProviderConfig = async (
  db: D1Database,
  env: EnvBindings
): Promise<GoogleProviderConfig> => {
  const row = await db
    .prepare(
      `SELECT provider, enabled, client_id, client_secret, redirect_uri, scope, updated_at, created_at
       FROM oauth_providers
       WHERE provider = 'google'`
    )
    .first<OAuthProviderRow>();

  const envClientId = env.OAUTH_GOOGLE_CLIENT_ID?.trim() ?? "";
  const envClientSecret = env.OAUTH_GOOGLE_CLIENT_SECRET?.trim() ?? "";
  const envRedirectUri = env.OAUTH_GOOGLE_REDIRECT_URI?.trim() ?? "";
  const envScope = env.GOOGLE_DEFAULT_SCOPE?.trim() || "openid email profile";

  const clientId = row?.client_id?.trim() || envClientId;
  const clientSecret = row?.client_secret?.trim() || envClientSecret;
  const redirectUri = row?.redirect_uri?.trim() || envRedirectUri;
  const scope = row?.scope?.trim() || envScope;

  return {
    provider: "google",
    enabled: Boolean(row?.enabled) || Boolean(clientId && clientSecret && redirectUri),
    clientId,
    clientSecret,
    redirectUri,
    scope
  };
};

export const createOAuthState = async (
  db: D1Database,
  params: {
    state: string;
    provider: string;
    redirectTo?: string | null;
    expiresAt: string;
  }
): Promise<void> => {
  await db
    .prepare(
      `INSERT INTO oauth_states (state, provider, redirect_to, expires_at, used_at, created_at)
       VALUES (?, ?, ?, ?, NULL, ?)`
    )
    .bind(params.state, params.provider, params.redirectTo ?? null, params.expiresAt, nowIso())
    .run();
};

export const consumeOAuthState = async (
  db: D1Database,
  state: string,
  provider: string
): Promise<OAuthStateRow | null> => {
  const row = await db
    .prepare(
      `SELECT state, provider, redirect_to, expires_at, used_at, created_at
       FROM oauth_states
       WHERE state = ? AND provider = ?`
    )
    .bind(state, provider)
    .first<OAuthStateRow>();

  if (!row) {
    return null;
  }

  if (row.used_at) {
    return null;
  }

  if (Date.parse(row.expires_at) <= Date.now()) {
    return null;
  }

  await db.prepare(`UPDATE oauth_states SET used_at = ? WHERE state = ?`).bind(nowIso(), state).run();
  return row;
};

export const findOAuthAccount = async (
  db: D1Database,
  provider: string,
  providerUserId: string
): Promise<OAuthAccountRow | null> =>
  db
    .prepare(
      `SELECT id, user_id, provider, provider_user_id, provider_email, access_token, refresh_token, token_expires_at, created_at, updated_at
       FROM oauth_accounts
       WHERE provider = ? AND provider_user_id = ?`
    )
    .bind(provider, providerUserId)
    .first<OAuthAccountRow>();

export const upsertOAuthAccount = async (
  db: D1Database,
  params: {
    id: string;
    userId: string;
    provider: string;
    providerUserId: string;
    providerEmail?: string | null;
    accessToken?: string | null;
    refreshToken?: string | null;
    tokenExpiresAt?: string | null;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO oauth_accounts (
         id, user_id, provider, provider_user_id, provider_email, access_token, refresh_token, token_expires_at, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(provider, provider_user_id) DO UPDATE SET
         user_id = excluded.user_id,
         provider_email = excluded.provider_email,
         access_token = excluded.access_token,
         refresh_token = excluded.refresh_token,
         token_expires_at = excluded.token_expires_at,
         updated_at = excluded.updated_at`
    )
    .bind(
      params.id,
      params.userId,
      params.provider,
      params.providerUserId,
      params.providerEmail ?? null,
      params.accessToken ?? null,
      params.refreshToken ?? null,
      params.tokenExpiresAt ?? null,
      now,
      now
    )
    .run();
};

export const updateUserProfile = async (
  db: D1Database,
  params: {
    userId: string;
    fullName?: string | null;
    imageUrl?: string | null;
    emailVerified?: boolean;
  }
): Promise<void> => {
  await db
    .prepare(
      `UPDATE users
       SET full_name = COALESCE(?, full_name),
           image_url = COALESCE(?, image_url),
           email_verified = CASE WHEN ? IS NULL THEN email_verified ELSE ? END,
           updated_at = ?
       WHERE id = ?`
    )
    .bind(
      params.fullName ?? null,
      params.imageUrl ?? null,
      params.emailVerified === undefined ? null : params.emailVerified ? 1 : 0,
      params.emailVerified === undefined ? null : params.emailVerified ? 1 : 0,
      nowIso(),
      params.userId
    )
    .run();
};

export const writeAuditLog = async (
  db: D1Database,
  params: {
    id: string;
    actorType: string;
    actorId?: string | null;
    eventType: string;
    metadataJson?: string | null;
  }
): Promise<void> => {
  await db
    .prepare(
      `INSERT INTO audit_logs (id, actor_type, actor_id, event_type, metadata_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(params.id, params.actorType, params.actorId ?? null, params.eventType, params.metadataJson ?? null, nowIso())
    .run();
};
