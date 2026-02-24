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

export type SessionRiskEventRow = {
  id: string;
  user_id: string;
  session_id: string;
  risk_score: number;
  reason: string;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
};

export type LatestSessionRiskRow = {
  session_id: string;
  risk_score: number;
  reason: string;
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

export type VerificationCodeRow = {
  id: string;
  user_id: string | null;
  email: string;
  purpose: string;
  code_hash: string;
  expires_at: string;
  used_at: string | null;
  created_at: string;
};

export type PasskeyCredentialRow = {
  id: string;
  user_id: string;
  credential_id: string;
  public_key_spki: string;
  algorithm: string;
  transports_json: string | null;
  name: string | null;
  sign_count: number;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
};

export type PasskeyChallengeRow = {
  id: string;
  user_id: string | null;
  challenge: string;
  purpose: "register" | "authenticate";
  rp_id: string;
  origin: string;
  expires_at: string;
  used_at: string | null;
  created_at: string;
};

export type MfaTotpFactorRow = {
  id: string;
  user_id: string;
  secret_base32: string;
  issuer: string;
  account_name: string;
  verified_at: string | null;
  disabled_at: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
};

export type MfaRecoveryCodeRow = {
  id: string;
  user_id: string;
  code_hash: string;
  used_at: string | null;
  created_at: string;
};

export type MfaChallengeRow = {
  id: string;
  user_id: string;
  purpose: "sign_in";
  metadata_json: string | null;
  expires_at: string;
  used_at: string | null;
  created_at: string;
};

export type AuditLogRow = {
  id: string;
  actor_type: string;
  actor_id: string | null;
  event_type: string;
  metadata_json: string | null;
  created_at: string;
};

type OAuthStateRow = {
  state: string;
  provider: string;
  redirect_to: string | null;
  expires_at: string;
  used_at: string | null;
  created_at: string;
};

export type OrganizationRole = "owner" | "admin" | "member";
export type TeamRole = "maintainer" | "member";

export type OrganizationRow = {
  id: string;
  slug: string;
  name: string;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
};

export type OrganizationMembershipRow = {
  organization_id: string;
  user_id: string;
  role: OrganizationRole;
  created_at: string;
  updated_at: string;
};

export type TeamRow = {
  id: string;
  organization_id: string;
  slug: string;
  name: string;
  created_at: string;
  updated_at: string;
};

export type TeamMembershipRow = {
  team_id: string;
  user_id: string;
  role: TeamRole;
  created_at: string;
  updated_at: string;
};

export type OrganizationPolicySubjectType = "user" | "role" | "team" | "service_account";
export type OrganizationPolicyEffect = "allow" | "deny";

export type OrganizationPolicyRow = {
  id: string;
  organization_id: string;
  subject_type: OrganizationPolicySubjectType;
  subject_id: string;
  resource: string;
  action: string;
  effect: OrganizationPolicyEffect;
  condition_json: string | null;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
};

export type OrganizationListItem = OrganizationRow & {
  membership_role: OrganizationRole;
  membership_created_at: string;
  membership_updated_at: string;
};

export type OrganizationMemberRow = OrganizationMembershipRow & {
  email: string;
  full_name: string | null;
  image_url: string | null;
  email_verified: number;
  user_created_at: string;
  user_updated_at: string;
};

export type TeamListItem = TeamRow & {
  my_role: TeamRole | null;
};

export type TeamMemberRow = TeamMembershipRow & {
  email: string;
  full_name: string | null;
  image_url: string | null;
  email_verified: number;
  user_created_at: string;
  user_updated_at: string;
};

export type ProjectRole = "owner" | "admin" | "member";

export type ProjectRow = {
  id: string;
  slug: string;
  name: string;
  auth_domain: string;
  branding_json: string | null;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
};

export type ProjectMembershipRow = {
  project_id: string;
  user_id: string;
  role: ProjectRole;
  created_at: string;
  updated_at: string;
};

export type ProjectListItem = ProjectRow & {
  membership_role: ProjectRole;
  membership_created_at: string;
  membership_updated_at: string;
};

export type ProjectOAuthProviderRow = {
  project_id: string;
  provider: string;
  enabled: number;
  client_id: string | null;
  client_secret: string | null;
  redirect_uri: string | null;
  scope: string | null;
  created_at: string;
  updated_at: string;
};

export type ServiceAccountRow = {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  created_by_user_id: string;
  disabled_at: string | null;
  created_at: string;
  updated_at: string;
};

export type ApiKeyOwnerType = "user" | "service_account";

export type ApiKeyRow = {
  id: string;
  owner_type: ApiKeyOwnerType;
  owner_user_id: string | null;
  service_account_id: string | null;
  name: string;
  key_prefix: string;
  key_hash: string;
  scopes_json: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
};

export type ScimTokenRow = {
  id: string;
  organization_id: string;
  name: string;
  token_prefix: string;
  token_hash: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
};

export type WebhookEndpointRow = {
  id: string;
  organization_id: string;
  url: string;
  signing_secret: string;
  event_types_json: string | null;
  is_active: number;
  created_by_user_id: string;
  last_delivery_at: string | null;
  created_at: string;
  updated_at: string;
};

export type WebhookDeliveryStatus = "pending" | "success" | "failed";

export type WebhookDeliveryRow = {
  id: string;
  endpoint_id: string;
  event_type: string;
  payload_json: string;
  status: WebhookDeliveryStatus;
  status_code: number | null;
  attempt_count: number;
  next_attempt_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
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

export const findSessionById = async (db: D1Database, sessionId: string): Promise<SessionRow | null> =>
  db
    .prepare(
      `SELECT id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, last_active_at, revoked_at, created_at
       FROM sessions
       WHERE id = ?`
    )
    .bind(sessionId)
    .first<SessionRow>();

export const revokeSession = async (db: D1Database, sessionId: string): Promise<void> => {
  await db
    .prepare(`UPDATE sessions SET revoked_at = ?, last_active_at = ? WHERE id = ?`)
    .bind(nowIso(), nowIso(), sessionId)
    .run();
};

export const listUserSessions = async (db: D1Database, userId: string): Promise<SessionRow[]> => {
  const result = await db
    .prepare(
      `SELECT id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, last_active_at, revoked_at, created_at
       FROM sessions
       WHERE user_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(userId)
    .all<SessionRow>();
  return result.results ?? [];
};

export const createSessionRiskEvent = async (
  db: D1Database,
  params: {
    id: string;
    userId: string;
    sessionId: string;
    riskScore: number;
    reason: string;
    ipAddress?: string | null;
    userAgent?: string | null;
  }
): Promise<void> => {
  await db
    .prepare(
      `INSERT INTO session_risk_events (
        id, user_id, session_id, risk_score, reason, ip_address, user_agent, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      params.id,
      params.userId,
      params.sessionId,
      params.riskScore,
      params.reason,
      params.ipAddress ?? null,
      params.userAgent ?? null,
      nowIso()
    )
    .run();
};

export const listSessionRiskEventsForUser = async (
  db: D1Database,
  params: {
    userId: string;
    limit?: number;
  }
): Promise<SessionRiskEventRow[]> => {
  const result = await db
    .prepare(
      `SELECT id, user_id, session_id, risk_score, reason, ip_address, user_agent, created_at
       FROM session_risk_events
       WHERE user_id = ?
       ORDER BY datetime(created_at) DESC
       LIMIT ?`
    )
    .bind(params.userId, params.limit ?? 100)
    .all<SessionRiskEventRow>();
  return result.results ?? [];
};

export const listLatestSessionRiskForUser = async (
  db: D1Database,
  userId: string
): Promise<LatestSessionRiskRow[]> => {
  const result = await db
    .prepare(
      `SELECT e.session_id,
              e.risk_score,
              e.reason,
              e.created_at
       FROM session_risk_events e
       INNER JOIN (
         SELECT session_id, MAX(created_at) AS max_created_at
         FROM session_risk_events
         WHERE user_id = ?
         GROUP BY session_id
       ) latest ON latest.session_id = e.session_id AND latest.max_created_at = e.created_at
       WHERE e.user_id = ?`
    )
    .bind(userId, userId)
    .all<LatestSessionRiskRow>();
  return result.results ?? [];
};

export const revokeUserSession = async (
  db: D1Database,
  params: {
    userId: string;
    sessionId: string;
  }
): Promise<boolean> => {
  const result = await db
    .prepare(
      `UPDATE sessions
       SET revoked_at = ?, last_active_at = ?
       WHERE id = ? AND user_id = ? AND revoked_at IS NULL`
    )
    .bind(nowIso(), nowIso(), params.sessionId, params.userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const revokeOtherUserSessions = async (
  db: D1Database,
  params: {
    userId: string;
    exceptSessionId: string;
  }
): Promise<number> => {
  const result = await db
    .prepare(
      `UPDATE sessions
       SET revoked_at = ?, last_active_at = ?
       WHERE user_id = ? AND id <> ? AND revoked_at IS NULL`
    )
    .bind(nowIso(), nowIso(), params.userId, params.exceptSessionId)
    .run();
  return result.meta.changes ?? 0;
};

export const revokeAllUserSessions = async (
  db: D1Database,
  params: {
    userId: string;
  }
): Promise<number> => {
  const result = await db
    .prepare(
      `UPDATE sessions
       SET revoked_at = ?, last_active_at = ?
       WHERE user_id = ? AND revoked_at IS NULL`
    )
    .bind(nowIso(), nowIso(), params.userId)
    .run();
  return result.meta.changes ?? 0;
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

export const getEffectiveGoogleProviderConfig = async (
  db: D1Database,
  env: EnvBindings,
  request: Request
): Promise<GoogleProviderConfig> => {
  const requestUrl = new URL(request.url);
  const host = requestUrl.host.toLowerCase();
  const hostname = requestUrl.hostname.toLowerCase();
  const project = (await findProjectByAuthDomain(db, host)) ?? (await findProjectByAuthDomain(db, hostname));
  if (project) {
    const projectProvider = await getProjectGoogleProviderConfig(db, project.id);
    const clientId = projectProvider?.client_id?.trim() ?? "";
    const clientSecret = projectProvider?.client_secret?.trim() ?? "";
    const redirectUri = projectProvider?.redirect_uri?.trim() ?? "";
    const scope = projectProvider?.scope?.trim() || env.GOOGLE_DEFAULT_SCOPE?.trim() || "openid email profile";
    const enabled = Boolean(projectProvider?.enabled) && Boolean(clientId && clientSecret && redirectUri);
    if (enabled) {
      return {
        provider: "google",
        enabled,
        clientId,
        clientSecret,
        redirectUri,
        scope
      };
    }
  }
  return getGoogleProviderConfig(db, env);
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

export const updateUserEmailVerification = async (
  db: D1Database,
  params: {
    userId: string;
    emailVerified: boolean;
  }
): Promise<void> => {
  await db
    .prepare(
      `UPDATE users
       SET email_verified = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(params.emailVerified ? 1 : 0, nowIso(), params.userId)
    .run();
};

export const updateUserPassword = async (
  db: D1Database,
  params: {
    userId: string;
    passwordHash: string;
    passwordSalt: string;
  }
): Promise<void> => {
  await db
    .prepare(
      `UPDATE users
       SET password_hash = ?, password_salt = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(params.passwordHash, params.passwordSalt, nowIso(), params.userId)
    .run();
};

export const invalidateVerificationCodes = async (
  db: D1Database,
  params: {
    purpose: string;
    userId?: string;
    email?: string;
  }
): Promise<number> => {
  const now = nowIso();
  if (params.userId) {
    const result = await db
      .prepare(
        `UPDATE verification_codes
         SET used_at = ?
         WHERE purpose = ? AND user_id = ? AND used_at IS NULL`
      )
      .bind(now, params.purpose, params.userId)
      .run();
    return result.meta.changes ?? 0;
  }
  if (params.email) {
    const result = await db
      .prepare(
        `UPDATE verification_codes
         SET used_at = ?
         WHERE purpose = ? AND email = ? AND used_at IS NULL`
      )
      .bind(now, params.purpose, normalizeEmail(params.email))
      .run();
    return result.meta.changes ?? 0;
  }
  return 0;
};

export const createVerificationCode = async (
  db: D1Database,
  params: {
    id: string;
    userId?: string | null;
    email: string;
    purpose: string;
    codeHash: string;
    expiresAt: string;
  }
): Promise<void> => {
  await db
    .prepare(
      `INSERT INTO verification_codes (
        id, user_id, email, purpose, code_hash, expires_at, used_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`
    )
    .bind(
      params.id,
      params.userId ?? null,
      normalizeEmail(params.email),
      params.purpose,
      params.codeHash,
      params.expiresAt,
      nowIso()
    )
    .run();
};

export const consumeVerificationCodeByHash = async (
  db: D1Database,
  params: {
    purpose: string;
    codeHash: string;
  }
): Promise<VerificationCodeRow | null> => {
  const row = await db
    .prepare(
      `SELECT id, user_id, email, purpose, code_hash, expires_at, used_at, created_at
       FROM verification_codes
       WHERE purpose = ? AND code_hash = ?`
    )
    .bind(params.purpose, params.codeHash)
    .first<VerificationCodeRow>();

  if (!row || row.used_at || Date.parse(row.expires_at) <= Date.now()) {
    return null;
  }

  const result = await db
    .prepare(`UPDATE verification_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`)
    .bind(nowIso(), row.id)
    .run();

  if ((result.meta.changes ?? 0) === 0) {
    return null;
  }

  return row;
};

export const createPasskeyChallenge = async (
  db: D1Database,
  params: {
    id: string;
    userId?: string | null;
    challenge: string;
    purpose: "register" | "authenticate";
    rpId: string;
    origin: string;
    expiresAt: string;
  }
): Promise<void> => {
  await db
    .prepare(
      `INSERT INTO passkey_challenges (
        id, user_id, challenge, purpose, rp_id, origin, expires_at, used_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`
    )
    .bind(
      params.id,
      params.userId ?? null,
      params.challenge,
      params.purpose,
      params.rpId,
      params.origin,
      params.expiresAt,
      nowIso()
    )
    .run();
};

export const consumePasskeyChallengeById = async (
  db: D1Database,
  params: {
    id: string;
    purpose: "register" | "authenticate";
  }
): Promise<PasskeyChallengeRow | null> => {
  const row = await db
    .prepare(
      `SELECT id, user_id, challenge, purpose, rp_id, origin, expires_at, used_at, created_at
       FROM passkey_challenges
       WHERE id = ? AND purpose = ?`
    )
    .bind(params.id, params.purpose)
    .first<PasskeyChallengeRow>();
  if (!row || row.used_at || Date.parse(row.expires_at) <= Date.now()) {
    return null;
  }
  const result = await db
    .prepare(`UPDATE passkey_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL`)
    .bind(nowIso(), row.id)
    .run();
  if ((result.meta.changes ?? 0) === 0) {
    return null;
  }
  return row;
};

export const createPasskeyCredential = async (
  db: D1Database,
  params: {
    id: string;
    userId: string;
    credentialId: string;
    publicKeySpki: string;
    algorithm?: string;
    transportsJson?: string | null;
    name?: string | null;
    signCount?: number;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO passkey_credentials (
        id,
        user_id,
        credential_id,
        public_key_spki,
        algorithm,
        transports_json,
        name,
        sign_count,
        last_used_at,
        revoked_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
      ON CONFLICT (credential_id) DO UPDATE SET
        user_id = excluded.user_id,
        public_key_spki = excluded.public_key_spki,
        algorithm = excluded.algorithm,
        transports_json = excluded.transports_json,
        name = excluded.name,
        sign_count = excluded.sign_count,
        revoked_at = NULL,
        updated_at = excluded.updated_at`
    )
    .bind(
      params.id,
      params.userId,
      params.credentialId,
      params.publicKeySpki,
      params.algorithm ?? "ES256",
      params.transportsJson ?? null,
      params.name ?? null,
      params.signCount ?? 0,
      now,
      now
    )
    .run();
};

export const listPasskeyCredentialsForUser = async (
  db: D1Database,
  userId: string
): Promise<PasskeyCredentialRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              user_id,
              credential_id,
              public_key_spki,
              algorithm,
              transports_json,
              name,
              sign_count,
              last_used_at,
              revoked_at,
              created_at,
              updated_at
       FROM passkey_credentials
       WHERE user_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(userId)
    .all<PasskeyCredentialRow>();
  return result.results ?? [];
};

export const listActivePasskeyCredentialsForUser = async (
  db: D1Database,
  userId: string
): Promise<PasskeyCredentialRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              user_id,
              credential_id,
              public_key_spki,
              algorithm,
              transports_json,
              name,
              sign_count,
              last_used_at,
              revoked_at,
              created_at,
              updated_at
       FROM passkey_credentials
       WHERE user_id = ? AND revoked_at IS NULL
       ORDER BY datetime(created_at) DESC`
    )
    .bind(userId)
    .all<PasskeyCredentialRow>();
  return result.results ?? [];
};

export const findActivePasskeyCredentialByCredentialId = async (
  db: D1Database,
  credentialId: string
): Promise<PasskeyCredentialRow | null> =>
  db
    .prepare(
      `SELECT id,
              user_id,
              credential_id,
              public_key_spki,
              algorithm,
              transports_json,
              name,
              sign_count,
              last_used_at,
              revoked_at,
              created_at,
              updated_at
       FROM passkey_credentials
       WHERE credential_id = ? AND revoked_at IS NULL`
    )
    .bind(credentialId)
    .first<PasskeyCredentialRow>();

export const touchPasskeyCredentialUsage = async (
  db: D1Database,
  params: {
    credentialId: string;
    nextSignCount: number;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `UPDATE passkey_credentials
       SET sign_count = ?,
           last_used_at = ?,
           updated_at = ?
       WHERE credential_id = ?`
    )
    .bind(params.nextSignCount, now, now, params.credentialId)
    .run();
};

export const createTotpFactor = async (
  db: D1Database,
  params: {
    id: string;
    userId: string;
    secretBase32: string;
    issuer: string;
    accountName: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO mfa_totp_factors (
        id, user_id, secret_base32, issuer, account_name, verified_at, disabled_at, last_used_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`
    )
    .bind(params.id, params.userId, params.secretBase32, params.issuer, params.accountName, now, now)
    .run();
};

export const findTotpFactorByIdForUser = async (
  db: D1Database,
  params: {
    factorId: string;
    userId: string;
  }
): Promise<MfaTotpFactorRow | null> =>
  db
    .prepare(
      `SELECT id,
              user_id,
              secret_base32,
              issuer,
              account_name,
              verified_at,
              disabled_at,
              last_used_at,
              created_at,
              updated_at
       FROM mfa_totp_factors
       WHERE id = ? AND user_id = ?`
    )
    .bind(params.factorId, params.userId)
    .first<MfaTotpFactorRow>();

export const findActiveVerifiedTotpFactorForUser = async (
  db: D1Database,
  userId: string
): Promise<MfaTotpFactorRow | null> =>
  db
    .prepare(
      `SELECT id,
              user_id,
              secret_base32,
              issuer,
              account_name,
              verified_at,
              disabled_at,
              last_used_at,
              created_at,
              updated_at
       FROM mfa_totp_factors
       WHERE user_id = ?
         AND verified_at IS NOT NULL
         AND disabled_at IS NULL
       ORDER BY datetime(verified_at) DESC
       LIMIT 1`
    )
    .bind(userId)
    .first<MfaTotpFactorRow>();

export const listTotpFactorsForUser = async (db: D1Database, userId: string): Promise<MfaTotpFactorRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              user_id,
              secret_base32,
              issuer,
              account_name,
              verified_at,
              disabled_at,
              last_used_at,
              created_at,
              updated_at
       FROM mfa_totp_factors
       WHERE user_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(userId)
    .all<MfaTotpFactorRow>();
  return result.results ?? [];
};

export const verifyTotpFactor = async (
  db: D1Database,
  params: {
    factorId: string;
    userId: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE mfa_totp_factors
       SET verified_at = COALESCE(verified_at, ?),
           disabled_at = NULL,
           updated_at = ?
       WHERE id = ? AND user_id = ?`
    )
    .bind(now, now, params.factorId, params.userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const disableTotpFactorsForUser = async (
  db: D1Database,
  params: {
    userId: string;
  }
): Promise<number> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE mfa_totp_factors
       SET disabled_at = ?, updated_at = ?
       WHERE user_id = ? AND disabled_at IS NULL`
    )
    .bind(now, now, params.userId)
    .run();
  return result.meta.changes ?? 0;
};

export const touchTotpFactorUsage = async (db: D1Database, factorId: string): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `UPDATE mfa_totp_factors
       SET last_used_at = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(now, now, factorId)
    .run();
};

export const replaceRecoveryCodes = async (
  db: D1Database,
  params: {
    userId: string;
    codeHashes: string[];
  }
): Promise<void> => {
  const now = nowIso();
  const statements: D1PreparedStatement[] = [
    db.prepare(`DELETE FROM mfa_recovery_codes WHERE user_id = ?`).bind(params.userId)
  ];
  for (const codeHash of params.codeHashes) {
    statements.push(
      db
        .prepare(
          `INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used_at, created_at)
           VALUES (?, ?, ?, NULL, ?)`
        )
        .bind(crypto.randomUUID(), params.userId, codeHash, now)
    );
  }
  await db.batch(statements);
};

export const countRemainingRecoveryCodes = async (db: D1Database, userId: string): Promise<number> => {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS count
       FROM mfa_recovery_codes
       WHERE user_id = ? AND used_at IS NULL`
    )
    .bind(userId)
    .first<{ count: number }>();
  return row?.count ?? 0;
};

export const consumeRecoveryCodeHash = async (
  db: D1Database,
  params: {
    userId: string;
    codeHash: string;
  }
): Promise<MfaRecoveryCodeRow | null> => {
  const row = await db
    .prepare(
      `SELECT id, user_id, code_hash, used_at, created_at
       FROM mfa_recovery_codes
       WHERE user_id = ? AND code_hash = ?`
    )
    .bind(params.userId, params.codeHash)
    .first<MfaRecoveryCodeRow>();
  if (!row || row.used_at) {
    return null;
  }
  const result = await db
    .prepare(`UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`)
    .bind(nowIso(), row.id)
    .run();
  if ((result.meta.changes ?? 0) === 0) {
    return null;
  }
  return row;
};

export const createMfaChallenge = async (
  db: D1Database,
  params: {
    id: string;
    userId: string;
    purpose: "sign_in";
    metadataJson?: string | null;
    expiresAt: string;
  }
): Promise<void> => {
  await db
    .prepare(
      `INSERT INTO mfa_challenges (
        id, user_id, purpose, metadata_json, expires_at, used_at, created_at
      ) VALUES (?, ?, ?, ?, ?, NULL, ?)`
    )
    .bind(params.id, params.userId, params.purpose, params.metadataJson ?? null, params.expiresAt, nowIso())
    .run();
};

export const consumeMfaChallengeById = async (
  db: D1Database,
  params: {
    challengeId: string;
    purpose: "sign_in";
  }
): Promise<MfaChallengeRow | null> => {
  const row = await db
    .prepare(
      `SELECT id, user_id, purpose, metadata_json, expires_at, used_at, created_at
       FROM mfa_challenges
       WHERE id = ? AND purpose = ?`
    )
    .bind(params.challengeId, params.purpose)
    .first<MfaChallengeRow>();
  if (!row || row.used_at || Date.parse(row.expires_at) <= Date.now()) {
    return null;
  }
  const result = await db
    .prepare(`UPDATE mfa_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL`)
    .bind(nowIso(), row.id)
    .run();
  if ((result.meta.changes ?? 0) === 0) {
    return null;
  }
  return row;
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

export const listAuditLogs = async (
  db: D1Database,
  params?: {
    limit?: number;
    actorType?: string;
    eventType?: string;
  }
): Promise<AuditLogRow[]> => {
  const limit = params?.limit && params.limit > 0 ? Math.min(params.limit, 500) : 100;
  if (params?.actorType && params?.eventType) {
    const result = await db
      .prepare(
        `SELECT id, actor_type, actor_id, event_type, metadata_json, created_at
         FROM audit_logs
         WHERE actor_type = ? AND event_type = ?
         ORDER BY datetime(created_at) DESC
         LIMIT ?`
      )
      .bind(params.actorType, params.eventType, limit)
      .all<AuditLogRow>();
    return result.results ?? [];
  }
  if (params?.actorType) {
    const result = await db
      .prepare(
        `SELECT id, actor_type, actor_id, event_type, metadata_json, created_at
         FROM audit_logs
         WHERE actor_type = ?
         ORDER BY datetime(created_at) DESC
         LIMIT ?`
      )
      .bind(params.actorType, limit)
      .all<AuditLogRow>();
    return result.results ?? [];
  }
  if (params?.eventType) {
    const result = await db
      .prepare(
        `SELECT id, actor_type, actor_id, event_type, metadata_json, created_at
         FROM audit_logs
         WHERE event_type = ?
         ORDER BY datetime(created_at) DESC
         LIMIT ?`
      )
      .bind(params.eventType, limit)
      .all<AuditLogRow>();
    return result.results ?? [];
  }
  const result = await db
    .prepare(
      `SELECT id, actor_type, actor_id, event_type, metadata_json, created_at
       FROM audit_logs
       ORDER BY datetime(created_at) DESC
       LIMIT ?`
    )
    .bind(limit)
    .all<AuditLogRow>();
  return result.results ?? [];
};

export const findOrganizationBySlug = async (
  db: D1Database,
  slug: string
): Promise<OrganizationRow | null> =>
  db
    .prepare(
      `SELECT id, slug, name, created_by_user_id, created_at, updated_at
       FROM organizations
       WHERE slug = ?`
    )
    .bind(slug)
    .first<OrganizationRow>();

export const findOrganizationById = async (
  db: D1Database,
  organizationId: string
): Promise<OrganizationRow | null> =>
  db
    .prepare(
      `SELECT id, slug, name, created_by_user_id, created_at, updated_at
       FROM organizations
       WHERE id = ?`
    )
    .bind(organizationId)
    .first<OrganizationRow>();

export const createOrganizationWithOwner = async (
  db: D1Database,
  params: {
    id: string;
    slug: string;
    name: string;
    ownerUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db.batch([
    db
      .prepare(
        `INSERT INTO organizations (id, slug, name, created_by_user_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(params.id, params.slug, params.name, params.ownerUserId, now, now),
    db
      .prepare(
        `INSERT INTO organization_memberships (organization_id, user_id, role, created_at, updated_at)
         VALUES (?, ?, 'owner', ?, ?)`
      )
      .bind(params.id, params.ownerUserId, now, now)
  ]);
};

export const listOrganizationsForUser = async (
  db: D1Database,
  userId: string
): Promise<OrganizationListItem[]> => {
  const result = await db
    .prepare(
      `SELECT o.id,
              o.slug,
              o.name,
              o.created_by_user_id,
              o.created_at,
              o.updated_at,
              m.role AS membership_role,
              m.created_at AS membership_created_at,
              m.updated_at AS membership_updated_at
       FROM organization_memberships m
       INNER JOIN organizations o ON o.id = m.organization_id
       WHERE m.user_id = ?
       ORDER BY lower(o.name) ASC`
    )
    .bind(userId)
    .all<OrganizationListItem>();
  return result.results ?? [];
};

export const createProjectWithOwner = async (
  db: D1Database,
  params: {
    id: string;
    slug: string;
    name: string;
    authDomain: string;
    brandingJson?: string | null;
    ownerUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db.batch([
    db
      .prepare(
        `INSERT INTO projects (
          id, slug, name, auth_domain, branding_json, created_by_user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        params.id,
        params.slug,
        params.name,
        params.authDomain.toLowerCase(),
        params.brandingJson ?? null,
        params.ownerUserId,
        now,
        now
      ),
    db
      .prepare(
        `INSERT INTO project_memberships (project_id, user_id, role, created_at, updated_at)
         VALUES (?, ?, 'owner', ?, ?)`
      )
      .bind(params.id, params.ownerUserId, now, now)
  ]);
};

export const findProjectById = async (db: D1Database, projectId: string): Promise<ProjectRow | null> =>
  db
    .prepare(
      `SELECT id, slug, name, auth_domain, branding_json, created_by_user_id, created_at, updated_at
       FROM projects
       WHERE id = ?`
    )
    .bind(projectId)
    .first<ProjectRow>();

export const findProjectBySlug = async (db: D1Database, slug: string): Promise<ProjectRow | null> =>
  db
    .prepare(
      `SELECT id, slug, name, auth_domain, branding_json, created_by_user_id, created_at, updated_at
       FROM projects
       WHERE slug = ?`
    )
    .bind(slug)
    .first<ProjectRow>();

export const findProjectByAuthDomain = async (
  db: D1Database,
  authDomain: string
): Promise<ProjectRow | null> =>
  db
    .prepare(
      `SELECT id, slug, name, auth_domain, branding_json, created_by_user_id, created_at, updated_at
       FROM projects
       WHERE lower(auth_domain) = lower(?)`
    )
    .bind(authDomain)
    .first<ProjectRow>();

export const findProjectMembership = async (
  db: D1Database,
  params: {
    projectId: string;
    userId: string;
  }
): Promise<ProjectMembershipRow | null> =>
  db
    .prepare(
      `SELECT project_id, user_id, role, created_at, updated_at
       FROM project_memberships
       WHERE project_id = ? AND user_id = ?`
    )
    .bind(params.projectId, params.userId)
    .first<ProjectMembershipRow>();

export const listProjectsForUser = async (
  db: D1Database,
  userId: string
): Promise<ProjectListItem[]> => {
  const result = await db
    .prepare(
      `SELECT p.id,
              p.slug,
              p.name,
              p.auth_domain,
              p.branding_json,
              p.created_by_user_id,
              p.created_at,
              p.updated_at,
              m.role AS membership_role,
              m.created_at AS membership_created_at,
              m.updated_at AS membership_updated_at
       FROM project_memberships m
       INNER JOIN projects p ON p.id = m.project_id
       WHERE m.user_id = ?
       ORDER BY lower(p.name) ASC`
    )
    .bind(userId)
    .all<ProjectListItem>();
  return result.results ?? [];
};

export const upsertProjectGoogleProvider = async (
  db: D1Database,
  params: {
    projectId: string;
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
      `INSERT INTO project_oauth_providers (
        project_id, provider, enabled, client_id, client_secret, redirect_uri, scope, created_at, updated_at
      ) VALUES (?, 'google', ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_id, provider) DO UPDATE SET
        enabled = excluded.enabled,
        client_id = excluded.client_id,
        client_secret = excluded.client_secret,
        redirect_uri = excluded.redirect_uri,
        scope = excluded.scope,
        updated_at = excluded.updated_at`
    )
    .bind(
      params.projectId,
      params.enabled ? 1 : 0,
      params.clientId,
      params.clientSecret,
      params.redirectUri,
      params.scope,
      now,
      now
    )
    .run();
};

export const getProjectGoogleProviderConfig = async (
  db: D1Database,
  projectId: string
): Promise<ProjectOAuthProviderRow | null> =>
  db
    .prepare(
      `SELECT project_id, provider, enabled, client_id, client_secret, redirect_uri, scope, created_at, updated_at
       FROM project_oauth_providers
       WHERE project_id = ? AND provider = 'google'`
    )
    .bind(projectId)
    .first<ProjectOAuthProviderRow>();

export const countOrganizationMembers = async (db: D1Database, organizationId: string): Promise<number> => {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS count
       FROM organization_memberships
       WHERE organization_id = ?`
    )
    .bind(organizationId)
    .first<{ count: number }>();
  return row?.count ?? 0;
};

export const findOrganizationMembership = async (
  db: D1Database,
  organizationId: string,
  userId: string
): Promise<OrganizationMembershipRow | null> =>
  db
    .prepare(
      `SELECT organization_id, user_id, role, created_at, updated_at
       FROM organization_memberships
       WHERE organization_id = ? AND user_id = ?`
    )
    .bind(organizationId, userId)
    .first<OrganizationMembershipRow>();

export const listOrganizationMembers = async (
  db: D1Database,
  organizationId: string
): Promise<OrganizationMemberRow[]> => {
  const result = await db
    .prepare(
      `SELECT m.organization_id,
              m.user_id,
              m.role,
              m.created_at,
              m.updated_at,
              u.email,
              u.full_name,
              u.image_url,
              u.email_verified,
              u.created_at AS user_created_at,
              u.updated_at AS user_updated_at
       FROM organization_memberships m
       INNER JOIN users u ON u.id = m.user_id
       WHERE m.organization_id = ?
       ORDER BY CASE m.role
         WHEN 'owner' THEN 0
         WHEN 'admin' THEN 1
         ELSE 2
       END ASC,
       lower(u.email) ASC`
    )
    .bind(organizationId)
    .all<OrganizationMemberRow>();
  return result.results ?? [];
};

export const countOrganizationOwners = async (db: D1Database, organizationId: string): Promise<number> => {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS count
       FROM organization_memberships
       WHERE organization_id = ? AND role = 'owner'`
    )
    .bind(organizationId)
    .first<{ count: number }>();
  return row?.count ?? 0;
};

export const listOrganizationPolicies = async (
  db: D1Database,
  organizationId: string
): Promise<OrganizationPolicyRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              subject_type,
              subject_id,
              resource,
              action,
              effect,
              condition_json,
              created_by_user_id,
              created_at,
              updated_at
       FROM organization_policies
       WHERE organization_id = ?
       ORDER BY datetime(updated_at) DESC`
    )
    .bind(organizationId)
    .all<OrganizationPolicyRow>();
  return result.results ?? [];
};

export const upsertOrganizationPolicy = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    subjectType: OrganizationPolicySubjectType;
    subjectId: string;
    resource: string;
    action: string;
    effect: OrganizationPolicyEffect;
    conditionJson?: string | null;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO organization_policies (
        id,
        organization_id,
        subject_type,
        subject_id,
        resource,
        action,
        effect,
        condition_json,
        created_by_user_id,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (organization_id, subject_type, subject_id, resource, action) DO UPDATE SET
        effect = excluded.effect,
        condition_json = excluded.condition_json,
        updated_at = excluded.updated_at`
    )
    .bind(
      params.id,
      params.organizationId,
      params.subjectType,
      params.subjectId,
      params.resource,
      params.action,
      params.effect,
      params.conditionJson ?? null,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const removeOrganizationPolicy = async (
  db: D1Database,
  params: {
    organizationId: string;
    policyId: string;
  }
): Promise<boolean> => {
  const result = await db
    .prepare(
      `DELETE FROM organization_policies
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.policyId, params.organizationId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const listApplicableOrganizationPolicies = async (
  db: D1Database,
  params: {
    organizationId: string;
    userId: string;
    role: OrganizationRole;
    resource: string;
    action: string;
  }
): Promise<OrganizationPolicyRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              subject_type,
              subject_id,
              resource,
              action,
              effect,
              condition_json,
              created_by_user_id,
              created_at,
              updated_at
       FROM organization_policies
       WHERE organization_id = ?
         AND (
           (subject_type = 'user' AND subject_id = ?)
           OR (subject_type = 'role' AND subject_id = ?)
         )
         AND (resource = ? OR resource = '*')
         AND (action = ? OR action = '*')
       ORDER BY CASE effect
         WHEN 'deny' THEN 0
         ELSE 1
       END ASC,
       datetime(updated_at) DESC`
    )
    .bind(params.organizationId, params.userId, params.role, params.resource, params.action)
    .all<OrganizationPolicyRow>();
  return result.results ?? [];
};

export const upsertOrganizationMembership = async (
  db: D1Database,
  params: {
    organizationId: string;
    userId: string;
    role: OrganizationRole;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO organization_memberships (organization_id, user_id, role, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (organization_id, user_id) DO UPDATE SET
         role = excluded.role,
         updated_at = excluded.updated_at`
    )
    .bind(params.organizationId, params.userId, params.role, now, now)
    .run();
};

export const removeOrganizationMembership = async (
  db: D1Database,
  params: {
    organizationId: string;
    userId: string;
  }
): Promise<boolean> => {
  const result = await db
    .prepare(
      `DELETE FROM organization_memberships
       WHERE organization_id = ? AND user_id = ?`
    )
    .bind(params.organizationId, params.userId)
    .run();

  await db
    .prepare(
      `DELETE FROM team_memberships
       WHERE user_id = ?
         AND team_id IN (
           SELECT id FROM teams WHERE organization_id = ?
         )`
    )
    .bind(params.userId, params.organizationId)
    .run();

  return (result.meta.changes ?? 0) > 0;
};

export const findTeamByIdInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    teamId: string;
  }
): Promise<TeamRow | null> =>
  db
    .prepare(
      `SELECT id, organization_id, slug, name, created_at, updated_at
       FROM teams
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.teamId, params.organizationId)
    .first<TeamRow>();

export const findTeamBySlugInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    slug: string;
  }
): Promise<TeamRow | null> =>
  db
    .prepare(
      `SELECT id, organization_id, slug, name, created_at, updated_at
       FROM teams
       WHERE organization_id = ? AND slug = ?`
    )
    .bind(params.organizationId, params.slug)
    .first<TeamRow>();

export const createTeam = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    slug: string;
    name: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO teams (id, organization_id, slug, name, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(params.id, params.organizationId, params.slug, params.name, now, now)
    .run();
};

export const countOrganizationTeams = async (db: D1Database, organizationId: string): Promise<number> => {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS count
       FROM teams
       WHERE organization_id = ?`
    )
    .bind(organizationId)
    .first<{ count: number }>();
  return row?.count ?? 0;
};

export const listTeamsForUserInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    userId: string;
  }
): Promise<TeamListItem[]> => {
  const result = await db
    .prepare(
      `SELECT t.id,
              t.organization_id,
              t.slug,
              t.name,
              t.created_at,
              t.updated_at,
              tm.role AS my_role
       FROM teams t
       LEFT JOIN team_memberships tm ON tm.team_id = t.id AND tm.user_id = ?
       WHERE t.organization_id = ?
       ORDER BY lower(t.name) ASC`
    )
    .bind(params.userId, params.organizationId)
    .all<TeamListItem>();
  return result.results ?? [];
};

export const findTeamMembership = async (
  db: D1Database,
  params: {
    teamId: string;
    userId: string;
  }
): Promise<TeamMembershipRow | null> =>
  db
    .prepare(
      `SELECT team_id, user_id, role, created_at, updated_at
       FROM team_memberships
       WHERE team_id = ? AND user_id = ?`
    )
    .bind(params.teamId, params.userId)
    .first<TeamMembershipRow>();

export const upsertTeamMembership = async (
  db: D1Database,
  params: {
    teamId: string;
    userId: string;
    role: TeamRole;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO team_memberships (team_id, user_id, role, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (team_id, user_id) DO UPDATE SET
         role = excluded.role,
         updated_at = excluded.updated_at`
    )
    .bind(params.teamId, params.userId, params.role, now, now)
    .run();
};

export const removeTeamMembership = async (
  db: D1Database,
  params: {
    teamId: string;
    userId: string;
  }
): Promise<boolean> => {
  const result = await db
    .prepare(
      `DELETE FROM team_memberships
       WHERE team_id = ? AND user_id = ?`
    )
    .bind(params.teamId, params.userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const listTeamMembers = async (db: D1Database, teamId: string): Promise<TeamMemberRow[]> => {
  const result = await db
    .prepare(
      `SELECT tm.team_id,
              tm.user_id,
              tm.role,
              tm.created_at,
              tm.updated_at,
              u.email,
              u.full_name,
              u.image_url,
              u.email_verified,
              u.created_at AS user_created_at,
              u.updated_at AS user_updated_at
       FROM team_memberships tm
       INNER JOIN users u ON u.id = tm.user_id
       WHERE tm.team_id = ?
       ORDER BY CASE tm.role
         WHEN 'maintainer' THEN 0
         ELSE 1
       END ASC,
       lower(u.email) ASC`
    )
    .bind(teamId)
    .all<TeamMemberRow>();
  return result.results ?? [];
};

export const createServiceAccount = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    name: string;
    description?: string | null;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO service_accounts (
        id, organization_id, name, description, created_by_user_id, disabled_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)`
    )
    .bind(
      params.id,
      params.organizationId,
      params.name,
      params.description ?? null,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const findServiceAccountByIdInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    serviceAccountId: string;
  }
): Promise<ServiceAccountRow | null> =>
  db
    .prepare(
      `SELECT id, organization_id, name, description, created_by_user_id, disabled_at, created_at, updated_at
       FROM service_accounts
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.serviceAccountId, params.organizationId)
    .first<ServiceAccountRow>();

export const findServiceAccountById = async (
  db: D1Database,
  serviceAccountId: string
): Promise<ServiceAccountRow | null> =>
  db
    .prepare(
      `SELECT id, organization_id, name, description, created_by_user_id, disabled_at, created_at, updated_at
       FROM service_accounts
       WHERE id = ?`
    )
    .bind(serviceAccountId)
    .first<ServiceAccountRow>();

export const listServiceAccountsForOrganization = async (
  db: D1Database,
  organizationId: string
): Promise<ServiceAccountRow[]> => {
  const result = await db
    .prepare(
      `SELECT id, organization_id, name, description, created_by_user_id, disabled_at, created_at, updated_at
       FROM service_accounts
       WHERE organization_id = ?
       ORDER BY lower(name) ASC`
    )
    .bind(organizationId)
    .all<ServiceAccountRow>();
  return result.results ?? [];
};

export const disableServiceAccount = async (
  db: D1Database,
  params: {
    organizationId: string;
    serviceAccountId: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE service_accounts
       SET disabled_at = ?, updated_at = ?
       WHERE id = ? AND organization_id = ? AND disabled_at IS NULL`
    )
    .bind(now, now, params.serviceAccountId, params.organizationId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const createApiKey = async (
  db: D1Database,
  params: {
    id: string;
    ownerType: ApiKeyOwnerType;
    ownerUserId?: string | null;
    serviceAccountId?: string | null;
    name: string;
    keyPrefix: string;
    keyHash: string;
    scopesJson?: string | null;
    expiresAt?: string | null;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO api_keys (
        id,
        owner_type,
        owner_user_id,
        service_account_id,
        name,
        key_prefix,
        key_hash,
        scopes_json,
        expires_at,
        last_used_at,
        revoked_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)`
    )
    .bind(
      params.id,
      params.ownerType,
      params.ownerUserId ?? null,
      params.serviceAccountId ?? null,
      params.name,
      params.keyPrefix,
      params.keyHash,
      params.scopesJson ?? null,
      params.expiresAt ?? null,
      now,
      now
    )
    .run();
};

export const findActiveApiKeyByHash = async (
  db: D1Database,
  keyHash: string
): Promise<ApiKeyRow | null> => {
  const row = await db
    .prepare(
      `SELECT id,
              owner_type,
              owner_user_id,
              service_account_id,
              name,
              key_prefix,
              key_hash,
              scopes_json,
              expires_at,
              last_used_at,
              revoked_at,
              created_at,
              updated_at
       FROM api_keys
       WHERE key_hash = ? AND revoked_at IS NULL`
    )
    .bind(keyHash)
    .first<ApiKeyRow>();

  if (!row) {
    return null;
  }
  if (row.expires_at && Date.parse(row.expires_at) <= Date.now()) {
    return null;
  }
  return row;
};

export const touchApiKeyUsage = async (db: D1Database, apiKeyId: string): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `UPDATE api_keys
       SET last_used_at = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(now, now, apiKeyId)
    .run();
};

export const listUserApiKeys = async (db: D1Database, userId: string): Promise<ApiKeyRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              owner_type,
              owner_user_id,
              service_account_id,
              name,
              key_prefix,
              key_hash,
              scopes_json,
              expires_at,
              last_used_at,
              revoked_at,
              created_at,
              updated_at
       FROM api_keys
       WHERE owner_type = 'user' AND owner_user_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(userId)
    .all<ApiKeyRow>();
  return result.results ?? [];
};

export const listServiceAccountApiKeys = async (
  db: D1Database,
  serviceAccountId: string
): Promise<ApiKeyRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              owner_type,
              owner_user_id,
              service_account_id,
              name,
              key_prefix,
              key_hash,
              scopes_json,
              expires_at,
              last_used_at,
              revoked_at,
              created_at,
              updated_at
       FROM api_keys
       WHERE owner_type = 'service_account' AND service_account_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(serviceAccountId)
    .all<ApiKeyRow>();
  return result.results ?? [];
};

export const revokeUserApiKey = async (
  db: D1Database,
  params: {
    userId: string;
    apiKeyId: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE api_keys
       SET revoked_at = ?, updated_at = ?
       WHERE id = ? AND owner_type = 'user' AND owner_user_id = ? AND revoked_at IS NULL`
    )
    .bind(now, now, params.apiKeyId, params.userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const revokeServiceAccountApiKey = async (
  db: D1Database,
  params: {
    serviceAccountId: string;
    apiKeyId: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE api_keys
       SET revoked_at = ?, updated_at = ?
       WHERE id = ? AND owner_type = 'service_account' AND service_account_id = ? AND revoked_at IS NULL`
    )
    .bind(now, now, params.apiKeyId, params.serviceAccountId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const createScimToken = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    name: string;
    tokenPrefix: string;
    tokenHash: string;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO scim_tokens (
        id,
        organization_id,
        name,
        token_prefix,
        token_hash,
        last_used_at,
        revoked_at,
        created_by_user_id,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)`
    )
    .bind(
      params.id,
      params.organizationId,
      params.name,
      params.tokenPrefix,
      params.tokenHash,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const listScimTokensForOrganization = async (
  db: D1Database,
  organizationId: string
): Promise<ScimTokenRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              name,
              token_prefix,
              token_hash,
              last_used_at,
              revoked_at,
              created_by_user_id,
              created_at,
              updated_at
       FROM scim_tokens
       WHERE organization_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(organizationId)
    .all<ScimTokenRow>();
  return result.results ?? [];
};

export const findActiveScimTokenByHash = async (
  db: D1Database,
  tokenHash: string
): Promise<ScimTokenRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              name,
              token_prefix,
              token_hash,
              last_used_at,
              revoked_at,
              created_by_user_id,
              created_at,
              updated_at
       FROM scim_tokens
       WHERE token_hash = ? AND revoked_at IS NULL`
    )
    .bind(tokenHash)
    .first<ScimTokenRow>();

export const touchScimTokenUsage = async (db: D1Database, tokenId: string): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `UPDATE scim_tokens
       SET last_used_at = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(now, now, tokenId)
    .run();
};

export const revokeScimToken = async (
  db: D1Database,
  params: {
    organizationId: string;
    tokenId: string;
  }
): Promise<boolean> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE scim_tokens
       SET revoked_at = ?, updated_at = ?
       WHERE id = ? AND organization_id = ? AND revoked_at IS NULL`
    )
    .bind(now, now, params.tokenId, params.organizationId)
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const createWebhookEndpoint = async (
  db: D1Database,
  params: {
    id: string;
    organizationId: string;
    url: string;
    signingSecret: string;
    eventTypesJson?: string | null;
    createdByUserId: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO webhook_endpoints (
        id,
        organization_id,
        url,
        signing_secret,
        event_types_json,
        is_active,
        created_by_user_id,
        last_delivery_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, 1, ?, NULL, ?, ?)`
    )
    .bind(
      params.id,
      params.organizationId,
      params.url,
      params.signingSecret,
      params.eventTypesJson ?? null,
      params.createdByUserId,
      now,
      now
    )
    .run();
};

export const listWebhookEndpointsForOrganization = async (
  db: D1Database,
  organizationId: string
): Promise<WebhookEndpointRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              url,
              signing_secret,
              event_types_json,
              is_active,
              created_by_user_id,
              last_delivery_at,
              created_at,
              updated_at
       FROM webhook_endpoints
       WHERE organization_id = ?
       ORDER BY datetime(created_at) DESC`
    )
    .bind(organizationId)
    .all<WebhookEndpointRow>();
  return result.results ?? [];
};

export const listActiveWebhookEndpointsForOrganization = async (
  db: D1Database,
  organizationId: string
): Promise<WebhookEndpointRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              organization_id,
              url,
              signing_secret,
              event_types_json,
              is_active,
              created_by_user_id,
              last_delivery_at,
              created_at,
              updated_at
       FROM webhook_endpoints
       WHERE organization_id = ? AND is_active = 1`
    )
    .bind(organizationId)
    .all<WebhookEndpointRow>();
  return result.results ?? [];
};

export const findWebhookEndpointByIdInOrganization = async (
  db: D1Database,
  params: {
    organizationId: string;
    webhookId: string;
  }
): Promise<WebhookEndpointRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              url,
              signing_secret,
              event_types_json,
              is_active,
              created_by_user_id,
              last_delivery_at,
              created_at,
              updated_at
       FROM webhook_endpoints
       WHERE id = ? AND organization_id = ?`
    )
    .bind(params.webhookId, params.organizationId)
    .first<WebhookEndpointRow>();

export const findWebhookEndpointById = async (
  db: D1Database,
  webhookId: string
): Promise<WebhookEndpointRow | null> =>
  db
    .prepare(
      `SELECT id,
              organization_id,
              url,
              signing_secret,
              event_types_json,
              is_active,
              created_by_user_id,
              last_delivery_at,
              created_at,
              updated_at
       FROM webhook_endpoints
       WHERE id = ?`
    )
    .bind(webhookId)
    .first<WebhookEndpointRow>();

export const updateWebhookEndpoint = async (
  db: D1Database,
  params: {
    organizationId: string;
    webhookId: string;
    url?: string;
    signingSecret?: string;
    eventTypesJson?: string | null;
    isActive?: boolean;
  }
): Promise<boolean> => {
  const existing = await findWebhookEndpointByIdInOrganization(db, {
    organizationId: params.organizationId,
    webhookId: params.webhookId
  });
  if (!existing) {
    return false;
  }
  const next = {
    url: params.url ?? existing.url,
    signingSecret: params.signingSecret ?? existing.signing_secret,
    eventTypesJson: params.eventTypesJson ?? existing.event_types_json,
    isActive: params.isActive === undefined ? Boolean(existing.is_active) : params.isActive
  };
  const now = nowIso();
  const result = await db
    .prepare(
      `UPDATE webhook_endpoints
       SET url = ?,
           signing_secret = ?,
           event_types_json = ?,
           is_active = ?,
           updated_at = ?
       WHERE id = ? AND organization_id = ?`
    )
    .bind(
      next.url,
      next.signingSecret,
      next.eventTypesJson ?? null,
      next.isActive ? 1 : 0,
      now,
      params.webhookId,
      params.organizationId
    )
    .run();
  return (result.meta.changes ?? 0) > 0;
};

export const updateWebhookEndpointLastDelivery = async (
  db: D1Database,
  webhookId: string
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `UPDATE webhook_endpoints
       SET last_delivery_at = ?, updated_at = ?
       WHERE id = ?`
    )
    .bind(now, now, webhookId)
    .run();
};

export const createWebhookDelivery = async (
  db: D1Database,
  params: {
    id: string;
    endpointId: string;
    eventType: string;
    payloadJson: string;
  }
): Promise<void> => {
  const now = nowIso();
  await db
    .prepare(
      `INSERT INTO webhook_deliveries (
        id,
        endpoint_id,
        event_type,
        payload_json,
        status,
        status_code,
        attempt_count,
        next_attempt_at,
        last_error,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, 'pending', NULL, 0, ?, NULL, ?, ?)`
    )
    .bind(params.id, params.endpointId, params.eventType, params.payloadJson, now, now, now)
    .run();
};

export const markWebhookDeliverySuccess = async (
  db: D1Database,
  params: {
    deliveryId: string;
    statusCode: number;
    attemptCount: number;
  }
): Promise<void> => {
  await db
    .prepare(
      `UPDATE webhook_deliveries
       SET status = 'success',
           status_code = ?,
           attempt_count = ?,
           next_attempt_at = NULL,
           last_error = NULL,
           updated_at = ?
       WHERE id = ?`
    )
    .bind(params.statusCode, params.attemptCount, nowIso(), params.deliveryId)
    .run();
};

export const markWebhookDeliveryFailure = async (
  db: D1Database,
  params: {
    deliveryId: string;
    statusCode?: number | null;
    attemptCount: number;
    nextAttemptAt: string | null;
    lastError: string;
  }
): Promise<void> => {
  await db
    .prepare(
      `UPDATE webhook_deliveries
       SET status = 'failed',
           status_code = ?,
           attempt_count = ?,
           next_attempt_at = ?,
           last_error = ?,
           updated_at = ?
       WHERE id = ?`
    )
    .bind(
      params.statusCode ?? null,
      params.attemptCount,
      params.nextAttemptAt,
      params.lastError,
      nowIso(),
      params.deliveryId
    )
    .run();
};

export const listWebhookDeliveriesForEndpoint = async (
  db: D1Database,
  endpointId: string,
  limit = 50
): Promise<WebhookDeliveryRow[]> => {
  const result = await db
    .prepare(
      `SELECT id,
              endpoint_id,
              event_type,
              payload_json,
              status,
              status_code,
              attempt_count,
              next_attempt_at,
              last_error,
              created_at,
              updated_at
       FROM webhook_deliveries
       WHERE endpoint_id = ?
       ORDER BY datetime(created_at) DESC
       LIMIT ?`
    )
    .bind(endpointId, limit)
    .all<WebhookDeliveryRow>();
  return result.results ?? [];
};

export const listDueWebhookDeliveries = async (
  db: D1Database,
  limit = 50
): Promise<WebhookDeliveryRow[]> => {
  const now = nowIso();
  const result = await db
    .prepare(
      `SELECT id,
              endpoint_id,
              event_type,
              payload_json,
              status,
              status_code,
              attempt_count,
              next_attempt_at,
              last_error,
              created_at,
              updated_at
       FROM webhook_deliveries
       WHERE status = 'failed'
         AND next_attempt_at IS NOT NULL
         AND datetime(next_attempt_at) <= datetime(?)
       ORDER BY datetime(next_attempt_at) ASC
       LIMIT ?`
    )
    .bind(now, limit)
    .all<WebhookDeliveryRow>();
  return result.results ?? [];
};
