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
