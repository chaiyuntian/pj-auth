# pj-auth

Cloudflare-native auth platform targeting Clerk-like behavior with D1 storage and Google OAuth support.

## Current Capabilities
- Email/password sign-up + sign-in.
- Access token + rotating refresh token session flow.
- Email verification flow (`start` + `confirm`) with one-time tokens.
- Password reset flow (`start` + `confirm`) with one-time tokens.
- Session management APIs (list sessions, revoke one, revoke others, revoke all).
- Organizations and teams with role-based memberships (`owner/admin/member`, `maintainer/member`).
- Fine-grained organization policy engine (`allow/deny` rules by user/role/team/service account).
- Personal API keys and organization service accounts with scoped machine keys.
- Organization webhooks with signed delivery logs and retry endpoint.
- Passkey (WebAuthn) registration/authentication flow with challenge + assertion verification.
- TOTP multi-factor authentication with recovery codes and challenge-gated sign-in.
- Session anomaly detection with risk scoring and automatic high-risk session containment.
- Multi-tenant project model with scoped auth domains, branding payloads, and project OAuth config.
- SCIM 2.0 provisioning endpoints with org-scoped bearer tokens.
- SAML SSO (SP metadata, AuthnRequest start, ACS assertion processing, and domain-based SSO discovery).
- Enterprise domain routing (`domain -> auth strategy`) with organization-managed routes.
- Compliance controls: retention policies, retention prune jobs, export jobs, and org KMS key management/encryption.
- Transactional email delivery via Resend (with safe log fallback).
- Google OAuth (`/v1/oauth/google/start`, `/v1/oauth/google/callback`).
- Provider config management via admin API key.
- D1-backed user/session/oauth state.
- DB-backed health check and explicit CORS allowlist support.
- D1-backed auth rate limiting for `/v1/auth/*` and `/v1/oauth/*`.
- Demo UI + browser SDK script at `/demo` and `/sdk/pj-auth-client.js`.
- Hosted auth UI + embeddable widget (`/hosted/sign-in`, `/hosted/sign-up`, `/sdk/pj-auth-widgets.js`).
- SDK package stubs for browser/react/nextjs/server runtimes under `packages/`.
- Built-in capability evolver loop for autonomous safe mutation cycles.

## Stack
- Cloudflare Workers (Hono runtime).
- Cloudflare D1 (SQLite at edge).
- Wrangler for local/dev/deploy.

## Project Layout
- `src/index.ts`: app entrypoint.
- `src/routes/auth.ts`: password/session APIs.
- `src/routes/oauth.ts`: Google OAuth flow.
- `src/routes/admin.ts`: OAuth provider settings + stats.
- `src/routes/orgs.ts`: organization/team and membership APIs.
- `src/routes/projects.ts`: tenant/project APIs and scoped OAuth settings.
- `src/routes/scim.ts`: SCIM 2.0 provisioning endpoints.
- `src/routes/saml.ts`: SAML public endpoints (discovery, metadata, start, ACS).
- `src/routes/org-enterprise.ts`: org enterprise APIs (SAML/domain/compliance/KMS/diagnostics).
- `src/routes/m2m.ts`: API key auth introspection endpoint.
- `src/routes/passkeys.ts`: WebAuthn passkey registration/authentication APIs.
- `src/routes/mfa.ts`: TOTP MFA setup/challenge/recovery APIs.
- `src/routes/hosted.ts`: hosted auth UI and embeddable widget JS.
- `src/lib/mailer.ts`: outbound email provider integration.
- `src/lib/session-risk.ts`: risk scoring + anomaly detection.
- `src/lib/policy.ts`: organization policy evaluation engine.
- `src/routes/demo.ts`: end-to-end browser demo and SDK script.
- `migrations/0001_init.sql`: initial D1 schema.
- `migrations/0002_verification_indexes.sql`: token/session indexes.
- `migrations/0003_rate_limits.sql`: D1 fixed-window rate-limit store.
- `migrations/0004_orgs_teams.sql`: organizations, memberships, teams, team memberships.
- `migrations/0005_machine_auth.sql`: service accounts and API key credentials.
- `migrations/0006_webhooks.sql`: webhook endpoints and delivery queue.
- `migrations/0007_session_risk.sql`: session risk telemetry.
- `migrations/0008_policy_engine.sql`: fine-grained organization policies.
- `migrations/0009_passkeys.sql`: WebAuthn credential/challenge storage.
- `migrations/0010_projects.sql`: project model + scoped OAuth provider config.
- `migrations/0011_mfa_totp.sql`: TOTP MFA factors/challenges/recovery codes.
- `migrations/0012_scim.sql`: SCIM token storage.
- `migrations/0013_enterprise_saml_compliance.sql`: SAML/domain routes/retention/export jobs/KMS key store.
- `scripts/bootstrap-cloudflare.ps1`: one-command cloud bootstrap/deploy.
- `packages/`: browser/react/nextjs/server SDK package stubs.
- `tools/capability-evolver/`: autonomous analyze->mutate->validate->log engine.
- `ROADMAP.md`: parity plan toward full Clerk-like surface.

## API Summary
- `POST /v1/auth/sign-up`
- `POST /v1/auth/sign-in`
- `POST /v1/auth/token/refresh`
- `GET /v1/auth/mfa/status` (Bearer)
- `POST /v1/auth/mfa/totp/setup/start` (Bearer)
- `POST /v1/auth/mfa/totp/setup/confirm` (Bearer)
- `POST /v1/auth/mfa/recovery-codes/regenerate` (Bearer)
- `POST /v1/auth/mfa/totp/disable` (Bearer)
- `POST /v1/auth/mfa/challenge/verify`
- `POST /v1/auth/email-verification/start` (Bearer)
- `POST /v1/auth/email-verification/confirm`
- `GET /v1/auth/email-verification/confirm?token=...`
- `POST /v1/auth/password-reset/start`
- `POST /v1/auth/password-reset/confirm`
- `GET /v1/auth/sessions` (Bearer)
- `GET /v1/auth/sessions/risk-events` (Bearer)
- `POST /v1/auth/sessions/:sessionId/revoke` (Bearer)
- `POST /v1/auth/sessions/revoke-others` (Bearer)
- `POST /v1/auth/sessions/revoke-all` (Bearer)
- `POST /v1/auth/sign-out`
- `GET /v1/auth/me`
- `GET /v1/auth/passkeys/credentials` (Bearer)
- `POST /v1/auth/passkeys/register/start` (Bearer)
- `POST /v1/auth/passkeys/register/finish` (Bearer)
- `POST /v1/auth/passkeys/authenticate/start`
- `POST /v1/auth/passkeys/authenticate/finish`
- `GET /v1/auth/api-keys` (Bearer)
- `POST /v1/auth/api-keys` (Bearer)
- `POST /v1/auth/api-keys/:apiKeyId/revoke` (Bearer)
- `GET /v1/oauth/google/start`
- `GET /v1/oauth/google/callback`
- `GET /v1/orgs` (Bearer)
- `POST /v1/orgs` (Bearer)
- `GET /v1/orgs/:orgId` (Bearer)
- `GET /v1/orgs/:orgId/members` (Bearer)
- `POST /v1/orgs/:orgId/members` (Bearer)
- `PATCH /v1/orgs/:orgId/members/:userId` (Bearer)
- `DELETE /v1/orgs/:orgId/members/:userId` (Bearer)
- `GET /v1/orgs/:orgId/teams` (Bearer)
- `POST /v1/orgs/:orgId/teams` (Bearer)
- `GET /v1/orgs/:orgId/teams/:teamId/members` (Bearer)
- `POST /v1/orgs/:orgId/teams/:teamId/members` (Bearer)
- `PATCH /v1/orgs/:orgId/teams/:teamId/members/:userId` (Bearer)
- `DELETE /v1/orgs/:orgId/teams/:teamId/members/:userId` (Bearer)
- `GET /v1/orgs/:orgId/service-accounts` (Bearer)
- `POST /v1/orgs/:orgId/service-accounts` (Bearer)
- `POST /v1/orgs/:orgId/service-accounts/:serviceAccountId/disable` (Bearer)
- `GET /v1/orgs/:orgId/service-accounts/:serviceAccountId/api-keys` (Bearer)
- `POST /v1/orgs/:orgId/service-accounts/:serviceAccountId/api-keys` (Bearer)
- `POST /v1/orgs/:orgId/service-accounts/:serviceAccountId/api-keys/:apiKeyId/revoke` (Bearer)
- `GET /v1/orgs/:orgId/scim/tokens` (Bearer)
- `POST /v1/orgs/:orgId/scim/tokens` (Bearer)
- `POST /v1/orgs/:orgId/scim/tokens/:tokenId/revoke` (Bearer)
- `GET /v1/orgs/:orgId/saml/connections` (Bearer)
- `POST /v1/orgs/:orgId/saml/connections` (Bearer)
- `PATCH /v1/orgs/:orgId/saml/connections/:connectionId` (Bearer)
- `POST /v1/orgs/:orgId/saml/connections/:connectionId/disable` (Bearer)
- `GET /v1/orgs/:orgId/domain-routes` (Bearer)
- `POST /v1/orgs/:orgId/domain-routes` (Bearer)
- `DELETE /v1/orgs/:orgId/domain-routes/:routeId` (Bearer)
- `GET /v1/orgs/:orgId/enterprise/diagnostics` (Bearer)
- `GET /v1/orgs/:orgId/compliance/retention` (Bearer)
- `PUT /v1/orgs/:orgId/compliance/retention` (Bearer)
- `POST /v1/orgs/:orgId/compliance/prune` (Bearer)
- `GET /v1/orgs/:orgId/compliance/exports` (Bearer)
- `POST /v1/orgs/:orgId/compliance/exports` (Bearer)
- `GET /v1/orgs/:orgId/compliance/exports/:jobId` (Bearer)
- `GET /v1/orgs/:orgId/kms/keys` (Bearer)
- `POST /v1/orgs/:orgId/kms/keys` (Bearer)
- `POST /v1/orgs/:orgId/kms/keys/:keyId/rotate` (Bearer)
- `POST /v1/orgs/:orgId/kms/keys/:keyId/disable` (Bearer)
- `POST /v1/orgs/:orgId/kms/keys/:keyId/encrypt` (Bearer)
- `POST /v1/orgs/:orgId/kms/keys/:keyId/decrypt` (Bearer)
- `GET /v1/orgs/:orgId/webhooks` (Bearer)
- `POST /v1/orgs/:orgId/webhooks` (Bearer)
- `PATCH /v1/orgs/:orgId/webhooks/:webhookId` (Bearer)
- `GET /v1/orgs/:orgId/webhooks/:webhookId/deliveries` (Bearer)
- `POST /v1/orgs/:orgId/webhooks/:webhookId/test` (Bearer)
- `GET /v1/orgs/:orgId/policies` (Bearer)
- `POST /v1/orgs/:orgId/policies` (Bearer)
- `DELETE /v1/orgs/:orgId/policies/:policyId` (Bearer)
- `GET /v1/m2m/me` (`x-api-key` or Bearer API key)
- `GET /v1/scim/v2/ServiceProviderConfig` (`Authorization: Bearer sct_...`)
- `GET /v1/scim/v2/Users` (`Authorization: Bearer sct_...`)
- `POST /v1/scim/v2/Users` (`Authorization: Bearer sct_...`)
- `GET /v1/scim/v2/Users/:userId` (`Authorization: Bearer sct_...`)
- `PATCH /v1/scim/v2/Users/:userId` (`Authorization: Bearer sct_...`)
- `DELETE /v1/scim/v2/Users/:userId` (`Authorization: Bearer sct_...`)
- `GET /v1/saml/discover?email=...`
- `GET /v1/saml/:connectionSlug/metadata`
- `GET /v1/saml/:connectionSlug/start`
- `POST /v1/saml/:connectionSlug/acs`
- `GET /v1/projects` (Bearer)
- `POST /v1/projects` (Bearer)
- `GET /v1/projects/:projectId` (Bearer)
- `GET /v1/projects/:projectId/oauth/providers/google` (Bearer)
- `PUT /v1/projects/:projectId/oauth/providers/google` (Bearer)
- `GET /v1/admin/oauth/providers/google` (`x-admin-api-key`)
- `PUT /v1/admin/oauth/providers/google` (`x-admin-api-key`)
- `GET /v1/admin/stats` (`x-admin-api-key`)
- `GET /v1/admin/system/status` (`x-admin-api-key`)
- `POST /v1/admin/webhooks/retry` (`x-admin-api-key`)
- `GET /v1/admin/audit-logs` (`x-admin-api-key`)
- `GET /hosted/sign-in` (Hosted UI)
- `GET /hosted/sign-up` (Hosted UI)
- `GET /sdk/pj-auth-widgets.js` (Embeddable widget)

## Local Setup
1. Install dependencies:
   - `npm install`
2. Copy secret template:
   - `Copy-Item .dev.vars.example .dev.vars`
3. Run local migrations:
   - `npm run db:migrate:local`
4. Start worker:
   - `npm run dev`
5. Open demo:
   - `http://127.0.0.1:8787/demo`
6. Open hosted auth UI:
   - `http://127.0.0.1:8787/hosted/sign-in`
   - `http://127.0.0.1:8787/hosted/sign-up`

## Cloudflare Deployment (D1 + Worker)
Fast path:
- `npm run bootstrap:cloudflare`

Manual path:
1. Authenticate:
   - `npx wrangler login`
2. Create D1 database:
   - `npx wrangler d1 create pj-auth-db --location enam`
3. Set `database_id` in `wrangler.toml` from the command output.
4. Set required secrets:
   - `npx wrangler secret put JWT_SIGNING_KEY`
   - `npx wrangler secret put KMS_MASTER_KEY` (optional, otherwise JWT secret is used as KMS master)
   - `npx wrangler secret put ADMIN_API_KEY`
   - `npx wrangler secret put RESEND_API_KEY` (optional, enables real email delivery)
   - `npx wrangler secret put TURNSTILE_SECRET_KEY` (optional unless `TURNSTILE_ENABLED=true`)
   - `npx wrangler secret put OAUTH_GOOGLE_CLIENT_ID`
   - `npx wrangler secret put OAUTH_GOOGLE_CLIENT_SECRET`
   - `npx wrangler secret put OAUTH_GOOGLE_REDIRECT_URI`
5. Apply remote migrations:
   - `npm run db:migrate:remote`
6. Deploy:
   - `npm run deploy`
7. Optional non-secret vars in `wrangler.toml` `[vars]`:
   - `SAML_XMLSIG_MODE=required` to enforce cryptographic XML DSig verification at ACS (recommended for production IdPs)

## Verification/Reset Token Delivery
- If `RESEND_API_KEY` + `EMAIL_FROM` are configured, emails are sent through Resend.
- If not configured, links are logged (safe fallback).
- For local/dev testing, set `EXPOSE_TEST_TOKENS=true` in `.dev.vars` to include one-time tokens in API responses.
- Keep `EXPOSE_TEST_TOKENS=false` in production.

## Auto Evolution
- Review cycle:
  - `npm run evolve:review`
- Apply one safe mutation:
  - `npm run evolve:apply`
- Continuous loop mode:
  - `EVOLVE_STRATEGY=innovate npm run evolve:loop`
- Controlled finite loop run:
  - `EVOLVE_STRATEGY=innovate node tools/capability-evolver/index.mjs --loop --repo . --target src --apply --interval-ms 2000 --heartbeat-ms 1000 --max-cycles 2`
- Events and reports:
  - `tools/capability-evolver/assets/gep/events.jsonl`
  - `tools/capability-evolver/assets/gep/capsules.json`
  - `tools/capability-evolver/memory/reports/latest.md`

## Live Smoke
- Run against deployed domain:
  - `npm run e2e:smoke`
- Script path:
  - `scripts/e2e-smoke.ps1`

## Configure Google OAuth
Use one of these approaches:

1. Via secrets/env:
   - `OAUTH_GOOGLE_CLIENT_ID`
   - `OAUTH_GOOGLE_CLIENT_SECRET`
   - `OAUTH_GOOGLE_REDIRECT_URI` (example: `https://users.pajamadot.com/v1/oauth/google/callback`)
2. Via admin endpoint:
   - `PUT /v1/admin/oauth/providers/google` with JSON:
```json
{
  "enabled": true,
  "clientId": "GOOGLE_CLIENT_ID",
  "clientSecret": "GOOGLE_CLIENT_SECRET",
  "redirectUri": "https://users.pajamadot.com/v1/oauth/google/callback",
  "scope": "openid email profile"
}
```
3. Per project (scoped domain credentials):
   - `PUT /v1/projects/:projectId/oauth/providers/google` with project-specific credentials
   - OAuth start/callback automatically resolve scoped provider by request host before falling back to global config.

## Bind to `users.pajamadot.com`
1. Ensure `pajamadot.com` is in your Cloudflare account.
2. In `wrangler.toml`, add:
```toml
routes = [
  { pattern = "users.pajamadot.com", custom_domain = true }
]
```
3. Deploy again:
   - `npm run deploy`

Cloudflare will create and manage the DNS record and certificate for the custom domain route.

## cURL Quick Test
```bash
curl -X POST https://users.pajamadot.com/v1/auth/sign-up \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@pajamadot.com","password":"Passw0rd123!","fullName":"Demo User"}'
```

## Security Notes
- Use long, random `JWT_SIGNING_KEY` and rotate periodically.
- Never expose `ADMIN_API_KEY` client-side.
- Restrict CORS origins for production.
- Set `PUBLIC_AUTH_URL` to your production auth domain.
- Enable rate-limiting / bot protection on auth endpoints before heavy traffic.
- Keep at least one `owner` per organization; role downgrade/removal of last owner is blocked.
- If `TURNSTILE_ENABLED=true`, clients must pass `turnstileToken` on `sign-up`, `sign-in`, and `password-reset/start`.
- Treat SCIM bearer tokens (`sct_...`) as high-privilege secrets and rotate/revoke them periodically.
- Enforce MFA enrollment for privileged users and monitor `auth.mfa_*` audit events.
- For passkeys, always use HTTPS/custom domain in production and monitor `auth.session_risk_detected` audit events.
- Use organization policy `deny` rules carefully; they override both base role grants and `allow` policies.
- Rotate SAML IdP certificates proactively and keep `requireSignedAssertions=true` for production connections.
- Set `SAML_XMLSIG_MODE=required` in production once your IdP signatures validate end-to-end.
- Treat org KMS keys as sensitive cryptographic material; rotate aliases regularly and keep `KMS_MASTER_KEY` separate from `JWT_SIGNING_KEY`.
