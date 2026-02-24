# pj-auth

Cloudflare-native auth platform targeting Clerk-like behavior with D1 storage and Google OAuth support.

## Current Capabilities
- Email/password sign-up + sign-in.
- Access token + rotating refresh token session flow.
- Email verification flow (`start` + `confirm`) with one-time tokens.
- Password reset flow (`start` + `confirm`) with one-time tokens.
- Session management APIs (list sessions, revoke one, revoke others, revoke all).
- Transactional email delivery via Resend (with safe log fallback).
- Google OAuth (`/v1/oauth/google/start`, `/v1/oauth/google/callback`).
- Provider config management via admin API key.
- D1-backed user/session/oauth state.
- DB-backed health check and explicit CORS allowlist support.
- Demo UI + browser SDK script at `/demo` and `/sdk/pj-auth-client.js`.
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
- `src/lib/mailer.ts`: outbound email provider integration.
- `src/routes/demo.ts`: end-to-end browser demo and SDK script.
- `migrations/0001_init.sql`: initial D1 schema.
- `migrations/0002_verification_indexes.sql`: token/session indexes.
- `tools/capability-evolver/`: autonomous analyze->mutate->validate->log engine.
- `ROADMAP.md`: parity plan toward full Clerk-like surface.

## API Summary
- `POST /v1/auth/sign-up`
- `POST /v1/auth/sign-in`
- `POST /v1/auth/token/refresh`
- `POST /v1/auth/email-verification/start` (Bearer)
- `POST /v1/auth/email-verification/confirm`
- `GET /v1/auth/email-verification/confirm?token=...`
- `POST /v1/auth/password-reset/start`
- `POST /v1/auth/password-reset/confirm`
- `GET /v1/auth/sessions` (Bearer)
- `POST /v1/auth/sessions/:sessionId/revoke` (Bearer)
- `POST /v1/auth/sessions/revoke-others` (Bearer)
- `POST /v1/auth/sessions/revoke-all` (Bearer)
- `POST /v1/auth/sign-out`
- `GET /v1/auth/me`
- `GET /v1/oauth/google/start`
- `GET /v1/oauth/google/callback`
- `GET /v1/admin/oauth/providers/google` (`x-admin-api-key`)
- `PUT /v1/admin/oauth/providers/google` (`x-admin-api-key`)
- `GET /v1/admin/stats` (`x-admin-api-key`)
- `GET /v1/admin/system/status` (`x-admin-api-key`)

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

## Cloudflare Deployment (D1 + Worker)
1. Authenticate:
   - `npx wrangler login`
2. Create D1 database:
   - `npx wrangler d1 create pj-auth-db --location enam`
3. Set `database_id` in `wrangler.toml` from the command output.
4. Set required secrets:
   - `npx wrangler secret put JWT_SIGNING_KEY`
   - `npx wrangler secret put ADMIN_API_KEY`
   - `npx wrangler secret put RESEND_API_KEY` (optional, enables real email delivery)
   - `npx wrangler secret put OAUTH_GOOGLE_CLIENT_ID`
   - `npx wrangler secret put OAUTH_GOOGLE_CLIENT_SECRET`
   - `npx wrangler secret put OAUTH_GOOGLE_REDIRECT_URI`
5. Apply remote migrations:
   - `npm run db:migrate:remote`
6. Deploy:
   - `npm run deploy`

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
