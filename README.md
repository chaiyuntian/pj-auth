# pj-auth

Cloudflare-native auth platform targeting Clerk-like behavior with D1 storage and Google OAuth support.

## Current Capabilities
- Email/password sign-up + sign-in.
- Access token + rotating refresh token session flow.
- Email verification flow (`start` + `confirm`) with one-time tokens.
- Password reset flow (`start` + `confirm`) with one-time tokens.
- Session management APIs (list sessions, revoke one, revoke others, revoke all).
- Google OAuth (`/v1/oauth/google/start`, `/v1/oauth/google/callback`).
- Provider config management via admin API key.
- D1-backed user/session/oauth state.
- Demo UI + browser SDK script at `/demo` and `/sdk/pj-auth-client.js`.

## Stack
- Cloudflare Workers (Hono runtime).
- Cloudflare D1 (SQLite at edge).
- Wrangler for local/dev/deploy.

## Project Layout
- `src/index.ts`: app entrypoint.
- `src/routes/auth.ts`: password/session APIs.
- `src/routes/oauth.ts`: Google OAuth flow.
- `src/routes/admin.ts`: OAuth provider settings + stats.
- `src/routes/demo.ts`: end-to-end browser demo and SDK script.
- `migrations/0001_init.sql`: initial D1 schema.
- `migrations/0002_verification_indexes.sql`: token/session indexes.
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
   - `npx wrangler secret put OAUTH_GOOGLE_CLIENT_ID`
   - `npx wrangler secret put OAUTH_GOOGLE_CLIENT_SECRET`
   - `npx wrangler secret put OAUTH_GOOGLE_REDIRECT_URI`
5. Apply remote migrations:
   - `npm run db:migrate:remote`
6. Deploy:
   - `npm run deploy`

## Verification/Reset Token Delivery
- Current implementation logs generated verification/reset links to Worker logs.
- For local/dev testing, set `EXPOSE_TEST_TOKENS=true` in `.dev.vars` to include one-time tokens in API responses.
- Keep `EXPOSE_TEST_TOKENS=false` in production.

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
- Add real outbound email/SMS delivery integration before production launch.
