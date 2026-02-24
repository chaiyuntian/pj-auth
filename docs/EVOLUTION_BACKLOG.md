# Evolution Backlog

Last refreshed: 2026-02-24T10:48:23.565Z

## Signals
- changed files: 15
- TODO/FIXME lines in target: 0
- db health check in source: yes
- e2e smoke script present: yes

## Working Tree Sample
- M .dev.vars.example
- M .prod.secrets.example.psd1
- M README.md
- M ROADMAP.md
- M package.json
- M src/index.ts
- M src/lib/config.ts
- M src/routes/admin.ts
- M src/routes/auth.ts
- M src/types.ts
- M wrangler.toml
- ?? scripts/e2e-smoke.ps1
- ?? src/lib/mailer.ts
- ?? src/middleware/cors.ts
- ?? tools/

## TODO/FIXME Sample
- no TODO/FIXME lines detected

## Next Mutation Priorities
- Keep CORS allowlist explicit for production domains.
- Keep e2e smoke script green in CI and before deploys.
- Add deeper integration tests for Google OAuth callback and reset flows.
- Add worker rate-limiting and abuse controls on auth endpoints.
