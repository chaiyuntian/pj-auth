# PajamaDot Auth Roadmap

## Objective
Build a Cloudflare-native auth platform that converges toward Clerk-like functionality while staying deployable with a minimal command path.

## Phase 0: Foundation (implemented)
- [x] Cloudflare Worker + TypeScript service scaffold.
- [x] D1 schema and migrations for users, sessions, OAuth providers/accounts, verification codes, and audit logs.
- [x] Password auth (`sign-up`, `sign-in`, `me`, `refresh`, `sign-out`).
- [x] Google OAuth start/callback flow with provider settings persisted in D1.
- [x] Admin API key-protected endpoints for Google OAuth configuration.
- [x] Explicit CORS allowlist and DB-backed health checks.
- [x] Transactional email delivery integration with safe fallback logging.
- [x] Browser demo and client SDK script.
- [x] Local migration + deploy dry-run validation.
- [x] Capability evolver loop (analyze->mutate->validate->log) for safe autonomous refinement.

## Phase 1: Clerk Feature Parity Core
- [x] Email verification flow with signed links and resend logic.
- [x] Password reset flow with one-time tokens.
- [x] Multi-session management endpoints (list/revoke per device).
- [ ] Organizations/teams and memberships.
- [ ] API keys and service account auth flows.

## Phase 2: Advanced Controls
- [x] Auth endpoint rate-limiting and abuse protection (D1 fixed-window).
- [ ] Turnstile challenge for suspicious auth actions.
- [ ] WebAuthn / passkey support.
- [ ] Fine-grained RBAC and policy engine.
- [ ] First-party webhook delivery and retry system.
- [ ] Session anomaly detection and risk scoring.

## Phase 3: Productization
- [ ] Tenant/project model with scoped domains, credentials, and branding.
- [ ] Hosted sign-in/sign-up UI + embeddable widgets.
- [ ] Client SDK packages for React/Next.js and server runtimes.
- [ ] Managed migrations and one-command bootstrap CLI.
