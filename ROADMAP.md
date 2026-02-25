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
- [x] Organizations/teams and memberships.
- [x] Organization invitations (issue/revoke/accept flow).
- [x] API keys and service account auth flows.

## Phase 2: Advanced Controls
- [x] Auth endpoint rate-limiting and abuse protection (D1 fixed-window).
- [x] Turnstile challenge for suspicious auth actions.
- [x] WebAuthn / passkey support.
- [x] Fine-grained RBAC and policy engine.
- [x] First-party webhook delivery and retry system.
- [x] Session anomaly detection and risk scoring.

## Phase 3: Productization
- [x] Tenant/project model with scoped domains, credentials, and branding.
- [x] Hosted sign-in/sign-up UI + embeddable widgets.
- [x] Client SDK packages for React/Next.js and server runtimes.
- [x] Managed migrations and one-command bootstrap CLI.

## Phase 4: Enterprise Parity
- [x] SCIM 2.0 provisioning API with org-scoped bearer tokens.
- [x] SAML IdP/SP protocol surface (metadata exchange + assertion validation checks + ACS session issuance).
- [x] Enterprise admin API parity (connections, domain routing, diagnostics).
- [x] Compliance controls (retention policies, export jobs, key management).

## Phase 5: Hardening
- [x] XML DSig cryptographic signature verification path for SAML assertions with configurable enforcement (`off|optional|required`).
- [x] XML DSig reference digest validation (URI fragment resolution, digest method checks, transform processing) with strict fail-closed behavior in `required` mode.
