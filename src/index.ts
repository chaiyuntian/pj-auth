import { Hono } from "hono";
import type { EnvBindings } from "./types";
import { assertCriticalSecrets } from "./lib/config";
import { authRoutes } from "./routes/auth";
import { oauthRoutes } from "./routes/oauth";
import { adminRoutes } from "./routes/admin";
import { demoRoutes } from "./routes/demo";
import { orgRoutes } from "./routes/orgs";
import { m2mRoutes } from "./routes/m2m";
import { passkeyRoutes } from "./routes/passkeys";
import { hostedRoutes } from "./routes/hosted";
import { projectRoutes } from "./routes/projects";
import { applyApiCors } from "./middleware/cors";
import { createAuthRateLimitMiddleware } from "./middleware/rate-limit";

const app = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

app.use("/v1/*", applyApiCors);

const authRateLimit = createAuthRateLimitMiddleware();

app.use("/v1/auth/*", authRateLimit);
app.use("/v1/oauth/*", authRateLimit);
app.use("/v1/orgs/*", authRateLimit);
app.use("/v1/projects/*", authRateLimit);

app.use("*", async (context, next) => {
  await next();
  context.header("x-content-type-options", "nosniff");
  context.header("x-frame-options", "DENY");
  context.header("referrer-policy", "same-origin");
});

app.use("*", async (context, next) => {
  try {
    assertCriticalSecrets(context.env);
  } catch (error) {
    return context.json(
      {
        error: {
          code: "SERVER_MISCONFIGURED",
          message: error instanceof Error ? error.message : "Missing critical environment configuration"
        }
      },
      500
    );
  }
  await next();
});

app.get("/", (context) =>
  context.json({
    service: "pj-auth",
    status: "ok",
    docs: "/README.md",
    demo: "/demo"
  })
);

app.get("/healthz", async (context) => {
  const dbCheck = await context.env.DB.prepare("SELECT 1 AS ok").first<{ ok: number }>().catch(() => null);
  const ok = dbCheck?.ok === 1;
  return context.json(
    {
      ok,
      db: ok ? "up" : "down",
      timestamp: new Date().toISOString()
    },
    ok ? 200 : 503
  );
});

app.route("/v1/auth", authRoutes);
app.route("/v1/oauth", oauthRoutes);
app.route("/v1/orgs", orgRoutes);
app.route("/v1/projects", projectRoutes);
app.route("/v1/m2m", m2mRoutes);
app.route("/v1/auth/passkeys", passkeyRoutes);
app.route("/v1/admin", adminRoutes);
app.route("/", demoRoutes);
app.route("/", hostedRoutes);

app.onError((error, context) => {
  console.error("Unhandled error", error);
  return context.json(
    {
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Unexpected server error"
      }
    },
    500
  );
});

export default app;
