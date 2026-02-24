import { Hono } from "hono";
import { cors } from "hono/cors";
import type { EnvBindings } from "./types";
import { assertCriticalSecrets } from "./lib/config";
import { authRoutes } from "./routes/auth";
import { oauthRoutes } from "./routes/oauth";
import { adminRoutes } from "./routes/admin";
import { demoRoutes } from "./routes/demo";

const app = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

app.use(
  "/v1/*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "PUT", "OPTIONS"],
    allowHeaders: ["authorization", "content-type", "x-admin-api-key"]
  })
);

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

app.get("/healthz", (context) =>
  context.json({
    ok: true,
    timestamp: new Date().toISOString()
  })
);

app.route("/v1/auth", authRoutes);
app.route("/v1/oauth", oauthRoutes);
app.route("/v1/admin", adminRoutes);
app.route("/", demoRoutes);

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
