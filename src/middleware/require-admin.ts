import { createMiddleware } from "hono/factory";
import type { EnvBindings } from "../types";

export const requireAdminApiKey = createMiddleware<{ Bindings: EnvBindings }>(async (context, next) => {
  const supplied = context.req.header("x-admin-api-key");
  if (!supplied || supplied !== context.env.ADMIN_API_KEY) {
    return context.json(
      {
        error: {
          code: "FORBIDDEN",
          message: "Invalid admin API key"
        }
      },
      403
    );
  }
  await next();
});
