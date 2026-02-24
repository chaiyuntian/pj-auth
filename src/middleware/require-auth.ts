import { createMiddleware } from "hono/factory";
import type { EnvBindings } from "../types";
import { authenticateAccessToken, parseBearerToken } from "../lib/auth";

export const requireAuth = createMiddleware<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>(async (context, next) => {
  const token = parseBearerToken(context.req.raw);
  const auth = await authenticateAccessToken(context.env, token);

  if (!auth) {
    return context.json(
      {
        error: {
          code: "UNAUTHORIZED",
          message: "A valid Bearer access token is required"
        }
      },
      401
    );
  }

  context.set("authUserId", auth.userId);
  context.set("authSessionId", auth.sessionId);
  await next();
});
