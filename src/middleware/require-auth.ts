import { createMiddleware } from "hono/factory";
import type { EnvBindings } from "../types";
import { authenticateAccessToken, parseBearerToken } from "../lib/auth";
import { findSessionById } from "../lib/db";
import { isIsoExpired } from "../lib/time";

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

  const session = await findSessionById(context.env.DB, auth.sessionId);
  if (!session || session.revoked_at || isIsoExpired(session.expires_at) || session.user_id !== auth.userId) {
    return context.json(
      {
        error: {
          code: "SESSION_INVALID",
          message: "Session is revoked or expired"
        }
      },
      401
    );
  }

  context.set("authUserId", auth.userId);
  context.set("authSessionId", auth.sessionId);
  await next();
});
