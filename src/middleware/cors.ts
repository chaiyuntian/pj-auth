import { createMiddleware } from "hono/factory";
import type { EnvBindings } from "../types";
import { getCorsOrigins } from "../lib/config";

const DEFAULT_METHODS = "GET,POST,PUT,OPTIONS";
const DEFAULT_HEADERS = "authorization,content-type,x-admin-api-key";

const resolveOrigin = (origin: string | null, allowedOrigins: string[]): { allowOrigin: string; credentials: boolean } | null => {
  if (allowedOrigins.includes("*")) {
    return {
      allowOrigin: "*",
      credentials: false
    };
  }

  if (!origin) {
    return null;
  }

  if (!allowedOrigins.includes(origin)) {
    return null;
  }

  return {
    allowOrigin: origin,
    credentials: true
  };
};

export const applyApiCors = createMiddleware<{ Bindings: EnvBindings }>(async (context, next) => {
  const requestOrigin = context.req.header("origin") ?? null;
  const allowed = getCorsOrigins(context.env);
  const resolved = resolveOrigin(requestOrigin, allowed);

  if (context.req.method === "OPTIONS") {
    if (!resolved) {
      return context.body(null, 403);
    }
    context.header("access-control-allow-origin", resolved.allowOrigin);
    context.header("access-control-allow-methods", DEFAULT_METHODS);
    context.header("access-control-allow-headers", DEFAULT_HEADERS);
    if (resolved.credentials) {
      context.header("access-control-allow-credentials", "true");
      context.header("vary", "Origin");
    }
    return context.body(null, 204);
  }

  await next();

  if (resolved) {
    context.header("access-control-allow-origin", resolved.allowOrigin);
    if (resolved.credentials) {
      context.header("access-control-allow-credentials", "true");
      context.header("vary", "Origin");
    }
  }
});
