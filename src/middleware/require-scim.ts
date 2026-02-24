import { createMiddleware } from "hono/factory";
import type { EnvBindings } from "../types";
import { parseBearerToken } from "../lib/auth";
import { sha256Hex } from "../lib/crypto";
import { findActiveScimTokenByHash, touchScimTokenUsage } from "../lib/db";

export const requireScimToken = createMiddleware<{
  Bindings: EnvBindings;
  Variables: {
    scimTokenId: string;
    scimOrganizationId: string;
  };
}>(async (context, next) => {
  const token = parseBearerToken(context.req.raw);
  if (!token || !token.startsWith("sct_")) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "A valid SCIM Bearer token is required",
        status: "401"
      },
      401
    );
  }

  const tokenHash = await sha256Hex(token);
  const scimToken = await findActiveScimTokenByHash(context.env.DB, tokenHash);
  if (!scimToken) {
    return context.json(
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "SCIM token is invalid, revoked, or expired",
        status: "401"
      },
      401
    );
  }

  context.set("scimTokenId", scimToken.id);
  context.set("scimOrganizationId", scimToken.organization_id);
  await touchScimTokenUsage(context.env.DB, scimToken.id);
  await next();
});
