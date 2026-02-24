import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import {
  createSamlAuthState,
  findActiveSamlConnectionBySlug,
  findDomainRouteByDomain,
  consumeSamlAuthStateById,
  type SamlConnectionRow
} from "../lib/enterprise-db";
import { addSecondsToIso } from "../lib/time";
import {
  buildSamlAuthnRequestXml,
  buildSamlSpMetadataXml,
  decodeSamlBase64Xml,
  encodeSamlXmlToBase64,
  parseSamlResponseXml,
  pickSamlAttributeValue,
  validateParsedSamlResponse
} from "../lib/saml";
import { getAppUrl } from "../lib/config";
import { appendQuery, publicUser } from "../lib/http";
import { createSessionAndTokens, readRequestIp } from "../lib/auth";
import { setRefreshTokenCookie } from "../lib/cookies";
import { assessAndRecordSessionRisk } from "../lib/session-risk";
import { issueSignInMfaChallengeIfNeeded } from "../lib/mfa-auth";
import { createUser, findUserByEmail, findUserById, updateUserProfile, writeAuditLog } from "../lib/db";
import { readJsonBody } from "../lib/request";

const startResponseModeSchema = z.enum(["json", "redirect"]);

const parseBodyForSamlCallback = async (request: Request): Promise<{
  samlResponse: string | null;
  relayState: string | null;
  mode: string | null;
}> => {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (contentType.includes("application/json")) {
    const json = await readJsonBody<{ SAMLResponse?: string; RelayState?: string; mode?: string }>(request);
    return {
      samlResponse: json?.SAMLResponse?.trim() || null,
      relayState: json?.RelayState?.trim() || null,
      mode: json?.mode?.trim() || null
    };
  }

  const raw = await request.text();
  const form = new URLSearchParams(raw);
  return {
    samlResponse: form.get("SAMLResponse")?.trim() || null,
    relayState: form.get("RelayState")?.trim() || null,
    mode: form.get("mode")?.trim() || null
  };
};

const toPublicSamlConnection = (connection: SamlConnectionRow) => ({
  id: connection.id,
  slug: connection.slug,
  name: connection.name,
  idpEntityId: connection.idp_entity_id,
  ssoUrl: connection.sso_url,
  spEntityId: connection.sp_entity_id,
  acsUrl: connection.acs_url,
  defaultRole: connection.default_role,
  requireSignedAssertions: Boolean(connection.require_signed_assertions),
  allowIdpInitiated: Boolean(connection.allow_idp_initiated),
  isActive: Boolean(connection.is_active),
  createdAt: connection.created_at,
  updatedAt: connection.updated_at
});

const resolveEmailFromAssertion = (params: {
  parsed: ReturnType<typeof parseSamlResponseXml>;
  attributeMapping: {
    email?: string;
  } | null;
}): string | null => {
  const mappedEmail = params.attributeMapping?.email
    ? pickSamlAttributeValue(params.parsed, [params.attributeMapping.email])
    : null;

  const fallback = pickSamlAttributeValue(params.parsed, [
    "email",
    "mail",
    "Email",
    "EmailAddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3"
  ]);

  const candidate = (mappedEmail || fallback || params.parsed.nameId || "").trim().toLowerCase();
  if (!candidate || !candidate.includes("@")) {
    return null;
  }
  return candidate;
};

const resolveFullNameFromAssertion = (params: {
  parsed: ReturnType<typeof parseSamlResponseXml>;
  attributeMapping: {
    fullName?: string;
    firstName?: string;
    lastName?: string;
  } | null;
}): string | null => {
  const mappedFullName = params.attributeMapping?.fullName
    ? pickSamlAttributeValue(params.parsed, [params.attributeMapping.fullName])
    : null;
  if (mappedFullName) {
    return mappedFullName;
  }

  const fallbackFullName = pickSamlAttributeValue(params.parsed, [
    "name",
    "displayName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
  ]);
  if (fallbackFullName) {
    return fallbackFullName;
  }

  const firstName = params.attributeMapping?.firstName
    ? pickSamlAttributeValue(params.parsed, [params.attributeMapping.firstName])
    : pickSamlAttributeValue(params.parsed, [
        "first_name",
        "given_name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
      ]);
  const lastName = params.attributeMapping?.lastName
    ? pickSamlAttributeValue(params.parsed, [params.attributeMapping.lastName])
    : pickSamlAttributeValue(params.parsed, [
        "last_name",
        "family_name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
      ]);

  const combined = `${firstName ?? ""} ${lastName ?? ""}`.trim();
  return combined || null;
};

export const samlRoutes = new Hono<{ Bindings: EnvBindings }>();

samlRoutes.get("/discover", async (context) => {
  const email = context.req.query("email")?.trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return context.json(
      {
        error: {
          code: "INVALID_EMAIL",
          message: "Query parameter 'email' must be a valid email address"
        }
      },
      400
    );
  }

  const domain = email.split("@").pop() ?? "";
  const route = await findDomainRouteByDomain(context.env.DB, domain);
  if (!route) {
    return context.json({
      strategy: "password",
      domain
    });
  }

  if (route.connection_type === "saml" && route.connection_id) {
    const connection = await context.env.DB
      .prepare(
        `SELECT slug, name, is_active
         FROM saml_connections
         WHERE id = ?`
      )
      .bind(route.connection_id)
      .first<{ slug: string; name: string; is_active: number }>();

    if (connection?.is_active) {
      const baseUrl = getAppUrl(context.env, context.req.raw);
      return context.json({
        strategy: "saml",
        domain,
        connection: {
          slug: connection.slug,
          name: connection.name
        },
        startUrl: `${baseUrl}/v1/saml/${encodeURIComponent(connection.slug)}/start`
      });
    }
  }

  if (route.connection_type === "google") {
    return context.json({
      strategy: "google",
      domain,
      startUrl: `${getAppUrl(context.env, context.req.raw)}/v1/oauth/google/start`
    });
  }

  return context.json({
    strategy: "password",
    domain
  });
});

samlRoutes.get("/:connectionSlug/metadata", async (context) => {
  const connection = await findActiveSamlConnectionBySlug(context.env.DB, context.req.param("connectionSlug"));
  if (!connection) {
    return context.json(
      {
        error: {
          code: "SAML_CONNECTION_NOT_FOUND",
          message: "SAML connection does not exist or is disabled"
        }
      },
      404
    );
  }

  const xml = buildSamlSpMetadataXml({
    entityId: connection.sp_entity_id,
    acsUrl: connection.acs_url,
    wantAssertionsSigned: Boolean(connection.require_signed_assertions)
  });

  context.header("content-type", "application/samlmetadata+xml; charset=utf-8");
  return context.body(xml, 200);
});

samlRoutes.get("/:connectionSlug/start", async (context) => {
  const connection = await findActiveSamlConnectionBySlug(context.env.DB, context.req.param("connectionSlug"));
  if (!connection) {
    return context.json(
      {
        error: {
          code: "SAML_CONNECTION_NOT_FOUND",
          message: "SAML connection does not exist or is disabled"
        }
      },
      404
    );
  }

  const stateId = crypto.randomUUID();
  await createSamlAuthState(context.env.DB, {
    id: stateId,
    samlConnectionId: connection.id,
    redirectTo: context.req.query("redirect_to") ?? null,
    expiresAt: addSecondsToIso(10 * 60)
  });

  const requestXml = buildSamlAuthnRequestXml({
    id: `_${crypto.randomUUID().replace(/-/g, "")}`,
    issueInstant: new Date().toISOString(),
    destination: connection.sso_url,
    assertionConsumerServiceUrl: connection.acs_url,
    issuer: connection.sp_entity_id
  });

  const samlRequest = encodeSamlXmlToBase64(requestXml);
  const redirectUrl = new URL(connection.sso_url);
  redirectUrl.searchParams.set("SAMLRequest", samlRequest);
  redirectUrl.searchParams.set("RelayState", stateId);

  const mode = startResponseModeSchema.safeParse(context.req.query("mode") || "redirect");
  if (mode.success && mode.data === "json") {
    return context.json({
      authorizationUrl: redirectUrl.toString(),
      relayState: stateId,
      requestXml,
      connection: toPublicSamlConnection(connection)
    });
  }

  return context.redirect(redirectUrl.toString(), 302);
});

samlRoutes.post("/:connectionSlug/acs", async (context) => {
  const connection = await findActiveSamlConnectionBySlug(context.env.DB, context.req.param("connectionSlug"));
  if (!connection) {
    return context.json(
      {
        error: {
          code: "SAML_CONNECTION_NOT_FOUND",
          message: "SAML connection does not exist or is disabled"
        }
      },
      404
    );
  }

  const body = await parseBodyForSamlCallback(context.req.raw);
  if (!body.samlResponse) {
    return context.json(
      {
        error: {
          code: "SAML_RESPONSE_MISSING",
          message: "SAMLResponse is required"
        }
      },
      400
    );
  }

  let xml: string;
  try {
    xml = decodeSamlBase64Xml(body.samlResponse);
  } catch {
    return context.json(
      {
        error: {
          code: "SAML_RESPONSE_INVALID",
          message: "SAMLResponse cannot be decoded"
        }
      },
      400
    );
  }

  const parsed = parseSamlResponseXml(xml);

  let redirectTo: string | null = null;
  let expectedInResponseTo: string | null = null;
  if (body.relayState) {
    const state = await consumeSamlAuthStateById(context.env.DB, body.relayState);
    if (!state || state.saml_connection_id !== connection.id) {
      return context.json(
        {
          error: {
            code: "SAML_STATE_INVALID",
            message: "RelayState is invalid, expired, or does not match this SAML connection"
          }
        },
        400
      );
    }
    redirectTo = state.redirect_to;
    expectedInResponseTo = state.id;
  }

  const validation = validateParsedSamlResponse({
    parsed,
    idpEntityId: connection.idp_entity_id,
    spEntityId: connection.sp_entity_id,
    acsUrl: connection.acs_url,
    requireSignedAssertions: Boolean(connection.require_signed_assertions),
    certificatePem: connection.x509_cert_pem,
    expectedInResponseTo,
    allowIdpInitiated: Boolean(connection.allow_idp_initiated)
  });

  if (!validation.ok) {
    return context.json(
      {
        error: {
          code: "SAML_ASSERTION_REJECTED",
          message: "SAML assertion validation failed",
          reasons: validation.errors
        }
      },
      400
    );
  }

  const attributeMapping = (() => {
    if (!connection.attribute_mapping_json) {
      return null;
    }
    try {
      const parsedValue = JSON.parse(connection.attribute_mapping_json) as {
        email?: string;
        fullName?: string;
        firstName?: string;
        lastName?: string;
      };
      if (!parsedValue || typeof parsedValue !== "object" || Array.isArray(parsedValue)) {
        return null;
      }
      return parsedValue;
    } catch {
      return null;
    }
  })();

  const email = resolveEmailFromAssertion({ parsed, attributeMapping });
  if (!email) {
    return context.json(
      {
        error: {
          code: "SAML_EMAIL_MISSING",
          message: "SAML assertion does not include a valid email attribute"
        }
      },
      400
    );
  }

  const fullName = resolveFullNameFromAssertion({ parsed, attributeMapping });
  const existingUser = await findUserByEmail(context.env.DB, email);
  const userId = existingUser?.id ?? crypto.randomUUID();
  if (!existingUser) {
    await createUser(context.env.DB, {
      id: userId,
      email,
      fullName,
      emailVerified: true
    });
  } else {
    await updateUserProfile(context.env.DB, {
      userId,
      fullName: fullName ?? existingUser.full_name,
      imageUrl: existingUser.image_url,
      emailVerified: true
    });
  }

  const mfaChallenge = await issueSignInMfaChallengeIfNeeded({
    db: context.env.DB,
    userId,
    primaryMethod: "saml",
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null
  });
  const redirectTarget = redirectTo || `${getAppUrl(context.env, context.req.raw)}/demo`;
  if (mfaChallenge.required) {
    if (redirectTo) {
      const withStatus = appendQuery(redirectTarget, "pj_auth", "mfa_required");
      const withChallenge = appendQuery(withStatus, "challenge_id", mfaChallenge.challengeId);
      return context.redirect(withChallenge, 302);
    }
    const user = await findUserById(context.env.DB, userId);
    return context.json({
      mfaRequired: true,
      challengeId: mfaChallenge.challengeId,
      expiresAt: mfaChallenge.expiresAt,
      methods: mfaChallenge.methods,
      primaryMethod: mfaChallenge.primaryMethod,
      user: user ? publicUser(user) : null
    });
  }

  const tokens = await createSessionAndTokens(context.env, {
    userId,
    userAgent: context.req.header("user-agent"),
    ipAddress: readRequestIp(context.req.raw)
  });
  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);

  const sessionRisk = await assessAndRecordSessionRisk({
    db: context.env.DB,
    userId,
    sessionId: tokens.sessionId,
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null,
    eventType: "auth.sign_in_saml"
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.sign_in_saml",
    metadataJson: JSON.stringify({
      organizationId: connection.organization_id,
      samlConnectionId: connection.id,
      issuer: parsed.assertionIssuer || parsed.issuer || null
    })
  });

  const user = await findUserById(context.env.DB, userId);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "SAML user cannot be loaded"
        }
      },
      500
    );
  }

  if (redirectTo) {
    const withStatus = appendQuery(redirectTarget, "pj_auth", "success");
    return context.redirect(`${withStatus}#access_token=${encodeURIComponent(tokens.accessToken)}`, 302);
  }

  return context.json({
    user: publicUser(user),
    session: {
      id: tokens.sessionId,
      accessToken: tokens.accessToken,
      tokenType: "Bearer"
    },
    sessionRisk: {
      score: sessionRisk.score,
      level: sessionRisk.level,
      reasons: sessionRisk.reasons,
      stepUpRecommended: sessionRisk.stepUpRecommended,
      autoRevokedOtherSessions: sessionRisk.autoRevokedOtherSessions,
      revokedCount: sessionRisk.revokedCount
    }
  });
});
