import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { addSecondsToIso } from "../lib/time";
import {
  createOAuthState,
  createUser,
  findOAuthAccount,
  findUserByEmail,
  findUserById,
  getGoogleProviderConfig,
  updateUserProfile,
  upsertOAuthAccount,
  writeAuditLog
} from "../lib/db";
import { randomToken } from "../lib/encoding";
import { consumeOAuthState } from "../lib/db";
import { createSessionAndTokens, readRequestIp } from "../lib/auth";
import { setRefreshTokenCookie } from "../lib/cookies";
import { appendQuery, publicUser } from "../lib/http";
import { getAppUrl } from "../lib/config";

const tokenResponseSchema = z.object({
  access_token: z.string(),
  expires_in: z.number().optional(),
  refresh_token: z.string().optional(),
  id_token: z.string().optional(),
  scope: z.string().optional(),
  token_type: z.string().optional()
});

const userInfoSchema = z.object({
  sub: z.string(),
  email: z.string().email().optional(),
  email_verified: z.boolean().optional(),
  name: z.string().optional(),
  picture: z.string().url().optional()
});

const buildGoogleAuthUrl = (params: {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
}) => {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", params.scope);
  url.searchParams.set("state", params.state);
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("include_granted_scopes", "true");
  url.searchParams.set("prompt", "consent");
  return url.toString();
};

const exchangeGoogleCode = async (params: {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}) => {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      code: params.code,
      client_id: params.clientId,
      client_secret: params.clientSecret,
      redirect_uri: params.redirectUri,
      grant_type: "authorization_code"
    }).toString()
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Failed token exchange (${response.status}): ${detail}`);
  }

  const json = await response.json();
  const parsed = tokenResponseSchema.safeParse(json);
  if (!parsed.success) {
    throw new Error("Google token response format is invalid");
  }
  return parsed.data;
};

const fetchGoogleUser = async (accessToken: string) => {
  const response = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: {
      authorization: `Bearer ${accessToken}`
    }
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Failed user info fetch (${response.status}): ${detail}`);
  }

  const json = await response.json();
  const parsed = userInfoSchema.safeParse(json);
  if (!parsed.success) {
    throw new Error("Google user info response format is invalid");
  }
  return parsed.data;
};

export const oauthRoutes = new Hono<{ Bindings: EnvBindings }>();

oauthRoutes.get("/google/start", async (context) => {
  const config = await getGoogleProviderConfig(context.env.DB, context.env);
  if (!config.enabled || !config.clientId || !config.clientSecret || !config.redirectUri) {
    return context.json(
      {
        error: {
          code: "GOOGLE_OAUTH_DISABLED",
          message: "Google OAuth is not configured or enabled"
        }
      },
      400
    );
  }

  const redirectTo = context.req.query("redirect_to");
  const state = randomToken(24);
  await createOAuthState(context.env.DB, {
    state,
    provider: "google",
    redirectTo: redirectTo ?? null,
    expiresAt: addSecondsToIso(10 * 60)
  });

  const authUrl = buildGoogleAuthUrl({
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scope: config.scope,
    state
  });

  if (context.req.query("mode") === "json") {
    return context.json({ authorizationUrl: authUrl, state });
  }

  return context.redirect(authUrl, 302);
});

oauthRoutes.get("/google/callback", async (context) => {
  const code = context.req.query("code");
  const state = context.req.query("state");
  if (!code || !state) {
    return context.json(
      {
        error: {
          code: "INVALID_OAUTH_CALLBACK",
          message: "Missing code or state"
        }
      },
      400
    );
  }

  const oauthState = await consumeOAuthState(context.env.DB, state, "google");
  if (!oauthState) {
    return context.json(
      {
        error: {
          code: "OAUTH_STATE_INVALID",
          message: "OAuth state is invalid, expired, or already consumed"
        }
      },
      400
    );
  }

  const config = await getGoogleProviderConfig(context.env.DB, context.env);
  if (!config.clientId || !config.clientSecret || !config.redirectUri) {
    return context.json(
      {
        error: {
          code: "GOOGLE_OAUTH_MISCONFIGURED",
          message: "Google provider config is incomplete"
        }
      },
      500
    );
  }

  let tokenPayload: z.infer<typeof tokenResponseSchema>;
  let userInfo: z.infer<typeof userInfoSchema>;
  try {
    tokenPayload = await exchangeGoogleCode({
      code,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri
    });
    userInfo = await fetchGoogleUser(tokenPayload.access_token);
  } catch (error) {
    return context.json(
      {
        error: {
          code: "GOOGLE_OAUTH_FAILED",
          message: error instanceof Error ? error.message : "Google OAuth failed"
        }
      },
      502
    );
  }

  let userId: string;
  const oauthAccount = await findOAuthAccount(context.env.DB, "google", userInfo.sub);
  if (oauthAccount) {
    userId = oauthAccount.user_id;
  } else if (userInfo.email) {
    const existingUser = await findUserByEmail(context.env.DB, userInfo.email);
    if (existingUser) {
      userId = existingUser.id;
    } else {
      userId = crypto.randomUUID();
      await createUser(context.env.DB, {
        id: userId,
        email: userInfo.email,
        fullName: userInfo.name ?? null,
        imageUrl: userInfo.picture ?? null,
        emailVerified: Boolean(userInfo.email_verified)
      });
    }
  } else {
    return context.json(
      {
        error: {
          code: "GOOGLE_EMAIL_MISSING",
          message: "Google account did not include an email address"
        }
      },
      400
    );
  }

  await upsertOAuthAccount(context.env.DB, {
    id: oauthAccount?.id ?? crypto.randomUUID(),
    userId,
    provider: "google",
    providerUserId: userInfo.sub,
    providerEmail: userInfo.email ?? null,
    accessToken: tokenPayload.access_token,
    refreshToken: tokenPayload.refresh_token ?? null,
    tokenExpiresAt: tokenPayload.expires_in ? addSecondsToIso(tokenPayload.expires_in) : null
  });

  await updateUserProfile(context.env.DB, {
    userId,
    fullName: userInfo.name ?? null,
    imageUrl: userInfo.picture ?? null,
    emailVerified: userInfo.email_verified
  });

  const tokens = await createSessionAndTokens(context.env, {
    userId,
    userAgent: context.req.header("user-agent"),
    ipAddress: readRequestIp(context.req.raw)
  });
  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: userId,
    eventType: "auth.sign_in_google",
    metadataJson: JSON.stringify({ providerUserId: userInfo.sub })
  });

  const user = await findUserById(context.env.DB, userId);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "OAuth user cannot be loaded"
        }
      },
      500
    );
  }

  const redirectTarget = oauthState.redirect_to || `${getAppUrl(context.env, context.req.raw)}/demo`;
  if (oauthState.redirect_to) {
    const urlWithStatus = appendQuery(redirectTarget, "pj_auth", "success");
    return context.redirect(`${urlWithStatus}#access_token=${encodeURIComponent(tokens.accessToken)}`, 302);
  }

  return context.json({
    user: publicUser(user),
    session: {
      id: tokens.sessionId,
      accessToken: tokens.accessToken,
      tokenType: "Bearer"
    }
  });
});
