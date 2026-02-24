import { Hono } from "hono";
import { z } from "zod";
import type { EnvBindings } from "../types";
import { requireAuth } from "../middleware/require-auth";
import {
  createPasskeyChallenge,
  createPasskeyCredential,
  consumePasskeyChallengeById,
  findActivePasskeyCredentialByCredentialId,
  findUserByEmail,
  findUserById,
  listActivePasskeyCredentialsForUser,
  listPasskeyCredentialsForUser,
  touchPasskeyCredentialUsage,
  writeAuditLog
} from "../lib/db";
import { addSecondsToIso } from "../lib/time";
import { randomChallenge, parseClientDataJSON, validateClientData, parseAuthenticatorData, verifyAssertionSignature, verifyRpIdHash, utf8ToBase64Url } from "../lib/webauthn";
import { createSessionAndTokens, readRequestIp } from "../lib/auth";
import { setRefreshTokenCookie } from "../lib/cookies";
import { publicUser } from "../lib/http";
import { assessAndRecordSessionRisk } from "../lib/session-risk";
import { issueSignInMfaChallengeIfNeeded } from "../lib/mfa-auth";

const CHALLENGE_TTL_SECONDS = 5 * 60;

const registerFinishSchema = z.object({
  challengeId: z.string().uuid(),
  credentialId: z.string().min(16).max(1000),
  clientDataJSON: z.string().min(16),
  publicKeySpki: z.string().min(16),
  transports: z.array(z.string().min(1).max(40)).max(16).optional(),
  name: z.string().min(1).max(120).optional()
});

const authenticateStartSchema = z.object({
  email: z.string().email().min(3).max(320)
});

const authenticateFinishSchema = z.object({
  challengeId: z.string().uuid(),
  credentialId: z.string().min(16).max(1000),
  clientDataJSON: z.string().min(16),
  authenticatorData: z.string().min(16),
  signature: z.string().min(16)
});

const invalidBody = (issues: z.ZodIssue[]) => ({
  error: {
    code: "INVALID_REQUEST",
    message: "Request body validation failed",
    issues
  }
});

const requestOrigin = (request: Request): string => {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
};

const requestRpId = (request: Request): string => new URL(request.url).hostname;

const formatSession = (session: { id: string; accessToken: string }) => ({
  id: session.id,
  accessToken: session.accessToken,
  tokenType: "Bearer"
});

export const passkeyRoutes = new Hono<{
  Bindings: EnvBindings;
  Variables: {
    authUserId: string;
    authSessionId: string;
  };
}>();

passkeyRoutes.get("/credentials", requireAuth, async (context) => {
  const credentials = await listPasskeyCredentialsForUser(context.env.DB, context.get("authUserId"));
  return context.json({
    passkeys: credentials.map((credential) => ({
      id: credential.id,
      credentialId: credential.credential_id,
      algorithm: credential.algorithm,
      name: credential.name,
      signCount: credential.sign_count,
      lastUsedAt: credential.last_used_at,
      revokedAt: credential.revoked_at,
      createdAt: credential.created_at,
      updatedAt: credential.updated_at
    }))
  });
});

passkeyRoutes.post("/register/start", requireAuth, async (context) => {
  const user = await findUserById(context.env.DB, context.get("authUserId"));
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "Authenticated user does not exist"
        }
      },
      404
    );
  }

  const challenge = randomChallenge(32);
  const challengeId = crypto.randomUUID();
  const rpId = requestRpId(context.req.raw);
  const origin = requestOrigin(context.req.raw);
  await createPasskeyChallenge(context.env.DB, {
    id: challengeId,
    userId: user.id,
    challenge,
    purpose: "register",
    rpId,
    origin,
    expiresAt: addSecondsToIso(CHALLENGE_TTL_SECONDS)
  });

  const credentials = await listActivePasskeyCredentialsForUser(context.env.DB, user.id);
  return context.json({
    challengeId,
    publicKey: {
      challenge,
      rp: {
        name: "PajamaDot Auth",
        id: rpId
      },
      user: {
        id: utf8ToBase64Url(user.id),
        name: user.email,
        displayName: user.full_name ?? user.email
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 60000,
      attestation: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      },
      excludeCredentials: credentials.map((credential) => ({
        id: credential.credential_id,
        type: "public-key"
      }))
    }
  });
});

passkeyRoutes.post("/register/finish", requireAuth, async (context) => {
  const payload = await context.req.json().catch(() => null);
  const parsed = registerFinishSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const challenge = await consumePasskeyChallengeById(context.env.DB, {
    id: parsed.data.challengeId,
    purpose: "register"
  });
  if (!challenge || challenge.user_id !== context.get("authUserId")) {
    return context.json(
      {
        error: {
          code: "PASSKEY_CHALLENGE_INVALID",
          message: "Passkey challenge is invalid, expired, or already used"
        }
      },
      400
    );
  }

  let clientData: ReturnType<typeof parseClientDataJSON>;
  try {
    clientData = parseClientDataJSON(parsed.data.clientDataJSON);
    validateClientData({
      clientData,
      expectedType: "webauthn.create",
      expectedChallenge: challenge.challenge,
      expectedOrigin: challenge.origin
    });
  } catch (error) {
    return context.json(
      {
        error: {
          code: "PASSKEY_REGISTRATION_INVALID",
          message: error instanceof Error ? error.message : "Invalid passkey registration payload"
        }
      },
      400
    );
  }

  await createPasskeyCredential(context.env.DB, {
    id: crypto.randomUUID(),
    userId: context.get("authUserId"),
    credentialId: parsed.data.credentialId,
    publicKeySpki: parsed.data.publicKeySpki,
    algorithm: "ES256",
    transportsJson: parsed.data.transports ? JSON.stringify(parsed.data.transports) : null,
    name: parsed.data.name ?? null,
    signCount: 0
  });
  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: context.get("authUserId"),
    eventType: "auth.passkey_registered",
    metadataJson: JSON.stringify({
      credentialId: parsed.data.credentialId,
      name: parsed.data.name ?? null
    })
  });

  return context.json(
    {
      ok: true,
      credentialId: parsed.data.credentialId,
      challengeId: challenge.id
    },
    201
  );
});

passkeyRoutes.post("/authenticate/start", async (context) => {
  const payload = await context.req.json().catch(() => null);
  const parsed = authenticateStartSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const user = await findUserByEmail(context.env.DB, parsed.data.email);
  if (!user) {
    return context.json(
      {
        error: {
          code: "PASSKEY_USER_NOT_FOUND",
          message: "User was not found"
        }
      },
      404
    );
  }

  const credentials = await listActivePasskeyCredentialsForUser(context.env.DB, user.id);
  if (credentials.length === 0) {
    return context.json(
      {
        error: {
          code: "PASSKEY_CREDENTIAL_NOT_FOUND",
          message: "No active passkeys found for this user"
        }
      },
      404
    );
  }

  const challenge = randomChallenge(32);
  const challengeId = crypto.randomUUID();
  const rpId = requestRpId(context.req.raw);
  const origin = requestOrigin(context.req.raw);
  await createPasskeyChallenge(context.env.DB, {
    id: challengeId,
    userId: user.id,
    challenge,
    purpose: "authenticate",
    rpId,
    origin,
    expiresAt: addSecondsToIso(CHALLENGE_TTL_SECONDS)
  });

  return context.json({
    challengeId,
    user: {
      id: user.id,
      email: user.email
    },
    publicKey: {
      challenge,
      rpId,
      allowCredentials: credentials.map((credential) => ({
        id: credential.credential_id,
        type: "public-key"
      })),
      timeout: 60000,
      userVerification: "preferred"
    }
  });
});

passkeyRoutes.post("/authenticate/finish", async (context) => {
  const payload = await context.req.json().catch(() => null);
  const parsed = authenticateFinishSchema.safeParse(payload);
  if (!parsed.success) {
    return context.json(invalidBody(parsed.error.issues), 400);
  }

  const challenge = await consumePasskeyChallengeById(context.env.DB, {
    id: parsed.data.challengeId,
    purpose: "authenticate"
  });
  if (!challenge) {
    return context.json(
      {
        error: {
          code: "PASSKEY_CHALLENGE_INVALID",
          message: "Passkey challenge is invalid, expired, or already used"
        }
      },
      400
    );
  }

  const credential = await findActivePasskeyCredentialByCredentialId(context.env.DB, parsed.data.credentialId);
  if (!credential) {
    return context.json(
      {
        error: {
          code: "PASSKEY_CREDENTIAL_NOT_FOUND",
          message: "Passkey credential was not found"
        }
      },
      404
    );
  }

  if (challenge.user_id && credential.user_id !== challenge.user_id) {
    return context.json(
      {
        error: {
          code: "PASSKEY_USER_MISMATCH",
          message: "Credential does not belong to challenge user"
        }
      },
      400
    );
  }

  let clientData: ReturnType<typeof parseClientDataJSON>;
  let authenticatorData: ReturnType<typeof parseAuthenticatorData>;
  try {
    clientData = parseClientDataJSON(parsed.data.clientDataJSON);
    validateClientData({
      clientData,
      expectedType: "webauthn.get",
      expectedChallenge: challenge.challenge,
      expectedOrigin: challenge.origin
    });
    authenticatorData = parseAuthenticatorData(parsed.data.authenticatorData);
    await verifyRpIdHash(authenticatorData.rpIdHash, challenge.rp_id);
    if (!authenticatorData.userPresent) {
      throw new Error("Passkey assertion missing user presence");
    }
  } catch (error) {
    return context.json(
      {
        error: {
          code: "PASSKEY_ASSERTION_INVALID",
          message: error instanceof Error ? error.message : "Invalid passkey assertion payload"
        }
      },
      400
    );
  }

  const signatureValid = await verifyAssertionSignature({
    publicKeySpkiBase64: credential.public_key_spki,
    authenticatorDataRaw: authenticatorData.rawBytes,
    clientDataJsonRaw: clientData.rawBytes,
    signatureBase64Url: parsed.data.signature
  }).catch(() => false);
  if (!signatureValid) {
    return context.json(
      {
        error: {
          code: "PASSKEY_SIGNATURE_INVALID",
          message: "Passkey signature verification failed"
        }
      },
      401
    );
  }

  if (credential.sign_count > 0 && authenticatorData.signCount <= credential.sign_count) {
    return context.json(
      {
        error: {
          code: "PASSKEY_COUNTER_REPLAY",
          message: "Passkey counter replay detected"
        }
      },
      401
    );
  }
  await touchPasskeyCredentialUsage(context.env.DB, {
    credentialId: credential.credential_id,
    nextSignCount: authenticatorData.signCount
  });

  const user = await findUserById(context.env.DB, credential.user_id);
  if (!user) {
    return context.json(
      {
        error: {
          code: "USER_NOT_FOUND",
          message: "Passkey user no longer exists"
        }
      },
      404
    );
  }

  const mfaChallenge = await issueSignInMfaChallengeIfNeeded({
    db: context.env.DB,
    userId: user.id,
    primaryMethod: "passkey",
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null
  });
  if (mfaChallenge.required) {
    return context.json({
      mfaRequired: true,
      challengeId: mfaChallenge.challengeId,
      expiresAt: mfaChallenge.expiresAt,
      methods: mfaChallenge.methods,
      primaryMethod: mfaChallenge.primaryMethod,
      user: publicUser(user)
    });
  }

  const tokens = await createSessionAndTokens(context.env, {
    userId: user.id,
    userAgent: context.req.header("user-agent"),
    ipAddress: readRequestIp(context.req.raw)
  });
  setRefreshTokenCookie(context, tokens.refreshToken, tokens.refreshTtlSeconds);
  const risk = await assessAndRecordSessionRisk({
    db: context.env.DB,
    userId: user.id,
    sessionId: tokens.sessionId,
    ipAddress: readRequestIp(context.req.raw),
    userAgent: context.req.header("user-agent") ?? null,
    eventType: "auth.passkey_sign_in"
  });

  await writeAuditLog(context.env.DB, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: user.id,
    eventType: "auth.passkey_sign_in",
    metadataJson: JSON.stringify({
      credentialId: credential.credential_id,
      signCount: authenticatorData.signCount
    })
  });

  return context.json({
    user: publicUser(user),
    session: formatSession({
      id: tokens.sessionId,
      accessToken: tokens.accessToken
    }),
    sessionRisk: {
      score: risk.score,
      level: risk.level,
      reasons: risk.reasons,
      stepUpRecommended: risk.stepUpRecommended,
      autoRevokedOtherSessions: risk.autoRevokedOtherSessions,
      revokedCount: risk.revokedCount
    }
  });
});
