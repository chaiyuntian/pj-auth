import { addSecondsToIso } from "./time";
import {
  createMfaChallenge,
  findActiveVerifiedTotpFactorForUser,
  writeAuditLog
} from "./db";

const MFA_SIGN_IN_CHALLENGE_TTL_SECONDS = 5 * 60;

export type MfaPrimaryMethod = "password" | "google_oauth" | "passkey" | "saml";

export type MfaSignInChallenge = {
  required: true;
  challengeId: string;
  expiresAt: string;
  methods: ("totp" | "recovery_code")[];
  primaryMethod: MfaPrimaryMethod;
};

export type MfaNotRequired = {
  required: false;
};

export const issueSignInMfaChallengeIfNeeded = async (params: {
  db: D1Database;
  userId: string;
  primaryMethod: MfaPrimaryMethod;
  ipAddress: string | null;
  userAgent: string | null;
}): Promise<MfaSignInChallenge | MfaNotRequired> => {
  const factor = await findActiveVerifiedTotpFactorForUser(params.db, params.userId);
  if (!factor) {
    return { required: false };
  }

  const challengeId = crypto.randomUUID();
  const expiresAt = addSecondsToIso(MFA_SIGN_IN_CHALLENGE_TTL_SECONDS);
  await createMfaChallenge(params.db, {
    id: challengeId,
    userId: params.userId,
    purpose: "sign_in",
    metadataJson: JSON.stringify({
      primaryMethod: params.primaryMethod,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent
    }),
    expiresAt
  });
  await writeAuditLog(params.db, {
    id: crypto.randomUUID(),
    actorType: "user",
    actorId: params.userId,
    eventType: "auth.mfa_challenge_issued",
    metadataJson: JSON.stringify({
      challengeId,
      primaryMethod: params.primaryMethod,
      expiresAt
    })
  });

  return {
    required: true,
    challengeId,
    expiresAt,
    methods: ["totp", "recovery_code"],
    primaryMethod: params.primaryMethod
  };
};
