import { isIsoExpired } from "./time";
import {
  createSessionRiskEvent,
  listUserSessions,
  revokeOtherUserSessions,
  writeAuditLog,
  type SessionRow
} from "./db";

export type SessionRiskLevel = "low" | "medium" | "high" | "critical";

export type SessionRiskEvaluation = {
  score: number;
  level: SessionRiskLevel;
  reasons: string[];
  stepUpRecommended: boolean;
  autoRevokedOtherSessions: boolean;
  revokedCount: number;
};

const normalizeUserAgent = (value: string | null | undefined): string =>
  (value ?? "").trim().toLowerCase();

const isLikelyAutomationUserAgent = (userAgent: string | null | undefined): boolean => {
  const normalized = normalizeUserAgent(userAgent);
  if (!normalized) {
    return false;
  }
  return /(curl|wget|python|bot|crawler|scrapy|postman|insomnia)/i.test(normalized);
};

const scoreToLevel = (score: number): SessionRiskLevel => {
  if (score >= 80) {
    return "critical";
  }
  if (score >= 60) {
    return "high";
  }
  if (score >= 30) {
    return "medium";
  }
  return "low";
};

const newestComparableSession = (sessions: SessionRow[], sessionId: string): SessionRow | null =>
  sessions
    .filter((session) => session.id !== sessionId)
    .sort((left, right) => Date.parse(right.last_active_at) - Date.parse(left.last_active_at))[0] ?? null;

const evaluate = (params: {
  sessions: SessionRow[];
  currentSessionId: string;
  ipAddress: string | null;
  userAgent: string | null;
}): Omit<SessionRiskEvaluation, "autoRevokedOtherSessions" | "revokedCount"> => {
  const reasons: string[] = [];
  let score = 5;

  const activeSessions = params.sessions.filter(
    (session) => !session.revoked_at && !isIsoExpired(session.expires_at)
  );
  const activeOtherSessions = activeSessions.filter((session) => session.id !== params.currentSessionId);
  const previousSession = newestComparableSession(activeSessions, params.currentSessionId);

  if (!params.ipAddress) {
    score += 20;
    reasons.push("missing_ip");
  }

  if (!params.userAgent) {
    score += 10;
    reasons.push("missing_user_agent");
  }

  if (isLikelyAutomationUserAgent(params.userAgent)) {
    score += 20;
    reasons.push("automation_like_user_agent");
  }

  if (previousSession?.ip_address && params.ipAddress && previousSession.ip_address !== params.ipAddress) {
    score += 35;
    reasons.push("ip_drift");
  }

  if (previousSession?.user_agent && params.userAgent) {
    const previousUa = normalizeUserAgent(previousSession.user_agent);
    const currentUa = normalizeUserAgent(params.userAgent);
    if (previousUa && currentUa && previousUa !== currentUa) {
      score += 20;
      reasons.push("user_agent_drift");
    }
  }

  const recentIps = new Set<string>();
  for (const session of activeSessions) {
    if (session.ip_address) {
      recentIps.add(session.ip_address);
    }
  }
  if (params.ipAddress) {
    recentIps.add(params.ipAddress);
  }
  if (recentIps.size >= 3) {
    score += 15;
    reasons.push("many_active_ips");
  }

  if (activeOtherSessions.length >= 4) {
    score += 15;
    reasons.push("many_active_sessions");
  }

  const bounded = Math.max(0, Math.min(100, score));
  const level = scoreToLevel(bounded);
  return {
    score: bounded,
    level,
    reasons,
    stepUpRecommended: bounded >= 70
  };
};

export const assessAndRecordSessionRisk = async (params: {
  db: D1Database;
  userId: string;
  sessionId: string;
  ipAddress: string | null;
  userAgent: string | null;
  eventType:
    | "auth.sign_up"
    | "auth.sign_in"
    | "auth.refresh"
    | "auth.sign_in_google"
    | "auth.passkey_sign_in"
    | "auth.sign_in_saml";
}): Promise<SessionRiskEvaluation> => {
  const sessions = await listUserSessions(params.db, params.userId);
  const evaluated = evaluate({
    sessions,
    currentSessionId: params.sessionId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent
  });

  await createSessionRiskEvent(params.db, {
    id: crypto.randomUUID(),
    userId: params.userId,
    sessionId: params.sessionId,
    riskScore: evaluated.score,
    reason: `${params.eventType}:${evaluated.reasons.join(",") || "baseline"}`,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent
  });

  let revokedCount = 0;
  const shouldAutoRevoke = evaluated.score >= 90;
  if (shouldAutoRevoke) {
    revokedCount = await revokeOtherUserSessions(params.db, {
      userId: params.userId,
      exceptSessionId: params.sessionId
    });
  }

  if (evaluated.score >= 60 || revokedCount > 0) {
    await writeAuditLog(params.db, {
      id: crypto.randomUUID(),
      actorType: "user",
      actorId: params.userId,
      eventType: "auth.session_risk_detected",
      metadataJson: JSON.stringify({
        sessionId: params.sessionId,
        score: evaluated.score,
        level: evaluated.level,
        reasons: evaluated.reasons,
        sourceEvent: params.eventType,
        revokedCount
      })
    });
  }

  return {
    ...evaluated,
    autoRevokedOtherSessions: revokedCount > 0,
    revokedCount
  };
};
