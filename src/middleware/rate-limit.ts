import type { Context, Next } from "hono";
import type { EnvBindings } from "../types";
import { getAuthRateLimitSettings } from "../lib/config";
import { readRequestIp } from "../lib/auth";

const buildWindowStartIso = (nowMs: number, windowSeconds: number): string => {
  const epochSeconds = Math.floor(nowMs / 1000);
  const windowStart = Math.floor(epochSeconds / windowSeconds) * windowSeconds;
  return new Date(windowStart * 1000).toISOString();
};

const buildResetUnix = (nowMs: number, windowSeconds: number): number => {
  const epochSeconds = Math.floor(nowMs / 1000);
  const resetAt = Math.floor(epochSeconds / windowSeconds) * windowSeconds + windowSeconds;
  return resetAt;
};

const consume = async (env: EnvBindings, key: string, windowStart: string, now: string): Promise<number> => {
  await env.DB.prepare(
    `INSERT INTO rate_limits (key, window_start, count, updated_at)
     VALUES (?, ?, 1, ?)
     ON CONFLICT(key, window_start) DO UPDATE SET
       count = count + 1,
       updated_at = excluded.updated_at`
  )
    .bind(key, windowStart, now)
    .run();

  const row = await env.DB.prepare(
    `SELECT count
     FROM rate_limits
     WHERE key = ? AND window_start = ?`
  )
    .bind(key, windowStart)
    .first<{ count: number }>();
  return row?.count ?? 0;
};

const maybeCleanup = async (env: EnvBindings, nowMs: number, windowSeconds: number): Promise<void> => {
  if (Math.random() > 0.01) {
    return;
  }
  const cutoffMs = nowMs - windowSeconds * 1000 * 12;
  const cutoffIso = new Date(cutoffMs).toISOString();
  await env.DB.prepare("DELETE FROM rate_limits WHERE updated_at < ?").bind(cutoffIso).run();
};

export const createAuthRateLimitMiddleware = (bucket = "auth") =>
  async (context: Context<{ Bindings: EnvBindings }>, next: Next) => {
    const settings = getAuthRateLimitSettings(context.env);
    if (!settings.enabled) {
      await next();
      return;
    }

    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const windowStart = buildWindowStartIso(nowMs, settings.windowSeconds);
    const ip = readRequestIp(context.req.raw) ?? "unknown";
    const key = `${bucket}:${ip}`;

    let count = 0;
    try {
      count = await consume(context.env, key, windowStart, nowIso);
      await maybeCleanup(context.env, nowMs, settings.windowSeconds);
    } catch (error) {
      console.error(`[rate_limit] fail-open key=${key} error=${error instanceof Error ? error.message : String(error)}`);
      await next();
      return;
    }

    const remaining = Math.max(settings.maxRequests - count, 0);
    context.header("x-ratelimit-limit", String(settings.maxRequests));
    context.header("x-ratelimit-remaining", String(remaining));
    context.header("x-ratelimit-reset", String(buildResetUnix(nowMs, settings.windowSeconds)));

    if (count > settings.maxRequests) {
      context.header("retry-after", String(settings.windowSeconds));
      return context.json(
        {
          error: {
            code: "RATE_LIMITED",
            message: "Too many requests. Please retry later."
          }
        },
        429
      );
    }

    await next();
  };
