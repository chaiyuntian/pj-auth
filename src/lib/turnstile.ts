import { readRequestIp } from "./auth";
import { getTurnstileSettings } from "./config";
import type { EnvBindings } from "../types";

type TurnstileVerifyResponse = {
  success?: boolean;
  "error-codes"?: string[];
};

export const assertTurnstileIfEnabled = async (params: {
  env: EnvBindings;
  request: Request;
  token?: string | null;
}): Promise<{ ok: true } | { ok: false; code: string; message: string; detail?: string[] }> => {
  const settings = getTurnstileSettings(params.env);
  if (!settings.enabled) {
    return { ok: true };
  }

  if (!settings.secretKey) {
    return {
      ok: false,
      code: "TURNSTILE_NOT_CONFIGURED",
      message: "Turnstile is enabled but secret key is missing"
    };
  }

  const token = params.token?.trim();
  if (!token) {
    return {
      ok: false,
      code: "TURNSTILE_TOKEN_REQUIRED",
      message: "Turnstile token is required"
    };
  }

  const verifyUrl = `${settings.apiBaseUrl}/turnstile/v0/siteverify`;
  const remoteIp = readRequestIp(params.request);
  const body = new URLSearchParams({
    secret: settings.secretKey,
    response: token
  });
  if (remoteIp) {
    body.set("remoteip", remoteIp);
  }

  const response = await fetch(verifyUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: body.toString()
  }).catch(() => null);

  if (!response || !response.ok) {
    return {
      ok: false,
      code: "TURNSTILE_VERIFY_FAILED",
      message: "Turnstile verification request failed"
    };
  }

  const json = (await response.json().catch(() => null)) as TurnstileVerifyResponse | null;
  if (!json?.success) {
    return {
      ok: false,
      code: "TURNSTILE_REJECTED",
      message: "Turnstile validation failed",
      detail: json?.["error-codes"] ?? []
    };
  }

  return { ok: true };
};
