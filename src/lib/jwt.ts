import { fromBase64Url, jsonToBase64Url, safeJsonParse, toBase64Url, toBytes } from "./encoding";
import type { SessionClaims } from "../types";
import { unixNow } from "./time";

const importHmacKey = (secret: string): Promise<CryptoKey> =>
  crypto.subtle.importKey("raw", toBytes(secret) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
    "verify"
  ]);

export const signJwt = async <TPayload extends Record<string, unknown>>(
  payload: TPayload,
  secret: string
): Promise<string> => {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = jsonToBase64Url(header);
  const encodedPayload = jsonToBase64Url(payload);
  const message = `${encodedHeader}.${encodedPayload}`;
  const key = await importHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, toBytes(message) as BufferSource);
  return `${message}.${toBase64Url(new Uint8Array(signature))}`;
};

export const verifyJwt = async <TPayload extends Record<string, unknown>>(
  token: string,
  secret: string
): Promise<TPayload | null> => {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const headerBytes = fromBase64Url(encodedHeader);
  const header = safeJsonParse<{ alg?: string; typ?: string }>(new TextDecoder().decode(headerBytes));
  if (!header || header.alg !== "HS256" || header.typ !== "JWT") {
    return null;
  }

  const key = await importHmacKey(secret);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    fromBase64Url(encodedSignature) as BufferSource,
    toBytes(`${encodedHeader}.${encodedPayload}`) as BufferSource
  );
  if (!valid) {
    return null;
  }

  const payload = safeJsonParse<TPayload>(new TextDecoder().decode(fromBase64Url(encodedPayload)));
  return payload;
};

export const signAccessToken = async (claims: SessionClaims, secret: string): Promise<string> =>
  signJwt(claims, secret);

export const verifyAccessToken = async (
  token: string,
  secret: string
): Promise<SessionClaims | null> => {
  const payload = await verifyJwt<SessionClaims>(token, secret);
  if (!payload || payload.typ !== "access" || typeof payload.exp !== "number") {
    return null;
  }
  if (payload.exp <= unixNow()) {
    return null;
  }
  return payload;
};

export const decodeJwtPayloadUnsafe = <TPayload extends Record<string, unknown>>(
  token: string
): TPayload | null => {
  const parts = token.split(".");
  if (parts.length < 2) {
    return null;
  }
  const payloadRaw = new TextDecoder().decode(fromBase64Url(parts[1]));
  return safeJsonParse<TPayload>(payloadRaw);
};
