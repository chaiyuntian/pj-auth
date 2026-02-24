const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const bytesToBase32 = (bytes: Uint8Array): string => {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
};

const base32ToBytes = (input: string): Uint8Array => {
  const normalized = input.toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid base32 character");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
};

const padNumber = (value: number, width: number): string => value.toString().padStart(width, "0");

const hmacSha1 = async (secretBytes: Uint8Array, message: Uint8Array): Promise<Uint8Array> => {
  const secretBuffer = secretBytes.buffer.slice(
    secretBytes.byteOffset,
    secretBytes.byteOffset + secretBytes.byteLength
  ) as ArrayBuffer;
  const messageBuffer = message.buffer.slice(
    message.byteOffset,
    message.byteOffset + message.byteLength
  ) as ArrayBuffer;
  const key = await crypto.subtle.importKey("raw", secretBuffer, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, messageBuffer);
  return new Uint8Array(signature);
};

const hotpCode = async (secretBase32: string, counter: number, digits: number): Promise<string> => {
  const secretBytes = base32ToBytes(secretBase32);
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(4, counter, false);
  const hmac = await hmacSha1(secretBytes, counterBytes);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = binary % Math.pow(10, digits);
  return padNumber(otp, digits);
};

export const generateTotpSecret = (length = 20): string => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToBase32(bytes);
};

export const buildTotpOtpauthUri = (params: {
  issuer: string;
  accountName: string;
  secretBase32: string;
  digits?: number;
  periodSeconds?: number;
}): string => {
  const digits = params.digits ?? 6;
  const period = params.periodSeconds ?? 30;
  const issuer = params.issuer.trim();
  const accountName = params.accountName.trim();
  const label = `${issuer}:${accountName}`;
  const url = new URL(`otpauth://totp/${encodeURIComponent(label)}`);
  url.searchParams.set("secret", params.secretBase32);
  url.searchParams.set("issuer", issuer);
  url.searchParams.set("algorithm", "SHA1");
  url.searchParams.set("digits", String(digits));
  url.searchParams.set("period", String(period));
  return url.toString();
};

export const verifyTotpCode = async (params: {
  secretBase32: string;
  code: string;
  digits?: number;
  periodSeconds?: number;
  skewWindows?: number;
  nowMs?: number;
}): Promise<boolean> => {
  const digits = params.digits ?? 6;
  const periodSeconds = params.periodSeconds ?? 30;
  const skewWindows = params.skewWindows ?? 1;
  const nowMs = params.nowMs ?? Date.now();
  const normalizedCode = params.code.replace(/\s+/g, "");
  if (!/^\d+$/.test(normalizedCode) || normalizedCode.length !== digits) {
    return false;
  }
  const counter = Math.floor(nowMs / 1000 / periodSeconds);
  for (let delta = -skewWindows; delta <= skewWindows; delta += 1) {
    const code = await hotpCode(params.secretBase32, counter + delta, digits);
    if (code === normalizedCode) {
      return true;
    }
  }
  return false;
};

const randomRecoveryChunk = (): string => {
  const bytes = new Uint8Array(5);
  crypto.getRandomValues(bytes);
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let index = 0; index < bytes.length; index += 1) {
    out += alphabet[bytes[index] % alphabet.length];
  }
  return out;
};

export const generateRecoveryCodes = (count = 8): string[] => {
  const codes: string[] = [];
  for (let index = 0; index < count; index += 1) {
    codes.push(`${randomRecoveryChunk()}-${randomRecoveryChunk()}`);
  }
  return codes;
};
