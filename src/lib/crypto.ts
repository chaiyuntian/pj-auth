import { fromBase64Url, randomToken, toBase64Url, toBytes } from "./encoding";

// Cloudflare Workers PBKDF2 currently supports up to 100000 iterations.
const HASH_ITERATIONS = 100_000;
const HASH_LENGTH = 32;

const importPasswordKey = async (password: string): Promise<CryptoKey> =>
  crypto.subtle.importKey("raw", toBytes(password) as BufferSource, { name: "PBKDF2" }, false, ["deriveBits"]);

const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let index = 0; index < a.length; index += 1) {
    mismatch |= a[index] ^ b[index];
  }
  return mismatch === 0;
};

const derivePasswordHash = async (password: string, salt: Uint8Array): Promise<Uint8Array> => {
  const key = await importPasswordKey(password);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: salt as BufferSource,
      iterations: HASH_ITERATIONS
    },
    key,
    HASH_LENGTH * 8
  );
  return new Uint8Array(bits);
};

export const createPasswordHash = async (
  password: string
): Promise<{ passwordHash: string; passwordSalt: string }> => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await derivePasswordHash(password, salt);
  return {
    passwordHash: toBase64Url(derived),
    passwordSalt: toBase64Url(salt)
  };
};

export const verifyPasswordHash = async (params: {
  password: string;
  storedHash: string;
  storedSalt: string;
}): Promise<boolean> => {
  const salt = fromBase64Url(params.storedSalt);
  const expected = fromBase64Url(params.storedHash);
  const derived = await derivePasswordHash(params.password, salt);
  return timingSafeEqual(expected, derived);
};

export const sha256Hex = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", toBytes(value) as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
};

export const generateRefreshToken = (): string => randomToken(48);
