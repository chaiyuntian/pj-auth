import type { EnvBindings } from "../types";
import { bytesToString, fromBase64Url, toBase64Url, toBytes } from "./encoding";

const KMS_ALGORITHM = "AES-GCM";
const IV_LENGTH_BYTES = 12;

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

const getMasterSecret = (env: EnvBindings): string => {
  const key = env.KMS_MASTER_KEY?.trim() || env.JWT_SIGNING_KEY.trim();
  if (!key) {
    throw new Error("KMS master key is not configured");
  }
  return key;
};

const sha256 = async (value: string): Promise<Uint8Array> => {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(toBytes(value)));
  return new Uint8Array(digest);
};

const importAesKey = async (rawKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> =>
  crypto.subtle.importKey("raw", toArrayBuffer(rawKey), { name: KMS_ALGORITHM, length: 256 }, false, usages);

const encryptWithAesKey = async (rawKey: Uint8Array, plaintext: string): Promise<string> => {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const key = await importAesKey(rawKey, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt(
    {
      name: KMS_ALGORITHM,
      iv: toArrayBuffer(iv)
    },
    key,
    toArrayBuffer(toBytes(plaintext))
  );
  return `${toBase64Url(iv)}.${toBase64Url(new Uint8Array(encrypted))}`;
};

const decryptWithAesKey = async (rawKey: Uint8Array, ciphertext: string): Promise<string> => {
  const [ivPart, dataPart] = ciphertext.split(".");
  if (!ivPart || !dataPart) {
    throw new Error("Ciphertext format is invalid");
  }
  const iv = fromBase64Url(ivPart);
  const encrypted = fromBase64Url(dataPart);
  const key = await importAesKey(rawKey, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt(
    {
      name: KMS_ALGORITHM,
      iv: toArrayBuffer(iv)
    },
    key,
    toArrayBuffer(encrypted)
  );
  return bytesToString(new Uint8Array(decrypted));
};

export const generateRandomDataKeyMaterial = (): string =>
  toBase64Url(crypto.getRandomValues(new Uint8Array(32)));

export const encryptManagedKeyMaterial = async (params: {
  env: EnvBindings;
  keyMaterial: string;
}): Promise<string> => {
  const masterKeyBytes = await sha256(getMasterSecret(params.env));
  return encryptWithAesKey(masterKeyBytes, params.keyMaterial);
};

export const decryptManagedKeyMaterial = async (params: {
  env: EnvBindings;
  encryptedKeyMaterial: string;
}): Promise<string> => {
  const masterKeyBytes = await sha256(getMasterSecret(params.env));
  return decryptWithAesKey(masterKeyBytes, params.encryptedKeyMaterial);
};

export const encryptWithManagedKey = async (params: {
  keyMaterial: string;
  plaintext: string;
}): Promise<string> => {
  const rawKey = fromBase64Url(params.keyMaterial);
  if (rawKey.length !== 32) {
    throw new Error("Managed key material is invalid length");
  }
  return encryptWithAesKey(rawKey, params.plaintext);
};

export const decryptWithManagedKey = async (params: {
  keyMaterial: string;
  ciphertext: string;
}): Promise<string> => {
  const rawKey = fromBase64Url(params.keyMaterial);
  if (rawKey.length !== 32) {
    throw new Error("Managed key material is invalid length");
  }
  return decryptWithAesKey(rawKey, params.ciphertext);
};
