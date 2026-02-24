const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index] ?? 0);
  }
  return btoa(binary);
};

const base64ToBytes = (base64: string): Uint8Array => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
};

export const base64UrlEncode = (bytes: Uint8Array): string =>
  bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

export const base64UrlDecode = (value: string): Uint8Array => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = normalized.length % 4;
  const padded = padLength === 0 ? normalized : `${normalized}${"=".repeat(4 - padLength)}`;
  return base64ToBytes(padded);
};

export const randomChallenge = (size = 32): string => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
};

export const utf8ToBase64Url = (value: string): string => base64UrlEncode(textEncoder.encode(value));

export const base64UrlToUtf8 = (value: string): string => textDecoder.decode(base64UrlDecode(value));

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
};

const concatBytes = (left: Uint8Array, right: Uint8Array): Uint8Array => {
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
};

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

export const sha256Bytes = async (value: string | Uint8Array): Promise<Uint8Array> => {
  const input = typeof value === "string" ? textEncoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(input));
  return new Uint8Array(digest);
};

export const parseClientDataJSON = (clientDataJsonBase64Url: string): {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  rawBytes: Uint8Array;
} => {
  const rawBytes = base64UrlDecode(clientDataJsonBase64Url);
  const parsed = JSON.parse(textDecoder.decode(rawBytes)) as {
    type?: unknown;
    challenge?: unknown;
    origin?: unknown;
    crossOrigin?: unknown;
  };
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Invalid clientDataJSON payload");
  }
  if (typeof parsed.type !== "string" || typeof parsed.challenge !== "string" || typeof parsed.origin !== "string") {
    throw new Error("Malformed clientDataJSON fields");
  }
  return {
    type: parsed.type,
    challenge: parsed.challenge,
    origin: parsed.origin,
    crossOrigin: typeof parsed.crossOrigin === "boolean" ? parsed.crossOrigin : undefined,
    rawBytes
  };
};

export const validateClientData = (params: {
  clientData: {
    type: string;
    challenge: string;
    origin: string;
    crossOrigin?: boolean;
  };
  expectedType: "webauthn.create" | "webauthn.get";
  expectedChallenge: string;
  expectedOrigin: string;
}): void => {
  if (params.clientData.type !== params.expectedType) {
    throw new Error("WebAuthn clientData type mismatch");
  }
  if (params.clientData.challenge !== params.expectedChallenge) {
    throw new Error("WebAuthn challenge mismatch");
  }
  if (params.clientData.origin !== params.expectedOrigin) {
    throw new Error("WebAuthn origin mismatch");
  }
  if (params.clientData.crossOrigin === true) {
    throw new Error("Cross-origin WebAuthn payload is not allowed");
  }
};

export const parseAuthenticatorData = (authenticatorDataBase64Url: string): {
  rawBytes: Uint8Array;
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  userPresent: boolean;
  userVerified: boolean;
} => {
  const bytes = base64UrlDecode(authenticatorDataBase64Url);
  if (bytes.length < 37) {
    throw new Error("Authenticator data is too short");
  }
  const rpIdHash = bytes.slice(0, 32);
  const flags = bytes[32] ?? 0;
  const signCount = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(33, false);
  return {
    rawBytes: bytes,
    rpIdHash,
    flags,
    signCount,
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0
  };
};

export const verifyRpIdHash = async (rpIdHash: Uint8Array, rpId: string): Promise<void> => {
  const expected = await sha256Bytes(rpId);
  if (!bytesEqual(rpIdHash, expected)) {
    throw new Error("RP ID hash mismatch");
  }
};

export const verifyAssertionSignature = async (params: {
  publicKeySpkiBase64: string;
  authenticatorDataRaw: Uint8Array;
  clientDataJsonRaw: Uint8Array;
  signatureBase64Url: string;
}): Promise<boolean> => {
  const keyData = base64ToBytes(params.publicKeySpkiBase64);
  const key = await crypto.subtle.importKey(
    "spki",
    toArrayBuffer(keyData),
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    false,
    ["verify"]
  );
  const clientDataHash = await sha256Bytes(params.clientDataJsonRaw);
  const signedPayload = concatBytes(params.authenticatorDataRaw, clientDataHash);
  const signature = base64UrlDecode(params.signatureBase64Url);
  return crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    key,
    toArrayBuffer(signature),
    toArrayBuffer(signedPayload)
  );
};
