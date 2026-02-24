const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const toBytes = (value: string): Uint8Array => textEncoder.encode(value);

export const bytesToString = (value: Uint8Array): string => textDecoder.decode(value);

export const toBase64Url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

export const fromBase64Url = (value: string): Uint8Array => {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const decoded = atob(padded);
  const result = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) {
    result[index] = decoded.charCodeAt(index);
  }
  return result;
};

export const jsonToBase64Url = (value: unknown): string => toBase64Url(toBytes(JSON.stringify(value)));

export const randomToken = (size = 32): string => {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return toBase64Url(bytes);
};

export const safeJsonParse = <T>(value: string): T | null => {
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
};
