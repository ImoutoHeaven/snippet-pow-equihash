const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;

export const utf8 = (value) => encoder.encode(value);

export const base64UrlEncodeNoPad = (value) => {
  const bytes = value instanceof Uint8Array
    ? value
    : ArrayBuffer.isView(value)
      ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
      : value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : null;
  if (!bytes) throw new TypeError("bytes required");
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/gu, "");
};

export const base64UrlDecodeNoPad = (value) => {
  if (typeof value !== "string" || !value || !BASE64URL_RE.test(value) || value.length % 4 === 1) return null;
  let base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return base64UrlEncodeNoPad(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
};

export const decodeUtf8 = (bytes) => {
  try {
    return decoder.decode(bytes);
  } catch {
    return null;
  }
};

export const isBase64UrlNoPad = (value, min = 1, max = Number.MAX_SAFE_INTEGER) =>
  typeof value === "string" && value.length >= min && value.length <= max && base64UrlDecodeNoPad(value) instanceof Uint8Array;
