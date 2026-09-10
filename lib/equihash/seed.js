import { base64UrlEncodeNoPad } from "./encoding.js";

const encoder = new TextEncoder();
const SEED_DOMAIN = "equihash-seed-v1";

const sha256 = async (text) => {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto unavailable");
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(text)));
};

const normalizedString = (value, name, fallback = "") => {
  const out = value === undefined ? fallback : value;
  if (typeof out !== "string" || /[\u0000-\u001F\u007F]/u.test(out)) throw new TypeError(`invalid seed ${name}`);
  return out;
};

export const captchaTagV1 = async (turnstileToken) =>
  base64UrlEncodeNoPad((await sha256(`ctag|v1|t=${normalizedString(turnstileToken, "token")}`)).subarray(0, 12));

export const deriveEquihashSeed = async (input = {}) => {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("seed input required");
  const ticketB64 = normalizedString(input.ticketB64, "ticket");
  const pathHash = normalizedString(input.pathHash, "pathHash");
  const captchaTag = normalizedString(input.captchaTag, "captchaTag", undefined);
  if (!ticketB64 || !pathHash || !captchaTag) throw new TypeError("invalid seed material");
  return sha256(JSON.stringify([SEED_DOMAIN, ticketB64, pathHash, captchaTag]));
};

export { SEED_DOMAIN as EQ_SEED_DOMAIN };
