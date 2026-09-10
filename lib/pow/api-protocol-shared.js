import { EQ_DEFAULT_K, EQ_DEFAULT_N, parseEquihashParams } from "../equihash/params.js";
import { captchaTagV1, deriveEquihashSeed } from "../equihash/seed.js";
import {
  encodeV5Ticket,
  makeTicketMac,
  parseV5Ticket,
  ticketMacInput,
  verifyV5Ticket,
} from "../equihash/ticket.js";
import {
  base64UrlDecodeToBytes,
  base64UrlEncodeNoPad,
  getHmacKey,
  hmacSha256Base64UrlNoPad,
  isPlaceholderConfigSecret,
  timingSafeEqual,
} from "./auth-primitives.js";
import { verifyViaSiteverifyAggregator } from "./siteverify-client.js";

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
export const B64_HASH_MAX_LEN = 64;
export const B64_TICKET_MAX_LEN = 256;
export const CAPTCHA_TAG_LEN = 16;
export const TURN_TOKEN_MIN_LEN = 20;
export const TURN_TOKEN_MAX_LEN = 4096;
// Keep this above the complete v5 body envelope, including nested JSON escaping.
export const VERIFY_BODY_MAX_BYTES = Math.max(
  65536,
  B64_TICKET_MAX_LEN + 2048 + 4 * Math.ceil(24 / 3) + 4 * Math.ceil((4 * 2 ** 8) / 3) + 8 * (TURN_TOKEN_MAX_LEN + 32) + 512,
);
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/u;
const encoder = new TextEncoder();

export { base64UrlDecodeToBytes, base64UrlEncodeNoPad, getHmacKey, hmacSha256Base64UrlNoPad, isPlaceholderConfigSecret, timingSafeEqual };

export const hmacSha256 = async (secret, data) => {
  const key = await getHmacKey(secret);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(data)));
};

export const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
};

export const isBase64Url = (value, minLen = 1, maxLen = Number.MAX_SAFE_INTEGER) =>
  typeof value === "string" && value.length >= minLen && value.length <= maxLen && BASE64URL_RE.test(value);

export const getPowDifficultyBinding = (config = {}) => {
  const eq = parseEquihashParams(
    config.POW_EQ_N === undefined ? EQ_DEFAULT_N : config.POW_EQ_N,
    config.POW_EQ_K === undefined ? EQ_DEFAULT_K : config.POW_EQ_K,
  );
  if (!eq) throw new TypeError("invalid equihash params");
  return { eqN: eq.n, eqK: eq.k };
};

export const makePowBindingString = (
  ticket,
  hostname,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  eqN = ticket?.n,
  eqK = ticket?.k,
) => ticketMacInput({
  ...ticket,
  v: 5,
  n: Number.isSafeInteger(ticket?.n) ? ticket.n : eqN,
  k: Number.isSafeInteger(ticket?.k) ? ticket.k : eqK,
  m: Number.isSafeInteger(ticket?.m) ? ticket.m : 1,
  mac: ticket?.mac || base64UrlEncodeNoPad(new Uint8Array(32)),
}, {
  host: typeof hostname === "string" ? hostname : "",
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
});

export const verifyTicketMac = async (ticket, url, bindingValues, config, powSecret) => {
  if (!powSecret || !ticket || !url || !bindingValues) return "";
  try {
    const { eqN, eqK } = getPowDifficultyBinding(config);
    if (ticket.n !== eqN || ticket.k !== eqK) return "";
    const expected = await makeTicketMac(powSecret, ticket, {
      ...bindingValues,
      host: url.hostname,
    });
    return timingSafeEqual(expected, ticket.mac)
      ? ticketMacInput(ticket, { ...bindingValues, host: url.hostname })
      : "";
  } catch {
    return "";
  }
};

export const encodePowTicket = encodeV5Ticket;
export const parsePowTicket = parseV5Ticket;
export { verifyV5Ticket };

export const parseProofCookie = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 7 || parts[0] !== "v1") return null;
  const ticketB64 = parts[1] || "";
  const iat = Number.parseInt(parts[2], 10);
  const last = Number.parseInt(parts[3], 10);
  const n = Number.parseInt(parts[4], 10);
  const m = Number.parseInt(parts[5], 10);
  const mac = parts[6] || "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) || !isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  if (![iat, last, n, m].every((number) => Number.isSafeInteger(number) && number >= 0)) return null;
  return { v: 1, ticketB64, iat, last, n, m, mac };
};

export const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `O|${ticketB64}|${iat}|${last}|${n}|${m}`);

export const parseConsumeToken = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 6 || parts[0] !== "v2") return null;
  const ticketB64 = parts[1] || "";
  const expRaw = parts[2] || "";
  const captchaTag = parts[3] || "";
  const maskRaw = parts[4] || "";
  const mac = parts[5] || "";
  if (!/^(0|[1-9][0-9]*)$/u.test(expRaw) || !/^(0|[1-9][0-9]*)$/u.test(maskRaw)) return null;
  const exp = Number(expRaw);
  const m = Number(maskRaw);
  if (!Number.isSafeInteger(exp) || exp <= 0 || !Number.isSafeInteger(m) || m < 0) return null;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!(captchaTag === "any" || isBase64Url(captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN))) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, exp, captchaTag, m, mac };
};

export const makeConsumeMac = async (powSecret, ticketB64, exp, captchaTag, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${captchaTag}|${m}`);

export const normalizePathHash = (pathHash, config) => {
  if (config.POW_BIND_PATH === false) return "any";
  return isBase64Url(pathHash, 1, B64_HASH_MAX_LEN) ? pathHash : "";
};

export const computePathHash = async (canonicalPath) => base64UrlEncodeNoPad(await sha256Bytes(canonicalPath));

export const getPowBindingValuesWithPathHash = async (pathHash, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const bindIp = config.POW_BIND_IPRANGE !== false;
  const bindCountry = config.POW_BIND_COUNTRY === true;
  const bindAsn = config.POW_BIND_ASN === true;
  const bindTls = config.POW_BIND_TLS === true;
  const normalizedPathHash = bindPath ? normalizePathHash(pathHash, config) : "any";
  if (bindPath && !normalizedPathHash) return null;
  const source = derived && typeof derived === "object" ? derived : null;
  const ipScope = bindIp && typeof source?.ipScope === "string" ? source.ipScope : "";
  const country = bindCountry && typeof source?.country === "string" ? source.country : "";
  const asn = bindAsn && typeof source?.asn === "string" ? source.asn : "";
  const tlsFingerprint = bindTls && typeof source?.tlsFingerprint === "string" ? source.tlsFingerprint : "";
  if ((bindIp && !ipScope) || (bindCountry && !country) || (bindAsn && !asn) || (bindTls && !tlsFingerprint)) return null;
  return {
    pathHash: normalizedPathHash,
    ipScope: bindIp ? ipScope : "any",
    country: bindCountry ? country : "any",
    asn: bindAsn ? asn : "any",
    tlsFingerprint: bindTls ? tlsFingerprint : "any",
  };
};

export const getPowBindingValues = async (canonicalPath, config, derived) =>
  getPowBindingValuesWithPathHash(config.POW_BIND_PATH !== false ? await computePathHash(canonicalPath) : "any", config, derived);

export const resolveCaptchaRequirements = (config) => ({
  needPow: config.powcheck === true,
  needTurn: config.turncheck === true,
});

const validateTurnToken = (value) => {
  if (typeof value !== "string") return null;
  const token = value.trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN || CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

export { captchaTagV1, deriveEquihashSeed };

export const parseCanonicalCaptchaTokens = (captchaToken, needTurn) => {
  if (!needTurn) return { ok: true, malformed: false, tokens: { turnstile: "" } };
  let envelope = captchaToken;
  if (typeof captchaToken === "string") {
    const raw = captchaToken.trim();
    if (!raw) return { ok: false, malformed: true, tokens: null };
    try {
      envelope = JSON.parse(raw);
    } catch {
      return { ok: false, malformed: true, tokens: null };
    }
  }
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return { ok: false, malformed: true, tokens: null };
  for (const [key, value] of Object.entries(envelope)) {
    if (key !== "turnstile" || typeof value !== "string") return { ok: false, malformed: true, tokens: null };
  }
  const turnstile = validateTurnToken(envelope.turnstile);
  return turnstile ? { ok: true, malformed: false, tokens: { turnstile } } : { ok: false, malformed: true, tokens: null };
};

const getClientIP = (request, fallback = "") =>
  request.headers.get("CF-Connecting-IP") || request.headers.get("cf-connecting-ip") || fallback;

export const verifyRequiredCaptchaForTicket = async (
  request,
  config,
  ticket,
  captchaToken,
  remoteIpFallback = "",
) => {
  const { needTurn } = resolveCaptchaRequirements(config);
  const aggregatorPowAtomic = config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  if (!needTurn && !aggregatorPowAtomic) return { ok: true, malformed: false, captchaTag: "any" };
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  const turnToken = parsed.tokens.turnstile;
  const payload = {
    ticketMac: ticket.mac,
    remoteip: getClientIP(request, remoteIpFallback),
    token: {},
    providers: {},
    checks: {},
  };
  if (needTurn) {
    if (!config.TURNSTILE_SECRET) return { ok: false, malformed: false, captchaTag: "" };
    payload.token.turnstile = turnToken;
    payload.providers.turnstile = { secret: config.TURNSTILE_SECRET };
  }
  const result = await verifyViaSiteverifyAggregator({
    config,
    payload,
    powConsume: { cfgId: ticket.cfgId, ticketMac: ticket.mac, expireAt: ticket.e },
  });
  if (!result || result.ok !== true) return { ok: false, malformed: false, captchaTag: "" };
  return { ok: true, malformed: false, captchaTag: needTurn ? await captchaTagV1(turnToken) : "any" };
};

export const deriveLocalCaptchaTag = async (config, captchaToken) => {
  const { needTurn } = resolveCaptchaRequirements(config);
  if (!needTurn) return { ok: true, malformed: false, captchaTag: "any" };
  const parsed = parseCanonicalCaptchaTokens(captchaToken, true);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  return { ok: true, malformed: false, captchaTag: await captchaTagV1(parsed.tokens.turnstile) };
};
