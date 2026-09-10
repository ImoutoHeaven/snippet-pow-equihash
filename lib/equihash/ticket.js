import {
  base64UrlDecodeNoPad,
  base64UrlEncodeNoPad,
  decodeUtf8,
  isBase64UrlNoPad,
  utf8,
} from "./encoding.js";
import { isValidEquihashParams, parseEquihashParams } from "./params.js";
import { hmacSha256Base64UrlNoPad, timingSafeEqual } from "../pow/auth-primitives.js";

const VERSION = 5;
const TICKET_DOMAIN = "equihash-ticket-v5";
const TICKET_MAX_LEN = 256;
const CHALLENGE_BYTES = 16;
const MAC_BYTES = 32;
const CONTROL_RE = /[\u0000-\u001F\u007F]/u;
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/u;

const asStrictInt = (value, name, minimum = 0) => {
  const parsed = typeof value === "number"
    ? Number.isSafeInteger(value) ? value : null
    : typeof value === "string" && DECIMAL_RE.test(value) ? Number(value) : null;
  if (parsed === null || !Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new TypeError(`invalid ticket ${name}`);
  }
  return parsed;
};

const asBindingString = (value, name) => {
  if (typeof value !== "string" || CONTROL_RE.test(value)) throw new TypeError(`invalid ticket ${name}`);
  return value;
};

const getBindings = (source = {}) => {
  if (!source || typeof source !== "object" || Array.isArray(source)) throw new TypeError("ticket bindings required");
  return {
    host: asBindingString(source.host, "host").trim().toLowerCase(),
    pathHash: asBindingString(source.pathHash, "pathHash"),
    ipScope: asBindingString(source.ipScope, "ipScope"),
    country: asBindingString(source.country, "country"),
    asn: asBindingString(source.asn, "asn"),
    tlsFingerprint: asBindingString(source.tlsFingerprint, "tlsFingerprint"),
  };
};

const strictTicketParts = (ticket) => {
  if (!ticket || typeof ticket !== "object" || Array.isArray(ticket)) throw new TypeError("ticket object required");
  if (ticket.v !== undefined && asStrictInt(ticket.v, "version", 1) !== VERSION) throw new TypeError("invalid ticket version");
  const e = asStrictInt(ticket.e, "expireAt", 1);
  const cfgId = asStrictInt(ticket.cfgId, "cfgId");
  const issuedAt = asStrictInt(ticket.issuedAt, "issuedAt", 1);
  const r = ticket.r;
  if (!isBase64UrlNoPad(r, 22, 22) || base64UrlDecodeNoPad(r).length !== CHALLENGE_BYTES) {
    throw new TypeError("invalid ticket challenge id");
  }
  const eq = parseEquihashParams(ticket.n, ticket.k);
  if (!eq) throw new TypeError("invalid equihash params");
  const m = asStrictInt(ticket.m, "mask");
  if (m < 1 || m > 3) throw new TypeError("invalid ticket mask");
  const mac = ticket.mac;
  if (!isBase64UrlNoPad(mac, 43, 43) || base64UrlDecodeNoPad(mac).length !== MAC_BYTES) {
    throw new TypeError("invalid ticket mac");
  }
  if (e < issuedAt) throw new TypeError("ticket expires before issue");
  return { v: VERSION, e, cfgId, issuedAt, r, n: eq.n, k: eq.k, m, mac };
};

export const ticketMacInput = (ticket, bindings) => {
  const normalized = strictTicketParts({ ...ticket, mac: ticket?.mac || base64UrlEncodeNoPad(new Uint8Array(MAC_BYTES)) });
  const b = getBindings(bindings);
  return JSON.stringify([
    TICKET_DOMAIN,
    VERSION,
    normalized.e,
    normalized.cfgId,
    normalized.issuedAt,
    normalized.r,
    normalized.n,
    normalized.k,
    normalized.m,
    b.host,
    b.pathHash,
    b.ipScope,
    b.country,
    b.asn,
    b.tlsFingerprint,
  ]);
};

export const makeTicketMac = async (secret, ticket, bindings) =>
  hmacSha256Base64UrlNoPad(secret, ticketMacInput(ticket, bindings));

export const encodeV5Ticket = (ticket) => {
  const normalized = strictTicketParts(ticket);
  return base64UrlEncodeNoPad(utf8(`${VERSION}.${normalized.e}.${normalized.cfgId}.${normalized.issuedAt}.${normalized.r}.${normalized.n}.${normalized.k}.${normalized.m}.${normalized.mac}`));
};

export const parseV5Ticket = (ticketB64) => {
  try {
    if (!isBase64UrlNoPad(ticketB64, 1, TICKET_MAX_LEN)) return null;
    const raw = decodeUtf8(base64UrlDecodeNoPad(ticketB64));
    if (raw === null || CONTROL_RE.test(raw)) return null;
    const parts = raw.split(".");
    if (parts.length !== 9 || parts[0] !== String(VERSION)) return null;
    const ticket = {
      v: asStrictInt(parts[0], "version", 1),
      e: asStrictInt(parts[1], "expireAt", 1),
      cfgId: asStrictInt(parts[2], "cfgId"),
      issuedAt: asStrictInt(parts[3], "issuedAt", 1),
      r: parts[4],
      n: asStrictInt(parts[5], "n", 1),
      k: asStrictInt(parts[6], "k", 1),
      m: asStrictInt(parts[7], "mask"),
      mac: parts[8],
    };
    if (ticket.v !== VERSION || !isValidEquihashParams(ticket.n, ticket.k) || ticket.m < 1 || ticket.m > 3) return null;
    if (!isBase64UrlNoPad(ticket.r, 22, 22) || base64UrlDecodeNoPad(ticket.r).length !== CHALLENGE_BYTES) return null;
    if (!isBase64UrlNoPad(ticket.mac, 43, 43) || base64UrlDecodeNoPad(ticket.mac).length !== MAC_BYTES) return null;
    if (ticket.e < ticket.issuedAt || encodeV5Ticket(ticket) !== ticketB64) return null;
    return ticket;
  } catch {
    return null;
  }
};

const randomChallengeId = () => {
  const bytes = new Uint8Array(CHALLENGE_BYTES);
  if (!globalThis.crypto?.getRandomValues) throw new Error("secure random source unavailable");
  globalThis.crypto.getRandomValues(bytes);
  return base64UrlEncodeNoPad(bytes);
};

export const issueV5Ticket = async (input = {}) => {
  if (input.v !== undefined && asStrictInt(input.v, "version", 1) !== VERSION) throw new TypeError("invalid ticket version");
  const e = asStrictInt(input.e, "expireAt", 1);
  const cfgId = asStrictInt(input.cfgId, "cfgId");
  const issuedAt = asStrictInt(input.issuedAt, "issuedAt", 1);
  const eq = parseEquihashParams(input.n, input.k);
  if (!eq) throw new TypeError("invalid equihash params");
  const m = asStrictInt(input.m, "mask");
  if (m < 1 || m > 3) throw new TypeError("invalid ticket mask");
  if (e < issuedAt) throw new TypeError("ticket expires before issue");
  const r = randomChallengeId();
  const ticket = { v: VERSION, e, cfgId, issuedAt, r, n: eq.n, k: eq.k, m, mac: base64UrlEncodeNoPad(new Uint8Array(MAC_BYTES)) };
  ticket.mac = await makeTicketMac(input.powSecret, ticket, input.bindings);
  return encodeV5Ticket(ticket);
};

export const verifyV5Ticket = async (input = {}) => {
  let ticket = null;
  try {
    ticket = parseV5Ticket(input.ticketB64);
    if (!ticket) return { ok: false, reason: "bad_ticket" };
    const now = asStrictInt(input.nowSeconds, "nowSeconds", 1);
    if (ticket.e <= now) return { ok: false, reason: "expired", ticket };
    const expectedCfgId = asStrictInt(input.expectedCfgId, "cfgId");
    const expectedN = asStrictInt(input.expectedN, "n");
    const expectedK = asStrictInt(input.expectedK, "k");
    const requiredMask = asStrictInt(input.requiredMask, "mask");
    if (ticket.cfgId !== expectedCfgId) return { ok: false, reason: "cfg_mismatch", ticket };
    if (!isValidEquihashParams(expectedN, expectedK) || ticket.n !== expectedN || ticket.k !== expectedK) {
      return { ok: false, reason: "params_mismatch", ticket };
    }
    if (requiredMask < 1 || requiredMask > 3 || ticket.m !== requiredMask) {
      return { ok: false, reason: "mask_mismatch", ticket };
    }
    const expected = await makeTicketMac(input.powSecret, ticket, input.bindings);
    return timingSafeEqual(expected, ticket.mac) ? { ok: true, ticket } : { ok: false, reason: "mac_mismatch", ticket };
  } catch (error) {
    const message = error && typeof error.message === "string" ? error.message : "";
    const reason = message.includes("nowSeconds")
      ? "invalid_now"
      : message.includes("HMAC secret")
        ? "missing_secret"
        : message.includes("bindings")
          ? "invalid_bindings"
          : "invalid_input";
    return ticket ? { ok: false, reason, ticket } : { ok: false, reason };
  }
};

export { VERSION as EQ_TICKET_VERSION, TICKET_DOMAIN as EQ_TICKET_DOMAIN, base64UrlEncodeNoPad, base64UrlDecodeNoPad };
