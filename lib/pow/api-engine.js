import { deriveEquihashSeed } from "../equihash/seed.js";
import { normalizeEquihashParams } from "../equihash/params.js";
import { issueV5Ticket } from "../equihash/ticket.js";
import { base64UrlDecodeNoPad } from "../equihash/encoding.js";
import { verifyEquihash } from "../equihash/verify.js";
import {
  VERIFY_BODY_MAX_BYTES,
  captchaTagV1,
  isBase64Url,
  makeConsumeMac,
  makeProofMac,
  parseCanonicalCaptchaTokens,
  parsePowTicket,
  resolveCaptchaRequirements,
  verifyRequiredCaptchaForTicket,
  verifyV5Ticket,
  getPowBindingValuesWithPathHash,
  timingSafeEqual,
} from "./api-protocol-shared.js";

const PROOF_COOKIE = "__Host-proof";
const POW_HINT_HEADER = "x-pow-h";
const NONCE_BYTES = 24;
const S = (status) => new Response(null, { status });
const J = (payload, status = 200, headers) => new Response(JSON.stringify(payload), { status, headers });

const denyApi = (hint) => {
  const headers = new Headers({ [POW_HINT_HEADER]: hint });
  return new Response(JSON.stringify({ ok: false, reason: hint }), { status: 403, headers });
};
const denyStale = () => denyApi("stale");
const denyCheat = () => denyApi("cheat");

const normalizePath = (pathname) => {
  if (typeof pathname !== "string") return null;
  try {
    const decoded = decodeURIComponent(pathname);
    if (!decoded) return "/";
    return decoded.startsWith("/") ? decoded : `/${decoded}`;
  } catch {
    return null;
  }
};

const isExpired = (expireAt, nowSeconds) => expireAt <= nowSeconds;

const readBoundedJsonBody = async (request) => {
  try {
    if (!request.body) return null;
    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        total += value.byteLength;
        if (total > VERIFY_BODY_MAX_BYTES) {
          try {
            const canceled = reader.cancel();
            if (canceled && typeof canceled.catch === "function") void canceled.catch(() => {});
          } catch {}
          return null;
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const decodePowEnvelope = (pow, count) => {
  if (!pow || typeof pow !== "object" || Array.isArray(pow)) return null;
  const nonceB64 = typeof pow.nonceB64 === "string" ? pow.nonceB64 : "";
  const proofB64 = typeof pow.proofB64 === "string" ? pow.proofB64 : "";
  const proofBytes = 4 * count;
  if (!isBase64Url(nonceB64, 1, 64) || !isBase64Url(proofB64, 1, 2048)) return null;
  const nonce = base64UrlDecodeNoPad(nonceB64);
  const proof = base64UrlDecodeNoPad(proofB64);
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) return null;
  if (!(proof instanceof Uint8Array) || proof.length !== proofBytes) return null;
  return { nonce, proof };
};

const parseVerifyBody = (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  if (!ticketB64 || !pathHash) return null;
  if (Object.prototype.hasOwnProperty.call(body, "captchaToken") &&
      typeof body.captchaToken !== "string" &&
      (!body.captchaToken || typeof body.captchaToken !== "object" || Array.isArray(body.captchaToken))) return null;
  if (Object.prototype.hasOwnProperty.call(body, "pow") &&
      (!body.pow || typeof body.pow !== "object" || Array.isArray(body.pow))) return null;
  return { ticketB64, pathHash, captchaToken: body.captchaToken, pow: body.pow || null };
};

const resolveVerifyTtl = (ticket, config, nowSeconds) => {
  const proofTtl = Math.max(0, Math.floor(Number(config.PROOF_TTL_SEC) || 0));
  const remaining = Math.floor(Number(ticket?.e) || 0) - nowSeconds;
  if (proofTtl <= 0 || remaining <= 0) return 0;
  return Math.max(1, Math.min(proofTtl, remaining));
};

const setCookie = (headers, name, value, maxAge) => {
  const parts = [`${name}=${encodeURIComponent(String(value || ""))}`, "Path=/", "Secure", "SameSite=Lax", "HttpOnly"];
  if (typeof maxAge === "number") parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  headers.append("Set-Cookie", parts.join("; "));
};

const issueProofCookie = async ({ headers, powSecret, ticket, url, bindingValues, nowSeconds, ttl, mask }) => {
  const proofTicketB64 = await issueV5Ticket({
    powSecret,
    cfgId: ticket.cfgId,
    issuedAt: nowSeconds,
    e: nowSeconds + ttl,
    n: ticket.n,
    k: ticket.k,
    m: mask,
    bindings: { ...bindingValues, host: url.hostname },
  });
  const mac = await makeProofMac(powSecret, proofTicketB64, nowSeconds, nowSeconds, 0, mask);
  setCookie(headers, PROOF_COOKIE, `v1.${proofTicketB64}.${nowSeconds}.${nowSeconds}.0.${mask}.${mac}`, ttl);
};

const handlePowVerify = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  if (!powSecret) return S(500);
  const body = parseVerifyBody(await readBoundedJsonBody(request));
  if (!body) return denyApi("bad_request");

  let eq;
  try {
    eq = normalizeEquihashParams(config.POW_EQ_N, config.POW_EQ_K);
  } catch {
    return S(500);
  }
  const requirements = resolveCaptchaRequirements(config);
  const requiredMask = (requirements.needPow ? 1 : 0) | (requirements.needTurn ? 2 : 0);
  const ticket = parsePowTicket(body.ticketB64);
  if (!ticket) return denyStale();
  if (ticket.cfgId !== cfgId || ticket.n !== eq.n || ticket.k !== eq.k || ticket.m !== requiredMask) return denyStale();
  if (isExpired(ticket.e, nowSeconds)) return denyStale();

  const bindingValues = await getPowBindingValuesWithPathHash(body.pathHash, config, derived);
  if (!bindingValues) return denyStale();
  const ticketCheck = await verifyV5Ticket({
    ticketB64: body.ticketB64,
    powSecret,
    nowSeconds,
    expectedCfgId: cfgId,
    expectedN: eq.n,
    expectedK: eq.k,
    requiredMask,
    bindings: { ...bindingValues, host: url.hostname },
  });
  if (!ticketCheck.ok) return denyStale();

  let captchaTag = "any";
  if (requirements.needTurn) {
    const parsedCaptcha = parseCanonicalCaptchaTokens(body.captchaToken, true);
    if (!parsedCaptcha.ok) return denyApi("captcha_required");
    captchaTag = await captchaTagV1(parsedCaptcha.tokens.turnstile);
  }

  if (requirements.needPow) {
    const decodedPow = decodePowEnvelope(body.pow, 2 ** eq.k);
    if (!decodedPow) return denyApi("bad_request");
    let seed;
    try {
      seed = await deriveEquihashSeed({ ticketB64: body.ticketB64, pathHash: bindingValues.pathHash, captchaTag });
    } catch {
      return denyApi("bad_request");
    }
    if (!verifyEquihash({ seed, nonce: decodedPow.nonce, proof: decodedPow.proof, n: eq.n, k: eq.k })) return denyCheat();
  }

  const atomicGateEnabled = config.ATOMIC_CONSUME === true && (
    requirements.needTurn || (requirements.needPow && config.AGGREGATOR_POW_ATOMIC_CONSUME === true)
  );
  if (atomicGateEnabled) {
    const ttl = resolveVerifyTtl(ticket, config, nowSeconds);
    if (!ttl) return denyStale();
    const expireAt = nowSeconds + ttl;
    const consumeMac = await makeConsumeMac(powSecret, body.ticketB64, expireAt, captchaTag, requiredMask);
    return J({
      ok: true,
      mode: "consume",
      consume: `v2.${body.ticketB64}.${expireAt}.${captchaTag}.${requiredMask}.${consumeMac}`,
      expireAt,
    });
  }

  const captcha = await verifyRequiredCaptchaForTicket(
    request, config, ticket, body.captchaToken,
  );
  if (!captcha.ok) return captcha.malformed ? denyApi("captcha_required") : denyStale();
  if (requirements.needTurn && !timingSafeEqual(captcha.captchaTag, captchaTag)) return denyCheat();

  const ttl = resolveVerifyTtl(ticket, config, nowSeconds);
  if (!ttl) return denyStale();

  const headers = new Headers();
  await issueProofCookie({ headers, powSecret, ticket, url, bindingValues, nowSeconds, ttl, mask: requiredMask });
  return J({ ok: true, mode: "proof", proofTtlSec: ttl }, 200, headers);
};

export const handlePowApi = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const config = innerCtx.config;
  const path = normalizePath(url.pathname);
  if (!path || path !== `${config.POW_API_PREFIX}/verify`) return S(404);
  if (request.method !== "POST") return S(405);
  return handlePowVerify(request, url, nowSeconds, innerCtx);
};

export { handlePowVerify, parseVerifyBody, readBoundedJsonBody };
