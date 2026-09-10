import { normalizeEquihashParams } from "../equihash/params.js";
import { issueV5Ticket, parseV5Ticket } from "../equihash/ticket.js";
import { base64UrlEncodeNoPad } from "../equihash/encoding.js";
import { stripPowInternalHeaders } from "./internal-headers.js";
import {
  getPowBindingValues,
  makeConsumeMac,
  makePowBindingString,
  makeProofMac,
  parseCanonicalCaptchaTokens,
  parseConsumeToken,
  parsePowTicket,
  parseProofCookie,
  resolveCaptchaRequirements,
  deriveLocalCaptchaTag,
  timingSafeEqual,
  verifyRequiredCaptchaForTicket,
  verifyV5Ticket,
} from "./api-protocol-shared.js";

const PROOF_COOKIE = "__Host-proof";
const encoder = new TextEncoder();
const S = (status) => new Response(null, { status });
const J = (payload, status = 200, headers) => new Response(JSON.stringify(payload), { status, headers });
const deny = () => S(403);
const denyApi = (hint) => new Response(null, { status: 403, headers: { "x-pow-h": hint } });

const withClearedCookie = (response, name) => {
  if (!name) return response;
  const headers = new Headers(response.headers);
  clearCookie(headers, name);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};

const isNavigationRequest = (request) =>
  request.headers.get("Sec-Fetch-Mode") === "navigate" || (request.headers.get("Accept") || "").includes("text/html");

const parseCookieHeader = (cookieHeader) => {
  const out = new Map();
  for (const part of String(cookieHeader || "").split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    let value = part.slice(eq + 1).trim();
    try {
      value = decodeURIComponent(value);
    } catch {}
    out.set(key, value);
  }
  return out;
};

const normalizeInnerStrategy = (snapshot) => {
  if (!snapshot || typeof snapshot !== "object") return null;
  const nav = snapshot.nav && typeof snapshot.nav === "object" ? snapshot.nav : null;
  const bypass = snapshot.bypass && typeof snapshot.bypass === "object" ? snapshot.bypass : null;
  const bind = snapshot.bind && typeof snapshot.bind === "object" ? snapshot.bind : null;
  const atomic = snapshot.atomic && typeof snapshot.atomic === "object" ? snapshot.atomic : null;
  if (!nav || !bypass || !bind || !atomic) return null;
  if (typeof bypass.bypass !== "boolean" || typeof bind.ok !== "boolean") return null;
  if (typeof bind.code !== "string" || typeof bind.canonicalPath !== "string") return null;
  if (typeof atomic.captchaToken !== "string" || typeof atomic.ticketB64 !== "string" || typeof atomic.consumeToken !== "string") return null;
  if (typeof atomic.fromCookie !== "boolean" || typeof atomic.cookieName !== "string") return null;
  return {
    nav,
    bypass: { bypass: bypass.bypass },
    bind: { ok: bind.ok, code: bind.code, canonicalPath: bind.canonicalPath },
    atomic: {
      captchaToken: atomic.captchaToken,
      ticketB64: atomic.ticketB64,
      consumeToken: atomic.consumeToken,
      fromCookie: atomic.fromCookie,
      cookieName: atomic.cookieName,
    },
  };
};

const loadConfigFromInner = (inner) => {
  if (!inner || typeof inner !== "object") return null;
  const config = inner.c && typeof inner.c === "object" ? inner.c : null;
  const strategy = normalizeInnerStrategy(inner.s);
  if (!config || !strategy) return null;
  return { config, powSecret: config.POW_TOKEN, derived: inner.d, cfgId: inner.id, strategy };
};

const setCookie = (headers, name, value, maxAge) => {
  const parts = [`${name}=${encodeURIComponent(String(value || ""))}`, "Path=/", "Secure", "SameSite=Lax", "HttpOnly"];
  if (typeof maxAge === "number") parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  headers.append("Set-Cookie", parts.join("; "));
};

const clearCookie = (headers, name) => setCookie(headers, name, "deleted", 0);
const isExpired = (expireAt, nowSeconds) => expireAt <= nowSeconds;

const verifyConsumeToken = async (consumeToken, powSecret, nowSeconds, requiredMask) => {
  const parsed = parseConsumeToken(consumeToken);
  if (!parsed || isExpired(parsed.exp, nowSeconds) || parsed.m !== requiredMask) return null;
  const mac = await makeConsumeMac(powSecret, parsed.ticketB64, parsed.exp, parsed.captchaTag, parsed.m);
  return timingSafeEqual(mac, parsed.mac) ? parsed : null;
};

const verifyProofCookie = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  derived,
  cfgId,
  requiredMask,
) => {
  const proof = parseProofCookie(parseCookieHeader(request.headers.get("Cookie")).get(PROOF_COOKIE) || "");
  if (!proof) return null;
  const ticket = parsePowTicket(proof.ticketB64);
  if (!ticket || ticket.cfgId !== cfgId || proof.last > ticket.e || proof.iat < ticket.issuedAt) return null;
  let eq;
  try {
    eq = normalizeEquihashParams(config.POW_EQ_N, config.POW_EQ_K);
  } catch {
    return null;
  }
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
  if (!bindingValues) return null;
  const ticketCheck = await verifyV5Ticket({
    ticketB64: proof.ticketB64,
    powSecret,
    nowSeconds,
    expectedCfgId: cfgId,
    expectedN: eq.n,
    expectedK: eq.k,
    requiredMask,
    bindings: { ...bindingValues, host: url.hostname },
  });
  if (!ticketCheck.ok) return null;
  const expected = await makeProofMac(powSecret, proof.ticketB64, proof.iat, proof.last, proof.n, proof.m);
  if (!timingSafeEqual(expected, proof.mac) || (proof.m & requiredMask) !== requiredMask) return null;
  return { proof, ticket, bindingValues };
};

const maybeRenewProof = async (request, url, nowSeconds, config, powSecret, cfgId, meta, response) => {
  if (!meta?.proof || !meta.bindingValues || !response || config.PROOF_RENEW_ENABLE !== true || !isNavigationRequest(request)) return response;
  const proof = meta.proof;
  const renewMax = Math.max(0, Math.floor(config.PROOF_RENEW_MAX));
  if (!renewMax || proof.n >= renewMax) return response;
  const ttl = Math.max(1, Math.floor(config.PROOF_TTL_SEC));
  const window = Math.max(0, Math.floor(config.PROOF_RENEW_WINDOW_SEC));
  const minSinceLast = Math.max(0, Math.floor(config.PROOF_RENEW_MIN_SEC));
  const currentExp = Number(meta.ticket?.e) || 0;
  if (currentExp <= 0 || currentExp - nowSeconds > window || nowSeconds - proof.last < minSinceLast) return response;
  const hardLimit = proof.iat + ttl * (renewMax + 1);
  const newExp = Math.min(nowSeconds + ttl, hardLimit);
  if (!Number.isFinite(newExp) || newExp <= nowSeconds || newExp <= currentExp) return response;
  const nextTicketB64 = await issueV5Ticket({
    powSecret,
    cfgId,
    issuedAt: meta.ticket.issuedAt,
    e: newExp,
    n: meta.ticket.n,
    k: meta.ticket.k,
    m: meta.ticket.m,
    bindings: { ...meta.bindingValues, host: url.hostname },
  });
  const nextN = proof.n + 1;
  const mac = await makeProofMac(powSecret, nextTicketB64, proof.iat, nowSeconds, nextN, proof.m);
  const headers = new Headers(response.headers);
  setCookie(headers, PROOF_COOKIE, `v1.${nextTicketB64}.${proof.iat}.${nowSeconds}.${nextN}.${proof.m}.${mac}`, newExp - nowSeconds);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};

const buildChallengeHtml = ({ bootstrapB64, bindingB64, reloadUrlB64, esmUrlB64, captchaCfgB64, glueUrl, atomicCfg }) =>
  __HTML_TEMPLATE__
    .replace("__Q__", bootstrapB64)
    .replace("__B__", bindingB64)
    .replace("__G__", glueUrl)
    .replace("__R__", reloadUrlB64)
    .replace("__E__", esmUrlB64)
    .replace("__K__", captchaCfgB64)
    .replace("__C__", atomicCfg);

const respondPowChallenge = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  derived,
  cfgId,
  requirements,
) => {
  let eq;
  try {
    eq = normalizeEquihashParams(config.POW_EQ_N, config.POW_EQ_K);
  } catch {
    return S(500);
  }
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
  if (!bindingValues) return deny();
  const needPow = requirements.needPow === true;
  const needTurn = requirements.needTurn === true;
  if (needPow && !config.POW_ESM_URL) return S(500);
  const expireAt = nowSeconds + Math.max(1, Math.floor(Number(config.POW_TICKET_TTL_SEC) || 0));
  const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0);
  const atomicGateEnabled = config.ATOMIC_CONSUME === true && (needTurn || (needPow && config.AGGREGATOR_POW_ATOMIC_CONSUME === true));
  const ticketB64 = await issueV5Ticket({
    powSecret,
    cfgId,
    issuedAt: nowSeconds,
    e: expireAt,
    n: eq.n,
    k: eq.k,
    m: requiredMask,
    bindings: { ...bindingValues, host: url.hostname },
  });
  const ticket = parseV5Ticket(ticketB64);
  if (!ticket) return S(500);
  const binding = makePowBindingString(ticket, url.hostname, bindingValues.pathHash, bindingValues.ipScope, bindingValues.country, bindingValues.asn, bindingValues.tlsFingerprint, eq.n, eq.k);
  const bootstrap = {
    v: 1,
    ticketB64,
    pathHash: bindingValues.pathHash,
    eq: { n: eq.n, k: eq.k },
    apiPrefix: config.POW_API_PREFIX,
    issuedAt: nowSeconds,
    expireAt,
    mask: requiredMask,
  };
  const b64 = (value) => base64UrlEncodeNoPad(encoder.encode(value));
  const captchaCfg = needTurn ? { turnstile: { sitekey: config.TURNSTILE_SITEKEY } } : {};
  const atomicCfg = [
    atomicGateEnabled ? "1" : "0",
    config.ATOMIC_TURN_QUERY.trim(),
    config.ATOMIC_TICKET_QUERY.trim(),
    config.ATOMIC_CONSUME_QUERY.trim(),
    config.ATOMIC_TURN_HEADER.trim(),
    config.ATOMIC_TICKET_HEADER.trim(),
    config.ATOMIC_CONSUME_HEADER.trim(),
    config.ATOMIC_COOKIE_NAME.trim(),
  ].join("|");
  const headers = new Headers({
    "Content-Type": "text/html",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
  });
  return new Response(buildChallengeHtml({
    bootstrapB64: b64(JSON.stringify(bootstrap)),
    bindingB64: b64(binding),
    reloadUrlB64: b64(url.toString()),
    esmUrlB64: needPow ? b64(config.POW_ESM_URL) : "",
    captchaCfgB64: b64(JSON.stringify(captchaCfg)),
    glueUrl: config.POW_GLUE_URL,
    atomicCfg,
  }), { status: 200, headers });
};

const loadAtomicTicket = async (ticketB64, url, canonicalPath, config, powSecret, derived, cfgId, nowSeconds, requiredMask) => {
  const ticket = parsePowTicket(ticketB64);
  if (!ticket || ticket.cfgId !== cfgId || ticket.e <= nowSeconds) return null;
  let eq;
  try {
    eq = normalizeEquihashParams(config.POW_EQ_N, config.POW_EQ_K);
  } catch {
    return null;
  }
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
  if (!bindingValues) return null;
  const result = await verifyV5Ticket({
    ticketB64,
    powSecret,
    nowSeconds,
    expectedCfgId: cfgId,
    expectedN: eq.n,
    expectedK: eq.k,
    requiredMask,
    bindings: { ...bindingValues, host: url.hostname },
  });
  return result.ok ? ticket : null;
};

export const handleBusinessGate = async ({ request, url, nowSeconds, inner, forward }) => {
  if (typeof forward !== "function") return S(500);
  const innerCtx = loadConfigFromInner(inner);
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId, strategy } = innerCtx;
  const requirements = resolveCaptchaRequirements(config);
  const { needPow, needTurn } = requirements;
  if (!needPow && !needTurn) return forward(stripPowInternalHeaders(request));
  if (strategy.bypass.bypass) return forward(stripPowInternalHeaders(request));
  if (!strategy.bind.ok) return strategy.bind.code === "missing" || strategy.bind.code === "invalid" ? S(400) : S(500);
  if (!powSecret) return S(500);
  if (needTurn && (!config.TURNSTILE_SITEKEY || !config.TURNSTILE_SECRET)) return S(500);
  if (needPow && !config.POW_ESM_URL) return S(500);

  const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0);
  const aggregatorPowAtomic = config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  const atomicGateEnabled = config.ATOMIC_CONSUME === true && (needTurn || (needPow && aggregatorPowAtomic));
  const proofMeta = atomicGateEnabled
    ? null
    : await verifyProofCookie(request, url, strategy.bind.canonicalPath, nowSeconds, config, powSecret, derived, cfgId, requiredMask);

  if (proofMeta) {
    const response = await forward(stripPowInternalHeaders(request));
    return maybeRenewProof(request, url, nowSeconds, config, powSecret, cfgId, proofMeta, response);
  }

  if (atomicGateEnabled) {
    const atomic = strategy.atomic;
    const fail = async (response, allowChallenge = true) => {
      if (allowChallenge && isNavigationRequest(request)) {
        const challenge = await respondPowChallenge(request, url, strategy.bind.canonicalPath, nowSeconds, config, powSecret, derived, cfgId, requirements);
        return atomic.fromCookie ? withClearedCookie(challenge, atomic.cookieName) : challenge;
      }
      return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
    };
    const hasAtomicInput = atomic.captchaToken || (!needTurn && needPow && aggregatorPowAtomic && atomic.consumeToken);
    if (hasAtomicInput) {
      const parsedCaptcha = parseCanonicalCaptchaTokens(atomic.captchaToken, needTurn);
      if (!parsedCaptcha.ok) return fail(parsedCaptcha.malformed ? S(400) : deny(), false);
      if (needPow) {
        const consume = await verifyConsumeToken(atomic.consumeToken, powSecret, nowSeconds, requiredMask);
        if (!consume) {
          const parsedConsume = parseConsumeToken(atomic.consumeToken);
          return fail(parsedConsume && isExpired(parsedConsume.exp, nowSeconds) ? denyApi("stale") : deny());
        }
        const ticket = await loadAtomicTicket(consume.ticketB64, url, strategy.bind.canonicalPath, config, powSecret, derived, cfgId, nowSeconds, requiredMask);
        if (!ticket) return fail(deny());
        if (consume.exp > ticket.e || (atomic.ticketB64 && atomic.ticketB64 !== consume.ticketB64)) return fail(deny(), false);
        const localCaptcha = await deriveLocalCaptchaTag(config, atomic.captchaToken);
        if (!localCaptcha.ok || !timingSafeEqual(localCaptcha.captchaTag, consume.captchaTag)) {
          return fail(localCaptcha.malformed ? S(400) : deny(), false);
        }
        const verifiedCaptcha = await verifyRequiredCaptchaForTicket(request, config, ticket, atomic.captchaToken, "0.0.0.0");
        if (!verifiedCaptcha.ok) return fail(verifiedCaptcha.malformed ? S(400) : deny(), false);
      } else {
        const ticket = await loadAtomicTicket(atomic.ticketB64, url, strategy.bind.canonicalPath, config, powSecret, derived, cfgId, nowSeconds, requiredMask);
        if (!ticket) return fail(deny());
        const localCaptcha = await deriveLocalCaptchaTag(config, atomic.captchaToken);
        if (!localCaptcha.ok) return fail(localCaptcha.malformed ? S(400) : deny(), false);
        const verifiedCaptcha = await verifyRequiredCaptchaForTicket(request, config, ticket, atomic.captchaToken, "0.0.0.0");
        if (!verifiedCaptcha.ok) return fail(verifiedCaptcha.malformed ? S(400) : deny(), false);
      }
      const response = await forward(stripPowInternalHeaders(request));
      return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
    }
  }

  if (!isNavigationRequest(request)) return J({ code: needPow ? "pow_required" : "captcha_required" }, 403);
  return respondPowChallenge(request, url, strategy.bind.canonicalPath, nowSeconds, config, powSecret, derived, cfgId, requirements);
};

export { parseCookieHeader, verifyProofCookie };
