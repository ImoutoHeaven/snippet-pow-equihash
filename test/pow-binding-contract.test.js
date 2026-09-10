import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  encodePowTicket,
  getPowBindingValues,
  makePowBindingString,
  makeConsumeMac,
  makeProofMac,
  verifyTicketMac,
} from "../lib/pow/api-protocol-shared.js";
import { handleBusinessGate } from "../lib/pow/business-gate.js";

const withGlobals = () => {
  const previous = { crypto: globalThis.crypto, btoa: globalThis.btoa, atob: globalThis.atob };
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  const canAssign = !descriptor || descriptor.writable || typeof descriptor.set === "function";
  const didSetCrypto = !globalThis.crypto && canAssign;
  if (didSetCrypto) globalThis.crypto = crypto.webcrypto;
  if (!globalThis.btoa) globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  if (!globalThis.atob) globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  return () => {
    for (const key of Object.keys(previous)) {
      if (key === "crypto" && !didSetCrypto) continue;
      if (previous[key] === undefined) delete globalThis[key];
      else globalThis[key] = previous[key];
    }
  };
};

const config = {
  POW_TOKEN: "pow-secret",
  POW_VERSION: 5,
  POW_EQ_N: 12,
  POW_EQ_K: 2,
  POW_BIND_PATH: false,
  POW_BIND_IPRANGE: false,
  POW_BIND_COUNTRY: false,
  POW_BIND_ASN: false,
  POW_BIND_TLS: false,
  powcheck: true,
  turncheck: false,
  POW_TICKET_TTL_SEC: 600,
  PROOF_TTL_SEC: 10,
  PROOF_RENEW_ENABLE: true,
  PROOF_RENEW_MAX: 2,
  PROOF_RENEW_WINDOW_SEC: 90,
  PROOF_RENEW_MIN_SEC: 0,
  ATOMIC_CONSUME: false,
  AGGREGATOR_POW_ATOMIC_CONSUME: false,
  POW_API_PREFIX: "/__pow",
  POW_GLUE_URL: "https://example.com/glue.js",
  POW_ESM_URL: "https://example.com/esm.js",
};

const makeTicket = ({ e, issuedAt, m = 1, cfgId = 7, n = 12, k = 2, mac = "" }) => ({
  v: 5,
  e,
  cfgId,
  issuedAt,
  r: "AAECAwQFBgcICQoLDA0ODw",
  n,
  k,
  m,
  mac,
});

const strategy = {
  nav: {},
  bypass: { bypass: false },
  bind: { ok: true, code: "", canonicalPath: "/protected" },
  atomic: { captchaToken: "", ticketB64: "", consumeToken: "", fromCookie: false, cookieName: "" },
};

const makeInner = (nextConfig = config, derived = null, nextStrategy = strategy) => ({
  v: 1,
  id: 7,
  c: nextConfig,
  d: derived || { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
  s: { ...nextStrategy, atomic: { ...nextStrategy.atomic } },
});

test("binding values preserve path, IP, country, ASN, and TLS switches", async () => {
  const restore = withGlobals();
  try {
    const boundConfig = { ...config, POW_BIND_PATH: true, POW_BIND_IPRANGE: true, POW_BIND_COUNTRY: true, POW_BIND_ASN: true, POW_BIND_TLS: true };
    const derived = { ipScope: "1.2.3.0/24", country: "US", asn: "64500", tlsFingerprint: "tls-hash" };
    const values = await getPowBindingValues("/protected", boundConfig, derived);
    assert.equal(values.ipScope, derived.ipScope);
    assert.equal(values.country, derived.country);
    assert.equal(values.asn, derived.asn);
    assert.equal(values.tlsFingerprint, derived.tlsFingerprint);
    assert.match(values.pathHash, /^[A-Za-z0-9_-]+$/u);

    const ticket = makeTicket({ e: 1700000200, issuedAt: 1700000000 });
    const one = makePowBindingString(ticket, "Example.COM", values.pathHash, values.ipScope, values.country, values.asn, values.tlsFingerprint);
    const two = makePowBindingString(ticket, "other.example", values.pathHash, values.ipScope, values.country, values.asn, values.tlsFingerprint);
    assert.notEqual(one, two);
  } finally {
    restore();
  }
});

test("valid proof remains usable while an unproved PoW request fails closed", async () => {
  const restore = withGlobals();
  try {
    const now = Math.floor(Date.now() / 1000);
    const ticket = makeTicket({ e: now + 1, issuedAt: now - 10 });
    const binding = makePowBindingString(ticket, "example.com", "any", "any", "any", "any", "any");
    ticket.mac = crypto.createHmac("sha256", config.POW_TOKEN).update(binding).digest("base64url");
    const ticketB64 = encodePowTicket(ticket);
    const proofMac = await makeProofMac(config.POW_TOKEN, ticketB64, ticket.issuedAt, ticket.issuedAt, 0, 1);
    const cookie = `__Host-proof=v1.${ticketB64}.${ticket.issuedAt}.${ticket.issuedAt}.0.1.${proofMac}`;
    const url = new URL("https://example.com/protected");
    const forwarded = [];
    const forward = async (request) => {
      forwarded.push(request);
      return new Response("ok", { status: 200 });
    };

    const valid = await handleBusinessGate({
      request: new Request(url, { headers: { Accept: "text/html", Cookie: cookie } }),
      url,
      nowSeconds: now,
      inner: makeInner(),
      forward,
    });
    assert.equal(valid.status, 200);
    assert.equal(forwarded.length, 1);
    const renewedCookie = (valid.headers.get("Set-Cookie") || "").split(";")[0];
    assert.match(renewedCookie, /^__Host-proof=/u);

    forwarded.length = 0;
    const second = await handleBusinessGate({
      request: new Request(url, { headers: { Accept: "text/html", Cookie: renewedCookie } }),
      url,
      nowSeconds: now,
      inner: makeInner(),
      forward,
    });
    assert.equal(second.status, 200);
    assert.equal(forwarded.length, 1);

    forwarded.length = 0;
    const blocked = await handleBusinessGate({
      request: new Request(url, { headers: { Accept: "application/json" } }),
      url,
      nowSeconds: now,
      inner: makeInner(),
      forward,
    });
    assert.equal(blocked.status, 403);
    assert.deepEqual(await blocked.json(), { code: "pow_required" });
    assert.equal(forwarded.length, 0);
  } finally {
    restore();
  }
});

test("ticket MAC rejects a changed bound path", async () => {
  const restore = withGlobals();
  try {
    const now = Math.floor(Date.now() / 1000);
    const boundConfig = { ...config, POW_BIND_PATH: true };
    const values = await getPowBindingValues("/protected", boundConfig, { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" });
    const ticket = makeTicket({ e: now + 100, issuedAt: now });
    const binding = makePowBindingString(ticket, "example.com", values.pathHash, values.ipScope, values.country, values.asn, values.tlsFingerprint);
    ticket.mac = await (async () => {
      const key = await crypto.webcrypto.subtle.importKey("raw", Buffer.from("pow-secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      return Buffer.from(await crypto.webcrypto.subtle.sign("HMAC", key, Buffer.from(binding))).toString("base64url");
    })();
    const url = new URL("https://example.com/protected");
    assert.equal(await verifyTicketMac(ticket, url, values, boundConfig, "pow-secret"), binding);
    const changed = await getPowBindingValues("/other", boundConfig, { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" });
    assert.equal(await verifyTicketMac(ticket, url, changed, boundConfig, "pow-secret"), "");
  } finally {
    restore();
  }
});

test("atomic receipt validation runs before provider timing and forwarding", async () => {
  const restore = withGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const atomicConfig = {
      ...config,
      powcheck: true,
      AGGREGATOR_POW_ATOMIC_CONSUME: true,
      ATOMIC_CONSUME: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "provider-secret",
    };
    const ticket = makeTicket({ e: now + 120, issuedAt: now });
    const binding = makePowBindingString(ticket, "example.com", "any", "any", "any", "any", "any");
    ticket.mac = crypto.createHmac("sha256", atomicConfig.POW_TOKEN).update(binding).digest("base64url");
    const ticketB64 = encodePowTicket(ticket);
    const consumeExp = now + 30;
    const consumeMac = await makeConsumeMac(atomicConfig.POW_TOKEN, ticketB64, consumeExp, "any", 1);
    const inner = makeInner({
      ...atomicConfig,
      SITEVERIFY_URLS: atomicConfig.SITEVERIFY_URLS,
      SITEVERIFY_AUTH_KID: atomicConfig.SITEVERIFY_AUTH_KID,
      SITEVERIFY_AUTH_SECRET: atomicConfig.SITEVERIFY_AUTH_SECRET,
    });
    inner.s.atomic.consumeToken = `v2.${ticketB64}.${consumeExp}.any.1.${consumeMac}`;
    let providerCalls = 0;
    let forwards = 0;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://sv.example/siteverify") {
        providerCalls += 1;
        return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
      }
      forwards += 1;
      return new Response("ok", { status: 200 });
    };
    const url = new URL("https://example.com/protected");
    const response = await handleBusinessGate({
      request: new Request(url, { headers: { Accept: "application/json" } }),
      url,
      nowSeconds: now,
      inner,
      forward: async (request) => {
        assert.equal(request.headers.get("x-pow-inner"), null);
        forwards += 1;
        return new Response("ok", { status: 200 });
      },
    });
    assert.equal(response.status, 200);
    assert.equal(providerCalls, 1);
    assert.equal(forwards, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("an atomic Turnstile route does not accept a proof cookie as a bypass", async () => {
  const restore = withGlobals();
  try {
    const atomicConfig = {
      ...config,
      powcheck: false,
      turncheck: true,
      ATOMIC_CONSUME: true,
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
    };
    let forwards = 0;
    const url = new URL("https://example.com/protected");
    const response = await handleBusinessGate({
      request: new Request(url, { headers: { Accept: "application/json", Cookie: "__Host-proof=v1.invalid.invalid.invalid.invalid.invalid.invalid" } }),
      url,
      nowSeconds: Math.floor(Date.now() / 1000),
      inner: makeInner(atomicConfig),
      forward: async () => {
        forwards += 1;
        return new Response("ok", { status: 200 });
      },
    });
    assert.equal(response.status, 403);
    assert.equal(forwards, 0);
  } finally {
    restore();
  }
});

const buildSignedTicket = async ({ nextConfig, derived, canonicalPath = "/protected", now, expires = now + 120, issuedAt = now }) => {
  const bindingValues = await getPowBindingValues(canonicalPath, nextConfig, derived);
  const mask = (nextConfig.powcheck ? 1 : 0) | (nextConfig.turncheck ? 2 : 0) || 1;
  const ticket = makeTicket({ e: expires, issuedAt: Math.min(issuedAt, expires), m: mask });
  const binding = makePowBindingString(
    ticket,
    "example.com",
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint,
  );
  ticket.mac = crypto.createHmac("sha256", nextConfig.POW_TOKEN).update(binding).digest("base64url");
  return { ticket, ticketB64: encodePowTicket(ticket), bindingValues };
};

const buildProofCookie = async ({ nextConfig, derived, now, mask = 3, expires = now + 120, issuedAt = now }) => {
  const signed = await buildSignedTicket({ nextConfig, derived, now, expires, issuedAt });
  const mac = await makeProofMac(nextConfig.POW_TOKEN, signed.ticketB64, issuedAt, issuedAt, 0, mask);
  return `__Host-proof=v1.${signed.ticketB64}.${issuedAt}.${issuedAt}.0.${mask}.${mac}`;
};

const runBusinessGate = async ({ nextConfig, derived, nextStrategy = strategy, cookie = "", now }) => {
  const url = new URL("https://example.com/protected");
  let forwards = 0;
  const response = await handleBusinessGate({
    request: new Request(url, { headers: { Accept: "application/json", ...(cookie ? { Cookie: cookie } : {}) } }),
    url,
    nowSeconds: now,
    inner: makeInner(nextConfig, derived, nextStrategy),
    forward: async () => {
      forwards += 1;
      return new Response("ok", { status: 200 });
    },
  });
  return { response, forwards };
};

test("signed proof cookies reject MAC, mask, expiry, and every enabled binding mutation", async () => {
  const restore = withGlobals();
  try {
    const now = Math.floor(Date.now() / 1000);
    const boundConfig = {
      ...config,
      powcheck: true,
      turncheck: true,
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: true,
      POW_BIND_ASN: true,
      POW_BIND_TLS: true,
    };
    const derived = { ipScope: "1.2.3.0/24", country: "US", asn: "64500", tlsFingerprint: "tls-hash" };
    const validCookie = await buildProofCookie({ nextConfig: boundConfig, derived, now, mask: 3, expires: now + 120 });
    const valid = await runBusinessGate({ nextConfig: boundConfig, derived, cookie: validCookie, now });
    assert.equal(valid.response.status, 200);
    assert.equal(valid.forwards, 1);

    const insufficientMask = await buildProofCookie({ nextConfig: boundConfig, derived, now, mask: 1, expires: now + 120 });
    const expired = await buildProofCookie({ nextConfig: boundConfig, derived, now, mask: 3, expires: now - 1 });
    const cases = [
      { name: "altered MAC", cookie: `${validCookie.slice(0, -1)}${validCookie.endsWith("A") ? "B" : "A"}` },
      { name: "insufficient mask", cookie: insufficientMask },
      { name: "expired ticket", cookie: expired },
      { name: "IP binding", derived: { ...derived, ipScope: "1.2.4.0/24" }, cookie: validCookie },
      { name: "country binding", derived: { ...derived, country: "CA" }, cookie: validCookie },
      { name: "ASN binding", derived: { ...derived, asn: "64501" }, cookie: validCookie },
      { name: "TLS binding", derived: { ...derived, tlsFingerprint: "other-tls" }, cookie: validCookie },
      {
        name: "path binding",
        cookie: validCookie,
        nextStrategy: { ...strategy, bind: { ...strategy.bind, canonicalPath: "/other" } },
      },
    ];
    for (const entry of cases) {
      const result = await runBusinessGate({
        nextConfig: boundConfig,
        derived: entry.derived || derived,
        nextStrategy: entry.nextStrategy || strategy,
        cookie: entry.cookie,
        now,
      });
      assert.equal(result.response.status, 403, entry.name);
      assert.equal(result.forwards, 0, entry.name);
    }
  } finally {
    restore();
  }
});

const buildReceipt = async ({ nextConfig, derived, now, mask = 1, expires = now + 30, ticketExpires = now + 120, ticketIssuedAt = now }) => {
  const signed = await buildSignedTicket({ nextConfig, derived, now, expires: ticketExpires, issuedAt: ticketIssuedAt });
  const mac = await makeConsumeMac(nextConfig.POW_TOKEN, signed.ticketB64, expires, "any", mask);
  return `v2.${signed.ticketB64}.${expires}.any.${mask}.${mac}`;
};

test("atomic receipts reject invalid input before provider or origin", async () => {
  const restore = withGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const atomicConfig = {
      ...config,
      powcheck: true,
      turncheck: false,
      ATOMIC_CONSUME: true,
      AGGREGATOR_POW_ATOMIC_CONSUME: true,
      POW_BIND_PATH: true,
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "provider-secret",
    };
    const valid = await buildReceipt({ nextConfig: atomicConfig, now, mask: 1, expires: now + 30 });
    const invalidMac = `${valid.slice(0, -1)}${valid.endsWith("A") ? "B" : "A"}`;
    const insufficientMask = await buildReceipt({ nextConfig: atomicConfig, now, mask: 0, expires: now + 30 });
    const expired = await buildReceipt({ nextConfig: atomicConfig, now, mask: 1, expires: now - 1 });
    const expiredTicket = await buildReceipt({ nextConfig: atomicConfig, now, mask: 1, expires: now + 30, ticketExpires: now - 1, ticketIssuedAt: now - 10 });
    const receiptPastTicket = await buildReceipt({ nextConfig: atomicConfig, now, mask: 1, expires: now + 30, ticketExpires: now + 20 });
    const noncanonicalExpiry = (() => {
      const parts = valid.split(".");
      parts[2] = `${parts[2]}abc`;
      return parts.join(".");
    })();
    let providerCalls = 0;
    globalThis.fetch = async () => {
      providerCalls += 1;
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };
    const accepted = await runBusinessGate({
      nextConfig: atomicConfig,
      nextStrategy: { ...strategy, atomic: { ...strategy.atomic, consumeToken: valid } },
      now,
    });
    assert.equal(accepted.response.status, 200);
    assert.equal(accepted.forwards, 1);
    assert.equal(providerCalls, 1);

    for (const [name, receipt, hint, nextStrategy] of [
      ["altered MAC", invalidMac, null, strategy],
      ["insufficient mask", insufficientMask, null, strategy],
      ["expired", expired, "stale", strategy],
      ["expired ticket", expiredTicket, null, strategy],
      ["receipt outlives ticket", receiptPastTicket, null, strategy],
      ["bound path", valid, null, { ...strategy, bind: { ...strategy.bind, canonicalPath: "/other" } }],
      ["noncanonical expiry", noncanonicalExpiry, null, strategy],
    ]) {
      const result = await runBusinessGate({
        nextConfig: atomicConfig,
        nextStrategy: { ...nextStrategy, atomic: { ...nextStrategy.atomic, consumeToken: receipt } },
        now,
      });
      assert.equal(result.response.status, 403, name);
      assert.equal(result.forwards, 0, name);
      assert.equal(result.response.headers.get("x-pow-h"), hint, name);
    }
    assert.equal(providerCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("Turnstile-only atomic requests verify at the business gate", async () => {
  const restore = withGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const atomicConfig = {
      ...config,
      powcheck: false,
      turncheck: true,
      ATOMIC_CONSUME: true,
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      SITEVERIFY_URLS: ["https://sv.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "provider-secret",
    };
    const signed = await buildSignedTicket({ nextConfig: atomicConfig, now });
    const token = JSON.stringify({ turnstile: "turnstile-token-1234567890" });
    const atomic = { ...strategy, atomic: { ...strategy.atomic, captchaToken: token, ticketB64: signed.ticketB64 } };
    let providerCalls = 0;
    globalThis.fetch = async () => {
      providerCalls += 1;
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };
    const accepted = await runBusinessGate({ nextConfig: atomicConfig, nextStrategy: atomic, now });
    assert.equal(accepted.response.status, 200);
    assert.equal(accepted.forwards, 1);
    assert.equal(providerCalls, 1);

    providerCalls = 0;
    globalThis.fetch = async () => {
      providerCalls += 1;
      return new Response(JSON.stringify({ ok: false, reason: "provider_failed", checks: {}, providers: {} }), { status: 200 });
    };
    const rejected = await runBusinessGate({ nextConfig: atomicConfig, nextStrategy: atomic, now });
    assert.equal(rejected.response.status, 403);
    assert.equal(rejected.forwards, 0);
    assert.equal(providerCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});
