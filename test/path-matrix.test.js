import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { captchaTagV1, encodePowTicket, makeConsumeMac, makePowBindingString } from "../lib/pow/api-protocol-shared.js";
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
    if (didSetCrypto) {
      if (previous.crypto === undefined) delete globalThis.crypto;
      else globalThis.crypto = previous.crypto;
    }
    if (previous.btoa === undefined) delete globalThis.btoa;
    else globalThis.btoa = previous.btoa;
    if (previous.atob === undefined) delete globalThis.atob;
    else globalThis.atob = previous.atob;
  };
};

const baseConfig = {
  POW_TOKEN: "pow-secret",
  POW_VERSION: 5,
  POW_API_PREFIX: "/__pow",
  POW_EQ_N: 12,
  POW_EQ_K: 2,
  POW_BIND_PATH: false,
  POW_BIND_IPRANGE: false,
  POW_BIND_COUNTRY: false,
  POW_BIND_ASN: false,
  POW_BIND_TLS: false,
  POW_TICKET_TTL_SEC: 600,
  PROOF_TTL_SEC: 600,
  PROOF_RENEW_ENABLE: false,
  PROOF_RENEW_MAX: 2,
  PROOF_RENEW_WINDOW_SEC: 90,
  PROOF_RENEW_MIN_SEC: 30,
  ATOMIC_CONSUME: false,
  AGGREGATOR_POW_ATOMIC_CONSUME: false,
  ATOMIC_TURN_QUERY: "__ts",
  ATOMIC_TICKET_QUERY: "__tt",
  ATOMIC_CONSUME_QUERY: "__ct",
  ATOMIC_TURN_HEADER: "x-turnstile",
  ATOMIC_TICKET_HEADER: "x-ticket",
  ATOMIC_CONSUME_HEADER: "x-consume",
  ATOMIC_COOKIE_NAME: "__Secure-pow_a",
  POW_GLUE_URL: "/glue.js",
  POW_ESM_URL: "/esm/esm.js",
  TURNSTILE_SITEKEY: "sitekey",
  TURNSTILE_SECRET: "turn-secret",
};

const makeTicket = ({ e, issuedAt, m = 1 }) => ({
  v: 5,
  e,
  cfgId: 7,
  issuedAt,
  r: "AAECAwQFBgcICQoLDA0ODw",
  n: 12,
  k: 2,
  m,
  mac: "",
});

const strategy = () => ({
  nav: {},
  bypass: { bypass: false },
  bind: { ok: true, code: "", canonicalPath: "/protected" },
  atomic: { captchaToken: "", ticketB64: "", consumeToken: "", fromCookie: false, cookieName: "" },
});

const inner = (config, atomic = {}) => ({
  v: 1,
  id: 7,
  c: { ...baseConfig, ...config },
  d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
  s: { ...strategy(), atomic: { ...strategy().atomic, ...atomic } },
});

const execute = async (config, atomic = {}) => {
  const calls = { forward: 0 };
  const url = new URL("https://example.com/protected");
  const response = await handleBusinessGate({
    request: new Request(url, { headers: { Accept: "application/json" } }),
    url,
    nowSeconds: Math.floor(Date.now() / 1000),
    inner: inner(config, atomic),
    forward: async () => {
      calls.forward += 1;
      return new Response("ok", { status: 200 });
    },
  });
  return { response, calls };
};

test("all eight gate combinations preserve closed and pass-through semantics", async () => {
  const restore = withGlobals();
  try {
    const matrix = [
      { powcheck: false, turncheck: false, atomic: false, status: 200, forwarded: 1 },
      { powcheck: false, turncheck: true, atomic: false, status: 403, code: "captcha_required" },
      { powcheck: false, turncheck: false, atomic: true, status: 200, forwarded: 1 },
      { powcheck: false, turncheck: true, atomic: true, status: 403, code: "captcha_required" },
      { powcheck: true, turncheck: false, atomic: false, status: 403, code: "pow_required" },
      { powcheck: true, turncheck: true, atomic: false, status: 403, code: "pow_required" },
      { powcheck: true, turncheck: false, atomic: true, AGGREGATOR_POW_ATOMIC_CONSUME: true, status: 403, code: "pow_required" },
      { powcheck: true, turncheck: true, atomic: true, AGGREGATOR_POW_ATOMIC_CONSUME: true, status: 403, code: "pow_required" },
    ];
    for (const entry of matrix) {
      const { response, calls } = await execute({ ...entry, ATOMIC_CONSUME: entry.atomic });
      assert.equal(response.status, entry.status, JSON.stringify(entry));
      if (entry.code) assert.deepEqual(await response.json(), { code: entry.code });
      assert.equal(calls.forward, entry.forwarded || 0, JSON.stringify(entry));
    }
  } finally {
    restore();
  }
});

test("atomic receipt policies fail closed before provider or origin calls", async () => {
  const restore = withGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const ticket = makeTicket({ e: now + 100, issuedAt: now });
    const binding = makePowBindingString(ticket, "example.com", "any", "any", "any", "any", "any");
    ticket.mac = crypto.createHmac("sha256", "pow-secret").update(binding).digest("base64url");
    const ticketB64 = encodePowTicket(ticket);
    const expired = now - 1;
    const mac = await makeConsumeMac("pow-secret", ticketB64, expired, "any", 1);
    let providerCalls = 0;
    let forwardCalls = 0;
    globalThis.fetch = async () => {
      providerCalls += 1;
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };
    const url = new URL("https://example.com/protected");
    const response = await handleBusinessGate({
      request: new Request(url, { headers: { Accept: "application/json" } }),
      url,
      nowSeconds: now,
      inner: inner({ powcheck: true, ATOMIC_CONSUME: true, AGGREGATOR_POW_ATOMIC_CONSUME: true }, { consumeToken: `v2.${ticketB64}.${expired}.any.1.${mac}` }),
      forward: async () => {
        forwardCalls += 1;
        return new Response("ok", { status: 200 });
      },
    });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("x-pow-h"), "stale");
    assert.equal(providerCalls, 0);
    assert.equal(forwardCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("the atomic PoW matrix consumes receipts at the business gate", async () => {
  const restore = withGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const now = Math.floor(Date.now() / 1000);
    const token = "turnstile-token-1234567890";
    const cases = [
      { turncheck: false, mask: 1, captchaToken: "", tag: "any" },
      { turncheck: true, mask: 3, captchaToken: JSON.stringify({ turnstile: token }), tag: await captchaTagV1(token) },
    ];
    let providerCalls = 0;
    globalThis.fetch = async () => {
      providerCalls += 1;
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };
    for (const entry of cases) {
      const config = {
        ...baseConfig,
        powcheck: true,
        turncheck: entry.turncheck,
        ATOMIC_CONSUME: true,
        AGGREGATOR_POW_ATOMIC_CONSUME: true,
        SITEVERIFY_URLS: ["https://sv.example/siteverify"],
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "provider-secret",
      };
      const ticket = makeTicket({ e: now + 120, issuedAt: now, m: entry.mask });
      const binding = makePowBindingString(ticket, "example.com", "any", "any", "any", "any", "any");
      ticket.mac = crypto.createHmac("sha256", config.POW_TOKEN).update(binding).digest("base64url");
      const ticketB64 = encodePowTicket(ticket);
      const exp = now + 30;
      const mac = await makeConsumeMac(config.POW_TOKEN, ticketB64, exp, entry.tag, entry.mask);
      const result = await execute({
        ...config,
        _unused: 0,
      }, {
        captchaToken: entry.captchaToken,
        consumeToken: `v2.${ticketB64}.${exp}.${entry.tag}.${entry.mask}.${mac}`,
      });
      assert.equal(result.response.status, 200);
      assert.equal(result.calls.forward, 1);
    }
    assert.equal(providerCalls, 2);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});
