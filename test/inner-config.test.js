import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPowRuntimeFixture } from "./helpers/pow-runtime-fixture.js";

const SECRET = "config-secret";
const b64 = (value) => Buffer.from(value).toString("base64url");

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

const validStrategy = {
  nav: {},
  bypass: { bypass: false },
  bind: { ok: true, code: "", canonicalPath: "/protected" },
  atomic: { captchaToken: "", ticketB64: "", consumeToken: "", fromCookie: false, cookieName: "" },
};

const innerObject = (config = {}, strategy = validStrategy, derived = null) => ({
  v: 1,
  id: 7,
  c: {
    POW_API_PREFIX: "/__pow",
    POW_TOKEN: "pow-secret",
    POW_VERSION: 4,
    powcheck: false,
    turncheck: false,
    POW_BIND_PATH: false,
    POW_BIND_IPRANGE: false,
    PROOF_TTL_SEC: 600,
    POW_TICKET_TTL_SEC: 600,
    ATOMIC_CONSUME: false,
    ...config,
  },
  d: derived || { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
  s: strategy,
});

const signedInner = (payload, exp = Math.floor(Date.now() / 1000) + 3) => {
  const encoded = b64(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", SECRET).update(`${encoded}.${exp}`).digest("base64url");
  return { encoded, mac, exp };
};

const transitHeaders = ({ method, pathname, kind = "biz", apiPrefix = "/__pow", exp = Math.floor(Date.now() / 1000) + 3 }) => {
  const input = `v1|${exp}|${kind}|${method.toUpperCase()}|${pathname}|${apiPrefix}`;
  return {
    "X-Pow-Transit": kind,
    "X-Pow-Transit-Mac": crypto.createHmac("sha256", SECRET).update(input).digest("base64url"),
    "X-Pow-Transit-Expire": String(exp),
    "X-Pow-Transit-Api-Prefix": apiPrefix,
  };
};

const loadCores = async () => {
  const { tmpDir } = await createPowRuntimeFixture({ secret: SECRET, tmpPrefix: "pow-inner-cleanup-" });
  const stamp = `${Date.now()}-${Math.random()}`;
  const [core1, core2] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${stamp}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${stamp}`),
  ]);
  return { core1: core1.default.fetch, core2: core2.default.fetch };
};

const readInner = (request) => {
  const count = Number.parseInt(request.headers.get("X-Pow-Inner-Count") || "0", 10);
  if (count > 0) return Array.from({ length: count }, (_, i) => request.headers.get(`X-Pow-Inner-${i}`) || "").join("");
  return request.headers.get("X-Pow-Inner") || "";
};

test("core2 authenticates chunked inner headers and strips both internal namespaces", async () => {
  const restore = withGlobals();
  const { core2 } = await loadCores();
  const originalFetch = globalThis.fetch;
  let forwarded = null;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };
    const signed = signedInner(innerObject());
    const midpoint = Math.floor(signed.encoded.length / 2);
    const headers = new Headers(transitHeaders({ method: "GET", pathname: "/protected" }));
    headers.set("X-Pow-Inner-Count", "2");
    headers.set("X-Pow-Inner-0", signed.encoded.slice(0, midpoint));
    headers.set("X-Pow-Inner-1", signed.encoded.slice(midpoint));
    headers.set("X-Pow-Inner-Mac", signed.mac);
    headers.set("X-Pow-Inner-Expire", String(signed.exp));
    headers.set("X-Pow-Transit-Extra", "spoofed");
    const response = await core2(new Request("https://example.com/protected", { headers }));
    assert.equal(response.status, 200);
    assert.ok(forwarded);
    assert.equal(readInner(forwarded), "");
    for (const key of forwarded.headers.keys()) assert.equal(key.toLowerCase().startsWith("x-pow-"), false, key);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("missing, malformed, or expired inner strategy fails closed before origin", async () => {
  const restore = withGlobals();
  const { core1 } = await loadCores();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("origin", { status: 200 });
    };
    for (const payload of [innerObject({}, null), innerObject({}, { ...validStrategy, bind: { ok: "true", code: "", canonicalPath: "/protected" } })]) {
      const signed = signedInner(payload);
      const response = await core1(new Request("https://example.com/protected", {
        headers: { "X-Pow-Inner": signed.encoded, "X-Pow-Inner-Mac": signed.mac, "X-Pow-Inner-Expire": String(signed.exp) },
      }));
      assert.equal(response.status, 500);
    }
    const expired = signedInner(innerObject(), Math.floor(Date.now() / 1000) - 1);
    const response = await core1(new Request("https://example.com/protected", {
      headers: { "X-Pow-Inner": expired.encoded, "X-Pow-Inner-Mac": expired.mac, "X-Pow-Inner-Expire": String(expired.exp) },
    }));
    assert.equal(response.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("missing, tampered, future, oversized, and invalid chunked inner headers stop before origin", async () => {
  const restore = withGlobals();
  const { core1 } = await loadCores();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("origin", { status: 200 });
    };
    const cases = [];
    cases.push(new Request("https://example.com/protected"));

    const signed = signedInner(innerObject());
    cases.push(new Request("https://example.com/protected", {
      headers: { "X-Pow-Inner": signed.encoded, "X-Pow-Inner-Mac": "tampered", "X-Pow-Inner-Expire": String(signed.exp) },
    }));

    const future = signedInner(innerObject(), Math.floor(Date.now() / 1000) + 10);
    cases.push(new Request("https://example.com/protected", {
      headers: { "X-Pow-Inner": future.encoded, "X-Pow-Inner-Mac": future.mac, "X-Pow-Inner-Expire": String(future.exp) },
    }));

    const oversized = signedInner(innerObject({ oversized: "x".repeat(130000) }));
    cases.push(new Request("https://example.com/protected", {
      headers: { "X-Pow-Inner": oversized.encoded, "X-Pow-Inner-Mac": oversized.mac, "X-Pow-Inner-Expire": String(oversized.exp) },
    }));

    const chunked = signedInner(innerObject());
    cases.push(new Request("https://example.com/protected", {
      headers: {
        "X-Pow-Inner-Count": "2",
        "X-Pow-Inner-0": chunked.encoded.slice(0, Math.floor(chunked.encoded.length / 2)),
        "X-Pow-Inner-Mac": chunked.mac,
        "X-Pow-Inner-Expire": String(chunked.exp),
      },
    }));

    for (const request of cases) assert.equal((await core1(request)).status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("binding failures return 400 while a signed bypass still forwards", async () => {
  const restore = withGlobals();
  const { core1 } = await loadCores();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("origin", { status: 200 });
    };
    for (const code of ["missing", "invalid"]) {
      const payload = innerObject({ powcheck: true }, { ...validStrategy, bind: { ok: false, code, canonicalPath: "/protected" } });
      const signed = signedInner(payload);
      const response = await core1(new Request("https://example.com/protected", {
        headers: { "X-Pow-Inner": signed.encoded, "X-Pow-Inner-Mac": signed.mac, "X-Pow-Inner-Expire": String(signed.exp) },
      }));
      assert.equal(response.status, 400);
    }
    const bypass = innerObject({ powcheck: true }, { ...validStrategy, bypass: { bypass: true }, bind: { ok: false, code: "missing", canonicalPath: "/protected" } });
    const signed = signedInner(bypass);
    const response = await core1(new Request("https://example.com/protected", {
      headers: { "X-Pow-Inner": signed.encoded, "X-Pow-Inner-Mac": signed.mac, "X-Pow-Inner-Expire": String(signed.exp) },
    }));
    assert.equal(response.status, 200);
    assert.equal(originCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("atomic query, header, and cookie precedence is preserved by pow-config", async () => {
  const restore = withGlobals();
  const root = fileURLToPath(new URL("..", import.meta.url));
  const [source, runtime, pathGlob, lru] = await Promise.all([
    readFile(join(root, "pow-config.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/runtime.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/path-glob.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/lru-cache.js"), "utf8"),
  ]);
  const compiled = JSON.stringify([{ host: { kind: "eq", value: "example.com" }, hostType: "exact", hostExact: "example.com", path: null, config: { powcheck: false, turncheck: true, POW_TOKEN: "pow-secret", POW_BIND_PATH: false, POW_BIND_IPRANGE: false, TURNSTILE_SITEKEY: "sitekey", TURNSTILE_SECRET: "secret" } }]);
  const temp = await mkdtemp(join(tmpdir(), "pow-config-cleanup-"));
  await mkdir(join(temp, "lib/rule-engine"), { recursive: true });
  await mkdir(join(temp, "lib/equihash"), { recursive: true });
  await mkdir(join(temp, "lib/pow"), { recursive: true });
  await writeFile(join(temp, "lib/rule-engine/runtime.js"), runtime);
  await writeFile(join(temp, "lib/rule-engine/path-glob.js"), pathGlob);
  await writeFile(join(temp, "lib/rule-engine/lru-cache.js"), lru);
  await Promise.all([
    readFile(join(root, "lib/equihash/encoding.js"), "utf8").then((text) => writeFile(join(temp, "lib/equihash/encoding.js"), text)),
    readFile(join(root, "lib/equihash/params.js"), "utf8").then((text) => writeFile(join(temp, "lib/equihash/params.js"), text)),
    readFile(join(root, "lib/equihash/ticket.js"), "utf8").then((text) => writeFile(join(temp, "lib/equihash/ticket.js"), text)),
    readFile(join(root, "lib/pow/auth-primitives.js"), "utf8").then((text) => writeFile(join(temp, "lib/pow/auth-primitives.js"), text)),
  ]);
  await writeFile(join(temp, "pow-config.js"), source.replace(/__COMPILED_CONFIG__/gu, compiled).replace(/const CONFIG_SECRET = "[^"]*";/u, 'const CONFIG_SECRET = "config-secret";'));
  const mod = await import(`${pathToFileURL(join(temp, "pow-config.js")).href}?v=${Date.now()}`);
  const originalFetch = globalThis.fetch;
  let forwarded = null;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };
    const response = await mod.default.fetch(new Request("https://example.com/protected?__ts=query-turn&__tt=query-ticket&__ct=query-consume&keep=1", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
        "x-turnstile": "header-turn",
        "x-ticket": "header-ticket",
        "x-consume": "header-consume",
        Cookie: "__Secure-pow_a=1%7Ct%7Ccookie-turn%7Ccookie-ticket",
      },
    }));
    assert.equal(response.status, 200);
    assert.ok(forwarded);
    assert.equal(new URL(forwarded.url).searchParams.get("__ts"), null);
    assert.equal(forwarded.headers.get("x-turnstile"), null);
    const payload = JSON.parse(Buffer.from(readInner(forwarded), "base64url").toString("utf8"));
    assert.equal(payload.s.atomic.captchaToken, "cookie-turn");
    assert.equal(payload.s.atomic.ticketB64, "cookie-ticket");
    assert.equal(payload.s.atomic.consumeToken, "");
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("atomic snapshot limits reject malformed or oversized transport before forwarding", async () => {
  const restore = withGlobals();
  const root = fileURLToPath(new URL("..", import.meta.url));
  const [source, runtime, pathGlob, lru] = await Promise.all([
    readFile(join(root, "pow-config.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/runtime.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/path-glob.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/lru-cache.js"), "utf8"),
  ]);
  const compiled = JSON.stringify([{ host: { kind: "eq", value: "example.com" }, hostType: "exact", hostExact: "example.com", path: null, config: { POW_TOKEN: "pow-secret" } }]);
  const temp = await mkdtemp(join(tmpdir(), "pow-config-limits-"));
  await mkdir(join(temp, "lib/rule-engine"), { recursive: true });
  await mkdir(join(temp, "lib/equihash"), { recursive: true });
  await mkdir(join(temp, "lib/pow"), { recursive: true });
  await writeFile(join(temp, "lib/rule-engine/runtime.js"), runtime);
  await writeFile(join(temp, "lib/rule-engine/path-glob.js"), pathGlob);
  await writeFile(join(temp, "lib/rule-engine/lru-cache.js"), lru);
  await Promise.all([
    readFile(join(root, "lib/equihash/encoding.js"), "utf8").then((text) => writeFile(join(temp, "lib/equihash/encoding.js"), text)),
    readFile(join(root, "lib/equihash/params.js"), "utf8").then((text) => writeFile(join(temp, "lib/equihash/params.js"), text)),
    readFile(join(root, "lib/equihash/ticket.js"), "utf8").then((text) => writeFile(join(temp, "lib/equihash/ticket.js"), text)),
    readFile(join(root, "lib/pow/auth-primitives.js"), "utf8").then((text) => writeFile(join(temp, "lib/pow/auth-primitives.js"), text)),
  ]);
  await writeFile(join(temp, "pow-config.js"), source.replace(/__COMPILED_CONFIG__/gu, compiled).replace(/const CONFIG_SECRET = "[^"]*";/u, 'const CONFIG_SECRET = "config-secret";'));
  const mod = await import(`${pathToFileURL(join(temp, "pow-config.js")).href}?v=${Date.now()}`);
  const { core1, core2 } = await loadCores();
  const originalFetch = globalThis.fetch;
  const trace = { core1: 0, core2: 0, origin: 0 };
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.headers.has("X-Pow-Transit")) {
        trace.core2 += 1;
        return core2(request);
      }
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        trace.core1 += 1;
        return core1(request);
      }
      trace.origin += 1;
      return new Response("ok");
    };
    const exact = await mod.default.fetch(new Request(`https://example.com/protected?__ts=${"t".repeat(8192)}`));
    assert.equal(exact.status, 200);
    assert.deepEqual(trace, { core1: 1, core2: 1, origin: 1 });
    trace.core1 = 0;
    trace.core2 = 0;
    trace.origin = 0;
    const oversized = await mod.default.fetch(new Request(`https://example.com/protected?__ts=${"t".repeat(8193)}`));
    assert.equal(oversized.status, 431);
    assert.deepEqual(trace, { core1: 0, core2: 0, origin: 0 });
    const malformed = await mod.default.fetch(new Request("https://example.com/protected?__tt=bad*ticket"));
    assert.equal(malformed.status, 400);
    assert.deepEqual(trace, { core1: 0, core2: 0, origin: 0 });
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});
