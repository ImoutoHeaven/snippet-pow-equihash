import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPowRuntimeFixture } from "./helpers/pow-runtime-fixture.js";

const CONFIG_SECRET = "config-secret";
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

const buildConfig = async (overrides = {}, compiledEntries = null) => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const [source, runtime, pathGlob, lru] = await Promise.all([
    readFile(join(root, "pow-config.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/runtime.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/path-glob.js"), "utf8"),
    readFile(join(root, "lib/rule-engine/lru-cache.js"), "utf8"),
  ]);
  const config = {
    POW_TOKEN: "pow-secret",
    powcheck: false,
    turncheck: true,
    POW_BIND_PATH: false,
    POW_BIND_IPRANGE: false,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    TURNSTILE_SITEKEY: "sitekey",
    TURNSTILE_SECRET: "turn-secret",
    SITEVERIFY_URLS: ["https://sv.example/siteverify"],
    SITEVERIFY_AUTH_KID: "v1",
    SITEVERIFY_AUTH_SECRET: "provider-secret",
    ...overrides,
  };
  const compiled = JSON.stringify(compiledEntries || [{ host: { kind: "eq", value: "example.com" }, hostType: "exact", hostExact: "example.com", path: null, config }]);
  const temp = await mkdtemp(join(tmpdir(), "pow-chain-cleanup-"));
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
  await writeFile(join(temp, "pow-config.js"), source.replace(/__COMPILED_CONFIG__/gu, compiled).replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${CONFIG_SECRET}";`));
  const mod = await import(`${pathToFileURL(join(temp, "pow-config.js")).href}?v=${Date.now()}-${Math.random()}`);
  return mod.default.fetch;
};

const loadCores = async () => {
  const { tmpDir } = await createPowRuntimeFixture({ secret: CONFIG_SECRET, tmpPrefix: "pow-chain-runtime-" });
  const stamp = `${Date.now()}-${Math.random()}`;
  const [core1, core2] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${stamp}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${stamp}`),
  ]);
  return { core1: core1.default.fetch, core2: core2.default.fetch };
};

const decodeInner = (request) => {
  const count = Number.parseInt(request.headers.get("X-Pow-Inner-Count") || "0", 10);
  const payload = count > 0
    ? Array.from({ length: count }, (_, i) => request.headers.get(`X-Pow-Inner-${i}`) || "").join("")
    : request.headers.get("X-Pow-Inner") || "";
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
};

const parseTemplate = (html) => {
  const match = html.match(/g\("([^"]+)","([^"]+)","([^"]+)","([^"]*)","([^"]+)","([^"]+)"\)/u);
  return match && { bootstrapB64: match[1], bindingB64: match[2], reloadB64: match[3], esmB64: match[4], captchaB64: match[5], atomicCfg: match[6] };
};

test("config -> core1 -> core2 preserves signed inner and transit boundaries", async () => {
  const restore = withGlobals();
  const config = await buildConfig();
  const { core1, core2 } = await loadCores();
  const originalFetch = globalThis.fetch;
  let innerRequest = null;
  let originRequest = null;
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return core1(request);
      }
      if (request.headers.has("X-Pow-Transit")) return core2(request);
      originRequest = request;
      return new Response("origin-ok", { status: 200 });
    };
    const response = await config(new Request("https://example.com/protected", { headers: { Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" } }));
    assert.equal(response.status, 200);
    assert.ok(innerRequest);
    assert.ok(originRequest === null, "unauthorized navigation stops at core1");
    const inner = decodeInner(innerRequest);
    assert.equal(inner.v, 1);
    assert.equal(inner.s.bind.ok, true);
    assert.equal(response.headers.get("X-Pow-Inner"), null);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("first-match asset bypasses reach origin through the actual snippet chain", async () => {
  const restore = withGlobals();
  const assetConfig = {
    POW_TOKEN: "pow-secret",
    powcheck: false,
    turncheck: false,
    POW_BIND_PATH: false,
    POW_BIND_IPRANGE: false,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    POW_GLUE_URL: "/glue.js",
    POW_ESM_URL: "/esm/esm.js",
  };
  const compiled = [
    { host: { kind: "eq", value: "example.com" }, path: { kind: "eq", value: "/glue.js" }, config: assetConfig },
    { host: { kind: "eq", value: "example.com" }, path: { kind: "glob", pattern: "/esm/**" }, config: assetConfig },
    { host: { kind: "eq", value: "example.com" }, path: { kind: "glob", pattern: "/**" }, config: { ...assetConfig, powcheck: true } },
  ];
  const config = await buildConfig({}, compiled);
  const { core1, core2 } = await loadCores();
  const originalFetch = globalThis.fetch;
  const originRequests = [];
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.headers.has("X-Pow-Transit")) return core2(request);
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) return core1(request);
      originRequests.push(request);
      const pathname = new URL(request.url).pathname;
      return new Response(`asset:${pathname}`, { status: 200 });
    };

    for (const pathname of ["/glue.js", "/esm/esm.js", "/esm/equihash-worker.js", "/esm/solver.wasm"]) {
      const response = await config(new Request(`https://example.com${pathname}`));
      assert.equal(response.status, 200, pathname);
      assert.equal(await response.text(), `asset:${pathname}`);
    }
    assert.equal(originRequests.length, 4);
    for (const request of originRequests) {
      assert.equal(request.headers.get("X-Pow-Inner"), null);
      assert.equal(request.headers.get("X-Pow-Transit"), null);
    }

    const protectedResponse = await config(new Request("https://example.com/protected", { headers: { Accept: "text/html" } }));
    assert.equal(protectedResponse.status, 200);
    assert.equal(originRequests.length, 4, "catch-all protected route must still challenge ordinary navigation");
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("Turnstile-only /verify issues a proof that authorizes the next business request", async () => {
  const restore = withGlobals();
  const config = await buildConfig();
  const { core1, core2 } = await loadCores();
  const originalFetch = globalThis.fetch;
  let pageInner = null;
  let originRequest = null;
  let siteverifyCalls = 0;
  let providerOk = true;
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.url === "https://sv.example/siteverify") {
        siteverifyCalls += 1;
        return new Response(JSON.stringify({ ok: providerOk, reason: providerOk ? "ok" : "provider_failed", checks: {}, providers: {} }), { status: 200 });
      }
      if (request.headers.has("X-Pow-Transit")) {
        return core2(request);
      }
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        pageInner = request;
        return core1(request);
      }
      originRequest = request;
      return new Response("origin-ok", { status: 200 });
    };

    const page = await config(new Request("https://example.com/protected", { headers: { Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" } }));
    assert.equal(page.status, 200);
    const args = parseTemplate(await page.text());
    assert.ok(args);
    assert.ok(pageInner);
    const bootstrap = JSON.parse(Buffer.from(args.bootstrapB64, "base64url").toString("utf8"));
    const verify = await core1(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { ...Object.fromEntries(pageInner.headers), "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
      body: JSON.stringify({ ticketB64: bootstrap.ticketB64, pathHash: bootstrap.pathHash, captchaToken: JSON.stringify({ turnstile: "turnstile-token-1234567890" }) }),
    }));
    assert.equal(verify.status, 200);
    assert.equal(siteverifyCalls, 1);
    const cookie = (verify.headers.get("Set-Cookie") || "").split(";")[0];
    assert.match(cookie, /^__Host-proof=/u);

    originRequest = null;
    const authorized = await config(new Request("https://example.com/protected", {
      headers: { Accept: "application/json", Cookie: cookie, "CF-Connecting-IP": "1.2.3.4" },
    }));
    assert.equal(authorized.status, 200);
    assert.equal(await authorized.text(), "origin-ok");
    assert.ok(originRequest);
    assert.equal(originRequest.headers.get("X-Pow-Inner"), null);
    assert.equal(originRequest.headers.get("X-Pow-Transit"), null);

    providerOk = false;
    const rejectedVerify = await core1(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { ...Object.fromEntries(pageInner.headers), "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
      body: JSON.stringify({ ticketB64: bootstrap.ticketB64, pathHash: bootstrap.pathHash, captchaToken: JSON.stringify({ turnstile: "turnstile-token-1234567890" }) }),
    }));
    assert.equal(rejectedVerify.status, 403);
    assert.equal(rejectedVerify.headers.get("x-pow-h"), "stale");
    assert.equal(rejectedVerify.headers.get("Set-Cookie"), null);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("atomic query/header transport is stripped before forwarding and remains in signed strategy", async () => {
  const restore = withGlobals();
  const config = await buildConfig({ ATOMIC_CONSUME: true });
  const originalFetch = globalThis.fetch;
  let forwarded = null;
  try {
    globalThis.fetch = async (request) => {
      forwarded = request;
      return new Response("ok", { status: 200 });
    };
    const response = await config(new Request("https://example.com/protected?__ts=query-turn&__tt=query-ticket&__ct=query-consume&keep=1", {
      headers: { "x-turnstile": "header-turn", "x-ticket": "header-ticket", "x-consume": "header-consume", "CF-Connecting-IP": "1.2.3.4" },
    }));
    assert.equal(response.status, 200);
    assert.ok(forwarded);
    assert.equal(new URL(forwarded.url).searchParams.get("__ts"), null);
    assert.equal(forwarded.headers.get("x-turnstile"), null);
    const inner = decodeInner(forwarded);
    assert.equal(inner.s.atomic.captchaToken, "header-turn");
    assert.equal(inner.s.atomic.ticketB64, "header-ticket");
    assert.equal(inner.s.atomic.consumeToken, "header-consume");
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});
