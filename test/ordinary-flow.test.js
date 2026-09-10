import test from "node:test";
import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { captchaTagV1, deriveEquihashSeed } from "../lib/equihash/seed.js";
import { base64UrlEncodeNoPad } from "../lib/equihash/encoding.js";
import { parseV5Ticket } from "../lib/equihash/ticket.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CONFIG_SECRET = "config-secret";
const b64 = (value) => Buffer.from(value, "utf8").toString("base64url");
const decodeB64 = (value) => Buffer.from(value, "base64url").toString("utf8");

const copyRuntimeDependencies = async (target) => {
  await mkdir(join(target, "lib", "pow"), { recursive: true });
  await cp(join(ROOT, "lib", "rule-engine"), join(target, "lib", "rule-engine"), { recursive: true });
  await cp(join(ROOT, "lib", "equihash"), join(target, "lib", "equihash"), { recursive: true });
  await cp(join(ROOT, "lib", "pow", "auth-primitives.js"), join(target, "lib", "pow", "auth-primitives.js"));
};

const loadConfig = async (config, pathRule = null) => {
  const source = await readFile(join(ROOT, "pow-config.js"), "utf8");
  const temp = await mkdtemp(join(tmpdir(), "pow-ordinary-config-"));
  await copyRuntimeDependencies(temp);
  const compiled = JSON.stringify([{
    host: { kind: "eq", value: "example.com" },
    hostType: "exact",
    hostExact: "example.com",
    path: pathRule ? { kind: "eq", value: pathRule } : null,
    ...(pathRule ? { pathType: "exact", pathExact: pathRule } : {}),
    config,
  }]);
  await writeFile(
    join(temp, "pow-config.js"),
    source
      .replace(/__COMPILED_CONFIG__/gu, compiled)
      .replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${CONFIG_SECRET}";`),
  );
  const module = await import(`${pathToFileURL(join(temp, "pow-config.js")).href}?v=${Date.now()}-${Math.random()}`);
  return module.default.fetch;
};

const loadCores = async () => {
  const temp = await mkdtemp(join(tmpdir(), "pow-ordinary-runtime-"));
  await cp(join(ROOT, "lib"), join(temp, "lib"), { recursive: true });
  const template = await readFile(join(ROOT, "template.html"), "utf8");
  for (const entry of ["pow-core-1.js", "pow-core-2.js"]) {
    let source = await readFile(join(ROOT, entry), "utf8");
    source = source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${CONFIG_SECRET}";`);
    await writeFile(join(temp, entry), source);
  }
  let gate = await readFile(join(ROOT, "lib/pow/business-gate.js"), "utf8");
  gate = gate.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  await writeFile(join(temp, "lib/pow/business-gate.js"), gate);
  const stamp = `${Date.now()}-${Math.random()}`;
  const [core1, core2] = await Promise.all([
    import(`${pathToFileURL(join(temp, "pow-core-1.js")).href}?v=${stamp}`),
    import(`${pathToFileURL(join(temp, "pow-core-2.js")).href}?v=${stamp}`),
  ]);
  return { core1: core1.default.fetch, core2: core2.default.fetch };
};

const parseTemplate = (html) => {
  const match = html.match(/g\("([^"]+)","([^"]+)","([^"]+)","([^"]*)","([^"]+)","([^"]+)"\)/u);
  assert.ok(match, "challenge template arguments missing");
  return {
    bootstrapB64: match[1],
    bindingB64: match[2],
    reloadUrlB64: match[3],
    esmUrlB64: match[4],
    captchaCfgB64: match[5],
    atomicCfg: match[6],
  };
};

const parseSetCookie = (response) => String(response.headers.get("set-cookie") || "").split(";")[0];

const solveArtifact = async (seed, n, k) => {
  const bytes = new Uint8Array(await readFile(join(ROOT, "esm", "solver.wasm")));
  const instanceResult = await WebAssembly.instantiate(bytes, {});
  const exports = (instanceResult.instance || instanceResult).exports;
  const proofLength = Number(exports.required_proof_len(k));
  const seedPtr = Number(exports.alloc(seed.length, 8));
  const nonce = new Uint8Array(24);
  const noncePtr = Number(exports.alloc(nonce.length, 8));
  const proofPtr = Number(exports.alloc(proofLength, 8));
  try {
    for (let attempt = 0; attempt < 32; attempt += 1) {
      nonce.fill(0);
      new DataView(nonce.buffer).setUint32(20, attempt, false);
      let view = new Uint8Array(exports.memory.buffer);
      view.set(seed, seedPtr);
      view.set(nonce, noncePtr);
      const rc = Number(exports.solve_once(seedPtr, seed.length, noncePtr, nonce.length, n, k, 64, proofPtr, proofLength));
      if (rc === proofLength) {
        view = new Uint8Array(exports.memory.buffer);
        return { nonce: nonce.slice(), proof: new Uint8Array(view.subarray(proofPtr, proofPtr + rc)) };
      }
      assert.equal(rc, 0, `unexpected solver result ${rc}`);
    }
    assert.fail("solver did not find a proof");
  } finally {
    exports.dealloc(proofPtr, proofLength, 8);
    exports.dealloc(noncePtr, nonce.length, 8);
    exports.dealloc(seedPtr, seed.length, 8);
  }
};

const makeHarness = async ({ turncheck, powcheck = true, proofTtl = 600, aggregator = false, atomic = false, apiPrefix = "/__pow", pathRule = null, providerResult = () => ({ ok: true, reason: "ok", checks: {}, providers: {} }) }) => {
  const config = await loadConfig({
    POW_TOKEN: "pow-secret",
    POW_API_PREFIX: apiPrefix,
    POW_EQ_N: 12,
    POW_EQ_K: 2,
    POW_ESM_URL: "/esm/esm.js",
    POW_GLUE_URL: "/glue.js",
    POW_TICKET_TTL_SEC: 600,
    PROOF_TTL_SEC: proofTtl,
    powcheck,
    turncheck,
    POW_BIND_PATH: false,
    POW_BIND_IPRANGE: false,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    TURNSTILE_SITEKEY: turncheck ? "sitekey" : "",
    TURNSTILE_SECRET: turncheck ? "turn-secret" : "",
    SITEVERIFY_URLS: turncheck || aggregator ? ["https://sv.example/siteverify"] : [],
    SITEVERIFY_AUTH_KID: "v1",
    SITEVERIFY_AUTH_SECRET: turncheck || aggregator ? "provider-secret" : "",
    AGGREGATOR_POW_ATOMIC_CONSUME: aggregator,
    ATOMIC_CONSUME: atomic,
  }, pathRule);
  const cores = await loadCores();
  const originalFetch = globalThis.fetch;
  const trace = { provider: 0, origin: 0 };
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (request.url === "https://sv.example/siteverify") {
      trace.provider += 1;
      return new Response(JSON.stringify(await providerResult(request)), { status: 200 });
    }
    if (request.headers.has("X-Pow-Transit")) return cores.core2(request);
    if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) return cores.core1(request);
    trace.origin += 1;
    return new Response("origin", { status: 200 });
  };
  const restore = () => { globalThis.fetch = originalFetch; };
  const challenge = await config(new Request("https://example.com/protected", {
    headers: { Accept: "text/html", "CF-Connecting-IP": "203.0.113.9" },
  }));
  return { config, trace, challenge, restore, apiPrefix };
};

const issueProof = async ({ harness, token = "" }) => {
  const args = parseTemplate(await harness.challenge.text());
  const bootstrap = JSON.parse(decodeB64(args.bootstrapB64));
  const captchaTag = token ? await captchaTagV1(token) : "any";
  const seed = await deriveEquihashSeed({ ticketB64: bootstrap.ticketB64, pathHash: bootstrap.pathHash, captchaTag });
  const solution = await solveArtifact(seed, bootstrap.eq.n, bootstrap.eq.k);
  const body = {
    ticketB64: bootstrap.ticketB64,
    pathHash: bootstrap.pathHash,
    pow: {
      nonceB64: base64UrlEncodeNoPad(solution.nonce),
      proofB64: base64UrlEncodeNoPad(solution.proof),
    },
  };
  if (token) body.captchaToken = JSON.stringify({ turnstile: token });
  return { args, bootstrap, body };
};

test("real WASM PoW proof crosses config, core1, core2 and issues a proof cookie", async () => {
  const harness = await makeHarness({ turncheck: false });
  try {
    const { body } = await issueProof({ harness });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    assert.equal((await verify.json()).mode, "proof");
    const cookie = parseSetCookie(verify);
    assert.match(cookie, /^__Host-proof=/u);
    const business = await harness.config(new Request("https://example.com/protected", {
      headers: { Accept: "application/json", Cookie: cookie, "CF-Connecting-IP": "203.0.113.9" },
    }));
    assert.equal(business.status, 200);
    assert.equal(await business.text(), "origin");
    assert.equal(harness.trace.origin, 1);
  } finally {
    harness.restore();
  }
});

test("Turnstile-only uses /verify without constructing a PoW proof", async () => {
  const harness = await makeHarness({ turncheck: true, powcheck: false });
  try {
    const args = parseTemplate(await harness.challenge.clone().text());
    const bootstrap = JSON.parse(decodeB64(args.bootstrapB64));
    const body = {
      ticketB64: bootstrap.ticketB64,
      pathHash: bootstrap.pathHash,
      captchaToken: JSON.stringify({ turnstile: "turnstile-token-1234567890" }),
    };
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    assert.equal((await verify.json()).mode, "proof");
    assert.match(parseSetCookie(verify), /^__Host-proof=/u);
    assert.equal(harness.trace.provider, 1);
  } finally {
    harness.restore();
  }
});

test("combined real proof validates before the configured provider and issues a proof cookie", async () => {
  const harness = await makeHarness({ turncheck: true });
  try {
    const { body } = await issueProof({ harness, token: "turnstile-token-1234567890" });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    assert.equal((await verify.json()).mode, "proof");
    assert.match(parseSetCookie(verify), /^__Host-proof=/u);
    assert.equal(harness.trace.provider, 1);
  } finally {
    harness.restore();
  }
});

test("ordinary PoW invokes the configured ledger only after proof validation", async () => {
  const harness = await makeHarness({ turncheck: false, aggregator: true });
  try {
    const { body } = await issueProof({ harness });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    assert.equal(harness.trace.provider, 1);
  } finally {
    harness.restore();
  }
});

test("raw atomic setting stays ordinary when its effective gate is disabled", async () => {
  const harness = await makeHarness({ turncheck: false, aggregator: false, atomic: true });
  try {
    const args = parseTemplate(await harness.challenge.clone().text());
    assert.equal(args.atomicCfg.split("|", 1)[0], "0");
    const { body } = await issueProof({ harness });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    assert.equal((await verify.json()).mode, "proof");
  } finally {
    harness.restore();
  }
});

test("combined atomic receipt defers provider consumption to the business gate", async () => {
  let consumed = false;
  const harness = await makeHarness({
    turncheck: true,
    atomic: true,
    providerResult: async () => {
      if (consumed) return { ok: false, reason: "duplicate", checks: {}, providers: {} };
      consumed = true;
      return { ok: true, reason: "ok", checks: {}, providers: {} };
    },
  });
  try {
    const token = "turnstile-token-1234567890";
    const { body } = await issueProof({ harness, token });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    const receipt = (await verify.json()).consume;
    assert.match(receipt, /^v2\./u);
    assert.equal(harness.trace.provider, 0);
    assert.equal(harness.trace.origin, 0);

    const request = () => new Request("https://example.com/protected", {
      headers: {
        Accept: "application/json",
        "x-turnstile": JSON.stringify({ turnstile: token }),
        "x-consume": receipt,
        "CF-Connecting-IP": "203.0.113.9",
      },
    });
    const accepted = await harness.config(request());
    assert.equal(accepted.status, 200);
    assert.equal(harness.trace.provider, 1);
    assert.equal(harness.trace.origin, 1);

    const substituted = await harness.config(new Request("https://example.com/protected", {
      headers: {
        Accept: "application/json",
        "x-turnstile": JSON.stringify({ turnstile: "turnstile-token-9999999999" }),
        "x-consume": receipt,
        "CF-Connecting-IP": "203.0.113.9",
      },
    }));
    assert.equal(substituted.status, 403);
    assert.equal(harness.trace.provider, 1);
    assert.equal(harness.trace.origin, 1);

    const replay = await harness.config(request());
    assert.equal(replay.status, 403);
    assert.equal(harness.trace.provider, 2);
    assert.equal(harness.trace.origin, 1);
  } finally {
    harness.restore();
  }
});

test("PoW-only atomic receipt defers the configured ledger consume to the business gate", async () => {
  let consumed = false;
  const harness = await makeHarness({
    turncheck: false,
    aggregator: true,
    atomic: true,
    providerResult: async () => {
      if (consumed) return { ok: false, reason: "duplicate", checks: {}, providers: {} };
      consumed = true;
      return { ok: true, reason: "ok", checks: {}, providers: {} };
    },
  });
  try {
    const { body } = await issueProof({ harness });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    const receipt = (await verify.json()).consume;
    assert.match(receipt, /^v2\./u);
    assert.equal(harness.trace.provider, 0);

    const request = () => new Request("https://example.com/protected", {
      headers: { Accept: "application/json", "x-consume": receipt, "CF-Connecting-IP": "203.0.113.9" },
    });
    const accepted = await harness.config(request());
    assert.equal(accepted.status, 200);
    assert.equal(harness.trace.provider, 1);
    assert.equal(harness.trace.origin, 1);
    const replay = await harness.config(request());
    assert.equal(replay.status, 403);
    assert.equal(harness.trace.provider, 2);
    assert.equal(harness.trace.origin, 1);
  } finally {
    harness.restore();
  }
});

test("config selects a custom proof API prefix from the signed v5 ticket", async () => {
  const harness = await makeHarness({ turncheck: false, apiPrefix: "/custom-gate", pathRule: "/protected" });
  try {
    const { body } = await issueProof({ harness });
    const verify = await harness.config(new Request("https://example.com/custom-gate/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
  } finally {
    harness.restore();
  }
});

test("a path-scoped custom prefix owns malformed and retired API requests", async () => {
  const harness = await makeHarness({ turncheck: false, apiPrefix: "/custom-gate", pathRule: "/protected" });
  try {
    const malformed = await harness.config(new Request("https://example.com/custom-gate/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "not-json",
    }));
    assert.equal(malformed.status, 403);
    assert.equal(malformed.headers.get("x-pow-h"), "bad_request");

    for (const action of ["cap", "commit", "challenge", "open", "anything"]) {
      const retired = await harness.config(new Request(`https://example.com/custom-gate/${action}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }));
      assert.equal(retired.status, 404, action);
    }

    const oversized = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`{"ticketB64":"${"x".repeat(70000)}"}`));
        controller.close();
      },
    });
    const oversizedVerify = await harness.config(new Request("https://example.com/custom-gate/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": "1" },
      body: oversized,
      duplex: "half",
    }));
    assert.equal(oversizedVerify.status, 403);
    assert.equal(oversizedVerify.headers.get("x-pow-h"), "bad_request");
    assert.equal(harness.trace.origin, 0);
  } finally {
    harness.restore();
  }
});

test("an invalid profile still owns its custom API prefix and fails closed", async () => {
  const config = await loadConfig({
    POW_TOKEN: "pow-secret",
    POW_API_PREFIX: "/custom-gate",
    POW_EQ_N: 91,
    POW_EQ_K: 5,
    POW_BIND_PATH: false,
    POW_BIND_IPRANGE: false,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
  }, "/protected");
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  globalThis.fetch = async () => {
    originCalls += 1;
    return new Response("origin", { status: 200 });
  };
  try {
    const verify = await config(new Request("https://example.com/custom-gate/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }));
    assert.equal(verify.status, 500);
    const retired = await config(new Request("https://example.com/custom-gate/cap", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }));
    assert.equal(retired.status, 500);
    const unrelated = await config(new Request("https://example.com/ordinary-verify", {
      headers: { Accept: "application/json" },
    }));
    assert.equal(unrelated.status, 200);
    assert.equal(originCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("combined proof with token A fails with token B before provider consumption", async () => {
  const harness = await makeHarness({ turncheck: true });
  try {
    const tokenA = "turnstile-token-aaaaaaaa";
    const tokenB = "turnstile-token-bbbbbbbb";
    const { body } = await issueProof({ harness, token: tokenA });
    body.captchaToken = JSON.stringify({ turnstile: tokenB });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 403);
    assert.equal(verify.headers.get("x-pow-h"), "cheat");
    assert.equal(harness.trace.provider, 0);
  } finally {
    harness.restore();
  }
});

test("ordinary proof cookie ticket expires with the configured proof lifetime", async () => {
  const harness = await makeHarness({ turncheck: false, proofTtl: 10 });
  try {
    const { body } = await issueProof({ harness });
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 200);
    const cookie = parseSetCookie(verify);
    const proofValue = decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1));
    const proofTicket = parseV5Ticket(proofValue.split(".")[1]);
    const now = Math.floor(Date.now() / 1000);
    assert.ok(proofTicket);
    assert.ok(proofTicket.e > now && proofTicket.e <= now + 10);
  } finally {
    harness.restore();
  }
});

test("verify body is bounded from received bytes before JSON parsing", async () => {
  const harness = await makeHarness({ turncheck: false });
  try {
    const oversized = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`{"ticketB64":"${"x".repeat(70000)}"}`));
        controller.close();
      },
    });
    const response = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": "1" },
      body: oversized,
      duplex: "half",
    }));
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("x-pow-h"), "bad_request");
    assert.equal(harness.trace.origin, 0);
  } finally {
    harness.restore();
  }
});

test("verify rejects a noncanonical proof encoding before solver verification", async () => {
  const harness = await makeHarness({ turncheck: false });
  try {
    const { body } = await issueProof({ harness });
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = body.pow.proofB64.slice(-1);
    const index = alphabet.indexOf(last);
    body.pow.proofB64 = `${body.pow.proofB64.slice(0, -1)}${alphabet[(index & 0x30) | 1]}`;
    const verify = await harness.config(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }));
    assert.equal(verify.status, 403);
    assert.equal(verify.headers.get("x-pow-h"), "bad_request");
  } finally {
    harness.restore();
  }
});
