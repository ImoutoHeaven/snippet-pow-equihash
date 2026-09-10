import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPowRuntimeFixture } from "./helpers/pow-runtime-fixture.js";

const secret = "config-secret";
const base64Url = (value) => Buffer.from(value).toString("base64url");

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

const innerHeaders = () => {
  const payload = {
    v: 1,
    id: 1,
    c: {
      POW_API_PREFIX: "/__pow",
      POW_TOKEN: "pow-secret",
      POW_VERSION: 4,
      powcheck: false,
      turncheck: true,
      POW_BIND_PATH: false,
      POW_BIND_IPRANGE: false,
      TURNSTILE_SITEKEY: "sitekey",
      TURNSTILE_SECRET: "turn-secret",
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      ATOMIC_CONSUME: false,
      SITEVERIFY_URLS: [],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "siteverify-secret",
    },
    d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
    s: {
      nav: {},
      bypass: { bypass: false },
      bind: { ok: true, code: "", canonicalPath: "/protected" },
      atomic: { captchaToken: "", ticketB64: "", consumeToken: "", fromCookie: false, cookieName: "" },
    },
  };
  const encoded = base64Url(JSON.stringify(payload));
  const exp = Math.floor(Date.now() / 1000) + 3;
  const mac = crypto.createHmac("sha256", secret).update(`${encoded}.${exp}`).digest("base64url");
  return { "X-Pow-Inner": encoded, "X-Pow-Inner-Mac": mac, "X-Pow-Inner-Expire": String(exp) };
};

const buildModules = async () => {
  const { tmpDir } = await createPowRuntimeFixture({ secret, tmpPrefix: "pow-route-cleanup-" });
  const nonce = `${Date.now()}-${Math.random()}`;
  const [core1, core2] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${nonce}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${nonce}`),
  ]);
  return { core1: core1.default.fetch, core2: core2.default.fetch };
};

test("core1 transits verify and removed API traffic to core2", async () => {
  const restore = withGlobals();
  const { core1 } = await buildModules();
  const originalFetch = globalThis.fetch;
  const downstream = [];
  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      downstream.push(request);
      return new Response("downstream", { status: 599 });
    };
    const verify = await core1(new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { ...innerHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }));
    assert.equal(verify.status, 599);
    assert.equal(downstream.length, 1);
    assert.equal(downstream[0].headers.get("X-Pow-Transit"), "api");

    const retired = await core1(new Request("https://example.com/__pow/cap", {
      method: "POST",
      headers: innerHeaders(),
      body: JSON.stringify({}),
    }));
    assert.equal(retired.status, 599);
    assert.equal(downstream.length, 2);
    assert.equal(downstream[1].headers.get("X-Pow-Transit"), "api");
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("core2 rejects every API action after transit validation without reaching origin", async () => {
  const restore = withGlobals();
  const { core2 } = await buildModules();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("origin", { status: 200 });
    };
    for (const pathname of ["/__pow/retired", "/__pow/anything"]) {
      const exp = Math.floor(Date.now() / 1000) + 3;
      const input = `v1|${exp}|api|POST|${pathname}|/__pow`;
      const transit = crypto.createHmac("sha256", secret).update(input).digest("base64url");
      const response = await core2(new Request(`https://example.com${pathname}`, {
        method: "POST",
        headers: {
          ...innerHeaders(),
          "X-Pow-Transit": "api",
          "X-Pow-Transit-Mac": transit,
          "X-Pow-Transit-Expire": String(exp),
          "X-Pow-Transit-Api-Prefix": "/__pow",
        },
        body: JSON.stringify({}),
      }));
      assert.equal(response.status, 404);
    }
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restore();
  }
});

test("retired runtime and route names are absent from shipped source", async () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const files = [
    "pow-config.js",
    "pow-core-1.js",
    "pow-core-2.js",
    "glue.js",
    "lib/pow/api-engine.js",
    "lib/pow/business-gate.js",
  ];
  const sources = await Promise.all(files.map((file) => readFile(join(root, file), "utf8")));
  for (const source of sources) {
    assert.doesNotMatch(source, /mhg|hashcash|POW_SAMPLE|POW_SEGMENT|POW_PAGE|POW_MIX/u);
    assert.doesNotMatch(source, /["'`]\/(?:commit|challenge|open)(?:["'`])/u);
  }
});
