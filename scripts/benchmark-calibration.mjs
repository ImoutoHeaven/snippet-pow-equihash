import { createServer } from "node:http";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import os from "node:os";
import { deriveEquihashSeed } from "../lib/equihash/seed.js";
import { encodeV5Ticket, makeTicketMac } from "../lib/equihash/ticket.js";
import { base64UrlEncodeNoPad } from "../lib/equihash/encoding.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SECRET = "calibration-secret";
const HOST = "127.0.0.1";
const DEFAULT_SAMPLES = 1;
const DEFAULT_TIMEOUT_MS = 180_000;
const PUBLISHED_DEFAULT = { n: 96, k: 5 };
const FIXED_NOW = 4_000_000_000;

// Fixed routes, tickets, seeds, and nonce sequences make each input case repeatable.
const REGRESSION_CASES = Array.from({ length: 10 }, (_, index) => ({
  id: index === 0 ? "eq-96-5" : `eq-96-5-${String.fromCharCode(96 + index)}`,
  n: 96,
  k: 5,
  cfgId: index,
  nonceAttempts: [0],
  required: false,
  regression: true,
}));

const COMPARISON_CASES = [
  { id: "eq-90-5", n: 90, k: 5, cfgId: 10, nonceAttempts: [0], required: true },
  { id: "eq-84-5", n: 84, k: 5, cfgId: 11, nonceAttempts: [0], required: true },
  { id: "eq-102-5", n: 102, k: 5, cfgId: 12, nonceAttempts: [0], required: true },
  { id: "eq-28-3", n: 28, k: 3, cfgId: 13, nonceAttempts: [0], required: true },
  { id: "eq-112-6", n: 112, k: 6, cfgId: 14, nonceAttempts: [0], required: true },
];

const DETERMINISTIC_CASE = {
  id: "fixed-eq-12-2",
  n: 12,
  k: 2,
  rows: 64,
  cfgId: 15,
  required: true,
};

const DEFAULT_CASES = Array.from({ length: 16 }, (_, index) => ({
  id: `eq-96-5-batch-${16 + index}`,
  n: 96,
  k: 5,
  cfgId: 16 + index,
  nonceAttempts: [0, 1],
  required: true,
}));

const CASES = [...REGRESSION_CASES, ...COMPARISON_CASES, DETERMINISTIC_CASE, ...DEFAULT_CASES];
const BENCHMARK_CASES = [...DEFAULT_CASES, ...COMPARISON_CASES];

const parseArgs = (argv) => {
  const options = {
    output: "",
    samples: Number(process.env.CALIBRATION_SAMPLES || DEFAULT_SAMPLES),
    profile: process.env.CALIBRATION_PROFILE || "docker-cpus-1",
    timeoutMs: Number(process.env.CALIBRATION_TIMEOUT_MS || DEFAULT_TIMEOUT_MS),
    only: String(process.env.CALIBRATION_ONLY || "").split(",").map((value) => value.trim()).filter(Boolean),
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--output") options.output = argv[++i] || "";
    else if (arg === "--samples") options.samples = Number(argv[++i]);
    else if (arg === "--profile") options.profile = argv[++i] || options.profile;
    else if (arg === "--timeout-ms") options.timeoutMs = Number(argv[++i]);
    else if (arg === "--only") options.only = String(argv[++i] || "").split(",").map((value) => value.trim()).filter(Boolean);
    else if (arg === "--help" || arg === "-h") {
      console.log("Usage: node scripts/benchmark-calibration.mjs [--samples N] [--profile NAME] [--only IDS] [--output FILE]");
      process.exit(0);
    } else {
      throw new Error(`unknown option: ${arg}`);
    }
  }
  if (!Number.isSafeInteger(options.samples) || options.samples < 1 || options.samples > 100) {
    throw new Error("--samples must be an integer in [1, 100]");
  }
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 10_000) {
    throw new Error("--timeout-ms must be an integer >= 10000");
  }
  return options;
};

const configFor = (item) => ({
  POW_TOKEN: SECRET,
  powcheck: true,
  turncheck: false,
  POW_EQ_N: item.n,
  POW_EQ_K: item.k,
  POW_API_PREFIX: "/__pow",
  POW_GLUE_URL: "/glue.js",
  POW_ESM_URL: "/esm/esm.js",
  POW_TICKET_TTL_SEC: 180,
  PROOF_TTL_SEC: 180,
  POW_BIND_PATH: false,
  POW_BIND_IPRANGE: false,
  POW_BIND_COUNTRY: false,
  POW_BIND_ASN: false,
  POW_BIND_TLS: false,
});

const makeCompiledConfig = () => CASES.map((item) => ({
  host: { kind: "eq", value: HOST },
  hostType: "exact",
  hostExact: HOST,
  path: { kind: "eq", value: `/calibration/${item.id}` },
  pathType: "exact",
  pathExact: `/calibration/${item.id}`,
  config: configFor(item),
}));

const fixtureBindings = () => ({
  host: HOST,
  pathHash: "any",
  ipScope: "any",
  country: "any",
  asn: "any",
  tlsFingerprint: "any",
});

const nonceForAttempt = (attempt) => {
  const nonce = new Uint8Array(24);
  new DataView(nonce.buffer).setUint32(20, attempt, false);
  return nonce;
};

const workerRowsFor = (n, k) => {
  const density = 2 ** (n / (k + 1) + 1);
  const budgetRows = Math.max(1, Math.floor((64 * 1024 * 1024) / (Math.ceil(n / 8) + 256)));
  return Math.max(2 ** k, Math.min(density, budgetRows));
};

const solveWithFixedNonces = async (wasmBytes, { ticket, seed, rows }) => {
  const { instance } = await WebAssembly.instantiate(wasmBytes, {});
  const exports = instance.exports;
  const proofLength = Number(exports.required_proof_len(ticket.k));
  const seedPtr = Number(exports.alloc(seed.length, 8));
  const nonce = new Uint8Array(24);
  const noncePtr = Number(exports.alloc(nonce.length, 8));
  const proofPtr = Number(exports.alloc(proofLength, 8));
  const nonceSequence = [];
  try {
    for (let attempt = 0; attempt < 128; attempt += 1) {
      nonce.set(nonceForAttempt(attempt));
      nonceSequence.push(nonce.slice());
      let memory = new Uint8Array(exports.memory.buffer);
      memory.set(seed, seedPtr);
      memory.set(nonce, noncePtr);
      const result = Number(exports.solve_once(
        seedPtr,
        seed.length,
        noncePtr,
        nonce.length,
        ticket.n,
        ticket.k,
        rows,
        proofPtr,
        proofLength,
      ));
      if (result === proofLength) {
        memory = new Uint8Array(exports.memory.buffer);
        const proof = new Uint8Array(memory.subarray(proofPtr, proofPtr + result));
        return { nonce: nonce.slice(), proof, nonceSequence: nonceSequence.slice() };
      }
      if (result < 0) throw new Error(`fixed-nonce solver failed: ${result}`);
    }
    throw new Error("fixed-nonce solver produced no proof in 128 cases");
  } finally {
    exports.dealloc(proofPtr, proofLength, 8);
    exports.dealloc(noncePtr, nonce.length, 8);
    exports.dealloc(seedPtr, seed.length, 8);
  }
};

const makeLiveFixture = async (item) => {
  const caseIndex = CASES.indexOf(item);
  const r = Uint8Array.from({ length: 16 }, (_, index) => (17 * (caseIndex + 1) + index) & 0xff);
  const ticket = {
    v: 5,
    e: FIXED_NOW + 180,
    cfgId: item.cfgId ?? caseIndex,
    issuedAt: FIXED_NOW,
    r: base64UrlEncodeNoPad(r),
    n: item.n,
    k: item.k,
    m: 1,
    mac: "A".repeat(43),
  };
  ticket.mac = await makeTicketMac(SECRET, ticket, fixtureBindings());
  const ticketB64 = encodeV5Ticket(ticket);
  const seed = await deriveEquihashSeed({ ticketB64, pathHash: "any", captchaTag: "any" });
  const rows = item.rows || workerRowsFor(item.n, item.k);
  const nonceAttempts = Array.isArray(item.nonceAttempts) && item.nonceAttempts.length
    ? item.nonceAttempts
    : [0];
  return {
    ticketB64,
    challengeBytes: r,
    seedB64: base64UrlEncodeNoPad(seed),
    nonceSequence: nonceAttempts.map(nonceForAttempt),
    params: { n: ticket.n, k: ticket.k, rows },
  };
};

const solveDeterministicFixture = async (wasmBytes) => {
  const bindings = fixtureBindings();
  const ticket = {
    v: 5,
    e: FIXED_NOW + 600,
    cfgId: DETERMINISTIC_CASE.cfgId,
    issuedAt: FIXED_NOW,
    r: "AAECAwQFBgcICQoLDA0ODw",
    n: DETERMINISTIC_CASE.n,
    k: DETERMINISTIC_CASE.k,
    m: 1,
    mac: "A".repeat(43),
  };
  ticket.mac = await makeTicketMac(SECRET, ticket, bindings);
  const ticketB64 = encodeV5Ticket(ticket);
  const seed = await deriveEquihashSeed({ ticketB64, pathHash: "any", captchaTag: "any" });
  const solved = await solveWithFixedNonces(wasmBytes, { ticket, seed, rows: DETERMINISTIC_CASE.rows });
  return {
    ticketB64,
    seedB64: base64UrlEncodeNoPad(seed),
    nonceB64: base64UrlEncodeNoPad(solved.nonce),
    proofB64: base64UrlEncodeNoPad(solved.proof),
    attempt: solved.nonceSequence.length - 1,
    params: { n: ticket.n, k: ticket.k, rows: DETERMINISTIC_CASE.rows },
  };
};

const copyRuntime = async () => {
  const temp = await mkdtemp(join(tmpdir(), "equihash-calibration-"));
  await cp(join(ROOT, "lib"), join(temp, "lib"), { recursive: true });
  const template = await readFile(join(ROOT, "template.html"), "utf8");
  const compiled = JSON.stringify(makeCompiledConfig());
  const [configSource, core1Source, core2Source, glueSource] = await Promise.all([
    readFile(join(ROOT, "pow-config.js"), "utf8"),
    readFile(join(ROOT, "pow-core-1.js"), "utf8"),
    readFile(join(ROOT, "pow-core-2.js"), "utf8"),
    readFile(join(ROOT, "glue.js"), "utf8"),
  ]);
  await writeFile(
    join(temp, "pow-config.js"),
    configSource
      .replace(/__COMPILED_CONFIG__/gu, compiled)
      .replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${SECRET}";`),
  );
  await writeFile(
    join(temp, "pow-core-1.js"),
    core1Source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${SECRET}";`),
  );
  await writeFile(
    join(temp, "pow-core-2.js"),
    core2Source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${SECRET}";`),
  );
  await writeFile(join(temp, "glue.js"), glueSource);
  await writeFile(join(temp, "template.html"), template);
  const gatePath = join(temp, "lib", "pow", "business-gate.js");
  const gate = await readFile(gatePath, "utf8");
  await writeFile(gatePath, gate.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template)));
  const stamp = `${Date.now()}-${Math.random()}`;
  const [config, core1, core2] = await Promise.all([
    import(`${pathToFileURL(join(temp, "pow-config.js")).href}?v=${stamp}`),
    import(`${pathToFileURL(join(temp, "pow-core-1.js")).href}?v=${stamp}`),
    import(`${pathToFileURL(join(temp, "pow-core-2.js")).href}?v=${stamp}`),
  ]);
  return {
    temp,
    config: config.default.fetch,
    core1: core1.default.fetch,
    core2: core2.default.fetch,
  };
};

const readRequestBody = async (request) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks);
};

const responseHeaders = (response) => {
  const headers = {};
  for (const [name, value] of response.headers) headers[name] = value;
  const cookies = typeof response.headers.getSetCookie === "function"
    ? response.headers.getSetCookie()
    : [];
  if (cookies.length) headers["set-cookie"] = cookies;
  return headers;
};

const writeResponse = async (nodeResponse, response) => {
  nodeResponse.writeHead(response.status, response.statusText, responseHeaders(response));
  nodeResponse.end(Buffer.from(await response.arrayBuffer()));
};

const asset = async (root, pathname) => {
  const assets = new Map([
    ["/glue.js", ["glue.js", "text/javascript; charset=utf-8"]],
    ["/esm/esm.js", ["esm/esm.js", "text/javascript; charset=utf-8"]],
    ["/esm/equihash-worker.js", ["esm/equihash-worker.js", "text/javascript; charset=utf-8"]],
    ["/esm/solver.wasm", ["esm/solver.wasm", "application/wasm"]],
  ]);
  const item = assets.get(pathname);
  if (!item) return null;
  return {
    bytes: await readFile(join(root, item[0])),
    contentType: item[1],
  };
};

const loadPlaywright = async () => {
  const specifier = process.env.CALIBRATION_PLAYWRIGHT || "playwright";
  const importSpecifier = specifier.startsWith("/") || specifier.startsWith(".")
    ? pathToFileURL(resolve(specifier)).href
    : specifier;
  try {
    const module = await import(importSpecifier);
    return module.default || module;
  } catch (error) {
    const hint = "Install Playwright in the browser container and set CALIBRATION_PLAYWRIGHT to its index.js";
    throw new Error(`${hint}: ${error.message}`);
  }
};

const installFetchRouter = ({ config, core1, core2 }) => {
  const previous = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (request.headers.has("X-Pow-Transit")) return core2(request);
    if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) return core1(request);
    return new Response("origin", { status: 200, headers: { "content-type": "text/plain" } });
  };
  return () => { globalThis.fetch = previous; };
};

const startServer = async (runtime, records, fixtures) => {
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", `http://${HOST}`);
      const staticAsset = await asset(ROOT, url.pathname);
      if (staticAsset) {
        response.writeHead(200, {
          "cache-control": "public, max-age=3600",
          "content-type": staticAsset.contentType,
          "content-length": staticAsset.bytes.length,
        });
        response.end(staticAsset.bytes);
        return;
      }
      const body = await readRequestBody(request);
      const startedAt = performance.now();
      const nodeRequest = new Request(`http://${HOST}:${server.address().port}${url.pathname}${url.search}`, {
        method: request.method,
        headers: request.headers,
        body: body.length ? body : undefined,
      });
      const fixture = fixtures.get(url.pathname);
      const deterministicChallenge = Boolean(
        fixture &&
        request.method === "GET" &&
        !String(request.headers.cookie || "").includes("__Host-proof="),
      );
      let result;
      if (deterministicChallenge) {
        const previousDateNow = Date.now;
        const previousRandom = globalThis.crypto.getRandomValues;
        let offset = 0;
        Date.now = () => FIXED_NOW * 1000;
        globalThis.crypto.getRandomValues = (target) => {
          const bytes = target instanceof Uint8Array ? target : new Uint8Array(target.buffer, target.byteOffset, target.byteLength);
          for (let i = 0; i < bytes.length; i += 1) bytes[i] = fixture.challengeBytes[(offset + i) % fixture.challengeBytes.length];
          offset += bytes.length;
          return target;
        };
        try {
          result = await runtime.config(nodeRequest);
        } finally {
          Date.now = previousDateNow;
          globalThis.crypto.getRandomValues = previousRandom;
        }
      } else {
        result = await runtime.config(nodeRequest);
      }
      const elapsedMs = performance.now() - startedAt;
      if (url.pathname === "/__pow/verify") {
        let parsed = null;
        try { parsed = JSON.parse(body.toString("utf8")); } catch {}
        let responseBody = null;
        try { responseBody = await result.clone().json(); } catch {}
        let browserMetrics = null;
        try {
          browserMetrics = JSON.parse(String(request.headers["x-calibration-metrics"] || ""));
        } catch {}
        records.push({
          receivedAt: startedAt,
          ticketB64: parsed?.ticketB64 || "",
          pathHash: parsed?.pathHash || "",
          pow: parsed?.pow || null,
          status: result.status,
          response: responseBody,
          serverVerifyMs: elapsedMs,
          browserMetrics,
          completedAt: performance.now(),
        });
      }
      await writeResponse(response, result);
    } catch (error) {
      response.writeHead(500, { "content-type": "text/plain" });
      response.end(String(error && error.stack ? error.stack : error));
    }
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, HOST, resolvePromise);
  });
  return { server, url: `http://${HOST}:${server.address().port}` };
};

const verifyDeterministicFixture = async (runtime, baseUrl, wasmBytes) => {
  const fixture = await solveDeterministicFixture(wasmBytes);
  const response = await runtime.config(new Request(`${baseUrl}/__pow/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ticketB64: fixture.ticketB64,
      pathHash: "any",
      pow: { nonceB64: fixture.nonceB64, proofB64: fixture.proofB64 },
    }),
  }));
  let payload = null;
  try { payload = await response.json(); } catch {}
  return {
    ...fixture,
    serverStatus: response.status,
    serverResponse: payload,
    serverVerifiable: response.status === 200 && payload?.ok === true,
  };
};

const closeServer = async (server) => {
  if (!server) return;
  await new Promise((resolvePromise) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolvePromise();
    };
    server.close(finish);
    server.closeAllConnections?.();
    setTimeout(finish, 2000);
  });
};

const measureDefaultVerifier = async (runs) => {
  const run = runs.find((entry) => entry.success && entry.n === PUBLISHED_DEFAULT.n && entry.k === PUBLISHED_DEFAULT.k && entry.proof);
  if (!run) {
    return {
      available: false,
      reason: "no successful published-default proof was recorded",
      params: PUBLISHED_DEFAULT,
    };
  }
  const decode = (value) => Uint8Array.from(Buffer.from(value, "base64url"));
  const seed = await deriveEquihashSeed({ ticketB64: run.proof.ticketB64, pathHash: run.proof.pathHash, captchaTag: "any" });
  const input = {
    n: run.n,
    k: run.k,
    seed,
    nonce: decode(run.proof.nonceB64),
    proof: decode(run.proof.proofB64),
  };
  const verifierUrl = `${pathToFileURL(join(ROOT, "lib/equihash/verify.js")).href}?calibration=${Date.now()}-${Math.random()}`;
  const importStarted = performance.now();
  const verifier = await import(verifierUrl);
  const importMs = performance.now() - importStarted;
  const heapBeforeCold = process.memoryUsage().heapUsed;
  const coldStarted = performance.now();
  const coldOk = verifier.verifyEquihash(input);
  const coldMs = performance.now() - coldStarted;
  const heapAfterCold = process.memoryUsage().heapUsed;
  const warmMs = [];
  const warmCpuMs = [];
  const warmHeapDeltas = [];
  for (let i = 0; i < 20; i += 1) {
    if (typeof global.gc === "function") global.gc();
    const before = process.memoryUsage().heapUsed;
    const cpuBefore = process.cpuUsage();
    const started = performance.now();
    const ok = verifier.verifyEquihash(input);
    const elapsed = performance.now() - started;
    const cpu = process.cpuUsage(cpuBefore);
    if (!ok) throw new Error("default verifier rejected its own browser proof");
    warmMs.push(elapsed);
    warmCpuMs.push((cpu.user + cpu.system) / 1000);
    warmHeapDeltas.push(process.memoryUsage().heapUsed - before);
  }
  return {
    available: true,
    params: { n: run.n, k: run.k },
    proofBytes: decode(run.proof.proofB64).length,
    cold: { importMs: round(importMs), verifyMs: round(coldMs), ok: coldOk, heapDeltaBytes: heapAfterCold - heapBeforeCold },
    warm: {
      samples: warmMs.length,
      medianMs: round(median(warmMs)),
      p95Ms: round(percentile(warmMs, 0.95)),
      processCpuMs: {
        median: round(median(warmCpuMs)),
        p95: round(percentile(warmCpuMs, 0.95)),
        scope: "Node process CPU includes JIT and background threads; it is not a Cloudflare isolate CPU measurement",
      },
      maxHeapDeltaBytes: Math.max(...warmHeapDeltas),
    },
    snippetBudget: { cpuMs: 5, allocationBytes: 2 * 1024 * 1024 },
    localBudgetComparison: {
      warmP95WithinCpu: percentile(warmCpuMs, 0.95) <= 5,
      warmP95WallWithinGuidance: percentile(warmMs, 0.95) <= 5,
      warmMaxHeapWithinAllocation: Math.max(...warmHeapDeltas) <= 2 * 1024 * 1024,
      qualification: "Local Node CPU, wall, and heap measurements; Cloudflare deployment and isolate allocation were not measured",
    },
  };
};

const measureResourceProbe = async (wasmBytes, n, k) => {
  const rows = workerRowsFor(n, k);
  const { instance } = await WebAssembly.instantiate(wasmBytes, {});
  const exports = instance.exports;
  const seed = Uint8Array.from({ length: 32 }, (_, index) => (index + n + k) & 0xff);
  const proofLength = Number(exports.required_proof_len(k));
  const seedPtr = Number(exports.alloc(seed.length, 8));
  const noncePtr = Number(exports.alloc(24, 8));
  const proofPtr = Number(exports.alloc(proofLength, 8));
  const results = [];
  let peakWasmLinearMemoryBytes = exports.memory.buffer.byteLength;
  try {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const nonce = nonceForAttempt(attempt);
      let memory = new Uint8Array(exports.memory.buffer);
      memory.set(seed, seedPtr);
      memory.set(nonce, noncePtr);
      const started = performance.now();
      const result = Number(exports.solve_once(seedPtr, seed.length, noncePtr, nonce.length, n, k, rows, proofPtr, proofLength));
      peakWasmLinearMemoryBytes = Math.max(peakWasmLinearMemoryBytes, exports.memory.buffer.byteLength);
      results.push({ attempt, result, elapsedMs: round(performance.now() - started) });
      if (result < 0) break;
    }
  } finally {
    exports.dealloc(proofPtr, proofLength, 8);
    exports.dealloc(noncePtr, 24, 8);
    exports.dealloc(seedPtr, seed.length, 8);
  }
  return {
    n,
    k,
    proofLength,
    collisionBits: n / (k + 1),
    densityRows: 2 ** (n / (k + 1) + 1),
    selectedRows: rows,
    attempts: results,
    wasmLinearMemoryBytes: peakWasmLinearMemoryBytes,
    peakServerRssBytes: process.memoryUsage().rss,
    finding: results.some((entry) => entry.result === -2)
      ? "Rust MAX_WORKING_BYTES rejected this population"
      : results.some((entry) => entry.result === proofLength)
        ? "Fixed nonce probes produced valid proofs"
        : "No proof in eight fixed nonces; candidate effectiveness needs broader sampling",
  };
};

const addInstrumentation = async (page, nonceSequence) => {
  await page.addInitScript(({ fixedNonces }) => {
    const metrics = {
      startedMs: 0,
      tokenReadyMs: 0,
      initSentMs: null,
      initDoneMs: null,
      solveSentMs: null,
      solveDoneMs: null,
      solveStatus: "",
      verifySentMs: null,
      verifyResponseParsedMs: null,
      glueCompletedMs: null,
      maxWasmMemoryBytes: null,
    };
    let glueCompletionObserved = false;
    const startedAtMs = performance.now();
    const elapsedMs = () => performance.now() - startedAtMs;
    const recordGlueCompletion = () => {
      if (metrics.verifyResponseParsedMs === null || glueCompletionObserved) return;
      const status = document.getElementById("t");
      if (status?.dataset?.state !== "success") return;
      metrics.glueCompletedMs = elapsedMs();
      glueCompletionObserved = true;
      if (typeof globalThis.__powCalibrationComplete === "function") {
        void globalThis.__powCalibrationComplete({ ...metrics });
      }
    };
    if (typeof MutationObserver === "function") {
      const observer = new MutationObserver(recordGlueCompletion);
      observer.observe(document, { subtree: true, attributes: true, attributeFilter: ["data-state"] });
      recordGlueCompletion();
    }
    globalThis.__powCalibration = metrics;
    const NativeWorker = globalThis.Worker;
    if (typeof NativeWorker === "function") {
      globalThis.Worker = class CalibrationWorker extends NativeWorker {
        postMessage(message, transfer) {
          const type = message && message.type;
          if (metrics.glueCompletedMs === null) {
            if (type === "INIT") metrics.initSentMs = elapsedMs();
            if (type === "SOLVE") metrics.solveSentMs = elapsedMs();
          }
          const nextMessage = type === "SOLVE" && fixedNonces.length
            ? { ...message, nonceSequence: fixedNonces.map((value) => Uint8Array.from(value)) }
            : message;
          return super.postMessage(nextMessage, transfer);
        }

        constructor(...args) {
          super(...args);
          this.addEventListener("message", (event) => {
            const data = event && event.data;
            if (!data) return;
            if (metrics.glueCompletedMs !== null) return;
            if (data.type === "PROGRESS" && Number.isFinite(data.wasmMemoryBytes)) {
              metrics.maxWasmMemoryBytes = Math.max(metrics.maxWasmMemoryBytes || 0, data.wasmMemoryBytes);
              return;
            }
            if (data.type !== "OK") return;
            if (metrics.initSentMs !== null && metrics.initDoneMs === null && metrics.solveSentMs === null) {
              metrics.initDoneMs = elapsedMs();
            }
            if (data.status) {
              metrics.solveStatus = String(data.status);
              if (metrics.solveDoneMs === null && ["solved", "timeout", "cancelled", "fatal"].includes(data.status)) {
                metrics.solveDoneMs = elapsedMs();
              }
            }
          });
        }
      };
    }
    const nativeFetch = globalThis.fetch;
    if (typeof nativeFetch === "function") {
      globalThis.fetch = async (...args) => {
        const requestUrl = String(args[0]?.url || args[0] || "");
        if (requestUrl.includes("/__pow/verify")) {
          if (metrics.glueCompletedMs === null) metrics.verifySentMs = elapsedMs();
          const init = args[1] || {};
          const headers = new Headers(init.headers || {});
          headers.set("X-Calibration-Metrics", JSON.stringify(metrics));
          const response = await nativeFetch(args[0], { ...init, headers });
          if (response && typeof response.json === "function") {
            const json = response.json.bind(response);
            response.json = async (...jsonArgs) => {
              const parsed = await json(...jsonArgs);
              if (metrics.glueCompletedMs === null) {
                metrics.verifyResponseParsedMs = elapsedMs();
                recordGlueCompletion();
              }
              return parsed;
            };
          }
          return response;
        }
        return nativeFetch(...args);
      };
    }
  }, { fixedNonces: nonceSequence.map((nonce) => Array.from(nonce)) });
};

const percentile = (values, p) => {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1));
  return sorted[index];
};

const median = (values) => {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

const round = (value) => Number.isFinite(value) ? Number(value.toFixed(2)) : null;

const summarize = (runs) => {
  const success = runs.filter((run) => run.success).length;
  const expiries = runs.filter((run) => run.status === "timeout" || run.status === "stale").length;
  const fatals = runs.filter((run) => run.status === "fatal" || run.status === "error").length;
  const metric = (name) => ({
    medianMs: round(median(runs.map((run) => run.timings?.[name]))),
    p95Ms: round(percentile(runs.map((run) => run.timings?.[name]), 0.95)),
  });
  return {
    samples: runs.length,
    success,
    expiry: expiries,
    fatal: fatals,
    acquisition: metric("acquisitionMs"),
    initialization: metric("initializationMs"),
    solve: metric("solveMs"),
    postToken: metric("postTokenMs"),
    verifyResponseParse: metric("verifyResponseParseMs"),
    fullPostToken: metric("fullPostTokenMs"),
    serverVerify: metric("serverVerifyMs"),
    memory: {
      wasmLinearMemoryBytes: { median: median(runs.map((run) => run.memory?.wasmLinearMemoryBytes)), p95: percentile(runs.map((run) => run.memory?.wasmLinearMemoryBytes), 0.95) },
      pageHeapUsedBytes: { median: median(runs.map((run) => run.memory?.pageHeapUsedBytes)), p95: percentile(runs.map((run) => run.memory?.pageHeapUsedBytes), 0.95) },
      serverRssBytes: { median: median(runs.map((run) => run.memory?.serverRssBytes)), p95: percentile(runs.map((run) => run.memory?.serverRssBytes), 0.95) },
    },
  };
};

const runCase = async ({ browserContext, baseUrl, item, sample, records, fixtures, timeoutMs }) => {
  const fixture = fixtures.get(`/calibration/${item.id}`);
  await browserContext.clearCookies();
  const page = await browserContext.newPage();
  let completionMetrics = null;
  await page.exposeFunction("__powCalibrationComplete", (value) => {
    if (value && typeof value === "object") completionMetrics = value;
  });
  await addInstrumentation(page, fixture.nonceSequence);
  const assetRequests = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname === "/glue.js" || url.pathname.startsWith("/esm/")) {
      assetRequests.push({ path: url.pathname, startMs: performance.now(), endMs: null, fromCache: false });
    }
  });
  page.on("response", (response) => {
    const url = new URL(response.url());
    const entry = assetRequests.find((candidate) => candidate.path === url.pathname && candidate.endMs === null);
    if (entry) entry.endMs = performance.now();
  });
  const target = `${baseUrl}/calibration/${item.id}`;
  const recordStart = records.length;
  let navigationStatus = 0;
  let navigationError = "";
  try {
    const navigation = await page.goto(target, { waitUntil: "domcontentloaded", timeout: timeoutMs });
    navigationStatus = navigation?.status() || 0;
  } catch (error) {
    navigationError = String(error?.message || error);
  }
  const deadline = performance.now() + timeoutMs;
  while (records.length === recordStart && performance.now() < deadline) {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  const serverRecord = records[recordStart] || null;
  if (serverRecord) {
    while (!completionMetrics && performance.now() < deadline) {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
    }
  }
  const clientCompletion = completionMetrics;
  const pageDiagnostics = clientCompletion ? null : await page.evaluate(() => ({
    solveStatus: globalThis.__powCalibration?.solveStatus || "",
    state: document.getElementById("t")?.dataset?.state || "",
  })).catch(() => null);
  const metrics = { ...(serverRecord?.browserMetrics || {}), ...(clientCompletion || {}) };
  if (!clientCompletion && pageDiagnostics?.solveStatus) metrics.solveStatus = pageDiagnostics.solveStatus;
  const pageMemory = await page.evaluate(() => {
    const memory = performance.memory;
    return memory ? { used: memory.usedJSHeapSize, total: memory.totalJSHeapSize } : { used: null, total: null };
  }).catch(() => ({ used: null, total: null }));
  await page.close();

  const timestamp = (value) => Number.isFinite(value) ? value : null;
  const elapsed = (end, start) => Number.isFinite(end) && Number.isFinite(start) ? end - start : null;
  const solveDone = timestamp(metrics?.solveDoneMs);
  const solveSent = timestamp(metrics?.solveSentMs);
  const initDone = timestamp(metrics?.initDoneMs);
  const initSent = timestamp(metrics?.initSentMs);
  const started = timestamp(metrics?.startedMs);
  const tokenReady = timestamp(metrics?.tokenReadyMs ?? metrics?.startedMs);
  const verifySent = timestamp(metrics?.verifySentMs);
  const verifyParsed = timestamp(metrics?.verifyResponseParsedMs);
  const glueCompleted = timestamp(metrics?.glueCompletedMs);
  const timings = {
    acquisitionMs: elapsed(initSent, started),
    initializationMs: elapsed(initDone, initSent),
    solveMs: elapsed(solveDone, solveSent),
    postTokenMs: elapsed(verifySent, solveDone),
    verifyResponseParseMs: elapsed(verifyParsed, verifySent),
    fullPostTokenMs: elapsed(glueCompleted, tokenReady),
    serverVerifyMs: serverRecord?.serverVerifyMs ?? null,
    totalMs: elapsed(glueCompleted, started),
  };
  const expectedNonceSequence = fixture.nonceSequence.map((nonce) => base64UrlEncodeNoPad(nonce));
  const proofAttempt = expectedNonceSequence.indexOf(serverRecord?.pow?.nonceB64 || "");
  const expectedMatch = Boolean(
    serverRecord?.status === 200 &&
    serverRecord?.response?.ok === true &&
    serverRecord.ticketB64 === fixture.ticketB64 &&
    proofAttempt >= 0 &&
    typeof serverRecord.pow?.proofB64 === "string" &&
    serverRecord.pow.proofB64,
  );
  const status = serverRecord?.status === 200 && serverRecord?.response?.ok === true
    && serverRecord.ticketB64 === fixture.ticketB64
    && proofAttempt >= 0
    && serverRecord.pow?.proofB64
    && clientCompletion?.glueCompletedMs !== undefined
    && Number.isFinite(clientCompletion.glueCompletedMs)
    ? "success"
    : metrics?.solveStatus === "timeout" ? "timeout"
      : metrics?.solveStatus === "fatal" ? "fatal"
        : pageDiagnostics?.state === "error" || navigationError ? "error" : "stale";
  const success = status === "success";
  return {
    sample,
    id: item.id,
    n: item.n,
    k: item.k,
    required: item.required,
    input: {
      route: `/calibration/${item.id}`,
      case: item.id,
      deterministic: true,
      seedB64: fixture.seedB64,
      nonceSequenceB64: fixture.nonceSequence.map((nonce) => base64UrlEncodeNoPad(nonce)),
    },
    proof: serverRecord ? {
      ticketB64: serverRecord.ticketB64,
      pathHash: serverRecord.pathHash,
      nonceB64: serverRecord.pow?.nonceB64 || "",
      proofB64: serverRecord.pow?.proofB64 || "",
      serverStatus: serverRecord.status,
      serverResponse: serverRecord.response,
      attempt: proofAttempt,
      expectedMatch,
    } : null,
    status,
    success,
    timings: Object.fromEntries(Object.entries(timings).map(([key, value]) => [key, round(value)])),
    memory: {
      wasmLinearMemoryBytes: metrics?.maxWasmMemoryBytes ?? null,
      pageHeapUsedBytes: pageMemory.used,
      pageHeapTotalBytes: pageMemory.total,
      serverRssBytes: process.memoryUsage().rss,
    },
    assets: {
      condition: sample === 1 && item.id === BENCHMARK_CASES[0].id ? "cold" : "warm",
      requested: assetRequests.map((entry) => ({ path: entry.path, durationMs: round(entry.endMs === null ? null : entry.endMs - entry.startMs) })),
    },
    worker: metrics,
    navigationStatus,
    navigationError,
  };
};

const main = async () => {
  const options = parseArgs(process.argv.slice(2));
  const activeCases = options.only.length ? CASES.filter((item) => options.only.includes(item.id)) : BENCHMARK_CASES;
  if (!activeCases.length) throw new Error("--only did not select a known calibration case");
  const runtime = await copyRuntime();
  const records = [];
  const restoreFetch = installFetchRouter(runtime);
  const wasmBytes = new Uint8Array(await readFile(join(ROOT, "esm", "solver.wasm")));
  const liveFixtures = new Map();
  for (const item of activeCases) {
    console.error(`[calibration] fixed fixture ${item.id}`);
    const fixture = await makeLiveFixture(item);
    liveFixtures.set(`/calibration/${item.id}`, fixture);
  }
  let server = null;
  let browser = null;
  let context = null;
  let deterministic = null;
  let browserVersion = "unknown";
  const runs = [];
  try {
    const startedServer = await startServer(runtime, records, liveFixtures);
    server = startedServer.server;
    const baseUrl = startedServer.url;
    deterministic = await verifyDeterministicFixture(runtime, baseUrl, wasmBytes);
    const playwright = await loadPlaywright();
    browser = await playwright.chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
    browserVersion = browser.version();
    context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    for (let sample = 1; sample <= options.samples; sample += 1) {
      for (const item of activeCases) {
        console.error(`[calibration] ${options.profile} sample ${sample}/${options.samples} ${item.id}`);
        runs.push(await runCase({ browserContext: context, baseUrl, item, sample, records, fixtures: liveFixtures, timeoutMs: options.timeoutMs }));
      }
    }
  } finally {
    try { await context?.close(); } catch {}
    try { await browser?.close(); } catch {}
    await closeServer(server);
    restoreFetch();
    await rm(runtime.temp, { recursive: true, force: true });
  }

  const summaries = Object.fromEntries(activeCases.map((item) => [
    item.id,
    summarize(runs.filter((run) => run.id === item.id)),
  ]));
  const defaultRuns = runs.filter((run) => run.n === PUBLISHED_DEFAULT.n && run.k === PUBLISHED_DEFAULT.k);
  const pairRuns = new Map();
  for (const run of runs) {
    const key = `${run.n}/${run.k}`;
    pairRuns.set(key, [...(pairRuns.get(key) || []), run]);
  }
  const verifier = await measureDefaultVerifier(runs);
  const resourceProbes = [];
  for (const [n, k] of [[102, 5], [108, 5]]) {
    resourceProbes.push(await measureResourceProbe(wasmBytes, n, k));
  }
  const requiredFailures = runs.filter((run) => run.required && !run.success);
  const nonDefaultRequired = activeCases.some((item) => item.n !== PUBLISHED_DEFAULT.n || item.k !== PUBLISHED_DEFAULT.k);
  const defaultRequired = activeCases.some((item) => item.required && item.n === PUBLISHED_DEFAULT.n && item.k === PUBLISHED_DEFAULT.k);
  const output = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    profile: options.profile,
    publishedDefault: PUBLISHED_DEFAULT,
    target: { desktopMs: 3000, mobileMs: 15000 },
    environment: {
      host: os.hostname(),
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpuModel: os.cpus()[0]?.model || "unknown",
      logicalCpus: os.cpus().length,
      totalMemoryBytes: os.totalmem(),
      browser: browserVersion,
      browserImage: "mcr.microsoft.com/playwright:v1.49.1-noble",
      browserEngine: "Chromium 131 (image-pinned)",
      proxy: options.profile.includes("cpus-0.2")
        ? "Docker whole-container CPU quota 0.2; validated slowdown proxy, not a phone measurement"
        : "Docker whole-container CPU quota 1; desktop/container measurement, not a phone measurement",
    },
    cases: activeCases,
    deterministicCases: [deterministic],
    verifier,
    resourceProbes,
    publishedDefaultDistribution: summarize(defaultRuns),
    pairDistributions: Object.fromEntries([...pairRuns].map(([key, values]) => [key, summarize(values)])),
    summaries,
    runs,
    acceptance: {
      requiredCases: activeCases.filter((item) => item.required).map((item) => item.id),
      requiredFailures: requiredFailures.map((run) => ({ id: run.id, sample: run.sample, status: run.status })),
      serverVerifiableProofs: runs.filter((run) => run.success).length,
      nonDefaultProofs: runs.filter((run) => run.success && (run.n !== PUBLISHED_DEFAULT.n || run.k !== PUBLISHED_DEFAULT.k)).length,
      nonDefaultRequired,
      defaultRequired,
      defaultVerifierAvailable: verifier.available,
      defaultVerifierReason: verifier.available ? null : verifier.reason,
      deterministicFailures: deterministic.serverVerifiable ? [] : [DETERMINISTIC_CASE.id],
    },
  };
  const json = `${JSON.stringify(output, null, 2)}\n`;
  if (options.output) await writeFile(resolve(options.output), json);
  console.log(json);
  if (requiredFailures.length || (defaultRequired && !verifier.available) || (nonDefaultRequired && output.acceptance.nonDefaultProofs === 0) || output.acceptance.deterministicFailures.length) {
    throw new Error(requiredFailures.length
      ? `required deterministic calibration cases failed: ${requiredFailures.map((run) => `${run.id}#${run.sample}`).join(", ")}`
      : defaultRequired && !verifier.available
        ? `default verifier measurement unavailable: ${verifier.reason}`
        : output.acceptance.deterministicFailures.length
        ? "deterministic shipped-WASM fixture failed server verification"
        : "no required nondefault operator pair produced a server-verifiable proof");
  }
};

main().catch((error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
