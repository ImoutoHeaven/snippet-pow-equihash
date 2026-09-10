import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const b64 = (value) => Buffer.from(String(value), "utf8").toString("base64url");
const captcha = b64(JSON.stringify({ turnstile: { sitekey: "sitekey" } }));
const ticket = b64(`5.1700000600.1.1700000000.AQIDBAUGBwgJCgsMDQ4PEA.12.2.2.${"A".repeat(43)}`);
const bootstrap = b64(JSON.stringify({ ticketB64: ticket, pathHash: "pathhash", apiPrefix: "/__pow", eq: { n: 12, k: 2 }, issuedAt: 1700000000, expireAt: 1700000600, mask: 2 }));

const setupDom = ({ onScriptAppend, clock, timers } = {}) => {
  const previous = {
    DateNow: Date.now,
    performance: globalThis.performance,
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    document: globalThis.document,
    window: globalThis.window,
    requestAnimationFrame: globalThis.requestAnimationFrame,
    clearAnimationFrame: globalThis.cancelAnimationFrame,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    navigator: Object.getOwnPropertyDescriptor(globalThis, "navigator"),
  };
  const elements = new Map();
  const windowListeners = new Map();
  const documentListeners = new Map();
  const addListener = (listeners, type, callback) => {
    listeners.set(type, [...(listeners.get(type) || []), callback]);
  };
  const removeListener = (listeners, type, callback) => {
    const callbacks = listeners.get(type) || [];
    listeners.set(type, callbacks.filter((entry) => entry !== callback));
  };
  const dispatch = (listeners, type, event = {}) => {
    for (const callback of listeners.get(type) || []) callback({ type, ...event });
  };
  const makeElement = (tag = "div") => {
    const classes = new Set();
    return {
    tagName: tag,
    style: { setProperty() {} },
    classList: {
      add(...names) { for (const name of names) classes.add(name); },
      remove(...names) { for (const name of names) classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    appendChild(child) {
      if (tag === "head" && typeof onScriptAppend === "function") onScriptAppend(child);
      else this.innerHTML = child;
    },
    addEventListener() {},
    remove() {},
    innerHTML: "",
    textContent: "",
    offsetHeight: 0,
    };
  };
  const getElementById = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
  };
  const head = makeElement("head");
  globalThis.document = {
    title: "",
    hidden: false,
    head,
    documentElement: makeElement("html"),
    body: makeElement("body"),
    createElement: (tag) => makeElement(tag),
    getElementById,
    querySelectorAll: () => [],
    addEventListener(type, callback) { addListener(documentListeners, type, callback); },
    removeEventListener(type, callback) { removeListener(documentListeners, type, callback); },
  };
  const session = new Map();
  globalThis.window = {
    location: { href: "https://example.com/protected", replace() {}, reload() {} },
    parent: null,
    opener: null,
    innerWidth: 1200,
    innerHeight: 800,
    addEventListener(type, callback) { addListener(windowListeners, type, callback); },
    removeEventListener(type, callback) { removeListener(windowListeners, type, callback); },
    sessionStorage: {
      getItem(key) { return session.get(key) || null; },
      setItem(key, value) { session.set(String(key), String(value)); },
      removeItem(key) { session.delete(String(key)); },
      clear() { session.clear(); },
    },
  };
  globalThis.window.parent = globalThis.window;
  Object.defineProperty(globalThis, "navigator", {
    value: { languages: ["en-US"], language: "en-US" },
    configurable: true,
  });
  const dispatchWindow = (type, event) => dispatch(windowListeners, type, event);
  const dispatchDocument = (type, event) => dispatch(documentListeners, type, event);
  if (clock) {
    Date.now = () => clock.wallMs;
    Object.defineProperty(globalThis, "performance", { value: { now: () => clock.monoMs }, configurable: true });
  }
  globalThis.requestAnimationFrame = () => 0;
  globalThis.cancelAnimationFrame = () => {};
  globalThis.setTimeout = (fn) => {
    if (typeof fn === "function") queueMicrotask(fn);
    return 0;
  };
  globalThis.clearTimeout = () => {};
  if (timers) {
    globalThis.setTimeout = (fn, delay) => {
      const timer = { fn, delay, cleared: false };
      timers.timeouts.push(timer);
      return timer;
    };
    globalThis.clearTimeout = (timer) => {
      if (timer) timer.cleared = true;
    };
    globalThis.setInterval = (fn, delay) => {
      const timer = { fn, delay, cleared: false };
      timers.intervals.push(timer);
      return timer;
    };
    globalThis.clearInterval = (timer) => {
      if (timer) timer.cleared = true;
    };
  }
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  if (!globalThis.crypto) Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  return {
    elements,
    dispatchWindow,
    dispatchDocument,
    restore() {
      Date.now = previous.DateNow;
      Object.defineProperty(globalThis, "performance", { value: previous.performance, configurable: true });
      globalThis.setTimeout = previous.setTimeout;
      globalThis.clearTimeout = previous.clearTimeout;
      globalThis.setInterval = previous.setInterval;
      globalThis.clearInterval = previous.clearInterval;
      globalThis.document = previous.document;
      globalThis.window = previous.window;
      globalThis.requestAnimationFrame = previous.requestAnimationFrame;
      globalThis.cancelAnimationFrame = previous.clearAnimationFrame;
      globalThis.atob = previous.atob;
      globalThis.btoa = previous.btoa;
      if (previous.navigator) Object.defineProperty(globalThis, "navigator", previous.navigator);
      else delete globalThis.navigator;
    },
  };
};

const loadGlue = async (domOptions) => {
  setupDom(domOptions);
  return import(`${pathToFileURL(join(root, "glue.js")).href}?v=${Date.now()}-${Math.random()}`);
};

const loadGlueWithDom = async (domOptions) => {
  const dom = setupDom(domOptions);
  const glue = await import(`${pathToFileURL(join(root, "glue.js")).href}?v=${Date.now()}-${Math.random()}`);
  return { glue, dom };
};

const args = (overrides = {}) => [
  overrides.bootstrapB64 || bootstrap,
  overrides.bindingB64 || b64("binding"),
  overrides.reloadUrlB64 || b64("https://example.com/protected"),
  overrides.esmUrlB64 === undefined ? "" : overrides.esmUrlB64,
  overrides.captchaCfgB64 === undefined ? captcha : overrides.captchaCfgB64,
  overrides.atomicCfg || "0",
];

const powEsm = (workerUrl = "https://example.com/worker.js") =>
  b64(`data:text/javascript,${encodeURIComponent(`export const workerUrl=${JSON.stringify(workerUrl)};export const solverUrl="https://example.com/solver.wasm";`)}`);

const powBootstrap = (wallMs, ttlSec) => {
  const issuedAt = Math.floor(wallMs / 1000);
  const ticketB64 = b64(`5.${issuedAt + ttlSec}.1.${issuedAt}.AAECAwQFBgcICQoLDA0ODw.12.2.1.${"A".repeat(43)}`);
  return b64(JSON.stringify({
    ticketB64,
    pathHash: "pathhash",
    apiPrefix: "/__pow",
    eq: { n: 12, k: 2 },
    issuedAt,
    expireAt: issuedAt + ttlSec,
    mask: 1,
  }));
};

const flush = async (turns = 128) => {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

const flushUntil = async (condition, turns = 10000) => {
  for (let i = 0; i < turns && !condition(); i += 1) await new Promise((resolve) => setImmediate(resolve));
};

const makeTurnstile = ({ token = "turnstile-token-1234567890", auto = true, onOptions } = {}) => {
  let active = false;
  let removed = 0;
  let options = null;
  return {
    get options() { return options; },
    get removed() { return removed; },
    render: (_el, nextOptions) => {
      active = true;
      options = {
        ...nextOptions,
        callback: (...values) => active && nextOptions.callback(...values),
        "expired-callback": (...values) => active && nextOptions["expired-callback"](...values),
        "error-callback": (...values) => active && nextOptions["error-callback"](...values),
      };
      onOptions?.(options);
      if (auto) queueMicrotask(() => options.callback(token));
      return 1;
    },
    reset: () => { active = true; },
    remove: () => { active = false; removed += 1; },
  };
};

test("glue keeps bounded hint routing and no-worker Turnstile entry", { concurrency: 1 }, async (t) => {
  await t.test("stale and empty 403 hints reload while cheat hard-fails", async () => {
    const glue = await loadGlue();
    assert.deepEqual(glue.routeHintAction({ status: 403, hint: "stale" }), { action: "reload", bounded: true });
    assert.deepEqual(glue.routeHintAction({ status: 403, hint: null }), { action: "reload", bounded: true });
    assert.deepEqual(glue.routeHintAction({ status: 403, hint: "cheat" }), { action: "hard_fail", bounded: false });
    assert.deepEqual(glue.routeHintAction({ status: 500, hint: "stale" }), { action: "hard_fail", bounded: false });
  });

  await t.test("Turnstile script failure can be retried", async () => {
    let scripts = 0;
    const glue = await loadGlue({ onScriptAppend: (element) => {
      if (element.tagName === "script") {
        scripts += 1;
        queueMicrotask(() => element.onerror && element.onerror());
      }
    } });
    await glue.default(...args({ atomicCfg: "1" }));
    await glue.default(...args({ atomicCfg: "1" }));
    assert.equal(scripts, 2);
  });

  await t.test("Turnstile-only flow posts the canonical envelope and never creates a Worker", async () => {
    let solve;
    let removed = 0;
    let workerCount = 0;
    const glue = await loadGlue();
    globalThis.Worker = class FakeWorker {
      constructor() { workerCount += 1; }
    };
    globalThis.window.turnstile = {
      render: (_el, options) => { solve = options.callback; return 1; },
      remove() { removed += 1; },
      reset() {},
    };
    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: JSON.parse(init.body) });
      return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
    };
    const run = glue.default(...args());
    await new Promise((resolve) => queueMicrotask(resolve));
    assert.equal(typeof solve, "function");
    solve("turnstile-token-1234567890");
    await run;
    assert.equal(workerCount, 0);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "/__pow/verify");
    assert.deepEqual(JSON.parse(calls[0].body.captchaToken), { turnstile: "turnstile-token-1234567890" });
    assert.equal(removed, 1);
  });

  await t.test("Turnstile-only atomic flow sends its ticket and token directly", async () => {
    let solve;
    let requests = 0;
    let redirect = "";
    const glue = await loadGlue();
    globalThis.window.location.replace = (value) => { redirect = String(value); };
    globalThis.window.turnstile = {
      render: (_el, options) => { solve = options.callback; return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => {
      requests += 1;
      throw new Error("atomic Turnstile should not call /verify");
    };
    const run = glue.default(...args({ atomicCfg: "1|__ts|__tt|__ct|x-turnstile|x-ticket|x-consume|__Secure-pow_a" }));
    await new Promise((resolve) => queueMicrotask(resolve));
    solve("turnstile-token-1234567890");
    await run;
    assert.equal(requests, 0);
    assert.equal(redirect, "https://example.com/protected");
  });

  await t.test("PoW flow uses the Worker ABI and posts one compact proof", async () => {
    const glue = await loadGlue();
    const now = Math.floor(Date.now() / 1000);
    const powTicket = b64(`5.${now + 60}.1.${now}.AAECAwQFBgcICQoLDA0ODw.12.2.1.${"A".repeat(43)}`);
    const powBootstrap = b64(JSON.stringify({ ticketB64: powTicket, pathHash: "pathhash", apiPrefix: "/__pow", eq: { n: 12, k: 2 }, issuedAt: now, expireAt: now + 60, mask: 1 }));
    const esm = b64(`data:text/javascript,${encodeURIComponent('export const workerUrl="https://example.com/worker.js";export const solverUrl="https://example.com/solver.wasm";')}`);
    const nonceB64 = b64("nonce");
    const proofB64 = b64("proof-proof-proof");
    let workerCount = 0;
    let verifyBody = null;
    globalThis.Worker = class FakeWorker {
      constructor() { workerCount += 1; this.listeners = new Map(); }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      postMessage(message) {
        if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        if (message.type === "SOLVE") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid, status: "solved", nonceB64, proofB64 }));
      }
      terminate() {}
    };
    globalThis.fetch = async (url, init) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(8) };
      if (String(url) === "/__pow/verify") {
        verifyBody = JSON.parse(init.body);
        return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
      }
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    await glue.default(...args({ bootstrapB64: powBootstrap, bindingB64: b64("binding"), esmUrlB64: esm, captchaCfgB64: b64("{}") }));
    assert.equal(workerCount, 1);
    assert.deepEqual(verifyBody.pow, { nonceB64, proofB64 });
  });

  await t.test("same-origin embedded atomic flow posts only to the parent", async () => {
    const posts = [];
    const glue = await loadGlue();
    globalThis.window.parent = {
      closed: false,
      location: { href: "https://example.com/outer" },
      postMessage(message, origin) { posts.push({ message, origin }); },
    };
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) });
    await glue.default(...args({ atomicCfg: "1|__ts|__tt|__ct|x-turnstile|x-ticket|x-consume|__Secure-pow_a" }));
    assert.equal(posts.length, 1);
    assert.equal(posts[0].origin, "https://example.com");
    assert.equal(posts[0].message.type, "POW_ATOMIC");
    assert.equal(posts[0].message.mode, "turn");
  });

  await t.test("network errors replay the same body with bounded retries", async () => {
    let attempts = 0;
    const bodies = [];
    const glue = await loadGlue();
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async (_url, init) => {
      attempts += 1;
      bodies.push(init.body);
      if (attempts < 3) throw new TypeError("network reset");
      return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
    };
    await glue.default(...args());
    assert.equal(attempts, 3);
    assert.deepEqual(bodies, [bodies[0], bodies[0], bodies[0]]);
  });

  await t.test("stale responses refresh at most twice within the storage window", async () => {
    let reloads = 0;
    let attempts = 0;
    const glue = await loadGlue();
    globalThis.window.location.reload = () => { reloads += 1; };
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return { ok: false, status: 403, headers: { get: () => "stale" }, json: async () => ({ ok: true, mode: "proof" }) };
    };
    await glue.default(...args());
    await glue.default(...args());
    await glue.default(...args());
    assert.equal(attempts, 3);
    assert.equal(reloads, 2);
  });

  await t.test("Turnstile stays hidden until interaction is requested", async () => {
    let options = null;
    const glue = await loadGlue();
    const tsEl = globalThis.document.getElementById("ts");
    globalThis.window.turnstile = {
      render: (_el, nextOptions) => { options = nextOptions; return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) });
    const run = glue.default(...args());
    await new Promise((resolve) => queueMicrotask(resolve));
    assert.equal(typeof options, "object");
    assert.equal(options.appearance, "interaction-only");
    assert.equal(tsEl.classList.contains("show"), false);
    globalThis.requestAnimationFrame = (fn) => {
      if (typeof fn === "function") fn();
      return 0;
    };
    options["before-interactive-callback"]();
    assert.equal(tsEl.classList.contains("show"), true);
    options["after-interactive-callback"]();
    assert.equal(tsEl.classList.contains("show"), false);
    options.callback("turnstile-token-1234567890");
    await run;
  });

  await t.test("unavailable sessionStorage fails stale refresh closed", async () => {
    let reloads = 0;
    const glue = await loadGlue();
    globalThis.window.sessionStorage = undefined;
    globalThis.window.location.reload = () => { reloads += 1; };
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => ({ ok: false, status: 403, headers: { get: () => "stale" }, json: async () => ({ ok: true, mode: "proof" }) });
    await glue.default(...args());
    assert.equal(reloads, 0);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("sessionStorage quota errors fail stale refresh closed", async () => {
    let reloads = 0;
    const glue = await loadGlue();
    globalThis.window.sessionStorage = { getItem() { return null; }, setItem() { throw new Error("quota"); } };
    globalThis.window.location.reload = () => { reloads += 1; };
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => ({ ok: false, status: 403, headers: { get: () => "stale" }, json: async () => ({ ok: true, mode: "proof" }) });
    await glue.default(...args());
    assert.equal(reloads, 0);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("malformed refresh storage is recoverable", async () => {
    let reloads = 0;
    const glue = await loadGlue();
    globalThis.window.sessionStorage.setItem("__pow_stale_reload_v1", "broken");
    globalThis.window.location.reload = () => { reloads += 1; };
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => ({ ok: false, status: 403, headers: { get: () => "stale" }, json: async () => ({ ok: true, mode: "proof" }) });
    await glue.default(...args());
    assert.equal(reloads, 1);
  });

  await t.test("HTTP 500 is a hard failure and does not retry", async () => {
    let renders = 0;
    let attempts = 0;
    const glue = await loadGlue();
    globalThis.window.turnstile = {
      render: (_el, options) => { renders += 1; queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return { ok: false, status: 500, headers: { get: () => null }, json: async () => ({ ok: true, mode: "proof" }) };
    };
    await glue.default(...args());
    assert.equal(attempts, 1);
    assert.equal(renders, 1);
  });

  await t.test("Turnstile submit callback does not loop after a 403", async () => {
    let renders = 0;
    let attempts = 0;
    const glue = await loadGlue();
    globalThis.window.turnstile = {
      render: (_el, options) => { renders += 1; queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      return { ok: false, status: 403, headers: { get: () => "cheat" }, json: async () => ({ ok: true, mode: "proof" }) };
    };
    await glue.default(...args());
    assert.equal(attempts, 1);
    assert.equal(renders, 1);
  });

  await t.test("unknown 403 hints hard-fail without refresh", async () => {
    let reloads = 0;
    const glue = await loadGlue();
    globalThis.window.location.reload = () => { reloads += 1; };
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => ({ ok: false, status: 403, headers: { get: () => "unknown" }, json: async () => ({ ok: true, mode: "proof" }) });
    await glue.default(...args());
    assert.equal(reloads, 0);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("external request errors are escaped in the log", async () => {
    const glue = await loadGlue();
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => { throw new Error('<img src="x" onerror="alert(1)">'); };
    await glue.default(...args());
    const log = globalThis.document.getElementById("log").innerHTML;
    assert.match(log, /&lt;img/);
    assert.equal(log.includes("<img"), false);
  });

  await t.test("exhausted network retries end in a hard failure", async () => {
    let attempts = 0;
    const glue = await loadGlue();
    globalThis.window.turnstile = {
      render: (_el, options) => { queueMicrotask(() => options.callback("turnstile-token-1234567890")); return 1; },
      remove() {},
      reset() {},
    };
    globalThis.fetch = async () => {
      attempts += 1;
      throw new TypeError("network reset");
    };
    await glue.default(...args());
    assert.equal(attempts, 4);
    assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
  });

  await t.test("lifetime starts before acquisition and reserves time only for computation", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    let initBudget = null;
    let solveBudget = null;
    let verifyCalls = 0;
    class WorkerWithElapsedInit {
      constructor() { this.listeners = new Map(); }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      postMessage(message) {
        if (message.type === "INIT") {
          initBudget = message.solvePolicy.deadlineMs;
          clock.monoMs += 300;
          queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        }
        if (message.type === "SOLVE") {
          solveBudget = message.deadlineMs;
          queueMicrotask(() => this.emit({ type: "OK", rid: message.rid, status: "solved", nonceB64: b64("nonce"), proofB64: b64("proof") }));
        }
      }
      terminate() {}
    }
    const { glue, dom } = await loadGlueWithDom({ clock, timers });
    const turnstile = makeTurnstile({ auto: false });
    globalThis.window.turnstile = turnstile;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") {
        return { ok: true, arrayBuffer: async () => { clock.monoMs += 100; return new ArrayBuffer(8); } };
      }
      if (String(url) === "https://worker.example/worker.js") {
        return { ok: true, text: async () => { clock.monoMs += 50; return "worker"; } };
      }
      if (String(url) === "/__pow/verify") {
        verifyCalls += 1;
        return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
      }
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    globalThis.Worker = WorkerWithElapsedInit;
    try {
      const run = glue.default(
        powBootstrap(clock.wallMs, 20),
        b64("binding"),
        b64("https://example.com/protected"),
        powEsm("https://worker.example/worker.js"),
        captcha,
        "0",
      );
      await flushUntil(() => turnstile.options);
      clock.monoMs += 200;
      turnstile.options.callback("turnstile-token-1234567890");
      await run;
      assert.equal(initBudget, 18_200);
      assert.equal(solveBudget, 17_850);
      assert.equal(verifyCalls, 1);
      assert.equal(turnstile.removed, 1);
    } finally {
      dom.restore();
    }
  });

  await t.test("valid challenges remain usable after three, fifteen, and thirty seconds", async () => {
    for (const elapsedMs of [3000, 15000, 30000]) {
      const clock = { wallMs: 1700000000000, monoMs: 1000 };
      let verifyCalls = 0;
      class ElapsedWorker {
        constructor() { this.listeners = new Map(); }
        addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
        emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
        postMessage(message) {
          if (message.type === "INIT") {
            clock.monoMs += elapsedMs;
            queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
          }
          if (message.type === "SOLVE") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid, status: "solved", nonceB64: b64("nonce"), proofB64: b64("proof") }));
        }
        terminate() {}
      }
      const { glue, dom } = await loadGlueWithDom({ clock });
      globalThis.Worker = ElapsedWorker;
      globalThis.fetch = async (url) => {
        if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
        if (String(url) === "/__pow/verify") {
          verifyCalls += 1;
          return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
        }
        throw new Error(`unexpected fetch ${String(url)}`);
      };
      try {
        await glue.default(powBootstrap(clock.wallMs, 60), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
        assert.equal(verifyCalls, 1, `${elapsedMs}ms elapsed`);
      } finally {
        dom.restore();
      }
    }
  });

  await t.test("pending captcha and stalled module expire through the bounded refresh route", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    const { glue, dom } = await loadGlueWithDom({ clock, timers });
    const turnstile = makeTurnstile({ auto: false });
    globalThis.window.turnstile = turnstile;
    let reloads = 0;
    globalThis.window.location.reload = () => { reloads += 1; };
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    try {
      const run = glue.default(powBootstrap(clock.wallMs, 5), b64("binding"), b64("https://example.com/protected"), powEsm(), captcha, "0");
      await flushUntil(() => turnstile.options);
      assert.ok(turnstile.options);
      clock.monoMs += 5001;
      for (const timer of timers.intervals) if (!timer.cleared) timer.fn();
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = timers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(reloads, 1);
      assert.equal(turnstile.removed, 1);
      turnstile.options.callback("late-token");
      assert.equal(turnstile.removed, 1);
    } finally {
      dom.restore();
    }

    const stalledClock = { wallMs: 1700000000000, monoMs: 1000 };
    const stalledTimers = { timeouts: [], intervals: [] };
    const stalled = await loadGlueWithDom({ clock: stalledClock, timers: stalledTimers });
    let stalledReloads = 0;
    globalThis.window.location.reload = () => { stalledReloads += 1; };
    try {
      const unresolvedEsm = b64(`data:text/javascript,${encodeURIComponent("await new Promise(() => {});")}`);
      const run = stalled.glue.default(powBootstrap(stalledClock.wallMs, 5), b64("binding"), b64("https://example.com/protected"), unresolvedEsm, b64("{}"), "0");
      await flush();
      stalledClock.monoMs += 5001;
      for (const timer of stalledTimers.intervals) if (!timer.cleared) timer.fn();
      await flushUntil(() => stalledTimers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = stalledTimers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(stalledReloads, 1);
    } finally {
      stalled.dom.restore();
    }
  });

  await t.test("parent termination is armed at the compute cutoff before ticket expiry", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    let worker;
    let solveStarted = false;
    class HangingWorker {
      constructor() { worker = this; this.listeners = new Map(); this.terminated = false; }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      postMessage(message) {
        if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        if (message.type === "SOLVE") solveStarted = true;
      }
      terminate() { this.terminated = true; }
    }
    const { glue, dom } = await loadGlueWithDom({ clock, timers });
    globalThis.Worker = HangingWorker;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    let reloads = 0;
    globalThis.window.location.reload = () => { reloads += 1; };
    try {
      const run = glue.default(powBootstrap(clock.wallMs, 5), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
      await flushUntil(() => solveStarted);
      assert.equal(solveStarted, true);
      clock.monoMs = 4501;
      assert.ok(clock.monoMs < 6000);
      for (const timer of timers.intervals) if (!timer.cleared) timer.fn();
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = timers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(worker.terminated, true);
      assert.equal(reloads, 1);
    } finally {
      dom.restore();
    }
  });

  await t.test("Turnstile uses the real 300-second token window and rejects replacement tokens", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    let tokenOptions;
    let verifyCalls = 0;
    class NeverStartedWorker {
      constructor() { this.listeners = new Map(); }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      postMessage() {}
      terminate() {}
    }
    const { glue, dom } = await loadGlueWithDom({ clock, timers });
    const turnstile = makeTurnstile({ auto: false, onOptions: (options) => { tokenOptions = options; } });
    globalThis.window.turnstile = turnstile;
    globalThis.Worker = NeverStartedWorker;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      if (String(url) === "/__pow/verify") {
        verifyCalls += 1;
        return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
      }
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    let reloads = 0;
    globalThis.window.location.reload = () => { reloads += 1; };
    try {
      const run = glue.default(powBootstrap(clock.wallMs, 600), b64("binding"), b64("https://example.com/protected"), powEsm(), captcha, "0");
      await flushUntil(() => tokenOptions);
      tokenOptions.callback("turnstile-token-1234567890");
      await flush();
      clock.monoMs += 300_001;
      for (const timer of timers.intervals) if (!timer.cleared) timer.fn();
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = timers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(verifyCalls, 0);
      assert.equal(reloads, 1);
      assert.equal(turnstile.removed, 1);
      tokenOptions.callback("late-replacement");
      assert.equal(turnstile.removed, 1);
    } finally {
      dom.restore();
    }
  });

  await t.test("a replacement token cancels old work and a fresh invocation derives a fresh seed", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    let firstSeed = null;
    class FirstWorker {
      constructor() { this.listeners = new Map(); }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      postMessage(message) {
        if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        if (message.type === "SOLVE") firstSeed = Array.from(message.seed);
      }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      terminate() {}
    }
    const first = await loadGlueWithDom({ clock, timers });
    const firstTurnstile = makeTurnstile({ auto: false });
    globalThis.window.turnstile = firstTurnstile;
    globalThis.Worker = FirstWorker;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    let firstReloads = 0;
    globalThis.window.location.reload = () => { firstReloads += 1; };
    try {
      const run = first.glue.default(powBootstrap(clock.wallMs, 600), b64("binding"), b64("https://example.com/protected"), powEsm(), captcha, "0");
      await flushUntil(() => firstTurnstile.options);
      firstTurnstile.options.callback("token-A-1234567890");
      await flushUntil(() => firstSeed !== null);
      assert.ok(firstSeed);
      const widgetDom = globalThis.document.getElementById("ts");
      clock.monoMs += 400;
      for (const timer of timers.timeouts) {
        if (!timer.cleared && timer.delay === 400) {
          timer.cleared = true;
          timer.fn();
        }
      }
      assert.notEqual(widgetDom.innerHTML, "");
      firstTurnstile.options.callback("token-B-1234567890");
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = timers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(firstReloads, 1);
      assert.equal(firstTurnstile.removed, 1);
      firstTurnstile.options.callback("token-C-1234567890");
    } finally {
      first.dom.restore();
    }

    let secondSeed = null;
    let secondVerifyCalls = 0;
    class SecondWorker {
      constructor() { this.listeners = new Map(); }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      postMessage(message) {
        if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        if (message.type === "SOLVE") {
          secondSeed = Array.from(message.seed);
          queueMicrotask(() => this.emit({ type: "OK", rid: message.rid, status: "solved", nonceB64: b64("nonce"), proofB64: b64("proof") }));
        }
      }
      terminate() {}
    }
    const second = await loadGlueWithDom({ clock, timers: { timeouts: [], intervals: [] } });
    const secondTurnstile = makeTurnstile({ auto: false });
    globalThis.window.turnstile = secondTurnstile;
    globalThis.Worker = SecondWorker;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      if (String(url) === "/__pow/verify") {
        secondVerifyCalls += 1;
        return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
      }
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    try {
      const run = second.glue.default(powBootstrap(clock.wallMs, 600), b64("binding"), b64("https://example.com/protected"), powEsm(), captcha, "0");
      await flushUntil(() => secondTurnstile.options);
      secondTurnstile.options.callback("token-B-1234567890");
      await run;
      assert.notDeepEqual(secondSeed, firstSeed);
      assert.equal(secondVerifyCalls, 1);
    } finally {
      second.dom.restore();
    }
  });

  await t.test("successful verification inside the submission reserve remains accepted", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    let verifyCalls = 0;
    let solveDoneMs = 0;
    let verifyDoneMs = 0;
    class FastWorker {
      constructor() { this.listeners = new Map(); }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      postMessage(message) {
        if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        if (message.type === "SOLVE") {
          clock.monoMs += 400;
          solveDoneMs = clock.monoMs;
          queueMicrotask(() => this.emit({ type: "OK", rid: message.rid, status: "solved", nonceB64: b64("nonce"), proofB64: b64("proof") }));
        }
      }
      terminate() {}
    }
    const { glue, dom } = await loadGlueWithDom({ clock });
    globalThis.Worker = FastWorker;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      if (String(url) === "/__pow/verify") {
        verifyCalls += 1;
        return { ok: true, status: 200, json: async () => {
          clock.monoMs += 300;
          verifyDoneMs = clock.monoMs;
          return { ok: true, mode: "proof" };
        } };
      }
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    let redirected = "";
    globalThis.window.location.replace = (value) => { redirected = String(value); };
    try {
      await glue.default(powBootstrap(clock.wallMs, 2), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
      assert.equal(verifyCalls, 1);
      assert.equal(redirected, "https://example.com/protected");
      assert.ok(solveDoneMs < 1500);
      assert.ok(verifyDoneMs > 1500 && verifyDoneMs < 3000);
    } finally {
      dom.restore();
    }
  });

  await t.test("server errors at the validity boundary retain their authoritative routing", async () => {
    for (const response of [
      { status: 500, hint: "" },
      { status: 403, hint: "cheat" },
      { status: 403, hint: "unknown" },
    ]) {
      const clock = { wallMs: 1700000000000, monoMs: 1000 };
      const timers = { timeouts: [], intervals: [] };
      class BoundaryWorker {
        constructor() { this.listeners = new Map(); }
        addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
        emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
        postMessage(message) {
          if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
          if (message.type === "SOLVE") {
            clock.monoMs += 1800;
            queueMicrotask(() => this.emit({ type: "OK", rid: message.rid, status: "solved", nonceB64: b64("nonce"), proofB64: b64("proof") }));
          }
        }
        terminate() {}
      }
      const { glue, dom } = await loadGlueWithDom({ clock, timers });
      globalThis.Worker = BoundaryWorker;
      let reloads = 0;
      globalThis.window.location.reload = () => { reloads += 1; };
      globalThis.fetch = async (url) => {
        if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
        if (String(url) === "/__pow/verify") return { ok: false, status: response.status, headers: { get: () => response.hint } };
        throw new Error(`unexpected fetch ${String(url)}`);
      };
      try {
        await glue.default(powBootstrap(clock.wallMs, 2), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
        assert.equal(reloads, 0, `${response.status}/${response.hint}`);
        assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
      } finally {
        dom.restore();
      }
    }
  });

  await t.test("postJson keeps exact retry delays and identical bodies", async () => {
    const timers = { timeouts: [], intervals: [] };
    const { glue, dom } = await loadGlueWithDom({ timers });
    const turnstile = makeTurnstile();
    globalThis.window.turnstile = turnstile;
    let attempts = 0;
    const bodies = [];
    globalThis.fetch = async (_url, init) => {
      bodies.push(init.body);
      attempts += 1;
      if (attempts <= 3) throw new TypeError("network reset");
      return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
    };
    try {
      const run = glue.default(...args());
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 500));
      for (const delay of [500, 1000, 2000]) {
        const timer = timers.timeouts.find((entry) => !entry.cleared && entry.delay === delay);
        assert.ok(timer, `missing retry timer ${delay}`);
        timer.cleared = true;
        timer.fn();
        await flush();
      }
      await run;
      assert.equal(attempts, 4);
      assert.deepEqual(bodies, [bodies[0], bodies[0], bodies[0], bodies[0]]);
    } finally {
      dom.restore();
    }
  });

  await t.test("partial response body transport errors replay the same body", async () => {
    const timers = { timeouts: [], intervals: [] };
    const { glue, dom } = await loadGlueWithDom({ timers });
    const turnstile = makeTurnstile();
    globalThis.window.turnstile = turnstile;
    let attempts = 0;
    const bodies = [];
    globalThis.fetch = async (_url, init) => {
      bodies.push(init.body);
      attempts += 1;
      return {
        ok: true,
        status: 200,
        json: async () => {
          if (attempts <= 3) throw new TypeError("stream reset");
          return { ok: true, mode: "proof" };
        },
      };
    };
    try {
      const run = glue.default(...args());
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 500));
      for (const delay of [500, 1000, 2000]) {
        const timer = timers.timeouts.find((entry) => !entry.cleared && entry.delay === delay);
        assert.ok(timer, `missing retry timer ${delay}`);
        timer.cleared = true;
        timer.fn();
        if (delay !== 2000) await flushUntil(() => timers.timeouts.some((entry) => !entry.cleared && entry.delay === delay * 2));
      }
      await run;
      assert.equal(attempts, 4);
      assert.deepEqual(bodies, [bodies[0], bodies[0], bodies[0], bodies[0]]);
    } finally {
      dom.restore();
    }
  });

  await t.test("reload allowance rolls over after fifteen seconds", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const { glue, dom } = await loadGlueWithDom({ clock });
    const turnstile = makeTurnstile();
    globalThis.window.turnstile = turnstile;
    let reloads = 0;
    globalThis.window.location.reload = () => { reloads += 1; };
    globalThis.fetch = async () => ({ ok: false, status: 403, headers: { get: () => "stale" } });
    try {
      await glue.default(...args());
      await glue.default(...args());
      await glue.default(...args());
      assert.equal(reloads, 2);
      clock.wallMs += 15001;
      await glue.default(...args());
      assert.equal(reloads, 3);
    } finally {
      dom.restore();
    }
  });

  await t.test("background and BFCache events retain valid work and recheck on wake", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    let worker;
    let solveStarted = false;
    class HangingWorker {
      constructor() { worker = this; this.listeners = new Map(); this.terminated = false; }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      postMessage(message) {
        if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        if (message.type === "SOLVE") solveStarted = true;
      }
      terminate() { this.terminated = true; }
    }
    const { glue, dom } = await loadGlueWithDom({ clock, timers });
    globalThis.Worker = HangingWorker;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    let reloads = 0;
    globalThis.window.location.reload = () => { reloads += 1; };
    try {
      const run = glue.default(powBootstrap(clock.wallMs, 60), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
      await flushUntil(() => solveStarted);
      assert.equal(solveStarted, true);
      globalThis.document.hidden = true;
      dom.dispatchDocument("visibilitychange");
      assert.equal(worker.terminated, false);
      globalThis.document.hidden = false;
      dom.dispatchDocument("visibilitychange");
      dom.dispatchWindow("pagehide", { persisted: true });
      assert.equal(worker.terminated, false);
      dom.dispatchWindow("pageshow");
      assert.equal(worker.terminated, false);
      clock.monoMs += 60001;
      dom.dispatchWindow("pageshow");
      worker.emit({ type: "PROGRESS", phase: "solve", elapsedMs: 1, remainingMs: 1, rows: 1, ewmaSolveMs: 1 });
      worker.emit({ type: "OK", rid: 999, status: "solved", nonceB64: b64("late"), proofB64: b64("late") });
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = timers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(worker.terminated, true);
      assert.equal(reloads, 1);
    } finally {
      dom.restore();
    }

    const teardownClock = { wallMs: 1700000000000, monoMs: 1000 };
    const teardownTimers = { timeouts: [], intervals: [] };
    let teardownWorker;
    class TeardownWorker extends HangingWorker {
      constructor() { super(); teardownWorker = this; }
    }
    const teardown = await loadGlueWithDom({ clock: teardownClock, timers: teardownTimers });
    globalThis.Worker = TeardownWorker;
    globalThis.fetch = async (url) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    let teardownReloads = 0;
    globalThis.window.location.reload = () => { teardownReloads += 1; };
    try {
      const run = teardown.glue.default(powBootstrap(teardownClock.wallMs, 60), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
      await flushUntil(() => teardownWorker);
      teardown.dom.dispatchWindow("pagehide", { persisted: false });
      await run;
      assert.equal(teardownWorker.terminated, true);
      assert.equal(teardownReloads, 0);
    } finally {
      teardown.dom.restore();
    }
  });

  await t.test("expiry aborts a pending solver asset body", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    const { glue, dom } = await loadGlueWithDom({ clock, timers });
    let signal;
    globalThis.fetch = async (url, init) => {
      if (String(url) !== "https://example.com/solver.wasm") throw new Error(`unexpected fetch ${String(url)}`);
      signal = init.signal;
      return new Promise((resolve, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
      });
    };
    let reloads = 0;
    globalThis.window.location.reload = () => { reloads += 1; };
    try {
      const run = glue.default(powBootstrap(clock.wallMs, 5), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
      await flushUntil(() => signal);
      assert.ok(signal);
      clock.monoMs += 5001;
      for (const timer of timers.intervals) if (!timer.cleared) timer.fn();
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = timers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(signal.aborted, true);
      assert.equal(reloads, 1);
    } finally {
      dom.restore();
    }
  });

  await t.test("expiry aborts a pending verification response body", async () => {
    const clock = { wallMs: 1700000000000, monoMs: 1000 };
    const timers = { timeouts: [], intervals: [] };
    let verifySignal;
    let responseBody;
    class FastWorker {
      constructor() { this.listeners = new Map(); }
      addEventListener(type, callback) { this.listeners.set(type, [...(this.listeners.get(type) || []), callback]); }
      emit(data) { for (const callback of this.listeners.get("message") || []) callback({ data }); }
      postMessage(message) {
        if (message.type === "INIT") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid }));
        if (message.type === "SOLVE") queueMicrotask(() => this.emit({ type: "OK", rid: message.rid, status: "solved", nonceB64: b64("nonce"), proofB64: b64("proof") }));
      }
      terminate() {}
    }
    const { glue, dom } = await loadGlueWithDom({ clock, timers });
    globalThis.Worker = FastWorker;
    globalThis.fetch = async (url, init) => {
      if (String(url) === "https://example.com/solver.wasm") return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      if (String(url) === "/__pow/verify") {
        verifySignal = init.signal;
        responseBody = new ReadableStream({
          start(controller) { controller.enqueue(new TextEncoder().encode('{"ok":')); },
        });
        return {
          ok: true,
          status: 200,
          body: responseBody,
          json: () => new Response(responseBody).json(),
        };
      }
      throw new Error(`unexpected fetch ${String(url)}`);
    };
    let reloads = 0;
    globalThis.window.location.reload = () => { reloads += 1; };
    try {
      const run = glue.default(powBootstrap(clock.wallMs, 5), b64("binding"), b64("https://example.com/protected"), powEsm(), b64("{}"), "0");
      await flushUntil(() => verifySignal);
      assert.ok(verifySignal);
      clock.monoMs += 5001;
      for (const timer of timers.intervals) if (!timer.cleared) timer.fn();
      await flushUntil(() => timers.timeouts.some((timer) => !timer.cleared && timer.delay === 1000));
      const refresh = timers.timeouts.find((timer) => !timer.cleared && timer.delay === 1000);
      assert.ok(refresh);
      refresh.cleared = true;
      refresh.fn();
      await run;
      assert.equal(verifySignal.aborted, true);
      assert.equal(responseBody.locked, true);
      assert.equal(reloads, 1);
    } finally {
      dom.restore();
    }
  });
});
