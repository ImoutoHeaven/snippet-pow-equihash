import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Worker } from "node:worker_threads";
import { fileURLToPath, pathToFileURL } from "node:url";

import { captchaTagV1, deriveEquihashSeed } from "../../lib/equihash/seed.js";
import { encodeV5Ticket, issueV5Ticket, makeTicketMac, parseV5Ticket, verifyV5Ticket } from "../../lib/equihash/ticket.js";
import { isValidEquihashParams } from "../../lib/equihash/params.js";
import { verifyEquihash } from "../../lib/equihash/verify.js";
import { base64UrlEncodeNoPad } from "../../lib/equihash/encoding.js";
import { defaultRowsFor } from "../../esm/equihash-worker.js";

const workerPath = fileURLToPath(new URL("../../esm/equihash-worker.js", import.meta.url));
const wasmPath = fileURLToPath(new URL("../../esm/solver.wasm", import.meta.url));

const spawnWorker = ({ mockMode = "", importDelayMs = 0 } = {}) => {
  const moduleUrl = pathToFileURL(workerPath).href;
  return new Worker(`
    const { parentPort } = require("node:worker_threads");
    const { webcrypto } = require("node:crypto");
    const NativeWebAssembly = globalThis.WebAssembly;
    globalThis.self = globalThis;
    globalThis.crypto = webcrypto;
    const mockMode = ${JSON.stringify(mockMode)};
    const importDelayMs = ${JSON.stringify(importDelayMs)};
    if (mockMode) {
      const memory = new NativeWebAssembly.Memory({ initial: 2 });
      let cursor = 1024;
      let solveCalls = 0;
      const alloc = (size) => { const pointer = cursor; cursor += size + 8; return pointer; };
      const dealloc = () => {};
      const solve_once = () => {
        solveCalls += 1;
        if (mockMode === "trap-once" && solveCalls === 1) throw new Error("mock wasm trap");
        if (mockMode === "trap-once") return 16;
        if (mockMode === "short") return 1;
        if (mockMode === "slow-zero") {
          const end = Date.now() + 50;
          while (Date.now() < end) {}
        }
        return 0;
      };
      globalThis.WebAssembly.instantiate = async () => {
        if (mockMode === "slow-init") await new Promise((resolve) => setTimeout(resolve, 50));
        return { instance: { exports: { memory, alloc, dealloc, solve_once, required_proof_len: () => 16 } } };
      };
    }
    globalThis.postMessage = (message) => parentPort.postMessage(message);
    const boot = async () => {
      if (importDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, importDelayMs));
      try {
        await import(${JSON.stringify(moduleUrl)});
        parentPort.on("message", (data) => globalThis.onmessage?.({ data }));
      } catch (error) {
        parentPort.postMessage({ type: "BOOT_ERROR", message: String(error) });
      }
    };
    void boot();
  `, { eval: true });
};

const rpc = (worker, onProgress) => {
  let rid = 0;
  const pending = new Map();
  const rejectPending = (error) => {
    for (const item of pending.values()) item.reject(error);
    pending.clear();
  };
  worker.on("message", (message) => {
    if (message?.type === "BOOT_ERROR") {
      rejectPending(new Error(message.message));
      return;
    }
    if (message?.type === "PROGRESS") {
      onProgress?.(message);
      return;
    }
    const item = pending.get(message?.rid);
    if (!item) return;
    pending.delete(message.rid);
    message.type === "ERROR" ? item.reject(new Error(message.message)) : item.resolve(message);
  });
  worker.on("error", rejectPending);
  return (type, payload = {}, transfer = []) => new Promise((resolve, reject) => {
    const id = ++rid;
    pending.set(id, { resolve, reject });
    worker.postMessage({ ...payload, type, rid: id }, transfer);
  });
};

const solveArtifact = async ({ n, k, rows, seed, nonce }) => {
  const bytes = new Uint8Array(await readFile(wasmPath));
  const result = await WebAssembly.instantiate(bytes, {});
  const instance = result.instance || result;
  const { exports } = instance;
  const proofLength = Number(exports.required_proof_len(k));
  const seedPtr = Number(exports.alloc(seed.length, 8));
  const noncePtr = Number(exports.alloc(nonce.length, 8));
  const proofPtr = Number(exports.alloc(proofLength, 8));
  try {
    let view = new Uint8Array(exports.memory.buffer);
    view.set(seed, seedPtr);
    view.set(nonce, noncePtr);
    const rc = Number(exports.solve_once(seedPtr, seed.length, noncePtr, nonce.length, n, k, rows, proofPtr, proofLength));
    view = new Uint8Array(exports.memory.buffer);
    return { rc, proof: rc > 0 ? new Uint8Array(view.subarray(proofPtr, proofPtr + rc)) : new Uint8Array() };
  } finally {
    exports.dealloc(proofPtr, proofLength, 8);
    exports.dealloc(noncePtr, nonce.length, 8);
    exports.dealloc(seedPtr, seed.length, 8);
  }
};

test("all legal parameter pairs agree with the strict domain", () => {
  for (let n = 8; n <= 256; n += 2) {
    for (let k = 2; k <= 8; k += 1) assert.equal(isValidEquihashParams(n, k), n % (k + 1) === 0);
  }
  assert.equal(isValidEquihashParams("090", 5), false);
  assert.equal(isValidEquihashParams(90, 5.1), false);
});

test("v5 ticket and seed contracts are canonical and bound", async () => {
  const fields = {
    powSecret: "task2-secret",
    cfgId: 7,
    issuedAt: 1700000000,
    e: 1700000600,
    n: 90,
    k: 5,
    m: 3,
    bindings: {
      host: "Example.COM",
      pathHash: "path-hash",
      ipScope: "203.0.113.0/24",
      country: "US",
      asn: "64500",
      tlsFingerprint: "ja4:test",
    },
  };
  const fixedTicket = {
    v: 5,
    e: fields.e,
    cfgId: fields.cfgId,
    issuedAt: fields.issuedAt,
    r: "AAECAwQFBgcICQoLDA0ODw",
    n: fields.n,
    k: fields.k,
    m: fields.m,
    mac: "",
  };
  fixedTicket.mac = await makeTicketMac(fields.powSecret, fixedTicket, fields.bindings);
  const ticketB64 = encodeV5Ticket(fixedTicket);
  assert.throws(() => encodeV5Ticket({ ...fixedTicket, v: 4 }), /version/u);
  const ticket = parseV5Ticket(ticketB64);
  assert.equal(ticketB64, "NS4xNzAwMDAwNjAwLjcuMTcwMDAwMDAwMC5BQUVDQXdRRkJnY0lDUW9MREEwT0R3LjkwLjUuMy5yVDhsVWkyVXZyQThqYktVN2NEaTU4djNjaVRJWWh0bWFRQjBldGVPWTFV");
  assert.equal(ticket.v, 5);
  assert.equal(ticket.r, fixedTicket.r);
  assert.equal(ticket.n, 90);
  assert.equal(ticket.mac, "rT8lUi2UvrA8jbKU7cDi58v3ciTIYhtmaQB0eteOY1U");
  const verifyInput = { ticketB64, powSecret: fields.powSecret, nowSeconds: 1700000001, expectedCfgId: 7, expectedN: 90, expectedK: 5, requiredMask: 3, bindings: fields.bindings };
  assert.equal((await verifyV5Ticket(verifyInput)).ok, true);
  const hostNegative = await verifyV5Ticket({ ...verifyInput, bindings: { ...fields.bindings, host: "other.example" } });
  assert.equal(hostNegative.ok, false);
  assert.equal(hostNegative.reason, "mac_mismatch");
  assert.equal((await verifyV5Ticket({ ...verifyInput, expectedCfgId: 8 })).reason, "cfg_mismatch");
  assert.equal((await verifyV5Ticket({ ...verifyInput, expectedN: 12, expectedK: 2 })).reason, "params_mismatch");
  assert.equal((await verifyV5Ticket({ ...verifyInput, requiredMask: 1 })).reason, "mask_mismatch");
  assert.equal((await verifyV5Ticket({ ...verifyInput, bindings: undefined })).reason, "invalid_input");
  const randomA = await issueV5Ticket({ ...fields, r: fixedTicket.r });
  const randomB = await issueV5Ticket({ ...fields, r: fixedTicket.r });
  assert.notEqual(randomA, randomB);
  const seed = await deriveEquihashSeed({ ticketB64, pathHash: fields.bindings.pathHash, captchaTag: "any" });
  assert.equal(seed.length, 32);
  assert.equal(base64UrlEncodeNoPad(seed), "BMy3Hopez5H-bv-XUJAueVsbfmVnIsAgFYQJtKyIfBs");
  assert.equal(await captchaTagV1("turnstile-token-1234567890"), "0VpAIT_TtVLcJm9w");
  assert.notDeepEqual(seed, await deriveEquihashSeed({ ticketB64, pathHash: "changed", captchaTag: "any" }));
  assert.notDeepEqual(seed, await deriveEquihashSeed({ ticketB64, pathHash: fields.bindings.pathHash, captchaTag: "token-tag" }));

  const raw = atob(ticketB64.replace(/-/g, "+").replace(/_/g, "/"));
  assert.equal(parseV5Ticket(`${ticketB64}=`), null);
  assert.equal(parseV5Ticket(base64UrlEncodeNoPad(new TextEncoder().encode(raw.replace("5.1700000600", "05.1700000600")))), null);
  assert.equal((await verifyV5Ticket(verifyInput)).ok, true);
  assert.equal((await verifyV5Ticket({ ticketB64, powSecret: fields.powSecret, bindings: fields.bindings })).ok, false);
  assert.equal((await verifyV5Ticket(null)).ok, false);
});

test("verifier rejects duplicate, tampered, and malformed proofs", () => {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const nonce = new Uint8Array(24);
  nonce[23] = 5;
  const proof = Uint8Array.from(Buffer.from("00000002000000200000002800000029", "hex"));
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce, proof }), true);
  const duplicate = proof.slice();
  duplicate.set(duplicate.subarray(0, 4), 4);
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce, proof: duplicate }), false);
  const tampered = proof.slice();
  tampered[tampered.length - 1] ^= 1;
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce, proof: tampered }), false);
  const swapped = proof.slice();
  swapped.set(proof.subarray(0, 4), 4);
  swapped.set(proof.subarray(4, 8), 0);
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce, proof: swapped }), false);
  const changedSeed = seed.slice();
  changedSeed[0] ^= 1;
  assert.equal(verifyEquihash({ n: 12, k: 2, seed: changedSeed, nonce, proof }), false);
  const changedNonce = nonce.slice();
  changedNonce[23] ^= 1;
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce: changedNonce, proof }), false);
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce, proof: proof.subarray(0, proof.length - 1) }), false);
  assert.equal(verifyEquihash({ n: 12, k: 2, seed: seed.subarray(0, 31), nonce, proof }), false);
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce: nonce.subarray(0, 23), proof }), false);
});

test("shipped WASM ABI solves the fixed regressions and reports resource failure", async () => {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const nonce = new Uint8Array(24);
  nonce[23] = 5;
  const small = await solveArtifact({ n: 12, k: 2, rows: 64, seed, nonce });
  assert.equal(small.rc, 16);
  assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce, proof: small.proof }), true);
  const defaultSeed = new TextEncoder().encode("0123456789abcdefghijklmnopqrstuv");
  const defaultNonce = new Uint8Array(24);
  const defaultProof = await solveArtifact({ n: 90, k: 5, rows: 65536, seed: defaultSeed, nonce: defaultNonce });
  assert.ok(defaultProof.rc > 0);
  assert.equal(verifyEquihash({ n: 90, k: 5, seed: defaultSeed, nonce: defaultNonce, proof: defaultProof.proof }), true);
  const resource = await solveArtifact({ n: 90, k: 5, rows: 0xffffffff, seed: defaultSeed, nonce: defaultNonce });
  assert.equal(resource.rc, -2);
});

test("real shipped Worker solves and the independent verifier accepts n=90,k=5", { timeout: 120_000 }, async () => {
  const bytes = new Uint8Array(await readFile(wasmPath));
  assert.ok(bytes.length > 0);
  const worker = spawnWorker();
  const call = rpc(worker);
  try {
    await call("INIT", { n: 90, k: 5, solvePolicy: { deadlineMs: 60_000, rows: 65536 }, solverWasmBytes: bytes }, [bytes.buffer]);
    const seed = Uint8Array.from({ length: 32 }, (_, index) => 31 - index);
    const result = await call("SOLVE", { seed });
    assert.equal(result.status, "solved");
    const decode = (value) => Uint8Array.from(Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
    assert.equal(verifyEquihash({ seed, nonce: decode(result.nonceB64), proof: decode(result.proofB64), n: 90, k: 5 }), true);
    await call("DISPOSE");
  } finally {
    await worker.terminate();
  }
});

test("Worker default rows preserve the minimum proof population and full default population", () => {
  assert.ok(defaultRowsFor(18, 8) >= 256);
  assert.equal(defaultRowsFor(96, 5), 131072);
});

test("real shipped Worker accepts a fixed nonce sequence for reproducible calibration", { timeout: 30_000 }, async () => {
  const bytes = new Uint8Array(await readFile(wasmPath));
  const worker = spawnWorker();
  const call = rpc(worker);
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const nonce = new Uint8Array(24);
  nonce[23] = 5;
  const decode = (value) => Uint8Array.from(Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
  try {
    await call("INIT", { n: 12, k: 2, solvePolicy: { deadlineMs: 30_000, rows: 64 }, solverWasmBytes: bytes }, [bytes.buffer]);
    const result = await call("SOLVE", { seed, nonceSequence: [nonce] });
    assert.equal(result.status, "solved");
    assert.equal(verifyEquihash({ n: 12, k: 2, seed, nonce: decode(result.nonceB64), proof: decode(result.proofB64) }), true);
    assert.deepEqual(decode(result.nonceB64), nonce);
  } finally {
    await worker.terminate();
  }
});

test("Worker queues early INIT until delayed module boot completes", { timeout: 30_000 }, async () => {
  const worker = spawnWorker({ mockMode: "trap-once", importDelayMs: 50 });
  const call = rpc(worker);
  try {
    await call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 5_000 }, solverWasmBytes: new Uint8Array([1]) });
    await call("DISPOSE");
  } finally {
    await worker.terminate();
  }
});

test("real shipped Worker solves additional practical profiles", { timeout: 120_000 }, async () => {
  const profiles = [
    { n: 12, k: 2, rows: 64 },
    { n: 18, k: 2, rows: 128 },
    { n: 24, k: 3, rows: 128 },
    { n: 28, k: 3, rows: 256 },
  ];
  const worker = spawnWorker();
  const call = rpc(worker);
  const decode = (value) => Uint8Array.from(Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
  try {
    for (const profile of profiles) {
      const bytes = new Uint8Array(await readFile(wasmPath));
      await call("INIT", { n: profile.n, k: profile.k, solvePolicy: { deadlineMs: 60_000, rows: profile.rows }, solverWasmBytes: bytes }, [bytes.buffer]);
      const seed = Uint8Array.from({ length: 32 }, (_, index) => (index + profile.n + profile.k) & 0xff);
      const result = await call("SOLVE", { seed });
      assert.equal(result.status, "solved", `${profile.n}/${profile.k} did not solve`);
      assert.equal(verifyEquihash({ n: profile.n, k: profile.k, seed, nonce: decode(result.nonceB64), proof: decode(result.proofB64) }), true);
    }
  } finally {
    await worker.terminate();
  }
});

test("Worker reports lifecycle, parameter, and resource failures explicitly", { timeout: 30_000 }, async () => {
  const bytes = new Uint8Array(await readFile(wasmPath));
  const worker = spawnWorker();
  const call = rpc(worker);
  try {
    assert.equal((await call("SOLVE", { seed: new Uint8Array(32) })).status, "fatal");
    await call("INIT", { n: 252, k: 2, solverWasmBytes: bytes }, [bytes.buffer]);
    await call("DISPOSE");
    const zeroBytes = new Uint8Array(await readFile(wasmPath));
    await call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 0 }, solverWasmBytes: zeroBytes }, [zeroBytes.buffer]);
    assert.equal((await call("SOLVE", { seed: new Uint8Array(32) })).status, "timeout");
    await call("DISPOSE");
    const secondBytes = new Uint8Array(await readFile(wasmPath));
    await call("INIT", { n: 90, k: 5, solvePolicy: { deadlineMs: 60_000, rows: 65536 }, solverWasmBytes: secondBytes }, [secondBytes.buffer]);
    await call("CANCEL");
    assert.equal((await call("SOLVE", { seed: new Uint8Array(32) })).status, "cancelled");
    await call("DISPOSE");
    assert.equal((await call("SOLVE", { seed: new Uint8Array(32) })).status, "fatal");
  } finally {
    await worker.terminate();
  }
});

test("real Worker cancels an active solve", { timeout: 30_000 }, async () => {
  const worker = spawnWorker({ mockMode: "slow-zero" });
  const call = rpc(worker);
  try {
    await call("INIT", { n: 12, k: 2, solvePolicy: { deadlineMs: 5_000, rows: 64 }, solverWasmBytes: new Uint8Array([1]) });
    const active = call("SOLVE", { seed: new Uint8Array(32) });
    await call("CANCEL");
    assert.equal((await active).status, "cancelled");
    await call("DISPOSE");
  } finally {
    await worker.terminate();
  }
});

test("Worker serializes active solve state and rejects overlapping reconfiguration", { timeout: 30_000 }, async () => {
  const worker = spawnWorker({ mockMode: "slow-zero" });
  const progress = [];
  const call = rpc(worker, (message) => progress.push(message));
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const seedA = new Uint8Array(32).fill(1);
  const seedB = new Uint8Array(32).fill(2);
  try {
    await call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 5_000 }, solverWasmBytes: new Uint8Array([1]) });
    const active = call("SOLVE", { seed: seedA });
    await wait(10);
    assert.equal((await call("SOLVE", { seed: seedB })).status, "busy");
    await assert.rejects(
      call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 5_000 }, solverWasmBytes: new Uint8Array([1]) }),
      /busy/u,
    );
    await call("CANCEL");
    assert.equal((await active).status, "cancelled");
    assert.ok(progress.some((message) => message.phase === "solve" && message.remainingMs > 0));
    await call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 5_000 }, solverWasmBytes: new Uint8Array([1]) });
    const disposedSolve = call("SOLVE", { seed: seedA });
    await wait(10);
    await call("DISPOSE");
    await call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 5_000 }, solverWasmBytes: new Uint8Array([1]) });
    assert.equal((await disposedSolve).status, "cancelled");
  } finally {
    await worker.terminate();
  }
});

test("Worker invalidates stale initialization completion", { timeout: 30_000 }, async () => {
  const worker = spawnWorker({ mockMode: "slow-init" });
  const call = rpc(worker);
  try {
    const init = call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64 }, solverWasmBytes: new Uint8Array([1]) });
    const initError = init.catch((error) => error);
    await new Promise((resolve) => setTimeout(resolve, 10));
    await call("DISPOSE");
    await call("INIT", { n: 12, k: 2, solvePolicy: { rows: 64 }, solverWasmBytes: new Uint8Array([1]) });
    assert.match((await initError).message, /stale initialization/u);
  } finally {
    await worker.terminate();
  }
});

test("Worker surfaces WASM initialization and trap failures, then recovers", { timeout: 30_000 }, async () => {
  const malformedWorker = spawnWorker();
  const malformedCall = rpc(malformedWorker);
  try {
    await assert.rejects(
      malformedCall("INIT", { n: 12, k: 2, solvePolicy: { rows: 64 }, solverWasmBytes: new Uint8Array([0]) }),
      /wasm|magic|compile|section|expected|fell/u,
    );
    const bytes = new Uint8Array(await readFile(wasmPath));
    await malformedCall("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 1 }, solverWasmBytes: bytes }, [bytes.buffer]);
  } finally {
    await malformedWorker.terminate();
  }

  const trapWorker = spawnWorker({ mockMode: "trap-once" });
  const trapCall = rpc(trapWorker);
  try {
    await trapCall("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 5_000 }, solverWasmBytes: new Uint8Array([1]) });
    const seed = new Uint8Array(32).fill(3);
    const first = await trapCall("SOLVE", { seed });
    assert.equal(first.status, "fatal");
    assert.match(String(first.message), /mock wasm trap/u);
    const second = await trapCall("SOLVE", { seed });
    assert.equal(second.status, "solved");
    assert.equal(Buffer.from(second.proofB64.replace(/-/g, "+").replace(/_/g, "/"), "base64").length, 16);
  } finally {
    await trapWorker.terminate();
  }

  const shortWorker = spawnWorker({ mockMode: "short" });
  const shortCall = rpc(shortWorker);
  try {
    await shortCall("INIT", { n: 12, k: 2, solvePolicy: { rows: 64, deadlineMs: 5_000 }, solverWasmBytes: new Uint8Array([1]) });
    const short = await shortCall("SOLVE", { seed: new Uint8Array(32).fill(4) });
    assert.equal(short.status, "fatal");
    assert.match(String(short.message), /invalid wasm proof length/u);
  } finally {
    await shortWorker.terminate();
  }
});
