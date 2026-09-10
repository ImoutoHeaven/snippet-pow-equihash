const NONCE_SIZE = 24;
const SEED_SIZE = 32;
const U32_MAX = 0xffffffff;
const DEFAULT_MEMORY_BUDGET = 64 * 1024 * 1024;

const toBytes = (value) => {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
};

const b64u = (bytes) => {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/gu, "");
};

const randomNonce = () => {
  const nonce = new Uint8Array(NONCE_SIZE);
  crypto.getRandomValues(nonce);
  return nonce;
};

const isValidParams = (normalizedN, normalizedK) => {
  if (!Number.isSafeInteger(normalizedN) || !Number.isSafeInteger(normalizedK)) return false;
  if (normalizedN < 8 || normalizedN > 256 || normalizedN % 2 !== 0) return false;
  if (normalizedK < 2 || normalizedK > 8) return false;
  return normalizedN % (normalizedK + 1) === 0;
};

const defaultRowsFor = (n, k) => {
  const densityExponent = n / (k + 1) + 1;
  const density = densityExponent < 53 ? 2 ** densityExponent : Infinity;
  const rowBytes = Math.ceil(n / 8) + 256;
  const budgetRows = Math.max(1, Math.floor(DEFAULT_MEMORY_BUDGET / rowBytes));
  const proofRows = 2 ** k;
  return Number.isFinite(density)
    ? Math.max(proofRows, Math.min(density, budgetRows))
    : Math.max(proofRows, budgetRows);
};

const normalizeNonceSequence = (value) => {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 1024) throw new Error("invalid nonce sequence");
  const sequence = value.map(toBytes);
  if (sequence.some((nonce) => !nonce || nonce.length !== NONCE_SIZE)) throw new Error("invalid nonce sequence");
  return sequence;
};

const normalizeParams = (n, k) => {
  const normalizedN = n === undefined ? 96 : n;
  const normalizedK = k === undefined ? 5 : k;
  if (!isValidParams(normalizedN, normalizedK)) throw new Error("invalid equihash params");
  return { n: normalizedN, k: normalizedK };
};

const normalizePolicy = (raw, n, k) => {
  if (raw !== undefined && raw !== null && (typeof raw !== "object" || Array.isArray(raw))) {
    throw new Error("invalid solve policy");
  }
  const policy = raw || {};
  // An omitted budget is intentionally unbounded; an explicit zero is an exhausted budget.
  let deadlineMs = null;
  if (Object.prototype.hasOwnProperty.call(policy, "deadlineMs")) {
    deadlineMs = policy.deadlineMs;
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 0) {
      throw new Error("invalid deadline");
    }
  }
  const rows = policy.rows === undefined ? defaultRowsFor(n, k) : policy.rows;
  if (!Number.isSafeInteger(rows) || rows <= 0 || rows > U32_MAX) throw new Error("invalid rows");
  return { deadlineMs, rows };
};

let runtime = null;
let generation = 0;
let initInFlight = null;
let activeSolve = null;
let cancelBeforeSolve = false;

const clearWasmRuntime = () => {
  runtime = null;
};

const nowMs = () => (typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now() : Date.now());

const asPointer = (value) => {
  const pointer = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(pointer) || pointer <= 0 || pointer > U32_MAX) throw new Error("wasm allocation failed");
  return pointer;
};

const instantiateSolver = async (solverWasmBytes) => {
  const bytes = toBytes(solverWasmBytes);
  if (!bytes || bytes.byteLength === 0) throw new Error("solverWasmBytes required");
  const instantiated = await WebAssembly.instantiate(bytes, {});
  const instance = instantiated && instantiated.instance ? instantiated.instance : instantiated;
  const exports = instance && instance.exports;
  if (!exports || !(exports.memory instanceof WebAssembly.Memory)) throw new Error("wasm memory export missing");
  if (typeof exports.alloc !== "function" || typeof exports.dealloc !== "function") throw new Error("wasm allocator export missing");
  if (typeof exports.solve_once !== "function") throw new Error("wasm solve_once export missing");
  if (typeof exports.required_proof_len !== "function") throw new Error("wasm required_proof_len export missing");
  return {
    memory: exports.memory,
    alloc: exports.alloc,
    dealloc: exports.dealloc,
    solveOnce: exports.solve_once,
    requiredProofLen: exports.required_proof_len,
  };
};

const emitProgress = (context, finishedAtMs, solveMs) => {
  const remainingMs = Number.isFinite(context.deadlineAtMs)
    ? Math.max(0, context.deadlineAtMs - finishedAtMs)
    : 0;
  postMessage({
    type: "PROGRESS",
    phase: "solve",
    elapsedMs: Math.max(0, finishedAtMs - context.startedAtMs),
    remainingMs,
    rows: context.runtime.rows,
    wasmMemoryBytes: context.runtime.memory.buffer.byteLength,
    solveMs,
    ewmaSolveMs: solveMs,
  });
};

const solveEquihash = async (context, data) => {
  const currentRuntime = context.runtime;
  if (runtime !== currentRuntime || generation !== context.generation) return { status: "cancelled" };
  const seed = toBytes(data.seed);
  if (!seed || seed.length !== SEED_SIZE) throw new Error("seed must be 32 bytes");
  const proofLen = Number(currentRuntime.requiredProofLen(currentRuntime.k));
  if (!Number.isSafeInteger(proofLen) || proofLen <= 0) throw new Error("invalid proof length");
  const solveDeadlineMs = data && Object.prototype.hasOwnProperty.call(data, "deadlineMs")
    ? data.deadlineMs
    : currentRuntime.deadlineMs;
  if (solveDeadlineMs !== null && (!Number.isSafeInteger(solveDeadlineMs) || solveDeadlineMs < 0)) {
    throw new Error("invalid deadline");
  }
  const deadlineAtMs = solveDeadlineMs === null
    ? Infinity
    : context.startedAtMs + solveDeadlineMs;
  context.deadlineAtMs = deadlineAtMs;
  if (nowMs() >= deadlineAtMs) return { status: "timeout" };

  const allocations = [];
  const nonceSequence = normalizeNonceSequence(data && data.nonceSequence);
  let nonceSequenceIndex = 0;
  const allocate = (size) => {
    const pointer = asPointer(currentRuntime.alloc(size, 8));
    allocations.push({ pointer, size });
    return pointer;
  };
  try {
    const seedPtr = allocate(seed.length);
    const noncePtr = allocate(NONCE_SIZE);
    const proofPtr = allocate(proofLen);
    let memoryView = new Uint8Array(currentRuntime.memory.buffer);
    memoryView.set(seed, seedPtr);

    for (;;) {
      if (context.cancelled || context.disposeRequested || runtime !== currentRuntime || generation !== context.generation) {
        return { status: "cancelled" };
      }
      const before = nowMs();
      if (before >= deadlineAtMs) return { status: "timeout" };
      const nonce = nonceSequenceIndex < nonceSequence.length
        ? nonceSequence[nonceSequenceIndex++]
        : randomNonce();
      memoryView = new Uint8Array(currentRuntime.memory.buffer);
      memoryView.set(nonce, noncePtr);
      const rc = Number(currentRuntime.solveOnce(
        seedPtr,
        seed.length,
        noncePtr,
        NONCE_SIZE,
        currentRuntime.n,
        currentRuntime.k,
        currentRuntime.rows,
        proofPtr,
        proofLen,
      ));
      const after = nowMs();
      emitProgress(context, after, Math.max(0, after - before));
      if (context.cancelled || context.disposeRequested || runtime !== currentRuntime || generation !== context.generation) {
        return { status: "cancelled" };
      }
      if (after >= deadlineAtMs) return { status: "timeout" };
      if (!Number.isInteger(rc)) throw new Error("invalid wasm result");
      if (rc < 0) throw new Error(`wasm solve_once failed: ${rc}`);
      if (rc !== 0 && rc !== proofLen) throw new Error(`invalid wasm proof length: ${rc}`);
      if (rc === proofLen) {
        memoryView = new Uint8Array(currentRuntime.memory.buffer);
        const proof = new Uint8Array(memoryView.subarray(proofPtr, proofPtr + rc));
        return { status: "solved", nonceB64: b64u(nonce), proofB64: b64u(proof) };
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  } finally {
    let releaseError = null;
    for (let i = allocations.length - 1; i >= 0; i -= 1) {
      try {
        currentRuntime.dealloc(allocations[i].pointer, allocations[i].size, 8);
      } catch (error) {
        releaseError ||= error;
      }
    }
    if (releaseError) throw releaseError;
  }
};

const sendLifecycleError = (rid, message) => postMessage({ type: "ERROR", rid, message });

const handleMessage = async (data) => {
  const type = data && data.type;
  const rid = data && data.rid;

  if (type === "CANCEL") {
    if (activeSolve) activeSolve.cancelled = true;
    else cancelBeforeSolve = true;
    postMessage({ type: "OK", rid });
    return;
  }

  if (type === "DISPOSE") {
    if (initInFlight) {
      const operation = initInFlight;
      operation.invalidated = true;
      generation += 1;
      clearWasmRuntime();
      await operation.done;
      postMessage({ type: "OK", rid });
      return;
    }
    if (activeSolve) {
      const context = activeSolve;
      context.cancelled = true;
      context.disposeRequested = true;
      generation += 1;
      await context.done;
      postMessage({ type: "OK", rid });
      return;
    }
    generation += 1;
    cancelBeforeSolve = false;
    clearWasmRuntime();
    postMessage({ type: "OK", rid });
    return;
  }

  if (type === "INIT") {
    if (activeSolve || initInFlight) {
      sendLifecycleError(rid, "worker busy");
      return;
    }
    let resolveDone;
    const operation = {
      generation: generation + 1,
      invalidated: false,
      done: new Promise((resolve) => { resolveDone = resolve; }),
      resolveDone,
    };
    generation = operation.generation;
    initInFlight = operation;
    cancelBeforeSolve = false;
    clearWasmRuntime();
    try {
      const params = normalizeParams(data.n, data.k);
      const solvePolicy = normalizePolicy(data.solvePolicy, params.n, params.k);
      const wasm = await instantiateSolver(data.solverWasmBytes);
      if (operation.invalidated || initInFlight !== operation || generation !== operation.generation) {
        throw new Error("stale initialization");
      }
      runtime = { ...wasm, ...params, ...solvePolicy, generation: operation.generation };
      initInFlight = null;
      operation.resolveDone();
      postMessage({ type: "OK", rid });
    } catch (error) {
      if (initInFlight === operation) {
        initInFlight = null;
        clearWasmRuntime();
      }
      operation.resolveDone();
      sendLifecycleError(rid, error && error.message ? error.message : String(error));
    }
    return;
  }

  if (type === "SOLVE") {
    if (activeSolve || initInFlight) {
      postMessage({ type: "OK", rid, status: "busy", message: "worker busy" });
      return;
    }
    if (!runtime) {
      postMessage({ type: "OK", rid, status: "fatal", message: "worker not initialized" });
      return;
    }
    if (cancelBeforeSolve) {
      cancelBeforeSolve = false;
      postMessage({ type: "OK", rid, status: "cancelled" });
      return;
    }
    let resolveDone;
    const context = {
      runtime,
      generation,
      startedAtMs: nowMs(),
      cancelled: false,
      disposeRequested: false,
      done: new Promise((resolve) => { resolveDone = resolve; }),
      resolveDone,
    };
    activeSolve = context;
    try {
      const result = await solveEquihash(context, data || {});
      postMessage({ type: "OK", rid, ...result });
    } catch (error) {
      const stale = context.cancelled || context.disposeRequested || runtime !== context.runtime || generation !== context.generation;
      postMessage({
        type: "OK",
        rid,
        status: stale ? "cancelled" : "fatal",
        ...(stale ? {} : { message: error && error.message ? error.message : String(error) }),
      });
    } finally {
      if (activeSolve === context) activeSolve = null;
      if (context.disposeRequested && runtime === context.runtime) clearWasmRuntime();
      context.resolveDone();
    }
    return;
  }

  sendLifecycleError(rid, "unknown command");
};

if (typeof self !== "undefined") {
  self.onmessage = (event) => {
    void handleMessage(event && event.data ? event.data : {});
  };
}

export { defaultRowsFor };
