import { blake2b } from "./blake2b.js";
import { isValidEquihashParams } from "./params.js";

const encoder = new TextEncoder();
const strictInt = (value) => {
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : null;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
};

const toBytes = (value) => {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
};

const u32be = (bytes, offset) =>
  ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;

const readBit = (bytes, index) => (bytes[index >> 3] >> (7 - (index & 7))) & 1;

const bitsAsBigInt = (bytes, start, length) => {
  let value = 0n;
  for (let i = 0; i < length; i += 1) value = (value << 1n) | BigInt(readBit(bytes, start + i));
  return value;
};

const makePersonalization = (n, k) => {
  const out = new Uint8Array(16);
  out.set(encoder.encode("ZcashPoW"));
  const view = new DataView(out.buffer);
  view.setUint32(8, n >>> 0, true);
  view.setUint32(12, k >>> 0, true);
  return out;
};

const parseIndices = (proof, count) => {
  const bytes = toBytes(proof);
  if (!bytes || bytes.length !== count * 4) return null;
  const out = new Array(count);
  for (let i = 0; i < count; i += 1) out[i] = u32be(bytes, i * 4);
  return out;
};

const hashIndexBits = (seed, nonce, index, n, personalization) => {
  const input = new Uint8Array(seed.length + nonce.length + 4);
  input.set(seed);
  input.set(nonce, seed.length);
  const offset = seed.length + nonce.length;
  input[offset] = index >>> 24;
  input[offset + 1] = index >>> 16;
  input[offset + 2] = index >>> 8;
  input[offset + 3] = index;
  return blake2b(input, Math.ceil(n / 8), { personalization });
};

const sameIndex = (left, right) => {
  for (const value of left) if (right.includes(value)) return true;
  return false;
};

export const verifyEquihashDetailed = (input) => {
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return { ok: false, reason: "input" };
    const n = strictInt(input.n);
    const k = strictInt(input.k);
    if (!isValidEquihashParams(n, k)) return { ok: false, reason: "params" };
    const seed = toBytes(input.seed);
    const nonce = toBytes(input.nonce);
    if (!seed || seed.length !== 32) return { ok: false, reason: "seed" };
    if (!nonce || nonce.length !== 24) return { ok: false, reason: "nonce" };

    const collisionBits = n / (k + 1);
    const count = 2 ** k;
    const indices = parseIndices(input.proof, count);
    if (!indices) return { ok: false, reason: "proof_length" };
    if (new Set(indices).size !== indices.length) return { ok: false, reason: "duplicate_index" };

    const personalization = makePersonalization(n, k);
    let layer = indices.map((index) => ({ bits: hashIndexBits(seed, nonce, index, n, personalization), first: index, indices: [index] }));
    let bitLength = n;
    for (let round = 0; round < k; round += 1) {
      if (layer.length === 0 || layer.length % 2 !== 0) return { ok: false, reason: "layer" };
      const next = [];
      const shift = bitLength - collisionBits;
      for (let i = 0; i < layer.length; i += 2) {
        const left = layer[i];
        const right = layer[i + 1];
        if (bitsAsBigInt(left.bits, 0, collisionBits) !== bitsAsBigInt(right.bits, 0, collisionBits)) {
          return { ok: false, reason: "collision" };
        }
        // Canonical order is local to each subtree. A flat global sort would reject valid tree layouts.
        if (left.first >= right.first || sameIndex(left.indices, right.indices)) {
          return { ok: false, reason: "subtree_order" };
        }
        const xorBytes = new Uint8Array(Math.ceil(shift / 8));
        for (let bit = 0; bit < shift; bit += 1) {
          const value = readBit(left.bits, collisionBits + bit) ^ readBit(right.bits, collisionBits + bit);
          if (value) xorBytes[bit >> 3] |= 1 << (7 - (bit & 7));
        }
        next.push({ bits: xorBytes, first: left.first, indices: left.indices.concat(right.indices) });
      }
      layer = next;
      bitLength = shift;
    }
    const final = layer[0];
    if (!final || final.bits.some((byte) => byte !== 0) || final.indices.length !== count) return { ok: false, reason: "final_xor" };
    return { ok: true, indices };
  } catch {
    return { ok: false, reason: "exception" };
  }
};

export const verifyEquihash = (input) => verifyEquihashDetailed(input).ok;
