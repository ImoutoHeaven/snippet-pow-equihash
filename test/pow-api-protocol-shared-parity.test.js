import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  encodePowTicket,
  parsePowTicket,
  makePowBindingString,
  hmacSha256Base64UrlNoPad,
  makeConsumeMac,
  makeProofMac,
  verifyTicketMac,
} from "../lib/pow/api-protocol-shared.js";

const withGlobals = () => {
  const previous = { crypto: globalThis.crypto, btoa: globalThis.btoa, atob: globalThis.atob };
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  const didSetCrypto = !globalThis.crypto && (!cryptoDescriptor || cryptoDescriptor.writable || typeof cryptoDescriptor.set === "function");
  if (didSetCrypto) Object.defineProperty(globalThis, "crypto", { value: crypto.webcrypto, configurable: true });
  if (!globalThis.btoa) globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  if (!globalThis.atob) globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  return () => {
    for (const [key, value] of Object.entries(previous)) {
      if (key === "crypto" && !didSetCrypto) continue;
      if (value === undefined) delete globalThis[key];
      else globalThis[key] = value;
    }
  };
};

const ticket = {
  v: 5,
  e: 1700000200,
  cfgId: 7,
  issuedAt: 1700000000,
  r: "AAECAwQFBgcICQoLDA0ODw",
  n: 12,
  k: 2,
  m: 1,
  mac: "A".repeat(43),
};

const bindings = {
  pathHash: "p_hash_123",
  ipScope: "1.2.3.4/32",
  country: "US",
  asn: "12345",
  tlsFingerprint: "tlsv1",
};

test("ticket encoding retains the canonical nine-field v5 envelope", () => {
  const encoded = encodePowTicket(ticket);
  assert.deepEqual(parsePowTicket(encoded), ticket);
  assert.equal(parsePowTicket(""), null);
  assert.equal(parsePowTicket("###"), null);
  assert.equal(parsePowTicket("MS4xLjEuYS4xLjEuYS4x"), null);
  assert.equal(parsePowTicket(`${encoded}=`), null);
});

test("binding canonicalization and ticket MAC bind host and policy values", async () => {
  const restore = withGlobals();
  try {
    const binding = makePowBindingString(ticket, "Example.COM", ...Object.values(bindings));
    const decoded = JSON.parse(binding);
    assert.equal(decoded[0], "equihash-ticket-v5");
    assert.equal(decoded[9], "example.com");
    assert.equal(decoded[10], bindings.pathHash);
    const mac = await hmacSha256Base64UrlNoPad("pow-secret-1", binding);
    const signed = { ...ticket, mac };
    const url = new URL("https://example.com/protected");
    assert.equal(await verifyTicketMac(signed, url, bindings, { POW_EQ_N: 12, POW_EQ_K: 2 }, "pow-secret-1"), binding);
    assert.equal(await verifyTicketMac(signed, url, { ...bindings, pathHash: "changed" }, { POW_EQ_N: 12, POW_EQ_K: 2 }, "pow-secret-1"), "");
  } finally {
    restore();
  }
});

test("consume and proof MACs are deterministic and mutation-sensitive", async () => {
  const restore = withGlobals();
  try {
    const consume = await makeConsumeMac("secret", "ticket", 1700000100, "any", 2);
    assert.equal(consume, await makeConsumeMac("secret", "ticket", 1700000100, "any", 2));
    assert.notEqual(consume, await makeConsumeMac("secret", "ticket", 1700000101, "any", 2));
    const proof = await makeProofMac("secret", "ticket", 10, 11, 0, 2);
    assert.equal(proof, await makeProofMac("secret", "ticket", 10, 11, 0, 2));
    assert.notEqual(proof, await makeProofMac("secret", "ticket", 10, 12, 0, 2));
  } finally {
    restore();
  }
});
