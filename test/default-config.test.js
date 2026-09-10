import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { __testNormalizeConfig } from "../pow-config.js";

test("normalizeConfig exposes the preserved gate, binding, renewal, and transport surface", () => {
  const config = __testNormalizeConfig({});
  assert.equal(config.powcheck, false);
  assert.equal(config.turncheck, false);
  assert.equal(config.POW_VERSION, 5);
  assert.equal(config.POW_API_PREFIX, "/__pow");
  assert.equal(config.POW_EQ_N, 96);
  assert.equal(config.POW_EQ_K, 5);
  assert.equal(config.POW_ESM_URL, "/esm/esm.js");
  assert.equal(config.POW_TICKET_TTL_SEC, 600);
  assert.equal(config.PROOF_TTL_SEC, 600);
  assert.equal(config.PROOF_RENEW_ENABLE, false);
  assert.equal(config.ATOMIC_CONSUME, false);
  assert.equal(config.ATOMIC_TURN_QUERY, "__ts");
  assert.equal(config.ATOMIC_TICKET_QUERY, "__tt");
  assert.equal(config.ATOMIC_CONSUME_QUERY, "__ct");
  assert.equal(config.ATOMIC_TURN_HEADER, "x-turnstile");
  assert.equal(config.ATOMIC_TICKET_HEADER, "x-ticket");
  assert.equal(config.ATOMIC_CONSUME_HEADER, "x-consume");
  assert.equal(config.ATOMIC_COOKIE_NAME, "__Secure-pow_a");
});

test("normalizeConfig removes retired kernel and exchange settings", () => {
  const config = __testNormalizeConfig({
    POW_DIFFICULTY_BASE: 1,
    POW_DIFFICULTY_COEFF: 2,
    POW_MIN_STEPS: 1,
    POW_MAX_STEPS: 2,
    POW_HASHCASH_X: 3,
    POW_PAGE_BYTES: 64,
    POW_MIX_ROUNDS: 2,
    POW_SEGMENT_LEN: 2,
    POW_SAMPLE_RATE: 0.5,
    POW_OPEN_BATCH: 4,
    POW_COMMIT_TTL_SEC: 120,
    POW_MAX_GEN_TIME_SEC: 300,
    POW_ESM_URL: "https://example.com/esm.js",
  });
  for (const key of [
    "POW_DIFFICULTY_BASE",
    "POW_DIFFICULTY_COEFF",
    "POW_MIN_STEPS",
    "POW_MAX_STEPS",
    "POW_HASHCASH_X",
    "POW_PAGE_BYTES",
    "POW_MIX_ROUNDS",
    "POW_SEGMENT_LEN",
    "POW_SAMPLE_RATE",
    "POW_OPEN_BATCH",
    "POW_COMMIT_TTL_SEC",
    "POW_MAX_GEN_TIME_SEC",
  ]) assert.equal(key in config, false, `${key} must stay out of normalized config`);
});

test("normalizeConfig keeps Turnstile and provider configuration strict", () => {
  const config = __testNormalizeConfig({
    turncheck: true,
    TURNSTILE_SITEKEY: "site-key",
    TURNSTILE_SECRET: "turn-secret",
    SITEVERIFY_URLS: ["https://one.example", " https://two.example ", "", 3],
    SITEVERIFY_AUTH_KID: 12,
    SITEVERIFY_AUTH_SECRET: "provider-secret",
    POW_TOKEN: 7,
  });
  assert.equal(config.turncheck, true);
  assert.equal(config.TURNSTILE_SITEKEY, "site-key");
  assert.equal(config.TURNSTILE_SECRET, "turn-secret");
  assert.deepEqual(config.SITEVERIFY_URLS, ["https://one.example", "https://two.example"]);
  assert.equal(config.SITEVERIFY_AUTH_KID, "v1");
  assert.equal(config.POW_TOKEN, undefined);
});

test("normalizeConfig rejects malformed operator Equihash pairs", () => {
  assert.throws(() => __testNormalizeConfig({ POW_EQ_N: 91, POW_EQ_K: 5 }), /invalid equihash params/u);
  assert.throws(() => __testNormalizeConfig({ POW_EQ_N: 90, POW_EQ_K: 7 }), /invalid equihash params/u);
});

test("pow-config source has no retired protocol route or setting names", async () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const source = await readFile(join(root, "pow-config.js"), "utf8");
  assert.doesNotMatch(source, /POW_(?:DIFFICULTY|MIN_STEPS|MAX_STEPS|HASHCASH|PAGE_BYTES|MIX_ROUNDS|SEGMENT|SAMPLE|OPEN|COMMIT|MAX_GEN)/u);
  assert.doesNotMatch(source, /["'`]\/(?:commit|challenge|open)(?:["'`])/u);
});
