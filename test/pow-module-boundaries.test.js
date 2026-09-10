import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

const readPowSource = (name) => readFile(join(repoRoot, "lib", "pow", name), "utf8");

test("auth modules import shared auth primitives", async () => {
  const [innerAuthSource, transitAuthSource] = await Promise.all([
    readPowSource("inner-auth.js"),
    readPowSource("transit-auth.js"),
  ]);

  assert.match(innerAuthSource, /from "\.\/auth-primitives\.js";/u);
  assert.match(transitAuthSource, /from "\.\/auth-primitives\.js";/u);
});

test("verify API imports shared protocol helpers", async () => {
  const [apiEngineSource, sharedSource] = await Promise.all([
    readPowSource("api-engine.js"),
    readPowSource("api-protocol-shared.js"),
  ]);

  assert.match(apiEngineSource, /from "\.\/api-protocol-shared\.js";/u);
  assert.match(sharedSource, /verifyRequiredCaptchaForTicket/u);
  assert.doesNotMatch(apiEngineSource, /lib\/mhg|hashcash|sample/u);
});

test("inner and transit auth do not define prohibited auth helper implementations", async () => {
  const [innerAuthSource, transitAuthSource] = await Promise.all([
    readPowSource("inner-auth.js"),
    readPowSource("transit-auth.js"),
  ]);

  const prohibitedDefinitions = [
    /\bbase64UrlEncodeNoPad\s*=\s*/u,
    /\btimingSafeEqual\s*=\s*/u,
    /\bgetHmacKey\s*=\s*/u,
    /\bhmacSha256Base64UrlNoPad\s*=\s*/u,
  ];

  for (const pattern of prohibitedDefinitions) {
    assert.doesNotMatch(innerAuthSource, pattern);
    assert.doesNotMatch(transitAuthSource, pattern);
  }
});
