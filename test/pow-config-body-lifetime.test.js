import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CHILD = String.raw`
import crypto from "node:crypto";
import { cp, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = ${JSON.stringify(ROOT)};
const source = await readFile(join(root, "pow-config.js"), "utf8");
const temp = await mkdtemp(join(tmpdir(), "pow-config-body-gc-"));
await mkdir(join(temp, "lib"), { recursive: true });
await cp(join(root, "lib", "rule-engine"), join(temp, "lib", "rule-engine"), { recursive: true });
await cp(join(root, "lib", "equihash"), join(temp, "lib", "equihash"), { recursive: true });
await mkdir(join(temp, "lib", "pow"), { recursive: true });
await cp(join(root, "lib", "pow", "auth-primitives.js"), join(temp, "lib", "pow", "auth-primitives.js"));

const config = {
  POW_TOKEN: "probe-secret",
  POW_EQ_N: 12,
  POW_EQ_K: 2,
  powcheck: true,
  turncheck: false,
  POW_BIND_PATH: false,
  POW_BIND_IPRANGE: false,
};
const compiled = JSON.stringify([{
  host: { kind: "eq", value: "example.com" },
  hostType: "exact",
  hostExact: "example.com",
  path: null,
  config,
}]);
await writeFile(
  join(temp, "pow-config.js"),
  source
    .replace(/__COMPILED_CONFIG__/gu, compiled)
    .replace(/const CONFIG_SECRET = "[^"]*";/u, 'const CONFIG_SECRET = "config-secret";'),
);

const mod = await import(pathToFileURL(join(temp, "pow-config.js")).href);
const originalSign = crypto.subtle.sign.bind(crypto.subtle);
crypto.subtle.sign = async (...args) => {
  globalThis.gc();
  await new Promise((resolve) => setImmediate(resolve));
  return originalSign(...args);
};
globalThis.fetch = async () => new Response("ok", { status: 200 });
const response = await mod.default.fetch(new Request("https://example.com/__pow/verify", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: "{}",
}));
if (response.status !== 200) throw new Error("unexpected response status: " + response.status);
`;

test("pow-config keeps a verify request body alive through signing", () => {
  const result = spawnSync(process.execPath, ["--expose-gc", "--input-type=module", "-e", CHILD], {
    cwd: ROOT,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
