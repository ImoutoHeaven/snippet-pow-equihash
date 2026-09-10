import { createHash } from "node:crypto";
import { readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WASM_PATH = join(ROOT, "esm", "solver.wasm");
const HARD_LIMIT = 32 * 1024;
const SNIPPETS = [
  "pow_config_snippet.js",
  "pow_core1_snippet.js",
  "pow_core2_snippet.js",
];

const runNode = (args, extraEnv = {}) => {
  const result = spawnSync(process.execPath, args, {
    cwd: ROOT,
    stdio: "inherit",
    env: { ...process.env, ...extraEnv },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${args.join(" ")} exited with status ${result.status}`);
};

const solverDigest = (bytes) => createHash("sha256").update(bytes).digest("hex");

const checkSnippetSizes = async (label) => {
  const sizes = {};
  for (const name of SNIPPETS) {
    const size = (await stat(join(ROOT, "dist", name))).size;
    if (size > HARD_LIMIT) throw new Error(`${label} ${name} is ${size} bytes; limit is ${HARD_LIMIT}`);
    sizes[name] = size;
  }
  console.log(`${label} snippet sizes: ${JSON.stringify(sizes)}`);
};

const makeRepresentativeConfig = (source) => {
  const marker = "const CONFIG = [];";
  if (!source.includes(marker)) throw new Error(`release representative config marker missing: ${marker}`);
  const rules = `const CONFIG = [
  { host: { eq: "example.com" }, path: { eq: "/glue.js" }, config: { powcheck: false, turncheck: false } },
  { host: { eq: "example.com" }, path: { glob: "/esm/**" }, config: { powcheck: false, turncheck: false } },
  {
    host: { eq: "example.com" },
    path: { glob: "/**" },
    when: { method: { in: ["GET", "POST"] } },
    config: {
      POW_TOKEN: "release-secret",
      powcheck: true,
      turncheck: true,
      POW_GLUE_URL: "/glue.js",
      POW_ESM_URL: "/esm/esm.js",
      POW_BIND_PATH: true,
      bindPathMode: "header",
      bindPathHeaderName: "x-release-path",
      stripBindPathHeader: true,
      TURNSTILE_SITEKEY: "release-sitekey",
      TURNSTILE_SECRET: "release-turn-secret",
      SITEVERIFY_URLS: ["https://provider.example/siteverify"],
      SITEVERIFY_AUTH_KID: "v1",
      SITEVERIFY_AUTH_SECRET: "release-provider-secret",
      ATOMIC_CONSUME: true,
      AGGREGATOR_POW_ATOMIC_CONSUME: true,
    },
  },
];`;
  return source.replace(marker, rules);
};

const shipped = new Uint8Array(await readFile(WASM_PATH));
const shippedDigest = solverDigest(shipped);
runNode(["scripts/build-solver.mjs"]);
const rebuilt = new Uint8Array(await readFile(WASM_PATH));
const rebuiltDigest = solverDigest(rebuilt);
if (!Buffer.from(shipped).equals(Buffer.from(rebuilt))) {
  throw new Error(`solver.wasm changed during locked rebuild (${shippedDigest} -> ${rebuiltDigest})`);
}
console.log(`Rebuilt solver.wasm matches shipped artifact: ${rebuilt.length}B sha256=${rebuiltDigest}`);

runNode(["build.mjs"]);
await checkSnippetSizes("default");

const configPath = join(ROOT, `.release-config-${process.pid}.js`);
try {
  const configSource = await readFile(join(ROOT, "pow-config.js"), "utf8");
  await writeFile(configPath, makeRepresentativeConfig(configSource), "utf8");
  runNode(["build.mjs"], { POW_CONFIG_SOURCE: configPath });
  await checkSnippetSizes("representative");
} finally {
  await rm(configPath, { force: true });
}

runNode(["build.mjs"]);
await checkSnippetSizes("default-restored");
runNode(["--test", "--test-concurrency=1"]);
console.log("Release checks passed: locked WASM rebuild, real artifact/mode tests, default and representative snippet budgets.");
