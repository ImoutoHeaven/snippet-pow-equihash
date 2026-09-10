import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { runBuild, distDir, repoRoot } from "../lib/build-lock.js";

const HARD_LIMIT = 32 * 1024;
const splitSnippets = [
  { file: "pow_config_snippet.js", token: "__COMPILED_CONFIG__" },
  { file: "pow_core1_snippet.js", token: "__HTML_TEMPLATE__" },
  { file: "pow_core2_snippet.js", token: "__HTML_TEMPLATE__" },
];

const powConfigSnippet = join(distDir, splitSnippets[0].file);
const powCore1Snippet = join(distDir, splitSnippets[1].file);
const powCore2Snippet = join(distDir, splitSnippets[2].file);
const legacyPowSnippet = join(distDir, "pow_snippet.js");

test("build emits pow-config and split core snippets", async () => {
  await runBuild({ cleanDist: true });

  const snippetStats = await Promise.all(
    splitSnippets.map(async ({ file }) => ({
      file,
      info: await stat(join(distDir, file)),
    }))
  );
  for (const { file, info } of snippetStats) {
    assert.ok(info.size > 0, `${file} is empty`);
    assert.ok(info.size <= HARD_LIMIT, `${file} exceeds 32KiB hard limit (${info.size}B)`);
  }

  await writeFile(legacyPowSnippet, "// stale artifact\n", "utf8");
  await runBuild();
  await assert.rejects(
    stat(legacyPowSnippet),
    { code: "ENOENT" },
    "legacy pow_snippet.js should be absent after build"
  );

  const snippetSources = await Promise.all(
    splitSnippets.map(async ({ file, token }) => ({
      file,
      token,
      source: await readFile(join(distDir, file), "utf8"),
    }))
  );
  for (const { file, token, source } of snippetSources) {
    assert.ok(!source.includes("__COMPILED_CONFIG__"), `${file} still contains config placeholder`);
    assert.ok(!source.includes(token), `${file} still contains inline placeholder ${token}`);
  }

  const probeDir = await mkdtemp(join(tmpdir(), "pow-build-crypto-"));
  const previousConfigSource = process.env.POW_CONFIG_SOURCE;
  try {
    const probe = join(probeDir, "config.js");
    const cryptoModule = join(repoRoot, "lib/equihash/blake2b.js").replaceAll("\\", "/");
    await writeFile(probe, `const CONFIG = [];\nexport { blake2b } from ${JSON.stringify(cryptoModule)};\n`);
    process.env.POW_CONFIG_SOURCE = probe;
    await runBuild();
    const built = await readFile(powConfigSnippet, "utf8");
    const { blake2b } = await import(`data:text/javascript;base64,${Buffer.from(built).toString("base64")}`);
    assert.equal(Buffer.from(blake2b("abc")).toString("hex"),
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
  } finally {
    if (previousConfigSource === undefined) delete process.env.POW_CONFIG_SOURCE;
    else process.env.POW_CONFIG_SOURCE = previousConfigSource;
    await rm(probeDir, { recursive: true, force: true });
    await runBuild();
  }
});
