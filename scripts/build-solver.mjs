import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const solverDir = resolve(repoRoot, "equihash-solver");
const manifest = resolve(solverDir, "Cargo.toml");
const wasm = resolve(solverDir, "target", "wasm32-unknown-unknown", "release", "equihash_solver.wasm");
const dist = resolve(solverDir, "dist");
const runtime = resolve(repoRoot, "esm", "solver.wasm");

const rustup = spawnSync("rustup", ["target", "list", "--installed"], { cwd: solverDir, encoding: "utf8" });
if (rustup.error?.code === "ENOENT") {
  throw new Error("rustup is required to build the solver");
}
if (rustup.status !== 0 || !rustup.stdout.includes("wasm32-unknown-unknown")) {
  throw new Error("missing Rust target wasm32-unknown-unknown; run rustup target add wasm32-unknown-unknown");
}
const toolchain = spawnSync("rustup", ["show", "active-toolchain"], { cwd: solverDir, encoding: "utf8" });
if (toolchain.status !== 0 || !/^1\.96\.0(?:[-\s]|$)/u.test(toolchain.stdout.trim())) {
  throw new Error("solver build requires Rust toolchain 1.96.0");
}

const build = spawnSync("cargo", ["build", "--locked", "--manifest-path", manifest, "--target", "wasm32-unknown-unknown", "--release"], {
  cwd: solverDir,
  stdio: "inherit",
});
if (build.status !== 0) throw new Error("failed to build solver wasm artifact");

const bytes = await readFile(wasm);
if (!bytes.length || bytes[0] !== 0 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
  throw new Error(`invalid wasm output: ${wasm}`);
}
const digest = createHash("sha256").update(bytes).digest("hex").slice(0, 12);
await mkdir(dist, { recursive: true });
await mkdir(dirname(runtime), { recursive: true });
await writeFile(resolve(dist, `equihash_solver.${digest}.wasm`), bytes);
await writeFile(runtime, bytes);
console.log(`Built solver wasm ${bytes.length}B (${digest})`);
