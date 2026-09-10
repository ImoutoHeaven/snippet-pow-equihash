# Workload calibration

The default `n=144, k=7` selects 524,288 initial rows and produces a
512-byte proof. Operators select parameters through
[configuration](configuration.md). The Worker uses the full parameter-derived
population, and the Rust solver allocates intermediate tables as needed.
Browser, wasm32 address space, and device capacity determine available memory.
Allocation failures return a resource error; ticket validity bounds solving.

## Choosing parameters

Initial rows are `max(2^k, 2^(n/(k+1)+1))`. At fixed `k`, increasing `n` by
`k+1` doubles the population when that pair is valid. Changing `k` also changes
collision width, tree depth, and proof size. Measure each candidate pair on
the intended devices.

Record complete solve times across multiple independent challenges, including
nonce retries. Compare medians, tail latency, success and expiry counts, and
memory peaks. WASM linear memory measures allocated address space; page heap
and process RSS measure different scopes. Mobile qualification uses real
phones, and Cloudflare CPU qualification uses actual isolate measurements.

## Browser benchmark

[benchmark-calibration.mjs](../scripts/benchmark-calibration.mjs) serves the
real bootstrap, glue, ESM, Worker, and WASM over local HTTP. Proof submission
uses the signed `pow-config -> pow-core-1 -> pow-core-2` chain. Success requires
both server authorization and the browser's observed
`#t[data-state="success"]` transition. Full post-token time includes resource
acquisition, initialization, solving, the response body, JSON parsing, and
that completion transition. The records also separate each phase and the
server verification interval.

Each JSON record identifies the parameters, runtime, solver digest, and
measurement scope so results can be matched to the tested artifacts.

Run from the repository root with a reachable Docker daemon. The source mount
is read-only; the output directory receives the measurement file:

```bash
docker info
repo_path="$(pwd -W 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 docker run --rm --cpus=1 \
  --mount type=bind,src="$repo_path",dst=/workspace,readonly \
  --mount type=bind,src="$repo_path/docs/calibration",dst=/output \
  --workdir /workspace mcr.microsoft.com/playwright:v1.49.1-noble \
  sh -c 'npm install --silent --prefix /runtime --no-save playwright@1.49.1 && \
    CALIBRATION_PLAYWRIGHT=/runtime/node_modules/playwright/index.js \
    node --expose-gc scripts/benchmark-calibration.mjs \
    --profile docker-cpus-1 --output /output/calibration-cpus-1.json'
```

`--samples N` repeats fixtures. `--only` selects named fixtures, such as
`eq-144-7-batch-16`. CPU quotas provide controlled comparisons on the same host.
Required solve, fixed-fixture verification, or verifier failures write a JSON
record and return a nonzero exit status.
