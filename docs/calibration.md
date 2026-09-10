# Default calibration

The default `n=96, k=5` uses a 131,072-row solver population. Its workload
targets are approximately three seconds on a desktop and fifteen seconds on
a phone. Ticket validity controls execution; operators select parameters
through [configuration](configuration.md).

## Measurements

The records use an AMD Ryzen 7 7700 host, with 8 logical CPUs and 15.2 GiB
visible to Docker, Node.js `v22.12.0`, and Chromium `131.0.6778.33` from
`mcr.microsoft.com/playwright:v1.49.1-noble`. The one-CPU profile is the desktop
container measurement. The 0.2-CPU profile throttles the whole container and
provides a mobile cost estimate. Real-phone performance and Cloudflare isolate
CPU/allocation qualification require measurements on those platforms.

| Profile | Default samples | Solve median / P95 | Full post-token median / P95 | Success / expiry / fatal |
| --- | ---: | ---: | ---: | ---: |
| Docker 1 CPU | 16 | 1,335.45 / 2,307 ms | 1,398.4 / 2,410.4 ms | 16 / 0 / 0 |
| Docker 0.2 CPU | 16 | 7,150 / 13,404.9 ms | 7,695.1 / 14,301.2 ms | 16 / 0 / 0 |

Both profiles use the same sixteen fixed routes, configuration IDs 16–31,
and nonce attempts 0 and 1. The first route is cold and the remaining routes
are warm. WASM linear memory is 43,057,152 bytes at the median and
60,555,264 bytes at P95 in both profiles. Page heap and server RSS are
separate process measurements in the records.

Each comparison pair has one browser sample per profile:

| Pair | 1 CPU solve / full post-token | 0.2 CPU solve / full post-token |
| --- | ---: | ---: |
| `90/5` | 701.6 / 797.9 ms | 3,399.5 / 3,896.7 ms |
| `84/5` | 377.2 / 411.1 ms | 1,506.8 / 2,292.6 ms |
| `102/5` | 1,996 / 2,084 ms | 11,298.3 / 11,794.1 ms |
| `28/3` | 2.4 / 92.8 ms | 2.2 / 592.2 ms |
| `112/6` | 1,716.2 / 1,801 ms | 10,302 / 10,800.6 ms |

All comparison samples produced server-verifiable proofs. The resource probes
select 249,475 of a 262,144-row density target for `102/5`, and 248,551 of
524,288 rows for `108/5`. The eight fixed `108/5` probes yielded zero proofs
in each profile. These observations bound the evidence for larger parameters.

## Verifier scope

The local Node verifier measurements use a fixed 128-byte browser proof and
twenty warm calls per profile:

| Metric | 1 CPU | 0.2 CPU |
| --- | ---: | ---: |
| Cold module import | 29.39 ms | 13.73 ms |
| First verification | 3.22 ms | 4.06 ms |
| Warm wall median / P95 | 1.77 / 1.97 ms | 1.88 / 96.6 ms |
| Warm process CPU median / P95 | 3.89 / 6.71 ms | 5.48 / 6.29 ms |
| Maximum observed net live-heap delta | 3,871,968 B | 1,784,888 B |

Wall time measures elapsed verification time. Process CPU includes Node JIT
and background-thread activity. The heap delta measures live allocation
around a call; peak allocation requires separate instrumentation. Comparisons
with the record's 5 ms reference apply to each named local metric. Cloudflare
budget qualification uses actual isolate measurements.

## Benchmark and records

[benchmark-calibration.mjs](../scripts/benchmark-calibration.mjs) serves the
real bootstrap, glue, ESM, Worker, and WASM over local HTTP. Proof submission
uses the signed `pow-config -> pow-core-1 -> pow-core-2` chain. Success requires
both server authorization and the browser's observed
`#t[data-state="success"]` transition. Full post-token time includes resource
acquisition, initialization, solving, the response body, JSON parsing, and
that completion transition. The records also separate each phase and the
server verification interval.

- [One-CPU record](calibration/calibration-cpus-1.json)
- [0.2-CPU record](calibration/calibration-cpus-0.2.json)

These records contain the proofs, seeds, nonces, timing distributions, resource
observations, and a fixed `12/2` proof-verification fixture. The checked-in
solver SHA-256 is
`ec6e3f35fa7627a276001e28bf37e178c745c8808c8081677553d9a73f31bab7`.

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

For the proxy, set Docker's `--cpus` to `0.2`, the script's `--profile` to
`docker-cpus-0.2`, and its output filename to `calibration-cpus-0.2.json`.
`--only` selects named fixtures, including ten additional `96/5` regressions.
Required solve, fixed-fixture verification, or verifier failures write a JSON
record and return a nonzero exit status.
