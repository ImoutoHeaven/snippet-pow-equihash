# snippet-pow-equihash

An Equihash v5 access gate for Cloudflare Snippets. Browsers solve a challenge
with a Rust/WASM Worker and submit a compact proof. Route rules select
Equihash, Turnstile, combined checks, atomic consumption, or bypass.

- [Configuration](docs/configuration.md): rules, bindings, credentials, and authorization modes.
- [Calibration](docs/calibration.md): workload selection and benchmark reproduction.

## Build

Use Node.js `22.20.0` and the dependency versions in `package-lock.json`:

```bash
npm ci
npm run build
npm test
```

The build writes three minified Snippets to `dist/` and fails when any file
exceeds **32,768 bytes**. Configure the deployment's rules and secrets before
building its artifacts.

## Solver and release checks

`npm run build:solver` builds `equihash-solver/` with Rust `1.96.0`, the
`wasm32-unknown-unknown` target, and `Cargo.lock`. It writes the browser
artifact to `esm/solver.wasm` and a hash-named copy to `equihash-solver/dist/`.

`npm run check:release` checks a checkout with the empty `CONFIG` rule list.
It rebuilds WASM, requires byte equality with the checked-in artifact, builds
empty and representative rule configurations, restores the empty-rule build,
and runs the full test suite. Required solver fixtures must return a valid proof. CI runs this
entry point with the locked Rust and Node versions.

## Deploy

1. Set the same `CONFIG_SECRET` in `pow-config.js`, `pow-core-1.js`, and
   `pow-core-2.js`. Set route secrets and rules as described in the
   [configuration guide](docs/configuration.md).
2. Build and deploy the Snippets in order:
   `pow-config -> pow-core-1 -> pow-core-2`.
3. The default browser resource URLs point to this repository's `main` branch
   on jsDelivr. For self-hosting, set `POW_GLUE_URL` and `POW_ESM_URL` to
   matching published release URLs, then host `glue.js`, `esm/esm.js`,
   `esm/equihash-worker.js`, and `esm/solver.wasm` together. Serve JavaScript
   with a JavaScript MIME type and WASM with `application/wasm`. A separate
   self-hosted asset hostname needs CORS access for the protected origin.

`pow-config` selects rules and signs request metadata. `pow-core-1` issues
challenges and gates business requests. `pow-core-2` handles
`POST ${POW_API_PREFIX}/verify` and authenticated forwarding. The ESM entry
resolves Worker and WASM URLs relative to its own URL; keep those files
together when using versioned resource paths.

Browser resources must be reachable under the configured route policy. The
configuration example places explicit resource rules before its protected
catch-all. Device costs and Cloudflare runtime qualification are described
with their measurement scope in the calibration guide.
