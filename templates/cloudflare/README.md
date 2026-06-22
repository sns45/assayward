# assayward-gate — Cloudflare Workers template

A Cloudflare Workers trust gate that evaluates supply-chain trust policies
using the assayward wasm policy engine at the edge.

This template is a thin HTTP shim. All policy logic lives in the wasm core;
the Worker only routes requests and maps results to HTTP status codes.

---

## Quick start

### 1. Build the wasm artifacts

From the repo root:

```sh
make wasm
# produces dist/assayward_js.wasm and dist/wasm_exec.js
```

### 2. Copy assets into this template

```sh
cd templates/cloudflare
bun run assets:copy
# copies dist/assayward_js.wasm -> assets/assayward_js.wasm
# copies dist/wasm_exec.js      -> assets/wasm_exec.js
```

### 3. Install dependencies

```sh
bun install
```

### 4. Run locally

```sh
bun run dev
# wraps: wrangler dev
```

### 5. Type-check

```sh
bun run typecheck
# wraps: tsc --noEmit
```

### 6. Run tests

```sh
bun test
# wraps: vitest run (via @cloudflare/vitest-pool-workers)
```

### 7. Deploy

```sh
bun run deploy
# wraps: wrangler deploy
# requires: wrangler login (or CLOUDFLARE_API_TOKEN env var)
```

---

## `/verify` contract

### Request

```
POST /verify
Content-Type: application/json

{
  "evidence":   <Evidence object>,
  "policy":     "<TrustPolicy YAML or JSON string>",
  "trustRoots": <TrustRoots object, optional>,
  "now":        "<RFC3339 timestamp, optional, defaults to current time>"
}
```

The `Evidence`, `TrustRoots`, and `Decision` types are defined in
`src/types.ts` and mirror `surfaces/npm/src/types.ts` and
`pkg/core/model.go`.

### Responses

| Status | Condition |
|--------|-----------|
| 200 | `result: "allow"` or `result: "audit"` |
| 400 | Malformed JSON, missing required fields, or wasm policy parse error |
| 403 | `result: "deny"` |
| 404 | Unknown path |
| 405 | Wrong HTTP method |
| 503 | Wasm runtime failed to initialize (see response body) |

The response body for 200 and 403 is always the full `Decision` object:

```json
{
  "result":    "allow",
  "policy":    "serverless-edge@v1alpha1",
  "reasons":   [{ "code": "...", "severity": "...", "detail": "...", "met": true }],
  "evidence":  { "image": {...}, "attestationTypes": [...], "identityPresent": true },
  "decidedAt": "2026-01-01T00:00:00Z"
}
```

---

## Decision-5 caveat: signature verification at the edge

**tl;dr**: If your policy sets `signature.required: true`, the edge gate
will always return HTTP 403 with `SIGNATURE_VERIFICATION_UNAVAILABLE`.
This is correct, fail-closed behavior, not a bug.

**Why**: The assayward wasm binary is compiled with `GOOS=js GOARCH=wasm`.
The signature verification implementation (`sigstore-go`, `in-toto-golang`)
imports unix-only syscalls that cannot be compiled to wasm. The wasm build
links a fail-closed stub that returns `Verified=false` for every attestation.

**Consequence**: `signature.required: true` always produces `deny` in wasm.

**For full signature verification, use**:
- The native CLI: `assayward verify --policy ... --evidence ...`
- The webhook integration: the webhook handler runs the native binary,
  which includes the real sigstore verifier.

**What the edge gate is best for**:
- Workload identity validation (SPIFFE/JWT)
- SLSA provenance level checks
- SBOM presence and completeness
- VEX status evaluation
- Any policy where `signature.required: false` (the default)

The `serverless-edge` built-in policy (`pkg/core/policy/builtin/serverless-edge.yaml`)
is designed for this: it sets `signature.required: false` and relies on
identity + attestation types instead.

---

## Wasm asset binding: how it works

Workers do not natively support Go's js/wasm ABI (which is not the
WebAssembly Component Model). This template uses two wrangler bindings:

| Binding | Type | Purpose |
|---------|------|---------|
| `ASSAYWARD_WASM` | `data_blobs` | The wasm binary as an `ArrayBuffer` |
| `WASM_EXEC_JS` | `text_blobs` | The Go runtime glue as a string |

At runtime, the Worker:
1. Calls `new Function(WASM_EXEC_JS)()` to register `globalThis.Go`
2. Calls `WebAssembly.instantiate(ASSAYWARD_WASM, go.importObject)`
3. Calls `go.run(instance)` (fire-and-forget; Go's `select{}` keeps it alive)
4. Yields one microtask tick for the Go scheduler to register `globalThis.assayEvaluate`
5. Caches `assayEvaluate` for the lifetime of the isolate

The `nodejs_compat` compatibility flag is required so that `wasm_exec.js`
can access `process`, `Buffer`, and other Node.js globals.

See `src/wasm-loader.ts` for implementation details and known caveats.

---

## Go wasm in workerd: status

The Go js/wasm ABI in Cloudflare Workers workerd has not been formally
verified by Cloudflare as a supported pattern. The approach used here
(`text_blobs` + `eval()` + `nodejs_compat`) follows the same pattern
used successfully by the npm wrapper (`surfaces/npm/src/index.ts`).

If `wrangler dev` or the vitest tests return HTTP 503 from the Worker,
check the Worker log output for the exact error (e.g. a missing global
or unsupported feature in workerd). The Worker logs all wasm init errors
to the response body for debuggability.

Common blockers and workarounds:

| Error | Cause | Fix |
|-------|-------|-----|
| `globalThis.Go not found` | WASM_EXEC_JS binding is empty/missing | Run `bun run assets:copy` |
| `assayEvaluate not registered` | Wrong wasm build (wasip1 not js) | Rebuild with `make wasm` |
| `require is not defined` | nodejs_compat missing | Add `nodejs_compat` to wrangler.jsonc |
| `Cannot read properties of undefined (reading 'fs')` | nodejs_compat `fs` stub incomplete | Use `nodejs_compat_v2` flag (wrangler 3.72+) |

---

## Project structure

```
templates/cloudflare/
  wrangler.jsonc         Worker config (bindings, compat flags)
  package.json           Scripts and devDependencies
  tsconfig.json          TypeScript config for Workers
  vitest.config.ts       vitest-pool-workers config
  .gitignore
  README.md              This file
  assets/                Wasm artifacts (git-ignored, copy via assets:copy)
    assayward_js.wasm    Go js/wasm binary (from make wasm)
    wasm_exec.js         Go runtime glue (from make wasm)
  src/
    index.ts             fetch handler (POST /verify gate)
    wasm-loader.ts       Go wasm initialization for Workers
    types.ts             TypeScript types (mirrors surfaces/npm/src/types.ts)
  test/
    gate.test.ts         vitest-pool-workers integration tests
```
