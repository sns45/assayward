# assayward Wasm ABI

## Overview

The `core/wasm` package compiles to two Wasm modules:

| Module | Target | File |
|--------|--------|------|
| `assayward.wasm` | `GOOS=wasip1 GOARCH=wasm` | stdin/stdout ABI |
| `assayward_js.wasm` | `GOOS=js GOARCH=wasm` | browser/Node `globalThis.assayEvaluate` |

Both modules share the same pure evaluation logic in `eval.go` (no build tag). Only the `main()` entrypoints differ, each behind their own build tag.

---

## Envelope Shape (Input)

A single JSON object passed to the module:

```json
{
  "evidence":   <core.Evidence JSON>,
  "policy":     "<policy YAML or JSON document string>",
  "trustRoots": <core.TrustRoots JSON>,
  "now":        "<RFC3339 timestamp>"
}
```

- `evidence` — a `core.Evidence` value marshaled as JSON. The `Attestation.Envelope` and `WorkloadIdentity.Raw` fields are `[]byte`, which JSON-encodes as base64.
- `policy` — a **JSON string** whose value is the full YAML (or JSON) TrustPolicy document. It is parsed by `policy.Parse` with strict field validation (unknown fields are rejected).
- `trustRoots` — a `core.TrustRoots` value marshaled as JSON. The `SigstoreTUF` and `SPIFFEBundles` values are base64-encoded bytes.
- `now` — an RFC3339 timestamp string used as the clock for `DecidedAt`.

---

## Decision Output

On success the module emits the `core.Decision` as **compact JSON** (`json.Marshal`, no indentation). Example:

```json
{"result":"deny","policy":"serverless-edge@v1alpha1","reasons":[{"code":"IDENTITY_UNVERIFIED","severity":"high","detail":"identity not verified","met":false}],"evidence":{"image":{"name":"ghcr.io/sns45/example:1.0.0","digest":"sha256:..."},"attestationTypes":["sigstore-bundle","https://slsa.dev/provenance/v1","https://cyclonedx.org/bom","https://openvex.dev/ns/v0.2.0"],"identityPresent":true},"decidedAt":"2026-01-01T00:00:00Z"}
```

---

## Host ABIs

### wasip1 (stdin/stdout)

```
echo '<envelope JSON>' | wasmtime dist/assayward.wasm
```

- stdin: ABI envelope JSON (UTF-8, any length).
- stdout: compact Decision JSON on success, exit code 0.
- stderr: error message string, exit code 1.

### js/wasm (browser / Node.js)

```html
<script src="wasm_exec.js"></script>
<script>
  const go = new Go();
  WebAssembly.instantiateStreaming(fetch("assayward_js.wasm"), go.importObject)
    .then(result => {
      go.run(result.instance);
      // assayEvaluate is now available on globalThis
      const decisionJSON = assayEvaluate(envelopeJSON);
      const decision = JSON.parse(decisionJSON);
    });
</script>
```

- `assayEvaluate(envelopeJSON: string): string` — synchronous call.
- Returns the compact Decision JSON string on success.
- On error returns `{"error":"<message>"}` (never throws).
- The module must remain running (the `select{}` in `main()` keeps it alive).

---

## Decision-5 Caveat: Signature Verification Unavailable in Wasm

The wasm build links the fail-closed signature stub (`pkg/core/verify/sigstore_wasm.go`, tagged `//go:build wasm`). This stub returns `Available=false, Verified=false` for every attestation because `sigstore-go` cannot be compiled to wasm (it transitively imports unix-only syscalls via `in-toto-golang`).

**Consequence:** when a policy sets `signature.required: true`, the wasm decision will be **deny** with reason code `SIGNATURE_VERIFICATION_UNAVAILABLE`. Signature verification requires either:

1. A native pre-pass (run the CLI outside wasm, pass a pre-verified `core.Evidence` with `Attestation.Verified=true`), or
2. A supplied verified assertion baked into the evidence before it enters wasm.

**Non-signature stages** (SLSA provenance, SBOM, VEX, workload identity) run fully in wasm and produce accurate results.

---

## Build Tag Layout

| File | Build tag | Purpose |
|------|-----------|---------|
| `eval.go` | none | Shared `runEvaluate` logic; compiles on all targets |
| `main_wasip1.go` | `wasip1` | wasip1 stdin/stdout entrypoint |
| `main_js.go` | `js && wasm` | js/wasm `assayEvaluate` entrypoint |
| `main_native.go` | `!wasm` | No-op stub so `go build ./...` succeeds natively |
| `eval_native_test.go` | none | Native unit tests for `runEvaluate` |

---

## Wasm Isolation

The wasm modules do NOT link `sigstore-go` or `in-toto-golang` (the latter is pulled in only by the native sigstore verifier, which is excluded by the `wasm` build tag). Verify:

```sh
GOOS=wasip1 GOARCH=wasm go list -deps ./core/wasm/ | grep -cE 'sigstore-go|in-toto-golang/in_toto$'
# expected: 0
```
