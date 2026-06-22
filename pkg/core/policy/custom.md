# Custom Policy Extension Point (Rego)

## Overview

`pkg/core/policy/custom.go` defines the `CustomEvaluator` interface: the designated
extension point for organisations that need to enforce bespoke admission logic beyond
the built-in typed evaluator.

**Build tag:** `//go:build !wasm`

The file is intentionally excluded from the `wasip1/wasm` target because the OPA/Rego
runtime is not wasm-friendly. The native-only guard ensures the wasm build stays clean
without any special handling.

## Decision 1: Native typed evaluator is the v0.1 path

v0.1 ships a **disabled stub** (`DisabledCustomEvaluator`). Calling `Evaluate` on it
always returns:

- result: `core.ResultDeny`
- reasons: `nil`
- error: `ErrCustomPolicyNotEnabled`

The fail-closed behaviour (deny on error) is intentional: any accidental wiring of the
stub into a live decision path is safe by default.

No OPA or Rego dependency is added. The interface is defined, the stub is registered,
and the extension point is documented for future use.

## How a future version would wire a Rego engine

A future release would:

1. Add the OPA Go SDK as a native-only dependency (guarded by `//go:build !wasm`).
2. Implement a concrete `regoEvaluator` struct that holds a compiled `rego.PreparedEvalQuery`.
3. Change `NewCustomEvaluator` to return the concrete evaluator when a policy bundle path
   is configured.
4. Pass serialised `Evidence` and `Views` (attestation summaries) as `input` to the Rego
   query so org policies can inspect the same structured data the built-in engine sees.

Because the interface is already fixed, the swap is purely additive: existing callers of
`CustomEvaluator.Evaluate` require no changes.

## Input contract (future)

When a real Rego engine is plugged in, `input` will be JSON-encoded and contain at
minimum:

```json
{
  "evidence": { ... },   // core.Evidence
  "views":    { ... }    // engine.Views (attestation layer results)
}
```

The Rego policy can then access fields such as `input.evidence.image.digest` or
`input.views.slsa.level` to make decisions.

## Usage

```go
ev := policy.NewCustomEvaluator() // returns DisabledCustomEvaluator in v0.1
result, reasons, err := ev.Evaluate(inputJSON)
if errors.Is(err, policy.ErrCustomPolicyNotEnabled) {
    // custom policy not active; fall through to built-in engine
}
```
