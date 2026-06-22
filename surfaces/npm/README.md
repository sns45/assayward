# @sns45/assayward

TypeScript wrapper around the assayward wasm core. Evaluate supply-chain trust policies at the edge with no native dependencies.

## Installation

```sh
npm install @sns45/assayward
# or
bun add @sns45/assayward
```

The package bundles `assayward_js.wasm` and Go's `wasm_exec.js` loader inside `dist/`.

## Usage

```ts
import { assay } from "@sns45/assayward";
import type { Evidence, TrustRoots, Decision } from "@sns45/assayward";

const policyYaml = `
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: serverless-edge
spec:
  mode: enforce
  identity:
    required: true
    trustDomain: "spiffe://example.org"
    idPattern: "spiffe://example.org/*"
`;

const evidence: Evidence = {
  image: {
    name: "ghcr.io/myorg/myapp:1.0.0",
    digest: "sha256:...",
  },
  attestations: [
    {
      predicateType: "https://slsa.dev/provenance/v1",
      // base64-encoded DSSE envelope bytes
      envelope: "<base64>",
    },
  ],
  identity: {
    spiffeID: "spiffe://example.org/ci/release",
    svidType: "jwt",
    // base64-encoded compact JWT-SVID token
    raw: "<base64>",
    claims: {},
    verified: false,
  },
};

const trustRoots: TrustRoots = {
  spiffeBundles: {
    "example.org": "<base64-encoded JWKS JSON>",
  },
};

const decision: Decision = await assay(evidence, policyYaml, trustRoots);

if (decision.result === "allow") {
  console.log("Deployment permitted");
} else {
  console.error("Deployment denied:", decision.reasons);
}
```

## API

### `assay(evidence, policy, trustRoots?, now?): Promise<Decision>`

| Parameter | Type | Description |
|-----------|------|-------------|
| `evidence` | `Evidence` | Supply-chain evidence for an image |
| `policy` | `string` | Full TrustPolicy document (YAML or JSON) |
| `trustRoots` | `TrustRoots?` | Trust material (Sigstore TUF, SPIFFE bundles). Defaults to `{}`. |
| `now` | `string?` | RFC3339 timestamp for the evaluation clock. Defaults to `new Date().toISOString()`. |

Returns a `Promise<Decision>`. Throws if the wasm engine encounters a fatal error.

The wasm module is instantiated once and cached; repeated `assay()` calls reuse the same instance.

### `Decision` shape

```ts
interface Decision {
  result: "allow" | "deny" | "audit";
  policy: string;           // "name@version" of the deciding policy
  reasons: Reason[];        // sorted by code for determinism
  evidence: EvidenceSummary;
  decidedAt: string;        // RFC3339
}

interface Reason {
  code: string;             // stable machine-readable, e.g. IDENTITY_REQUIRED_MISSING
  severity: "low" | "medium" | "high" | "critical";
  detail: string;
  met: boolean;
}
```

## Decision-5 Caveat: Signature Verification Unavailable in Wasm

When a policy sets `signature.required: true`, the wasm engine returns `deny` with reason code `SIGNATURE_VERIFICATION_UNAVAILABLE`. This is because `sigstore-go` cannot be compiled to wasm (it transitively imports unix-only syscalls). The engine is fail-closed by design.

**Non-signature stages** (SLSA provenance, SBOM, VEX, workload identity) run fully in wasm and produce accurate results.

For full signature verification use the native assayward CLI, or run a pre-verification pass outside wasm and pass `attestation.verified: true` in the evidence before calling `assay()`.

## Publishing / Bundling the Wasm Artifacts

When publishing this package, copy `dist/assayward_js.wasm` and `dist/wasm_exec.js` from the repo's `dist/` directory into `surfaces/npm/dist/` before running `bun pack`:

```sh
# From repo root:
make wasm
cp dist/assayward_js.wasm dist/wasm_exec.js surfaces/npm/dist/
cd surfaces/npm && bun pack
```

The `files` field in `package.json` includes `dist/` so both artifacts are bundled.

## Prerequisites for Local Development

```sh
# Build the wasm artifacts (Go 1.21+ required)
make wasm

# Install deps and run tests
cd surfaces/npm
bun install
bun test
```

## License

Apache-2.0
