# assayward-action

A GitHub Marketplace composite action that runs `assayward verify` as a supply-chain gate in CI/CD pipelines.

## Quick Start

```yaml
- uses: sns45/assayward-action@v0.1
  with:
    image: "ghcr.io/myorg/myapp:1.2.3@sha256:<digest>"
    policy: "slsa-l3"
    bundle: |
      ${{ github.workspace }}/attestations/provenance.bundle.json
      ${{ github.workspace }}/attestations/sbom.bundle.json
    sigstore-trust-root: "${{ github.workspace }}/trust/sigstore-root.json"
```

## Sample Workflow

```yaml
name: Supply Chain Gate

on:
  workflow_dispatch:
    inputs:
      image:
        description: "Image reference (name@sha256:...)"
        required: true

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify supply-chain evidence
        id: assayward
        uses: sns45/assayward-action@v0.1
        with:
          image: ${{ github.event.inputs.image }}
          policy: "slsa-l3"
          bundle: |
            attestations/provenance.bundle.json
            attestations/sbom.bundle.json
          sigstore-trust-root: "trust/sigstore-root.json"
          spiffe-bundle: |
            myorg.dev=trust/spiffe-bundle.json
          svid: "credentials/workload.jwt"

      - name: Show decision
        if: always()
        run: |
          echo "Result: ${{ steps.assayward.outputs.result }}"
          echo "Decision JSON:"
          echo '${{ steps.assayward.outputs.decision }}'
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `image` | Yes | | Container image reference in `name@sha256:<hex>` format. |
| `policy` | No | `slsa-l3` | Built-in policy name: `baseline`, `slsa-l3`, or `serverless-edge`. Ignored when `policy-file` is set. |
| `policy-file` | No | | Path to a custom TrustPolicy YAML file. When set, overrides `policy`. |
| `bundle` | No | | Attestation bundle file paths, one per line. Each line becomes a separate `--bundle` argument. |
| `from-oci` | No | `false` | Set to `true` to discover attestations via the OCI referrers API. |
| `sigstore-trust-root` | No | | Path to a Sigstore trusted-root JSON file. |
| `spiffe-bundle` | No | | SPIFFE bundle entries in `trustDomain=path` format, one per line. |
| `svid` | No | | Path to a workload SVID credential (JWT or PEM X.509). |
| `version` | No | `latest` | assayward release version to download (e.g. `v0.1.0`). |
| `binary-path` | No | | Path to a pre-built assayward binary. Skips download when set (useful for testing or air-gapped environments). |

## Outputs

| Output | Description |
|---|---|
| `result` | The verification outcome: `allow`, `deny`, or `audit`. |
| `decision` | The full decision JSON emitted by `assayward verify`. |

## Exit Code and Job Failure Behavior

`assayward verify` uses the following exit codes:

| Exit Code | Meaning | Job outcome |
|---|---|---|
| `0` | Allow or audit (non-blocking) | Job continues |
| `1` | Deny (policy blocked the image) | Job fails with `::error::` annotation listing failed reason codes |
| `2` | Usage or operational error | Job fails |

Because this is a composite action, the step exit code propagates directly to the job. A deny result causes the step to fail, which fails the job unless you set `continue-on-error: true` on the step.

## Consuming Outputs After a Deny

To inspect the decision even when the step fails, add a subsequent step with `if: always()`:

```yaml
- name: Assayward verify
  id: gate
  uses: sns45/assayward-action@v0.1
  with:
    image: "${{ env.IMAGE_REF }}"
    policy: slsa-l3

- name: Inspect decision
  if: always()
  run: echo '${{ steps.gate.outputs.decision }}' | jq .
```

## Built-in Policies

| Policy name | Description |
|---|---|
| `baseline` | Requires a valid Sigstore bundle (signature and transparency log). Audit mode for most additional checks. |
| `slsa-l3` | Requires SLSA Build Level 3 provenance with a hosted, isolated builder. Strict mode. |
| `serverless-edge` | Policy tuned for serverless/edge workloads. |

## Air-gapped or Testing Use

Set `binary-path` to skip the GitHub releases download:

```yaml
- uses: sns45/assayward-action@v0.1
  with:
    image: "${{ env.IMAGE_REF }}"
    policy: baseline
    binary-path: "/usr/local/bin/assayward"
```
