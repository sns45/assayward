# forgeseal adapter content discovery + release blob signature channel (assayward#2)

**Issue:** https://github.com/sns45/assayward/issues/2
**Status:** design approved 2026-07-18, pending spec review.
**Scope decision:** close both gaps. Gap 1 (adapter does not find forgeseal's real output) via content based discovery that also carries forgeseal's real signed bundles. Gap 2 (no channel for the release blob's own signature) via a new pure blob signature verify path fed by a `--signed-blob` CLI flag.

## Problem

Building smithmark's release gate (smithmark composes forgeseal for its dependency SBOM and SLSA provenance, then assayward gates the release), two gaps surfaced. Both were confirmed by running forgeseal v0.5.1 and assayward v0.1.0 against each other, not theorised.

### Gap 1: the adapter under consumes forgeseal's output

`internal/forgeseal/adapter.go` reads three fixed filenames:

- `slsa.sigstore-bundle.json` (fallback `slsa.intoto.jsonl`)
- `sbom.cdx.json`
- `vex.openvex.json`

forgeseal v0.5.1 `pipeline --sign --attest` derives every name from the SBOM basename and defaults to keyed (offline self signed CA) signing:

| Artifact | forgeseal v0.5.1 writes | adapter reads today | Match |
|---|---|---|---|
| SBOM (raw CycloneDX) | `sbom.cdx.json` | `sbom.cdx.json` | yes |
| SBOM signature (messageSignature bundle) | `sbom.cdx.json.sigstore.json` | (ignored) | n/a |
| SLSA provenance (raw in-toto) | `sbom.cdx.json.intoto.jsonl` | `slsa.intoto.jsonl` | no |
| SLSA provenance signature (DSSE bundle) | `sbom.cdx.json.intoto.jsonl.sigstore.json` | `slsa.sigstore-bundle.json` | no |
| VEX (only under `--vex-triage`) | `vex.json` | `vex.openvex.json` | no |
| Signing CA cert (keyed mode) | `forgeseal-signing-ca.crt` | (ignored) | n/a |

Consequences:

1. `assayward verify --forgeseal-output <dir>` against an unmodified forgeseal directory fails closed with a file not found error, because the SLSA and VEX names never match. Consumers must insert a `cp` staging step (which is what smithmark's release workflow does today) to rename the SLSA bundle and synthesise a VEX file.
2. Even when staged, the adapter reads the raw `sbom.cdx.json` and wraps it into a synthetic in-toto DSSE with an **empty signatures slice**, discarding forgeseal's real signed SLSA bundle. The keyed signature is never presented for verification, and the exported CA cert is never wired, so assayward cannot cryptographically check what forgeseal actually signed.
3. A missing VEX file is a hard error today. forgeseal only writes VEX under `--vex-triage`, so a normal pipeline run cannot be ingested at all.

### Gap 2: no channel for the release blob's own signature

forgeseal's `pipeline` signs the SBOM (`SignBlob`) and the SLSA provenance of the SBOM (`SignDSSE`), whose subject is the SBOM. It never signs the release binaries. The release blob's own signature comes from a separate `forgeseal sign <blob>` invocation and is a Sigstore **messageSignature** (blob) bundle over raw bytes, written outside the pipeline directory.

assayward's engine verifies signatures only over DSSE envelopes: `VerifyKeyedBundle` routes on `content.dsseEnvelope`, and the native path parses a Sigstore bundle but is invoked per attestation. There is no path that binds a messageSignature bundle to an artifact digest, and no evidence carrier for a standalone blob signature. So there is no first class way to hand assayward the release artifact's own signature for evaluation.

## Design

Two cohesive changes that narrow the gap between what forgeseal emits and what assayward consumes.

### Gap 1: content based discovery in the adapter (I/O layer)

`internal/forgeseal/adapter.go` stops reading fixed names. `EvidenceFromOutput` globs the output directory and classifies each regular file by content:

| Detected content | Becomes |
|---|---|
| JSON with top level `"bomFormat": "CycloneDX"` | SBOM attestation: raw document wrapped into synthetic in-toto Statement v1 + bare DSSE (unchanged wrapping) |
| JSON with `"@context"` referencing `openvex.dev` | VEX attestation: raw document wrapped into synthetic DSSE |
| Sigstore bundle carrying a `dsseEnvelope` whose decoded in-toto payload `predicateType` contains `slsa.dev/provenance` | SLSA attestation carrying the **full signed bundle** as the Envelope (verifiable, keyed or keyless), exactly as `readSLSAAttestation`'s bundle path does today |
| JSON in-toto Statement (`_type` in-toto, `predicateType` slsa) with no signed bundle present | SLSA attestation via the synthetic DSSE fallback (unsigned), only when no signed SLSA bundle was found |

Classification rules:

- A Sigstore bundle is recognised **structurally**, not by exact `mediaType`: a JSON object carrying a `dsseEnvelope` or a `messageSignature`, at the top level or nested under `content` (the two shapes the existing `sigstoreBundle`/`bundleDSSEEnvelope` helpers already handle: forgeseal keyed bundles nest under `content`, canonical Sigstore v0.3 bundles are top level). `mediaType` is used only as a corroborating hint. A DSSE bundle's category is then decided by decoding the inner DSSE payload's `predicateType`, so the same routing generalises to a `cyclonedx` or `openvex` DSSE bundle if forgeseal ever signs those.
- A Sigstore bundle carrying a `messageSignature` rather than a `dsseEnvelope` (the SBOM's own blob signature, `sbom.cdx.json.sigstore.json`) is **not** attached to any attestation: its signed bytes are the raw SBOM, which do not match assayward's synthetic wrapped DSSE, so attaching it would present a signature that cannot verify against the envelope. It is left unconsumed in this iteration (see Scope boundary).
- The raw SLSA in-toto statement and the signed SLSA bundle can both be present (forgeseal writes both). The signed bundle wins; the raw statement is only used when no signed bundle exists.

Required versus optional, decided by the adapter, not by hardcoded presence:

- The adapter errors (fail fast, exit 2 at the CLI) only when it finds **neither an SBOM nor a SLSA artifact**, i.e. the directory is clearly not a forgeseal output directory.
- A missing VEX is a soft skip (no VEX attestation), fixing the hard error above. What is required for a pass is the policy's decision, not the adapter's.

CA auto detection, surfaced to the CLI:

- A new exported helper `DetectSigningCA(dir string) ([]byte, error)` scans `dir` for a PEM file containing a `CERTIFICATE` block (forgeseal writes `forgeseal-signing-ca.crt` in keyed mode). It returns the PEM bytes, or `(nil, nil)` when absent. Detection is by content (a `-----BEGIN CERTIFICATE-----` block), not by exact filename, for the same robustness reason as the rest of Gap 1.
- `EvidenceFromOutput`'s signature is unchanged (`(core.Evidence, error)`); CA detection is a sibling function so the adapter keeps one clear responsibility per function and the caller merges trust material.

### Gap 2: a blob signature verify path (pure core)

New pure model carrier in `pkg/core/model.go`:

```go
// BlobSignature is a standalone Sigstore messageSignature bundle over a raw
// artifact (e.g. the release archive or checksums), not wrapped in a DSSE
// statement. It is verified against ArtifactDigest, not against a predicate.
type BlobSignature struct {
	Bundle         []byte `json:"bundle"`         // Sigstore messageSignature bundle JSON
	ArtifactDigest string `json:"artifactDigest"` // "sha256:<hex>" the bundle must bind to
}
```

`Evidence` gains one optional field:

```go
BlobSignature *BlobSignature `json:"blobSignature,omitempty"`
```

New pure verify function in `pkg/core/verify/` (a new file `blob_signature.go`):

```go
// VerifyBlobBundle verifies a Sigstore messageSignature bundle binds to
// artifactDigest (form "sha256:<hex>"). It tries keyed (self signed CA)
// verification first via roots.SignatureCAs; if the bundle is keyless
// (tlogEntries present) or no SignatureCAs are configured, it verifies the
// keyless path against the trusted root, binding to the artifact digest.
// It returns the same SignatureResult shape the DSSE paths return.
func VerifyBlobBundle(bundle []byte, artifactDigest string, roots core.TrustRoots) SignatureResult
```

- **Keyless path:** parse with sigstore-go's `bundle.Bundle`, build the verifier as the native DSSE path does, but the policy uses `sgverify.WithArtifactDigest("sha256", digestBytes)` instead of `WithoutArtifactUnsafe()`, so the messageSignature is cryptographically bound to `ArtifactDigest`. Identity fields (issuer, SAN, Rekor) are extracted from the verified certificate exactly as the native DSSE path does.
- **Keyed path:** parse the bundle's leaf certificate, chain it to `roots.SignatureCAs`, confirm the bundle's `messageSignature.messageDigest` equals `ArtifactDigest`, and verify the raw signature under the leaf public key. Mirrors `VerifyKeyedBundle` but for `messageSignature` rather than `dsseEnvelope`. Returns `handled=false` semantics folded inline (keyed attempted first, keyless fallback), matching the native verifier's structure.
- Fail closed: a malformed bundle, a digest mismatch, or a bundle that is not a messageSignature bundle returns `Verified:false` with an explanatory `Err`. `Available` is true whenever the verifier ran.

Engine integration in `pkg/core/engine/engine.go`, Step 1, immediately after the existing per attestation aggregation loop:

```go
if ev.BlobSignature != nil {
	r := verify.VerifyBlobBundle(ev.BlobSignature.Bundle, ev.BlobSignature.ArtifactDigest, roots)
	if r.Available {
		sigView.Available = true
	}
	if r.Verified && !sigView.Verified {
		sigView.Verified = true
		sigView.Issuer = r.Issuer
		sigView.SubjectIdentity = r.SubjectIdentity
		sigView.RekorLogged = r.RekorLogged
	}
}
```

The blob signature therefore participates in the single aggregate `SignatureResultView` the policy already evaluates: a verified blob signature satisfies `signature.required`, and its keyless certificate identity feeds `signature.keyless`. Ordering is deterministic (attestations first, then the blob signature), so a verified attestation's identity still wins when both verify, preserving today's behaviour for the forgeseal output path.

### CLI wiring (`cmd/assayward/inputs.go`)

- New flag `--signed-blob <path>`: reads the bundle bytes and sets `ev.BlobSignature = &core.BlobSignature{Bundle: raw, ArtifactDigest: imageRef.Digest}`. It binds to the existing `--image` digest (the release artifact being gated). It is additive: usable alongside `--forgeseal-output`, `--bundle`, or `--from-oci`, and not part of the "at least one attestation source" requirement (a blob signature alone is a signature source, so a run with only `--signed-blob` is allowed and evaluated).
- CA auto merge: after the `--forgeseal-output` branch assembles evidence, when `o.SignatureCA == ""`, call `forgeseal.DetectSigningCA(o.ForgesealOutput)` and, if it returns bytes, set `roots.SignatureCAs = detected`. An explicit `--signature-ca` always wins (the auto merge only runs when the flag is empty). This is what makes forgeseal's keyed SLSA bundle actually verify with no extra flag.

## Interfaces (exact signatures)

- `internal/forgeseal`:
  - `EvidenceFromOutput(dir string, artifactDigest string) (core.Evidence, error)` (unchanged signature, rewritten internals).
  - `DetectSigningCA(dir string) ([]byte, error)` (new).
- `pkg/core`:
  - `type BlobSignature struct { Bundle []byte; ArtifactDigest string }` (new).
  - `Evidence.BlobSignature *BlobSignature` (new optional field).
- `pkg/core/verify`:
  - `VerifyBlobBundle(bundle []byte, artifactDigest string, roots core.TrustRoots) SignatureResult` (new).
- `pkg/core/engine`:
  - `Evaluate` gains the blob signature fold in Step 1 (no signature change).
- `cmd/assayward`:
  - `evalInputs` gains `SignedBlob string` and the `--signed-blob` flag; `build` reads it and wires CA auto merge.

## Error handling

- Empty or unrecognisable directory (no SBOM and no SLSA): the adapter returns an error naming what it looked for; the CLI maps it to exit 2.
- A file that matches a class by shape but fails to parse (e.g. a truncated Sigstore bundle whose `mediaType` says bundle but whose body will not decode): error names the file and the expected shape, improving on today's opaque errors.
- `--signed-blob` bundle that is not a messageSignature bundle, or whose signature does not bind to `imageRef.Digest`: `VerifyBlobBundle` returns `Verified:false` with a reason; the policy decides whether that denies (fail closed under `signature.required`).
- Keyed CA present but the SLSA bundle is keyless, or vice versa: the existing keyed then keyless routing already resolves this; the blob path uses the same order.
- `--signed-blob` set without a usable `--image` digest: `--image` is already required by `build`, so `imageRef.Digest` is always present when `--signed-blob` is read.

## Determinism and purity

- `pkg/core` and `pkg/core/verify` additions are pure: `VerifyBlobBundle` takes bytes and injected `roots`, performs no directory or clock access, and returns a value. The keyless path may fetch a public good trusted root exactly as the existing native path already does (same escape hatch, same behaviour), and tests inject `roots.SigstoreTUF` or `roots.SignatureCAs` to stay offline.
- `internal/forgeseal` remains the I/O layer. Directory globbing is deterministic: files are classified by content, and each predicate type maps to at most one attestation with the signed bundle preferred, so the assembled `Evidence.Attestations` order is stable (SLSA, SBOM, VEX in a fixed emit order regardless of filesystem iteration order).
- No network in tests. Fixtures are committed. The keyed fixtures verify against a committed CA cert with no live infrastructure.

## Testing (real fixtures, no network)

1. **Committed real fixtures** under `internal/forgeseal/testdata/` (and shared with verify tests as needed): run forgeseal v0.5.1 once with `pipeline --sign --attest --vex-triage` (keyed default) and `forgeseal sign <blob>`, then commit the **actual** output directory (`sbom.cdx.json`, `sbom.cdx.json.intoto.jsonl`, `sbom.cdx.json.intoto.jsonl.sigstore.json`, `sbom.cdx.json.sigstore.json`, `vex.json`, `forgeseal-signing-ca.crt`) plus the standalone release blob bundle and the blob's digest. This is the anti drift guarantee the issue asks for: the adapter is tested against reality, not against names chosen by hand.
2. **Adapter discovery tests** (`internal/forgeseal`): content classification finds SLSA, SBOM, and VEX from the real fixture regardless of filename; a directory missing VEX yields evidence with SLSA + SBOM and no error; a directory with neither SBOM nor SLSA errors; `DetectSigningCA` returns the CA PEM from the fixture and `(nil, nil)` from a directory without one; the carried SLSA attestation Envelope is the full signed bundle (not an empty signature wrap).
3. **Blob verify tests** (`pkg/core/verify`): the committed release blob bundle verifies against its artifact digest and the fixture CA (keyed); a one bit change to the digest fails closed; a DSSE bundle handed to `VerifyBlobBundle` is rejected with a clear error; `Available` is true on every path that ran.
4. **Engine aggregation test** (`pkg/core/engine`): an `Evidence` with only a verified `BlobSignature` yields `sigView.Verified == true` and satisfies a `signature.required` policy; an evidence with a verified attestation and an unverifiable blob signature keeps the attestation's identity in `sigView` (ordering preserved).
5. **CLI wiring test** (`cmd/assayward`): `--forgeseal-output <fixture>` composes with no `cp` step and no `--signature-ca`, and the keyed SLSA signature verifies via the auto detected CA; `--signed-blob <fixture-bundle>` with `--image <ref@digest>` binds and verifies; an explicit `--signature-ca` overrides the auto detected one.
6. **Honesty test**: an unsigned release blob (a messageSignature bundle over a different digest) is reported not verified, never silently passed; the empty signatures synthetic wraps for SBOM and VEX remain reported as unsigned.

## Scope boundary

- **In scope:** content based discovery, carrying the real signed SLSA bundle, `DetectSigningCA` and CA auto merge, the VEX optional fix, the `BlobSignature` model carrier, `VerifyBlobBundle` (keyed + keyless), the `--signed-blob` flag, the engine aggregation fold, and real committed fixtures.
- **Out of scope:**
  - Widening `ImageRef` to `ArtifactRef` and carrying lint findings (assayward#1, a separate cross repo contract item).
  - Gating on the SBOM's own blob signature (`sbom.cdx.json.sigstore.json`). It is discovered but not wired, because the SLSA provenance whose subject is the SBOM is already DSSE signed and verifiable, making the SBOM's separate blob signature redundant for this iteration. Wiring it would reuse `VerifyBlobBundle` and is a clean follow up.
  - Changing forgeseal's output naming (the fix belongs in the consumer; forgeseal's `sbom.cdx.json.*` derivation is its established convention).
  - Keyless Fulcio and Rekor infrastructure for forgeseal itself (forgeseal's own tracked gap); this spec verifies whatever forgeseal actually produces, keyed today and keyless when forgeseal ships it.
  - A per blob subject override distinct from `--image` (YAGNI now; `--signed-blob` binds to the `--image` digest).

## Success criteria

- `assayward verify --forgeseal-output <unmodified forgeseal dir>` assembles SLSA + SBOM (+ VEX when present) with no `cp` staging and no manual rename.
- The keyed SLSA signature verifies with no explicit `--signature-ca`, via the auto detected `forgeseal-signing-ca.crt`.
- `assayward verify --image <ref@digest> --signed-blob <blob.sigstore.json>` binds the messageSignature to the artifact digest, and a verified blob signature satisfies `signature.required`.
- A missing VEX no longer errors; a directory that is not forgeseal output still fails fast.
- The full suite, `go vet`, `gofmt`, and the wasip1 build stay green; the new fixtures are committed and no test reaches the network.
