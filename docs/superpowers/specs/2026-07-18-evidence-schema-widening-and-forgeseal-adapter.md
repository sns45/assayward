# Evidence schema widening + forgeseal adapter content discovery + release blob signature (assayward#1 + #2)

**Issues:** https://github.com/sns45/assayward/issues/1 and https://github.com/sns45/assayward/issues/2
**Status:** design approved 2026-07-18, pending spec review.
**Supersedes:** `2026-07-18-forgeseal-adapter-content-discovery-and-blob-signature.md` (the #2-only spec), which this document absorbs.

**Scope decision:** close both issues on one branch, sequenced. assayward#1 widens the `Evidence` schema (kind tagged `ArtifactRef` with an algorithm keyed digest, an explicit `schemaVersion`, and carried lint findings). assayward#2 aligns the forgeseal adapter with forgeseal v0.5.1's real output and adds a release blob signature channel. Both touch `core.Evidence`, `verify/`, `engine.go`, the adapter, and the CLI, so the schema widening lands first and #2 builds on the new shape; widening the core twice is avoided.

## Problem

### assayward#1: the Evidence schema cannot carry agent artifact evidence faithfully

smithmark emits an `Evidence` block structurally compatible with `pkg/core.Evidence`, pinned by a cross repo contract test at assayward v0.1.0. Three gaps block faithful agent artifact evidence, each additive, none breaking existing container evidence:

1. **`ImageRef` is too narrow.** `Evidence.Image` is `ImageRef{Name, Digest}` with `Digest` documented as `sha256:...`. smithmark attests MCP servers (npm/pypi/OCI, npm carrying sha512) and skills (canonical bundle digest prefixed `smithmark-bundle-v1:`, not `sha256:`). There is no way to tell an evaluator what KIND the subject is (smithmark smuggles it into `Attestation.SignatureNote` as a `kind=` prefix, a stopgap), and `verify/slsa.go` does `strings.TrimPrefix(img.Digest, "sha256:")` unconditionally, so a non sha256 subject silently mis matches rather than erroring. The fix must be digest algorithm aware, not just kind tagged.
2. **No `schemaVersion`.** A cross repo consumer cannot pin a shape and detect drift loudly; adding a field decodes silently to the zero value under `encoding/json`, so a version only becomes a loud signal if consumers validate it.
3. **No findings channel.** smithmark's capability lint produces declared versus detected gap findings (`UNDECLARED_NETWORK_EGRESS`, `UNDECLARED_FILESYSTEM`, `UNDECLARED_EXEC`, `UNDECLARED_ENV`) with severities. `Evidence` has no findings field, so the portfolio's worked example policy ("MCP servers with no undeclared network egress") is not expressible from Evidence; a gate would have to re run the lint, defeating attestable evidence.

### assayward#2: the adapter under consumes forgeseal's output, and there is no release blob signature channel

`internal/forgeseal/adapter.go` reads three fixed filenames (`slsa.sigstore-bundle.json` fallback `slsa.intoto.jsonl`, `sbom.cdx.json`, `vex.openvex.json`). forgeseal v0.5.1 `pipeline --sign --attest` derives every name from the SBOM basename and defaults to keyed (offline self signed CA) signing:

| Artifact | forgeseal v0.5.1 writes | adapter reads today | Match |
|---|---|---|---|
| SBOM (raw CycloneDX) | `sbom.cdx.json` | `sbom.cdx.json` | yes |
| SBOM signature (messageSignature bundle) | `sbom.cdx.json.sigstore.json` | (ignored) | n/a |
| SLSA provenance (raw in-toto) | `sbom.cdx.json.intoto.jsonl` | `slsa.intoto.jsonl` | no |
| SLSA provenance signature (DSSE bundle) | `sbom.cdx.json.intoto.jsonl.sigstore.json` | `slsa.sigstore-bundle.json` | no |
| VEX (only under `--vex-triage`) | `vex.json` | `vex.openvex.json` | no |
| Signing CA cert (keyed mode) | `forgeseal-signing-ca.crt` | (ignored) | n/a |

Consequences: `assayward verify --forgeseal-output <dir>` on an unmodified forgeseal directory fails closed with a file not found error (forcing a `cp` staging step, which is smithmark's current workaround); even when staged, the adapter wraps the raw SBOM into a synthetic DSSE with an empty signatures slice, discarding forgeseal's real signed SLSA bundle and never wiring the exported CA; and a missing VEX is a hard error even though forgeseal only writes VEX under `--vex-triage`.

Separately, forgeseal's pipeline signs the SBOM and the SLSA of the SBOM, never the release binaries. The release blob's own signature comes from a standalone `forgeseal sign <blob>` and is a Sigstore **messageSignature** (blob) bundle over raw bytes. assayward's engine verifies signatures only over DSSE envelopes, so there is no path to bind a messageSignature bundle to an artifact digest, and no evidence carrier for a standalone blob signature.

## Design

### Part 1: Evidence schema widening (assayward#1)

#### A1. `ArtifactRef` with an algorithm keyed digest (Request 1)

New pure types in `pkg/core/model.go`:

```go
// DigestSet maps a digest algorithm to its hex value, e.g.
// {"sha256": "ab..."} or {"smithmark-bundle-v1": "cd..."}.
// This mirrors in-toto Statement subject digests, so matching a SLSA subject
// is a direct algorithm keyed comparison rather than an assumed sha256 strip.
type DigestSet map[string]string

// ArtifactRef identifies the attested subject and its kind.
type ArtifactRef struct {
	Kind   string    `json:"kind"`             // "container" | "mcp-server" | "skill"
	Name   string    `json:"name"`             // registry/repo:tag, purl, or skill name
	Digest DigestSet `json:"digest"`           // algorithm keyed
	Source string    `json:"source,omitempty"`
}
```

`Evidence.Image ImageRef` is **replaced** by `Evidence.Artifact ArtifactRef` as the single canonical field. `ImageRef` is kept as a container convenience helper with conversions:

```go
func (i ImageRef) AsArtifact() ArtifactRef // {Kind:"container", Name:i.Name, Digest: parseDigest(i.Digest)}
func (a ArtifactRef) PrimaryDigest() (alg, hex string, ok bool) // first/canonical entry for display + blob binding
```

**Legacy decode shim.** `Evidence` gets a custom `UnmarshalJSON` that accepts either the new `"artifact"` object or a legacy `"image"` object (`{name, digest}` with `digest` in `alg:hex` form), mapping the latter to `ArtifactRef{Kind:"container", Name, Digest:{alg: hex}}`. Existing container evidence therefore still decodes. `MarshalJSON` emits `"artifact"` only (the canonical shape); the legacy field is input only. `parseDigest("sha256:ab...")` yields `{"sha256":"ab..."}`; a bare hex with no `alg:` prefix is rejected with an explicit error rather than assumed sha256.

Because a custom `UnmarshalJSON` bypasses `json.Decoder.DisallowUnknownFields`, the unknown field strictness is enforced **inside** the custom unmarshaler: it decodes into an auxiliary struct carrying both `artifact` and `image` via a `json.Decoder` with `DisallowUnknownFields()`, so `DecodeEvidence`'s strict guarantee holds for Evidence's own fields. Precedence: when `artifact` is present it wins and `image` is ignored; `image` is consulted only when `artifact` is absent; a document carrying neither is an explicit error.

**Algorithm aware SLSA matching (the load bearing fix).** `verify/slsa.go` stops doing `strings.TrimPrefix(img.Digest, "sha256:")`. It compares the SLSA statement subject's digest map against the artifact `DigestSet` by shared algorithm: a subject matches when they share at least one algorithm whose hex is equal. A subject whose only algorithm is absent from the artifact `DigestSet` is an explicit non match (surfaced as a subject mismatch reason), not a silent one. smithmark then drops its `SignatureNote` `kind=` shim.

#### A2. `schemaVersion` on `Evidence` (Request 2)

- New constant `core.EvidenceSchemaVersion = "0.2.0"` (the evidence schema's own semver, independent of the module version).
- `Evidence` gains `SchemaVersion string json:"schemaVersion"` (required). Every assayward producer (the forgeseal adapter, `discover`, and the CLI assembly in `inputs.go`) sets it to `EvidenceSchemaVersion`.
- New exported `core.DecodeEvidence(b []byte) (Evidence, error)` performs strict JSON decoding (unknown fields rejected, consistent with assayward's strict parsing elsewhere) and **validates** `SchemaVersion` is present and within the supported set (`{"0.2.0"}`), returning a loud `unsupported evidence schemaVersion` error on drift. This is the helper a cross repo consumer (smithmark's contract test) calls so drift fails at decode, not silently.

#### A3. Capability lint findings + a findings policy rule (Request 3)

New pure type and carrier in `pkg/core/model.go`:

```go
type Finding struct {
	Code     string   `json:"code"`               // e.g. UNDECLARED_NETWORK_EGRESS
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
	Location string   `json:"location,omitempty"` // human oriented, e.g. file:line
}
// Evidence gains:
Findings []Finding `json:"findings,omitempty"`
```

New policy rule in `pkg/core/policy/policy.go`, following the existing typed rule + private wire type pattern:

```go
type FindingsRule struct {
	ForbiddenCodes []string // any finding carrying one of these codes denies
	MaxSeverity    string   // deny if any finding severity exceeds this (low<medium<high<critical); "" disables the severity gate
}
```

with a parallel `wireFindingsRule{ ForbiddenCodes []string yaml:"forbiddenCodes"; MaxSeverity string yaml:"maxSeverity" }` under `wireSpec.Findings yaml:"findings"`, mapped in `Parse`.

`EvaluatePolicy` receives the evidence findings and emits deterministic reasons (sorted by code, as all reasons already are):

- `FINDINGS_FORBIDDEN_CODE_PRESENT` (Met=false, severity = the finding's severity) when a finding's code is in `ForbiddenCodes`.
- `FINDINGS_SEVERITY_EXCEEDED` (Met=false) when any finding's severity is above `MaxSeverity`.
- `FINDINGS_WITHIN_POLICY` (Met=true) when a findings rule is configured and no finding violates it.

When no findings rule is configured, findings are carried on Evidence but produce no reasons (presence alone never denies). This makes the worked example expressible: `findings: { forbiddenCodes: [UNDECLARED_NETWORK_EGRESS] }` denies an MCP server with undeclared egress from Evidence alone.

#### A4. Consumer migration

Every `Evidence.Image` / `ImageRef` / `img.Digest` consumer moves to the new shape (60 references, 16 files). The semantic work is confined to `verify/slsa.go` (algorithm aware match); the rest is mechanical:

- `pkg/core/verify/*`: signature verifiers take `art core.ArtifactRef` instead of `img core.ImageRef` (most ignore the digest today; `keyed_signature.go` already takes `_`). `slsa.go` uses the `DigestSet`.
- `pkg/core/engine/engine.go`: passes `ev.Artifact`; `buildSummary` projects `EvidenceSummary.Artifact`.
- `pkg/core/model.go`: `EvidenceSummary.Image ImageRef` becomes `EvidenceSummary.Artifact ArtifactRef` (kind surfaced in the decision output).
- `internal/discover/oci.go`, `internal/forgeseal/adapter.go`, `cmd/assayward/inputs.go`: build `ArtifactRef`. `parseImageRef` stays and maps `--image` to `ArtifactRef{Kind:"container", ...}`.
- `surfaces/k8s-webhook/*.go`: build and read `Artifact` (must compile and pass its tests).
- `surfaces/npm/src/types.ts`: mirror `ArtifactRef`, `DigestSet`, `schemaVersion`, and `findings` as TypeScript type definitions (type only; the npm surface has its own bun toolchain and is updated for schema parity, no new logic).

### Part 2: forgeseal adapter content discovery (assayward#2, restated in ArtifactRef terms)

`internal/forgeseal/adapter.go` stops reading fixed names. `EvidenceFromOutput(dir, artifactDigest string) (core.Evidence, error)` globs the output directory and classifies each regular file by content:

| Detected content | Becomes |
|---|---|
| JSON with top level `"bomFormat": "CycloneDX"` | SBOM attestation: raw document wrapped into synthetic in-toto Statement v1 + bare DSSE (unchanged wrapping) |
| JSON with `"@context"` referencing `openvex.dev` | VEX attestation: raw document wrapped into synthetic DSSE |
| Sigstore bundle carrying a `dsseEnvelope` whose decoded in-toto payload `predicateType` contains `slsa.dev/provenance` | SLSA attestation carrying the **full signed bundle** as the Envelope (verifiable, keyed or keyless) |
| JSON in-toto Statement (`_type` in-toto, `predicateType` slsa) with no signed bundle present | SLSA attestation via the synthetic DSSE fallback (unsigned), only when no signed SLSA bundle was found |

Classification rules:

- A Sigstore bundle is recognised **structurally**: a JSON object carrying a `dsseEnvelope` or a `messageSignature`, at the top level or nested under `content` (the two shapes the existing `sigstoreBundle`/`bundleDSSEEnvelope` helpers already handle). `mediaType` is a corroborating hint only. A DSSE bundle's category is decided by decoding the inner payload's `predicateType`, generalising to cyclonedx or openvex DSSE bundles.
- A Sigstore bundle carrying a `messageSignature` rather than a `dsseEnvelope` (the SBOM's own blob signature) is **not** attached to any attestation: its signed bytes are the raw SBOM, which do not match assayward's synthetic wrapped DSSE. Left unconsumed this iteration (see Scope boundary).
- Both the raw SLSA statement and its signed bundle can be present; the signed bundle wins.

Required versus optional, decided by the adapter:

- Error (fail fast, exit 2 at the CLI) only when **neither an SBOM nor a SLSA artifact** is found.
- A missing VEX is a soft skip (fixes today's hard error).

The adapter sets `ev.Artifact = ArtifactRef{Kind:"container", Name: <from --image>, Digest: parseDigest(artifactDigest)}` and `ev.SchemaVersion = core.EvidenceSchemaVersion`.

CA auto detection: new exported `DetectSigningCA(dir string) ([]byte, error)` scans `dir` for a PEM file containing a `CERTIFICATE` block (forgeseal writes `forgeseal-signing-ca.crt`); returns PEM bytes or `(nil, nil)`. Detection is by content, not exact filename.

### Part 3: release blob signature channel (assayward#2 Gap 2)

New pure carrier in `pkg/core/model.go`:

```go
type BlobSignature struct {
	Bundle         []byte `json:"bundle"`         // Sigstore messageSignature bundle JSON
	ArtifactDigest string `json:"artifactDigest"` // "sha256:<hex>" the bundle must bind to
}
// Evidence gains:
BlobSignature *BlobSignature `json:"blobSignature,omitempty"`
```

New pure verify function `pkg/core/verify/blob_signature.go`:

```go
// VerifyBlobBundle verifies a Sigstore messageSignature bundle binds to
// artifactDigest (form "sha256:<hex>"). Keyed (roots.SignatureCAs) first;
// else keyless against the trusted root. Returns the SignatureResult shape.
func VerifyBlobBundle(bundle []byte, artifactDigest string, roots core.TrustRoots) SignatureResult
```

- **Keyless:** parse with `bundle.Bundle`, build the verifier as the native DSSE path does, but the policy uses `sgverify.WithArtifactDigest("sha256", digestBytes)` instead of `WithoutArtifactUnsafe()`, binding the messageSignature to `ArtifactDigest`. Identity fields extracted from the verified certificate as the native path does.
- **Keyed:** parse the leaf certificate, chain it to `roots.SignatureCAs`, confirm the bundle's `messageSignature.messageDigest` equals `ArtifactDigest`, verify the raw signature under the leaf public key. Reuses the cert chain logic of `VerifyKeyedBundle` but for `messageSignature`. The committed real fixture is the correctness oracle for the crypto.
- Fail closed: malformed bundle, digest mismatch, or a non messageSignature bundle returns `Verified:false` with an explanatory `Err`; `Available` is true whenever the verifier ran.

Engine integration in `engine.go` Step 1, immediately after the per attestation aggregation loop:

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

The blob signature participates in the single aggregate `SignatureResultView`: a verified blob signature satisfies `signature.required`, and its keyless certificate identity feeds `signature.keyless`. Ordering is deterministic (attestations first, then the blob signature), so a verified attestation's identity still wins when both verify.

CLI wiring in `cmd/assayward/inputs.go`:

- New flag `--signed-blob <path>`: reads bundle bytes, sets `ev.BlobSignature = &core.BlobSignature{Bundle: raw, ArtifactDigest: <artifact sha256 from --image>}`. Additive: usable alongside `--forgeseal-output`, `--bundle`, or `--from-oci`; a run with only `--signed-blob` is a valid signature source (the "at least one attestation source" guard is widened to accept it).
- CA auto merge: after the `--forgeseal-output` branch assembles evidence, when `o.SignatureCA == ""`, call `DetectSigningCA(o.ForgesealOutput)` and set `roots.SignatureCAs` from the result. An explicit `--signature-ca` always wins.

## Interfaces (exact signatures)

- `pkg/core`:
  - `type DigestSet map[string]string` (new).
  - `type ArtifactRef struct { Kind, Name string; Digest DigestSet; Source string }` (new).
  - `type Finding struct { Code string; Severity Severity; Detail, Location string }` (new).
  - `type BlobSignature struct { Bundle []byte; ArtifactDigest string }` (new).
  - `Evidence{ Artifact ArtifactRef; Attestations []Attestation; Identity *WorkloadIdentity; Findings []Finding; BlobSignature *BlobSignature; SchemaVersion string; FetchedAt time.Time }` with custom `UnmarshalJSON`/`MarshalJSON`.
  - `EvidenceSummary.Artifact ArtifactRef` (replaces `Image`).
  - `const EvidenceSchemaVersion = "0.2.0"`.
  - `func DecodeEvidence(b []byte) (Evidence, error)` (new).
  - `func (ImageRef) AsArtifact() ArtifactRef`, `func (ArtifactRef) PrimaryDigest() (string, string, bool)` (new).
- `pkg/core/verify`:
  - Signature/SLSA/identity verifiers take `core.ArtifactRef` in place of `core.ImageRef`.
  - `func VerifyBlobBundle(bundle []byte, artifactDigest string, roots core.TrustRoots) SignatureResult` (new).
- `pkg/core/policy`:
  - `type FindingsRule struct { ForbiddenCodes []string; MaxSeverity string }` (new); `Policy.Findings FindingsRule`.
  - `EvaluatePolicy` gains findings evaluation.
- `internal/forgeseal`:
  - `EvidenceFromOutput(dir, artifactDigest string) (core.Evidence, error)` (rewritten internals, sets Artifact + SchemaVersion).
  - `DetectSigningCA(dir string) ([]byte, error)` (new).
- `cmd/assayward`:
  - `evalInputs` gains `SignedBlob string`; `build` reads `--signed-blob` and wires CA auto merge.

## Error handling

- Legacy `image` with a bare hex digest (no `alg:` prefix): explicit decode error, never assumed sha256.
- Evidence JSON missing `schemaVersion` or carrying an unsupported one: `DecodeEvidence` errors loudly.
- SLSA subject whose algorithm is absent from the artifact `DigestSet`: explicit subject mismatch reason (not a silent pass).
- forgeseal directory with no SBOM and no SLSA: adapter errors, CLI maps to exit 2. Missing VEX: soft skip.
- `--signed-blob` bundle that is not a messageSignature bundle or does not bind to the digest: `VerifyBlobBundle` returns `Verified:false`; policy decides (fail closed under `signature.required`).
- Findings rule referencing codes not present: no violation, `FINDINGS_WITHIN_POLICY` met.

## Determinism and purity

- All `pkg/core` and `pkg/core/verify` additions are pure: value in, value out, injected `roots` and `Clock`, no directory or wall clock access. The keyless blob path may fetch a public good trusted root exactly as the existing native path does; tests inject `SigstoreTUF`/`SignatureCAs` to stay offline.
- `internal/forgeseal` stays the I/O layer. Content classification yields a stable attestation order (SLSA, SBOM, VEX) regardless of filesystem iteration order.
- Reasons remain sorted by code, findings reasons included. Evidence marshalling is canonical (`artifact` only).
- No network in tests; fixtures committed.

## Testing (real fixtures, no network)

1. **Schema round trip** (`pkg/core`): a new `artifact` shaped Evidence marshals and `DecodeEvidence`s back equal; a legacy `image` shaped JSON decodes to `Artifact{Kind:"container", Digest:{"sha256":...}}`; a bare hex digest errors; a missing or unsupported `schemaVersion` errors; unknown fields rejected.
2. **Algorithm aware SLSA** (`pkg/core/verify`): a sha256 subject matches a sha256 `DigestSet`; a `smithmark-bundle-v1` subject matches only its own algorithm; a subject whose algorithm is absent is a non match with a clear reason (this is the regression the unconditional strip caused).
3. **Findings policy** (`pkg/core/policy`, `engine`): a `forbiddenCodes: [UNDECLARED_NETWORK_EGRESS]` rule denies evidence carrying that finding and allows evidence without it; a `maxSeverity: medium` rule denies a high finding; no rule carries findings without denying; reasons sorted by code.
4. **Committed real forgeseal fixtures** under `internal/forgeseal/testdata/`: an actual `pipeline --sign --attest --vex-triage` (keyed) output directory plus a standalone `forgeseal sign` blob bundle and the blob digest.
5. **Adapter discovery** (`internal/forgeseal`): classification finds SLSA/SBOM/VEX regardless of filename; missing VEX is a soft skip; a directory with neither SBOM nor SLSA errors; `DetectSigningCA` returns the fixture CA and `(nil,nil)` without one; the carried SLSA Envelope is the full signed bundle; `Artifact.Kind == "container"` and `SchemaVersion` set.
6. **Blob verify** (`pkg/core/verify`): the committed blob bundle verifies against its digest and the fixture CA (keyed); a one bit digest change fails closed; a DSSE bundle is rejected; `Available` true on every path that ran.
7. **Engine aggregation** (`engine`): evidence with only a verified `BlobSignature` yields `sigView.Verified` and satisfies `signature.required`; a verified attestation plus an unverifiable blob keeps the attestation identity.
8. **CLI** (`cmd/assayward`): `--forgeseal-output <fixture>` composes with no `cp` and no `--signature-ca`, keyed SLSA verifies via auto detected CA; `--signed-blob <fixture-bundle>` with `--image` binds and verifies; explicit `--signature-ca` overrides the auto detected one.
9. **k8s webhook** (`surfaces/k8s-webhook`): existing tests pass against the `Artifact` shape.
10. **Honesty**: an unsigned release blob (messageSignature over a different digest) is reported not verified; synthetic SBOM/VEX wraps remain reported unsigned.

## Scope boundary

- **In scope:** `ArtifactRef` + `DigestSet` (replacing `Image`, legacy decode), algorithm aware SLSA matching, `schemaVersion` + `DecodeEvidence`, `Finding` + `FindingsRule` + evaluation, consumer migration including the k8s webhook and a type only npm mirror, content based discovery, carrying the signed SLSA bundle, `DetectSigningCA` + CA auto merge, VEX optional fix, `BlobSignature` + `VerifyBlobBundle` + `--signed-blob` + engine fold, and real committed fixtures.
- **Out of scope:**
  - Gating the SBOM's own blob signature (redundant with the DSSE signed SLSA of the SBOM); a clean follow up reusing `VerifyBlobBundle`.
  - Changing forgeseal's output naming (the fix belongs in the consumer).
  - Keyless Fulcio/Rekor infrastructure for forgeseal itself (forgeseal's tracked gap); this spec verifies whatever forgeseal produces, keyed today.
  - A per blob subject override distinct from `--image` (YAGNI; `--signed-blob` binds to the `--image` digest).
  - The smithmark side bump to emit `artifact` and drop the `kind=` shim (smithmark's own follow up once a tagged assayward release carries these changes).

## Success criteria

- `Evidence` carries a kind tagged `ArtifactRef` with an algorithm keyed digest; a `smithmark-bundle-v1` subject matches by algorithm and a sha256 assumption never mis matches silently.
- `Evidence` carries a validated `schemaVersion`; `DecodeEvidence` fails loudly on drift or unknown fields.
- A `findings` policy rule denies undeclared network egress from Evidence alone.
- `assayward verify --forgeseal-output <unmodified forgeseal dir>` composes with no `cp` staging; the keyed SLSA signature verifies with no explicit `--signature-ca`.
- `assayward verify --image <ref@digest> --signed-blob <blob.sigstore.json>` binds and a verified blob signature satisfies `signature.required`; a missing VEX no longer errors.
- The full Go suite, `go vet`, `gofmt`, and the wasip1 build stay green; the npm surface type mirror compiles; new fixtures are committed and no test reaches the network.

## Implementation ordering

1. Core schema: `DigestSet`, `ArtifactRef`, `Finding`, `SchemaVersion`, `BlobSignature` types, custom Evidence JSON, `DecodeEvidence`, conversions. (Foundational; everything imports it.)
2. Consumer migration to `Artifact` (verify signatures, engine, summary, discover, k8s webhook, npm types) with the algorithm aware SLSA fix.
3. Findings policy rule + evaluation.
4. forgeseal adapter content discovery + `DetectSigningCA`, setting `Artifact` + `SchemaVersion`.
5. `VerifyBlobBundle` + engine fold + `--signed-blob` + CA auto merge.
6. Real fixtures + cross cutting CLI and honesty tests.
