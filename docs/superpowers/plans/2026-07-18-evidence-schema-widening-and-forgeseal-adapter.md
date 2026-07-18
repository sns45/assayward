# Evidence Schema Widening + forgeseal Adapter + Blob Signature Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close assayward#1 (kind tagged `ArtifactRef` with algorithm keyed digest, `schemaVersion`, carried lint findings) and assayward#2 (content based forgeseal adapter discovery, CA auto detect, release blob signature channel) on one branch.

**Architecture:** Widen the pure `core.Evidence` schema first, migrate every consumer to the new `Artifact` shape (the only semantic change is algorithm aware SLSA subject matching), then add the findings policy rule, then rewrite the forgeseal adapter to discover by content, then add the `VerifyBlobBundle` path and its `--signed-blob` CLI channel, and finally commit real forgeseal fixtures with cross cutting tests.

**Tech Stack:** Go 1.25, `sigstore-go` (bundle + verify), `oras-go` v2, `gopkg.in/yaml.v3`, `encoding/json`. Runtime: use `go test`, `go build`, `go vet`, `gofmt`.

## Global Constraints

- Module `github.com/sns45/assayward`, Apache-2.0. Pure core (`pkg/core`, `pkg/core/verify`, `pkg/core/policy`, `pkg/core/engine`) stays I/O free and deterministic: value in, value out, injected `TrustRoots` and `Clock`, no directory or wall clock access.
- Strict schema parsing: unknown JSON/YAML fields are errors (custom `UnmarshalJSON` must enforce this itself, since it bypasses `json.Decoder.DisallowUnknownFields`).
- Stable machine readable codes: reason codes are documented strings, never repurposed (`FINDINGS_FORBIDDEN_CODE_PRESENT`, `FINDINGS_SEVERITY_EXCEEDED`, `FINDINGS_WITHIN_POLICY`).
- Reuse never re-implement: signature verification uses `sigstore-go`; no hand rolled envelope/JWT/crypto beyond the existing keyed cert chain pattern in `verify/keyed_signature.go`.
- Determinism: `Decision.Reasons` sorted by `Code`; assembled `Evidence.Attestations` in a fixed order (SLSA, SBOM, VEX) regardless of filesystem iteration; Evidence marshals canonically (`artifact` only).
- No network in tests; real fixtures committed under `testdata/`.
- `EvidenceSchemaVersion = "0.2.0"`.
- Every producer of `Evidence` (adapter, discover, CLI) sets `SchemaVersion`.
- The wasip1 build (`GOOS=wasip1 GOARCH=wasm go build ./pkg/...`) and `gofmt`/`go vet` stay green.

---

## File Structure

- `pkg/core/model.go` — add `DigestSet`, `ArtifactRef`, `Finding`, `BlobSignature`; replace `Evidence.Image` with `Evidence.Artifact`; add `Findings`, `BlobSignature`, `SchemaVersion`; custom Evidence JSON; `EvidenceSummary.Artifact`.
- `pkg/core/evidence_codec.go` (new) — `EvidenceSchemaVersion`, `DecodeEvidence`, `parseDigest`, `Evidence.UnmarshalJSON`/`MarshalJSON`, `ImageRef.AsArtifact`, `ArtifactRef.PrimaryDigest`. (Keeps `model.go` a plain type file.)
- `pkg/core/verify/slsa.go` — algorithm aware subject matching against `DigestSet`.
- `pkg/core/verify/{signature.go,sigstore_native.go,sigstore_wasm.go,keyed_signature.go,identity.go}` — take `core.ArtifactRef` instead of `core.ImageRef`.
- `pkg/core/verify/blob_signature.go` (new) — `VerifyBlobBundle`.
- `pkg/core/engine/engine.go` — pass `ev.Artifact`; fold blob signature into `sigView`; project `EvidenceSummary.Artifact`; pass findings to policy.
- `pkg/core/policy/policy.go` — `FindingsRule` + wire type + `Parse` mapping.
- `pkg/core/policy/evaluate.go` — findings evaluation + reasons.
- `internal/forgeseal/adapter.go` — content based discovery; sets `Artifact` + `SchemaVersion`; `DetectSigningCA`.
- `internal/discover/oci.go` — build `ArtifactRef`.
- `cmd/assayward/inputs.go` — build `ArtifactRef`; `--signed-blob`; CA auto merge; set `SchemaVersion`.
- `surfaces/k8s-webhook/{images.go,evaluator.go,admission.go}` — build/read `Artifact`.
- `surfaces/npm/src/types.ts` — mirror `ArtifactRef`, `DigestSet`, `schemaVersion`, `findings`.
- `internal/forgeseal/testdata/` (new) — real forgeseal output + blob bundle fixtures.

---

## Task 1: Core schema types and digest helpers

**Files:**
- Modify: `pkg/core/model.go`
- Create: `pkg/core/evidence_codec.go`
- Test: `pkg/core/artifact_test.go` (new)

**Interfaces:**
- Produces: `type DigestSet map[string]string`; `type ArtifactRef struct { Kind, Name string; Digest DigestSet; Source string }`; `type Finding struct { Code string; Severity Severity; Detail, Location string }`; `type BlobSignature struct { Bundle []byte; ArtifactDigest string }`; `func parseDigest(s string) (DigestSet, error)`; `func (ImageRef) AsArtifact() ArtifactRef`; `func (ArtifactRef) PrimaryDigest() (alg, hex string, ok bool)`.

- [ ] **Step 1: Write the failing test**

Create `pkg/core/artifact_test.go`:

```go
package core

import "testing"

func TestParseDigestAlgorithmKeyed(t *testing.T) {
	ds, err := parseDigest("sha256:ab12")
	if err != nil {
		t.Fatalf("parseDigest: %v", err)
	}
	if ds["sha256"] != "ab12" {
		t.Fatalf("got %v", ds)
	}
	if _, err := parseDigest("deadbeef"); err == nil {
		t.Fatal("bare hex without alg prefix must error")
	}
	if _, err := parseDigest("smithmark-bundle-v1:cd34"); err != nil {
		t.Fatalf("non-sha256 algorithm must parse: %v", err)
	}
}

func TestImageRefAsArtifactAndPrimaryDigest(t *testing.T) {
	a := ImageRef{Name: "reg/repo:tag", Digest: "sha256:ab12"}.AsArtifact()
	if a.Kind != "container" || a.Name != "reg/repo:tag" || a.Digest["sha256"] != "ab12" {
		t.Fatalf("AsArtifact wrong: %+v", a)
	}
	alg, hex, ok := a.PrimaryDigest()
	if !ok || alg != "sha256" || hex != "ab12" {
		t.Fatalf("PrimaryDigest wrong: %q %q %v", alg, hex, ok)
	}
	if _, _, ok := (ArtifactRef{}).PrimaryDigest(); ok {
		t.Fatal("empty digest set must report ok=false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/core/ -run 'TestParseDigest|TestImageRefAsArtifact' -v`
Expected: FAIL (undefined: `parseDigest`, `AsArtifact`, `PrimaryDigest`).

- [ ] **Step 3: Add the types to `pkg/core/model.go`**

Add near `ImageRef` (keep `ImageRef` as-is for now; it is removed from `Evidence` in Task 2):

```go
// DigestSet maps a digest algorithm to its hex value, mirroring in-toto
// Statement subject digests, e.g. {"sha256": "ab.."} or
// {"smithmark-bundle-v1": "cd.."}.
type DigestSet map[string]string

// ArtifactRef identifies the attested subject and its kind.
type ArtifactRef struct {
	Kind   string    `json:"kind"`   // "container" | "mcp-server" | "skill"
	Name   string    `json:"name"`   // registry/repo:tag, purl, or skill name
	Digest DigestSet `json:"digest"` // algorithm keyed
	Source string    `json:"source,omitempty"`
}

// Finding is one capability lint declared-versus-detected gap.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
	Location string   `json:"location,omitempty"`
}

// BlobSignature is a standalone Sigstore messageSignature bundle over a raw
// artifact (e.g. a release archive), verified against ArtifactDigest, not a
// predicate.
type BlobSignature struct {
	Bundle         []byte `json:"bundle"`
	ArtifactDigest string `json:"artifactDigest"` // "sha256:<hex>"
}
```

- [ ] **Step 4: Add helpers to `pkg/core/evidence_codec.go`**

Create the file:

```go
package core

import (
	"fmt"
	"strings"
)

// EvidenceSchemaVersion is the semver of the Evidence wire schema. Producers
// set Evidence.SchemaVersion to this; DecodeEvidence validates it.
const EvidenceSchemaVersion = "0.2.0"

// parseDigest converts "alg:hex" into a single-entry DigestSet. A value with
// no "alg:" prefix is rejected rather than assumed to be sha256.
func parseDigest(s string) (DigestSet, error) {
	alg, hex, ok := strings.Cut(s, ":")
	if !ok || alg == "" || hex == "" {
		return nil, fmt.Errorf("digest %q must be in alg:hex form", s)
	}
	return DigestSet{alg: hex}, nil
}

// AsArtifact maps a container ImageRef onto an ArtifactRef.
func (i ImageRef) AsArtifact() ArtifactRef {
	ds, _ := parseDigest(i.Digest) // best effort; empty on malformed
	return ArtifactRef{Kind: "container", Name: i.Name, Digest: ds}
}

// PrimaryDigest returns a stable canonical entry from the DigestSet for display
// and blob binding. sha256 is preferred; otherwise the lexicographically
// smallest algorithm is chosen so the result is deterministic.
func (a ArtifactRef) PrimaryDigest() (alg, hex string, ok bool) {
	if len(a.Digest) == 0 {
		return "", "", false
	}
	if h, present := a.Digest["sha256"]; present {
		return "sha256", h, true
	}
	best := ""
	for k := range a.Digest {
		if best == "" || k < best {
			best = k
		}
	}
	return best, a.Digest[best], true
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/core/ -run 'TestParseDigest|TestImageRefAsArtifact' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/core/model.go pkg/core/evidence_codec.go pkg/core/artifact_test.go
git commit -m "core: add ArtifactRef, DigestSet, Finding, BlobSignature and digest helpers"
```

---

## Task 2: Evidence schema change, custom JSON, and DecodeEvidence

**Files:**
- Modify: `pkg/core/model.go` (Evidence struct, EvidenceSummary)
- Modify: `pkg/core/evidence_codec.go` (Evidence Marshal/Unmarshal, DecodeEvidence)
- Test: `pkg/core/evidence_codec_test.go` (new)

**Interfaces:**
- Consumes: Task 1 types + `parseDigest`.
- Produces: `Evidence{ Artifact ArtifactRef; Attestations []Attestation; Identity *WorkloadIdentity; Findings []Finding; BlobSignature *BlobSignature; SchemaVersion string; FetchedAt time.Time }`; `EvidenceSummary.Artifact ArtifactRef`; `func DecodeEvidence(b []byte) (Evidence, error)`; `Evidence.UnmarshalJSON`, `Evidence.MarshalJSON`.

- [ ] **Step 1: Write the failing test**

Create `pkg/core/evidence_codec_test.go`:

```go
package core

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvidenceRoundTripArtifact(t *testing.T) {
	in := Evidence{
		SchemaVersion: EvidenceSchemaVersion,
		Artifact:      ArtifactRef{Kind: "skill", Name: "hello", Digest: DigestSet{"smithmark-bundle-v1": "cd34"}},
		FetchedAt:     time.Unix(0, 0).UTC(),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEvidence(b)
	if err != nil {
		t.Fatalf("DecodeEvidence: %v", err)
	}
	if got.Artifact.Kind != "skill" || got.Artifact.Digest["smithmark-bundle-v1"] != "cd34" {
		t.Fatalf("round trip lost artifact: %+v", got.Artifact)
	}
}

func TestEvidenceDecodesLegacyImage(t *testing.T) {
	legacy := `{"schemaVersion":"0.2.0","image":{"name":"reg/repo:tag","digest":"sha256:ab12"},"attestations":[],"fetchedAt":"1970-01-01T00:00:00Z"}`
	got, err := DecodeEvidence([]byte(legacy))
	if err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if got.Artifact.Kind != "container" || got.Artifact.Digest["sha256"] != "ab12" {
		t.Fatalf("legacy image not mapped: %+v", got.Artifact)
	}
}

func TestDecodeEvidenceRejectsBadSchemaAndUnknownFields(t *testing.T) {
	cases := map[string]string{
		"missing version": `{"artifact":{"kind":"container","name":"x","digest":{"sha256":"ab"}},"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"wrong version":   `{"schemaVersion":"9.9.9","artifact":{"kind":"container","name":"x","digest":{"sha256":"ab"}},"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"unknown field":   `{"schemaVersion":"0.2.0","artifact":{"kind":"container","name":"x","digest":{"sha256":"ab"}},"bogus":1,"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"bare hex image":  `{"schemaVersion":"0.2.0","image":{"name":"x","digest":"deadbeef"},"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"neither":         `{"schemaVersion":"0.2.0","fetchedAt":"1970-01-01T00:00:00Z"}`,
	}
	for name, doc := range cases {
		if _, err := DecodeEvidence([]byte(doc)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/core/ -run TestEvidence -v` and `-run TestDecodeEvidence`
Expected: FAIL (Evidence still has `Image`; no `DecodeEvidence`).

- [ ] **Step 3: Change the Evidence and EvidenceSummary structs in `model.go`**

Replace the `Evidence` struct:

```go
type Evidence struct {
	Artifact      ArtifactRef       `json:"artifact"`
	Attestations  []Attestation     `json:"attestations"`
	Identity      *WorkloadIdentity `json:"identity,omitempty"`
	Findings      []Finding         `json:"findings,omitempty"`
	BlobSignature *BlobSignature    `json:"blobSignature,omitempty"`
	SchemaVersion string            `json:"schemaVersion"`
	FetchedAt     time.Time         `json:"fetchedAt"`
}
```

Replace `EvidenceSummary.Image ImageRef` with `Artifact ArtifactRef` (json:"artifact").

- [ ] **Step 4: Implement custom JSON + DecodeEvidence in `evidence_codec.go`**

```go
// evidenceWire is the strict decode target: it accepts both the canonical
// "artifact" and the legacy "image" object, and rejects unknown fields.
type evidenceWire struct {
	Artifact      *ArtifactRef      `json:"artifact"`
	Image         *ImageRef         `json:"image"`
	Attestations  []Attestation     `json:"attestations"`
	Identity      *WorkloadIdentity `json:"identity"`
	Findings      []Finding         `json:"findings"`
	BlobSignature *BlobSignature    `json:"blobSignature"`
	SchemaVersion string            `json:"schemaVersion"`
	FetchedAt     time.Time         `json:"fetchedAt"`
}

func (e *Evidence) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w evidenceWire
	if err := dec.Decode(&w); err != nil {
		return err
	}
	switch {
	case w.Artifact != nil:
		e.Artifact = *w.Artifact
	case w.Image != nil:
		ds, err := parseDigest(w.Image.Digest)
		if err != nil {
			return fmt.Errorf("legacy image digest: %w", err)
		}
		e.Artifact = ArtifactRef{Kind: "container", Name: w.Image.Name, Digest: ds}
	default:
		return fmt.Errorf("evidence has neither artifact nor image")
	}
	e.Attestations, e.Identity = w.Attestations, w.Identity
	e.Findings, e.BlobSignature = w.Findings, w.BlobSignature
	e.SchemaVersion, e.FetchedAt = w.SchemaVersion, w.FetchedAt
	return nil
}

// evidenceAlias avoids infinite recursion in MarshalJSON.
type evidenceAlias Evidence

func (e Evidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(evidenceAlias(e))
}

// DecodeEvidence strictly decodes Evidence JSON and validates schemaVersion.
func DecodeEvidence(b []byte) (Evidence, error) {
	var ev Evidence
	if err := ev.UnmarshalJSON(b); err != nil {
		return Evidence{}, err
	}
	if ev.SchemaVersion != EvidenceSchemaVersion {
		return Evidence{}, fmt.Errorf("unsupported evidence schemaVersion %q (want %q)", ev.SchemaVersion, EvidenceSchemaVersion)
	}
	return ev, nil
}
```

Add imports `bytes`, `encoding/json` to `evidence_codec.go`.

Note: `MarshalJSON` on the alias emits `artifact` (canonical) and never `image`, because `evidenceAlias` has no custom marshaller and the struct tag is `artifact`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/core/ -run 'TestEvidence|TestDecodeEvidence' -v`
Expected: PASS. (`go build ./pkg/core/` will now fail elsewhere — those consumers are Task 3+.)

- [ ] **Step 6: Commit**

```bash
git add pkg/core/model.go pkg/core/evidence_codec.go pkg/core/evidence_codec_test.go
git commit -m "core: replace Evidence.Image with Artifact; add schemaVersion, findings, blobSignature, strict DecodeEvidence"
```

---

## Task 3: Migrate verify signatures, engine, and summary to ArtifactRef

**Files:**
- Modify: `pkg/core/verify/signature.go`, `sigstore_native.go`, `sigstore_wasm.go`, `keyed_signature.go`, `identity.go`
- Modify: `pkg/core/engine/engine.go`
- Test: existing `pkg/core/verify/*_test.go`, `pkg/core/engine/*_test.go` (update call sites)

**Interfaces:**
- Consumes: `core.ArtifactRef`.
- Produces: `SignatureVerifier.Verify(att core.Attestation, art core.ArtifactRef, roots core.TrustRoots) SignatureResult`; `VerifyIdentity(id, art, roots)`; `VerifySLSA(env, art)` (body in Task 4). Engine passes `ev.Artifact`; `buildSummary` sets `EvidenceSummary.Artifact`.

- [ ] **Step 1: Change the signatures (mechanical, compiler-driven)**

Replace every `img core.ImageRef` parameter with `art core.ArtifactRef` in the five verify files and the `SignatureVerifier` interface. In `slsa.go` change the parameter name but keep the body for now (Task 4 rewrites the match). In `engine.go`, change `sigVerifier.Verify(att, ev.Image, roots)` to `sigVerifier.Verify(att, ev.Artifact, roots)`, `VerifyIdentity(*ev.Identity, ev.Artifact, roots)`, `VerifySLSA(env, ev.Artifact)`, and `buildSummary` to set `Artifact: ev.Artifact`.

- [ ] **Step 2: Update test call sites and build**

Run: `go build ./pkg/core/... 2>&1`
Fix each reported call site: replace `core.ImageRef{Name:.., Digest:"sha256:hex"}` construction in verify/engine tests with `core.ArtifactRef{Kind:"container", Name:.., Digest: core.DigestSet{"sha256":"hex"}}` (or `core.ImageRef{...}.AsArtifact()`).

- [ ] **Step 3: Run the verify and engine suites**

Run: `go test ./pkg/core/verify/ ./pkg/core/engine/ 2>&1 | tail -20`
Expected: PASS except any SLSA subject-match assertion that depends on the old sha256 strip (leave those for Task 4 if they fail on non-sha256; sha256 cases must still pass).

- [ ] **Step 4: Commit**

```bash
git add pkg/core/verify pkg/core/engine
git commit -m "verify+engine: thread ArtifactRef through signature, identity, SLSA, and summary"
```

---

## Task 4: Algorithm aware SLSA subject matching

**Files:**
- Modify: `pkg/core/verify/slsa.go`
- Test: `pkg/core/verify/slsa_test.go`

**Interfaces:**
- Consumes: `core.ArtifactRef.Digest DigestSet`, the SLSA statement subject digest map.

- [ ] **Step 1: Write the failing test**

Add to `pkg/core/verify/slsa_test.go` (adapt to the file's existing helpers for building a decoded SLSA envelope with a subject digest map):

```go
func TestSLSASubjectMatchIsAlgorithmAware(t *testing.T) {
	// A skill subject carries smithmark-bundle-v1, not sha256.
	art := core.ArtifactRef{Kind: "skill", Name: "hello",
		Digest: core.DigestSet{"smithmark-bundle-v1": "cd34"}}
	env := slsaEnvelopeWithSubjectDigest(t, "hello", map[string]string{"smithmark-bundle-v1": "cd34"})
	if got := VerifySLSA(env, art); !got.SubjectMatched {
		t.Fatalf("smithmark-bundle-v1 subject must match its own algorithm")
	}
	// A sha256-only artifact must NOT silently match a smithmark subject.
	sha := core.ArtifactRef{Kind: "container", Name: "hello",
		Digest: core.DigestSet{"sha256": "cd34"}}
	if got := VerifySLSA(env, sha); got.SubjectMatched {
		t.Fatalf("sha256 artifact must not match a smithmark-bundle-v1 subject")
	}
}
```

If `SLSAResult` has no `SubjectMatched` field, assert on the existing subject-mismatch reason the function returns. Also add `slsaEnvelopeWithSubjectDigest` if the file lacks an equivalent helper.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pkg/core/verify/ -run TestSLSASubjectMatchIsAlgorithmAware -v`
Expected: FAIL (unconditional `sha256:` strip matches by hex regardless of algorithm).

- [ ] **Step 3: Implement algorithm aware matching**

In `slsa.go`, replace the `strings.TrimPrefix(img.Digest, "sha256:")` comparison with a shared-algorithm match against the subject digest map:

```go
// subjectMatches reports whether any algorithm in the artifact DigestSet is
// present in the statement subject with an equal hex value.
func subjectMatches(subjectDigest map[string]string, art core.ArtifactRef) bool {
	for alg, hex := range art.Digest {
		if subjectDigest[alg] == hex && hex != "" {
			return true
		}
	}
	return false
}
```

Call `subjectMatches(subj.Digest, art)` where the old strip/compare was; keep the existing mismatch reason path for a false result.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./pkg/core/verify/ -run TestSLSA -v`
Expected: PASS (both the new test and existing sha256 cases).

- [ ] **Step 5: Commit**

```bash
git add pkg/core/verify/slsa.go pkg/core/verify/slsa_test.go
git commit -m "verify: match SLSA subject digest by algorithm, not an assumed sha256 strip"
```

---

## Task 5: Migrate producers and surfaces to ArtifactRef

**Files:**
- Modify: `internal/discover/oci.go`, `cmd/assayward/inputs.go`, `surfaces/k8s-webhook/{images.go,evaluator.go,admission.go}`, `surfaces/npm/src/types.ts`
- Test: existing tests in those packages

**Interfaces:**
- Consumes: `core.ArtifactRef`, `ImageRef.AsArtifact()`, `EvidenceSchemaVersion`.

- [ ] **Step 1: Build the whole module to enumerate call sites**

Run: `go build ./... 2>&1`
Every remaining error is an `Evidence.Image` / `EvidenceSummary.Image` / `core.ImageRef`-into-Evidence site.

- [ ] **Step 2: Fix each site (mechanical)**

- `inputs.go`: where it builds `core.Evidence{ Image: imageRef, ... }`, use `Artifact: imageRef.AsArtifact()` and add `SchemaVersion: core.EvidenceSchemaVersion`. Keep `parseImageRef` (still parses `--image`).
- `internal/discover/oci.go`: same `Artifact:` construction + `SchemaVersion`.
- `surfaces/k8s-webhook/*.go`: build `Artifact` where it built `Image`; read `decision.Evidence.Artifact` where it read `.Image`.
- `surfaces/npm/src/types.ts`: replace the `image` interface field with `artifact: ArtifactRef` and add `DigestSet`, `schemaVersion: string`, `findings?: Finding[]` type-only definitions mirroring the Go shapes.

- [ ] **Step 3: Build + test the Go module and the k8s webhook**

Run: `go build ./... && go test ./internal/... ./cmd/... ./surfaces/k8s-webhook/... 2>&1 | tail -20`
Expected: PASS. (The adapter tests referencing old filenames may still pass here because Task 8 rewrites them; if any adapter test constructs `Evidence.Image`, fix it to `Artifact`.)

- [ ] **Step 4: Wasip1 build check**

Run: `GOOS=wasip1 GOARCH=wasm go build ./pkg/...`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add internal/discover cmd/assayward surfaces
git commit -m "migrate discover, CLI, k8s webhook, and npm types to Artifact; set SchemaVersion"
```

---

## Task 6: Findings policy rule and evaluation

**Files:**
- Modify: `pkg/core/policy/policy.go` (FindingsRule + wire + Parse), `pkg/core/policy/evaluate.go` (evaluation), `pkg/core/engine/engine.go` (pass findings)
- Test: `pkg/core/policy/findings_test.go` (new)

**Interfaces:**
- Consumes: `core.Finding`, `core.Severity`.
- Produces: `Policy.Findings FindingsRule`; reasons `FINDINGS_FORBIDDEN_CODE_PRESENT`, `FINDINGS_SEVERITY_EXCEEDED`, `FINDINGS_WITHIN_POLICY`.

- [ ] **Step 1: Write the failing test**

Create `pkg/core/policy/findings_test.go`:

```go
package policy

import (
	"testing"

	core "github.com/sns45/assayward/pkg/core"
)

func hasReason(rs []core.Reason, code string, met bool) bool {
	for _, r := range rs {
		if r.Code == code && r.Met == met {
			return true
		}
	}
	return false
}

func TestFindingsForbiddenCodeDenies(t *testing.T) {
	rule := FindingsRule{ForbiddenCodes: []string{"UNDECLARED_NETWORK_EGRESS"}}
	rs := evaluateFindings(rule, []core.Finding{{Code: "UNDECLARED_NETWORK_EGRESS", Severity: core.SeverityHigh}})
	if !hasReason(rs, "FINDINGS_FORBIDDEN_CODE_PRESENT", false) {
		t.Fatalf("forbidden code must deny: %+v", rs)
	}
	clean := evaluateFindings(rule, []core.Finding{{Code: "UNDECLARED_ENV", Severity: core.SeverityLow}})
	if !hasReason(clean, "FINDINGS_WITHIN_POLICY", true) {
		t.Fatalf("no forbidden code must pass: %+v", clean)
	}
}

func TestFindingsMaxSeverityDenies(t *testing.T) {
	rule := FindingsRule{MaxSeverity: "medium"}
	rs := evaluateFindings(rule, []core.Finding{{Code: "UNDECLARED_EXEC", Severity: core.SeverityHigh}})
	if !hasReason(rs, "FINDINGS_SEVERITY_EXCEEDED", false) {
		t.Fatalf("high finding must exceed medium: %+v", rs)
	}
}

func TestNoFindingsRuleProducesNoReasons(t *testing.T) {
	rs := evaluateFindings(FindingsRule{}, []core.Finding{{Code: "UNDECLARED_ENV", Severity: core.SeverityCritical}})
	if len(rs) != 0 {
		t.Fatalf("no configured rule must not gate: %+v", rs)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pkg/core/policy/ -run TestFindings -v` and `-run TestNoFindings`
Expected: FAIL (undefined `FindingsRule`, `evaluateFindings`).

- [ ] **Step 3: Add the rule, wire type, and Parse mapping in `policy.go`**

Add to `Policy`: `Findings FindingsRule`. Add:

```go
type FindingsRule struct {
	ForbiddenCodes []string
	MaxSeverity    string // "" disables the severity gate
}
```

Add `Findings wireFindingsRule yaml:"findings"` to `wireSpec`, define `wireFindingsRule{ ForbiddenCodes []string yaml:"forbiddenCodes"; MaxSeverity string yaml:"maxSeverity" }`, and map it in `Parse`:

```go
Findings: FindingsRule{
	ForbiddenCodes: doc.Spec.Findings.ForbiddenCodes,
	MaxSeverity:    doc.Spec.Findings.MaxSeverity,
},
```

- [ ] **Step 4: Implement `evaluateFindings` in `evaluate.go`**

```go
var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// evaluateFindings returns reasons for a configured FindingsRule. An empty rule
// (no forbidden codes and no max severity) returns nil: findings are carried
// but never gate.
func evaluateFindings(rule FindingsRule, findings []core.Finding) []core.Reason {
	if len(rule.ForbiddenCodes) == 0 && rule.MaxSeverity == "" {
		return nil
	}
	forbidden := map[string]bool{}
	for _, c := range rule.ForbiddenCodes {
		forbidden[c] = true
	}
	var reasons []core.Reason
	violated := false
	max := severityRank[strings.ToLower(rule.MaxSeverity)]
	for _, f := range findings {
		if forbidden[f.Code] {
			violated = true
			reasons = append(reasons, core.Reason{Code: "FINDINGS_FORBIDDEN_CODE_PRESENT", Severity: f.Severity, Met: false,
				Detail: "finding " + f.Code + " is forbidden by policy"})
		}
		if max > 0 && severityRank[strings.ToLower(string(f.Severity))] > max {
			violated = true
			reasons = append(reasons, core.Reason{Code: "FINDINGS_SEVERITY_EXCEEDED", Severity: f.Severity, Met: false,
				Detail: "finding " + f.Code + " severity exceeds " + rule.MaxSeverity})
		}
	}
	if !violated {
		reasons = append(reasons, core.Reason{Code: "FINDINGS_WITHIN_POLICY", Severity: core.SeverityLow, Met: true,
			Detail: "no finding violates the findings policy"})
	}
	return reasons
}
```

Wire it into `EvaluatePolicy`: accept the evidence findings (add a `findings []core.Finding` parameter or pass via the existing views struct) and append `evaluateFindings(pol.Findings, findings)` to the reasons before the final sort. Update `engine.go` to pass `ev.Findings`.

- [ ] **Step 5: Run tests**

Run: `go test ./pkg/core/policy/ ./pkg/core/engine/ 2>&1 | tail -20`
Expected: PASS. Confirm `Decision.Reasons` remains sorted by code (existing engine test covers this).

- [ ] **Step 6: Commit**

```bash
git add pkg/core/policy pkg/core/engine
git commit -m "policy: add findings rule (forbiddenCodes, maxSeverity) with deterministic reasons"
```

---

## Task 7: forgeseal content classification and CA detection

**Files:**
- Modify: `internal/forgeseal/adapter.go` (add classification + DetectSigningCA helpers)
- Test: `internal/forgeseal/classify_test.go` (new, small inline fixtures)

**Interfaces:**
- Produces: `func classifyForgesealFile(b []byte) forgesealKind`; `func DetectSigningCA(dir string) ([]byte, error)`. `forgesealKind` enumerates `kindSBOM, kindVEX, kindSLSABundle, kindSLSAStatement, kindBlobSig, kindOther`.

- [ ] **Step 1: Write the failing test**

Create `internal/forgeseal/classify_test.go`:

```go
package forgeseal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyByContent(t *testing.T) {
	cases := map[string]forgesealKind{
		`{"bomFormat":"CycloneDX","specVersion":"1.5"}`:                    kindSBOM,
		`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`:     kindVEX,
		`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}`: kindSLSAStatement,
	}
	for body, want := range cases {
		if got := classifyForgesealFile([]byte(body)); got != want {
			t.Errorf("classify %q = %v, want %v", body, got, want)
		}
	}
}

func TestDetectSigningCA(t *testing.T) {
	dir := t.TempDir()
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(dir, "forgeseal-signing-ca.crt"), []byte(pem), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := DetectSigningCA(dir)
	if err != nil || string(got) != pem {
		t.Fatalf("DetectSigningCA = %q, %v", got, err)
	}
	empty, err := DetectSigningCA(t.TempDir())
	if err != nil || empty != nil {
		t.Fatalf("absent CA must be (nil,nil): %q %v", empty, err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/forgeseal/ -run 'TestClassify|TestDetectSigningCA' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Implement the classifier and CA detector**

Add to `adapter.go` (reuse the existing `sigstoreBundle`/`bundleDSSEEnvelope` helpers for bundle detection):

```go
type forgesealKind int

const (
	kindOther forgesealKind = iota
	kindSBOM
	kindVEX
	kindSLSABundle    // Sigstore bundle whose DSSE payload is a SLSA provenance
	kindSLSAStatement // raw in-toto SLSA statement (unsigned fallback)
	kindBlobSig       // Sigstore messageSignature bundle (not attached)
)

func classifyForgesealFile(b []byte) forgesealKind {
	var probe struct {
		BomFormat     string          `json:"bomFormat"`
		Context       json.RawMessage `json:"@context"`
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
	}
	_ = json.Unmarshal(b, &probe)
	switch {
	case probe.BomFormat == "CycloneDX":
		return kindSBOM
	case len(probe.Context) > 0 && bytes.Contains(probe.Context, []byte("openvex.dev")):
		return kindVEX
	case strings.Contains(probe.Type, "in-toto.io/Statement") && strings.Contains(probe.PredicateType, "slsa.dev/provenance"):
		return kindSLSAStatement
	}
	// Structural Sigstore bundle detection.
	var bundle sigstoreBundle
	if err := json.Unmarshal(b, &bundle); err == nil {
		if env := bundleDSSEEnvelope(bundle); env != nil {
			if predicateTypeOfDSSE(env) == "slsa" { // helper: decode payload predicateType, coarse category
				return kindSLSABundle
			}
			return kindOther
		}
		if bundleHasMessageSignature(bundle) { // helper mirroring bundleDSSEEnvelope for content.messageSignature / top-level
			return kindBlobSig
		}
	}
	return kindOther
}

// DetectSigningCA returns the first PEM file in dir containing a CERTIFICATE
// block, or (nil, nil) if none is present.
func DetectSigningCA(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte("-----BEGIN CERTIFICATE-----")) {
			return b, nil
		}
	}
	return nil, nil
}
```

Add the small helpers `predicateTypeOfDSSE` (base64-decode the DSSE `payload`, read `predicateType`, return a coarse label) and `bundleHasMessageSignature` (extend `sigstoreBundle` with a `messageSignature`/`content.messageSignature` probe). Add imports `bytes`, `os`, `path/filepath` as needed.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/forgeseal/ -run 'TestClassify|TestDetectSigningCA' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/forgeseal/adapter.go internal/forgeseal/classify_test.go
git commit -m "forgeseal: classify output files by content; detect signing CA by content"
```

---

## Task 8: Rewrite EvidenceFromOutput to discover by content

**Files:**
- Modify: `internal/forgeseal/adapter.go` (`EvidenceFromOutput`)
- Test: `internal/forgeseal/adapter_test.go` (update existing; add missing-VEX and no-input cases). Full real-fixture assertions land in Task 11.

**Interfaces:**
- Consumes: `classifyForgesealFile`, Task 1/2 core types.
- Produces: `EvidenceFromOutput(dir, artifactDigest string) (core.Evidence, error)` sets `Artifact` (kind container) + `SchemaVersion`; SLSA/SBOM in fixed order; VEX optional.

- [ ] **Step 1: Write/adjust the failing tests**

In `adapter_test.go` add (using small synthesized files, real fixtures come in Task 11):

```go
func TestEvidenceFromOutputMissingVEXIsSoftSkip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sbom.cdx.json", `{"bomFormat":"CycloneDX","specVersion":"1.5"}`)
	writeFile(t, dir, "sbom.cdx.json.intoto.jsonl", `{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[]}`)
	ev, err := EvidenceFromOutput(dir, "sha256:ab12")
	if err != nil {
		t.Fatalf("missing VEX must not error: %v", err)
	}
	if ev.Artifact.Kind != "container" || ev.SchemaVersion != core.EvidenceSchemaVersion {
		t.Fatalf("artifact/schemaVersion not set: %+v", ev)
	}
}

func TestEvidenceFromOutputNoSBOMNoSLSAErrors(t *testing.T) {
	if _, err := EvidenceFromOutput(t.TempDir(), "sha256:ab12"); err == nil {
		t.Fatal("empty dir must error")
	}
}
```

Add a `writeFile` helper if absent.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/forgeseal/ -run TestEvidenceFromOutput -v`
Expected: FAIL (current code reads fixed names / errors on missing VEX).

- [ ] **Step 3: Rewrite `EvidenceFromOutput`**

Glob `dir`, classify each file, and assemble in fixed order:

```go
func EvidenceFromOutput(dir, artifactDigest string) (core.Evidence, error) {
	ds, err := parseArtifactDigest(artifactDigest) // reuse core.parseDigest via a thin wrapper or inline
	if err != nil {
		return core.Evidence{}, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return core.Evidence{}, err
	}
	var slsaBundle, slsaStmt, sbomRaw, vexRaw []byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		switch classifyForgesealFile(b) {
		case kindSLSABundle:
			slsaBundle = b
		case kindSLSAStatement:
			if slsaStmt == nil {
				slsaStmt = b
			}
		case kindSBOM:
			sbomRaw = b
		case kindVEX:
			vexRaw = b
		}
	}
	if sbomRaw == nil && slsaBundle == nil && slsaStmt == nil {
		return core.Evidence{}, fmt.Errorf("forgeseal: no SBOM or SLSA artifact found in %s", dir)
	}
	ev := core.Evidence{
		Artifact:      core.ArtifactRef{Kind: "container", Name: "forgeseal-artifact", Digest: ds},
		SchemaVersion: core.EvidenceSchemaVersion,
	}
	digestHex := ds["sha256"]
	// SLSA first (signed bundle preferred), then SBOM, then VEX if present.
	if slsaBundle != nil {
		if err := validateSLSABundle(slsaBundle); err != nil {
			return core.Evidence{}, err
		}
		ev.Attestations = append(ev.Attestations, core.Attestation{PredicateType: "https://slsa.dev/provenance/v1", Envelope: slsaBundle})
	} else if slsaStmt != nil {
		env, err := wrapStatementInDSSE(slsaStmt, "application/vnd.in-toto+json")
		if err != nil {
			return core.Evidence{}, err
		}
		ev.Attestations = append(ev.Attestations, core.Attestation{PredicateType: "https://slsa.dev/provenance/v1", Envelope: env})
	}
	if sbomRaw != nil {
		env, err := wrapRawStatement(sbomRaw, "forgeseal-artifact", digestHex, "https://cyclonedx.org/bom")
		if err != nil {
			return core.Evidence{}, err
		}
		ev.Attestations = append(ev.Attestations, core.Attestation{PredicateType: "https://cyclonedx.org/bom", Envelope: env})
	}
	if vexRaw != nil {
		env, err := wrapRawStatement(vexRaw, "forgeseal-artifact", digestHex, "https://openvex.dev/ns/v0.2.0")
		if err != nil {
			return core.Evidence{}, err
		}
		ev.Attestations = append(ev.Attestations, core.Attestation{PredicateType: "https://openvex.dev/ns/v0.2.0", Envelope: env})
	}
	return ev, nil
}
```

Reuse the existing `wrapStatementInDSSE`/`readAndWrapRaw` bodies (rename `readAndWrapRaw` to `wrapRawStatement` taking bytes, or keep reading and pass bytes). Add `validateSLSABundle` (the existing `sigstoreBundle` parse + `bundleDSSEEnvelope != nil` check). The caller (`inputs.go`) still overrides `ev.Artifact.Name` from `--image` and sets `FetchedAt`.

- [ ] **Step 4: Run tests + package**

Run: `go test ./internal/forgeseal/ 2>&1 | tail -20`
Expected: PASS (new cases; adjust any legacy test asserting the old fixed-name errors).

- [ ] **Step 5: Commit**

```bash
git add internal/forgeseal
git commit -m "forgeseal: discover SLSA/SBOM/VEX by content; VEX optional; set Artifact + SchemaVersion"
```

---

## Task 9: VerifyBlobBundle (keyed + keyless)

**Files:**
- Create: `pkg/core/verify/blob_signature.go`
- Test: `pkg/core/verify/blob_signature_test.go` (structural cases; the real keyed fixture verifies in Task 11)

**Interfaces:**
- Produces: `func VerifyBlobBundle(bundle []byte, artifactDigest string, roots core.TrustRoots) SignatureResult`.

- [ ] **Step 1: Write the failing test**

```go
package verify

import (
	"testing"

	core "github.com/sns45/assayward/pkg/core"
)

func TestVerifyBlobBundleRejectsNonMessageSignature(t *testing.T) {
	// A DSSE bundle is not a blob signature bundle.
	dsse := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{"payload":"e30=","payloadType":"application/vnd.in-toto+json","signatures":[]}}`)
	got := VerifyBlobBundle(dsse, "sha256:ab12", core.TrustRoots{})
	if got.Verified {
		t.Fatal("a DSSE bundle must not verify as a blob signature")
	}
	if !got.Available {
		t.Fatal("verifier ran, so Available must be true")
	}
}

func TestVerifyBlobBundleRejectsMalformed(t *testing.T) {
	got := VerifyBlobBundle([]byte("not json"), "sha256:ab12", core.TrustRoots{})
	if got.Verified || got.Err == "" {
		t.Fatalf("malformed bundle must fail closed with an error: %+v", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pkg/core/verify/ -run TestVerifyBlobBundle -v`
Expected: FAIL (undefined `VerifyBlobBundle`).

- [ ] **Step 3: Implement `VerifyBlobBundle`**

Model it on `sigstore_native.go` and `keyed_signature.go`. Keyed attempt first (chain leaf to `roots.SignatureCAs`, confirm `messageSignature.messageDigest` equals `artifactDigest`, verify the raw signature), else keyless via `bundle.Bundle` + `sgverify.NewVerifier(...)` with a policy using `sgverify.WithArtifactDigest("sha256", digestBytes)`. Parse `artifactDigest` with `strings.Cut(":")` to get algorithm + hex; decode hex to bytes for `WithArtifactDigest`. Return `SignatureResult{Available:true, Verified:..., Issuer:..., SubjectIdentity:..., RekorLogged:...}`; on any parse/mismatch return `Available:true, Verified:false, Err:...`. Reject a bundle carrying a `dsseEnvelope` (no `messageSignature`) with `Err:"not a messageSignature bundle"`.

Keep the keyed cert-chain logic factored from `keyed_signature.go` (extract a shared `chainLeafToCAs(leafDER []byte, roots core.TrustRoots) error` if it reduces duplication; otherwise mirror it with a comment pointing to the shared intent).

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/core/verify/ -run TestVerifyBlobBundle -v`
Expected: PASS (structural cases). Keyed happy-path is asserted in Task 11 against the real fixture.

- [ ] **Step 5: Commit**

```bash
git add pkg/core/verify/blob_signature.go pkg/core/verify/blob_signature_test.go
git commit -m "verify: add VerifyBlobBundle binding a messageSignature bundle to an artifact digest"
```

---

## Task 10: Engine fold, --signed-blob flag, and CA auto merge

**Files:**
- Modify: `pkg/core/engine/engine.go` (blob fold)
- Modify: `cmd/assayward/inputs.go` (`SignedBlob`, `--signed-blob`, source guard, CA auto merge)
- Test: `pkg/core/engine/engine_test.go`, `cmd/assayward/inputs_test.go`

**Interfaces:**
- Consumes: `VerifyBlobBundle`, `DetectSigningCA`.

- [ ] **Step 1: Write the failing engine test**

```go
func TestEngineFoldsVerifiedBlobSignature(t *testing.T) {
	// A fake verifier is not available here; assert the wiring by using a
	// blob bundle that VerifyBlobBundle marks Available but unverified, and a
	// policy with signature.required=false, then assert sigView.Available.
	ev := core.Evidence{
		SchemaVersion: core.EvidenceSchemaVersion,
		Artifact:      core.ArtifactRef{Kind: "container", Name: "x", Digest: core.DigestSet{"sha256": "ab12"}},
		BlobSignature: &core.BlobSignature{Bundle: []byte(`{"mediaType":"x","messageSignature":{}}`), ArtifactDigest: "sha256:ab12"},
	}
	dec := Evaluate(ev, minimalPolicy(t), core.TrustRoots{}, fixedClock{})
	_ = dec // assert via a signature-availability reason or EvidenceSummary as the engine exposes it
}
```

Adapt the assertion to how the engine surfaces signature availability (a reason code, or add a focused test that a verified blob would set `sigView.Verified`; if a real verified fixture is needed, defer the positive assertion to Task 11 and keep this test on the Available/ordering path).

- [ ] **Step 2: Run to verify it fails / add the fold**

Add to `engine.go` Step 1, immediately after the attestation aggregation loop:

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

- [ ] **Step 3: Add the CLI flag, source guard, and CA auto merge in `inputs.go`**

- Add `SignedBlob string` to `evalInputs`; register `cmd.Flags().StringVar(&o.SignedBlob, "signed-blob", "", "path to a Sigstore messageSignature bundle over the release artifact")`.
- Widen the "at least one attestation source" guard to also accept `o.SignedBlob != ""`.
- After `imageRef` is parsed, if `o.SignedBlob != ""`, read the file and set `ev.BlobSignature = &core.BlobSignature{Bundle: raw, ArtifactDigest: imageRef.Digest}` (set on whichever evidence branch built `ev`; do it after `ev` is assigned).
- After the `--forgeseal-output` branch, if `o.SignatureCA == ""`, call `forgeseal.DetectSigningCA(o.ForgesealOutput)` and set `roots.SignatureCAs` from a non-nil result.

- [ ] **Step 4: Write the failing CLI test**

In `inputs_test.go` add a case: `--signed-blob <path>` alone (with `--image`) is accepted (no "attestation source required" error) and sets `ev.BlobSignature`; and that `--forgeseal-output <dir-with-CA>` sets `roots.SignatureCAs` while an explicit `--signature-ca` overrides it.

- [ ] **Step 5: Run tests + module build**

Run: `go build ./... && go test ./cmd/assayward/ ./pkg/core/engine/ 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/core/engine cmd/assayward
git commit -m "engine+cli: fold blob signature into the signature verdict; add --signed-blob and CA auto merge"
```

---

## Task 11: Real forgeseal fixtures and cross cutting tests

**Files:**
- Create: `internal/forgeseal/testdata/pipeline-output/` (real forgeseal output), `internal/forgeseal/testdata/blob/` (standalone blob bundle + digest)
- Test: `internal/forgeseal/adapter_realfixture_test.go`, `pkg/core/verify/blob_signature_realfixture_test.go`, `cmd/assayward/forgeseal_compose_test.go`

**Interfaces:** none new; asserts end to end against reality.

- [ ] **Step 1: Generate the real fixtures (documented commands; run once)**

Requires forgeseal v0.5.1 built from source (`/Users/shantanu/dev/forgeseal`).

```bash
FX=internal/forgeseal/testdata
mkdir -p $FX/pipeline-output $FX/blob
# From a tiny throwaway project dir with a lockfile forgeseal can read:
forgeseal pipeline --dir <tiny-project> --output-dir $FX/pipeline-output --sign --attest --vex-triage --keyed
# A standalone release blob and its own signature:
printf 'release-artifact-bytes' > $FX/blob/artifact.bin
forgeseal sign $FX/blob/artifact.bin   # writes artifact.bin.sigstore.json (+ CA if keyed)
shasum -a 256 $FX/blob/artifact.bin | cut -d' ' -f1 > $FX/blob/artifact.sha256
```

Commit the actual output (`sbom.cdx.json`, `sbom.cdx.json.intoto.jsonl`, `sbom.cdx.json.intoto.jsonl.sigstore.json`, `sbom.cdx.json.sigstore.json`, `vex.json`, `forgeseal-signing-ca.crt`, the blob bundle, and `artifact.sha256`). If `--vex-triage` produces no VEX (no vulns), synthesize a minimal committed `vex.json` real OpenVEX doc and note it in a `README` in the fixture dir.

- [ ] **Step 2: Adapter real-fixture test**

```go
func TestEvidenceFromOutputRealFixture(t *testing.T) {
	ev, err := EvidenceFromOutput("testdata/pipeline-output", "sha256:"+strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	// SLSA carried as the full signed bundle (verifiable), SBOM present.
	var haveSLSA, haveSBOM bool
	for _, a := range ev.Attestations {
		switch a.PredicateType {
		case "https://slsa.dev/provenance/v1":
			haveSLSA = true
			if !bytes.Contains(a.Envelope, []byte("dsseEnvelope")) && !bytes.Contains(a.Envelope, []byte("messageSignature")) {
				t.Error("SLSA envelope is not the signed bundle")
			}
		case "https://cyclonedx.org/bom":
			haveSBOM = true
		}
	}
	if !haveSLSA || !haveSBOM {
		t.Fatalf("missing SLSA or SBOM: %+v", ev.Attestations)
	}
	ca, err := DetectSigningCA("testdata/pipeline-output")
	if err != nil || ca == nil {
		t.Fatalf("CA not detected: %v", err)
	}
}
```

- [ ] **Step 3: Blob keyed happy-path test**

Read `testdata/blob/artifact.bin.sigstore.json` and `testdata/blob/artifact.sha256`, read the CA from the pipeline output (or the blob dir), and assert `VerifyBlobBundle(bundle, "sha256:"+digest, core.TrustRoots{SignatureCAs: ca}).Verified == true`; then a one-hex-flip digest fails closed.

- [ ] **Step 4: CLI compose + honesty test**

`cmd/assayward` test: run the `verify` command wiring against `--forgeseal-output testdata/.../pipeline-output` with no `--signature-ca` and a policy requiring SLSA; assert the keyed SLSA verifies via auto detected CA and the command composes with no `cp`. Assert an unsigned blob (messageSignature over a different digest) reports not verified.

- [ ] **Step 5: Run the whole suite + vet + fmt + wasip1**

Run:
```bash
go test ./... 2>&1 | tail -30
go vet ./...
gofmt -l . | (grep . && echo "UNFORMATTED" || echo "fmt clean")
GOOS=wasip1 GOARCH=wasm go build ./pkg/...
```
Expected: all PASS/clean.

- [ ] **Step 6: Commit**

```bash
git add internal/forgeseal/testdata internal/forgeseal/adapter_realfixture_test.go pkg/core/verify/blob_signature_realfixture_test.go cmd/assayward/forgeseal_compose_test.go
git commit -m "forgeseal: commit real forgeseal v0.5.1 fixtures; end-to-end adapter, blob verify, and compose tests"
```

---

## Self-Review notes

- Every spec requirement maps to a task: ArtifactRef/DigestSet (T1-T2), legacy decode + schemaVersion + DecodeEvidence (T2), algorithm aware SLSA (T4), findings + policy (T6), content discovery + CA (T7-T8), blob channel (T9-T10), real fixtures + cross cutting + honesty (T11). Consumer migration incl. k8s webhook + npm mirror (T3, T5).
- Type consistency: `Evidence.Artifact` (T2) is consumed as `ev.Artifact` in T3/T5/T8; `FindingsRule` (T6) consumed by engine (T6); `VerifyBlobBundle` (T9) consumed by engine + CLI (T10) and asserted in T11; `classifyForgesealFile`/`DetectSigningCA` (T7) consumed by T8/T10/T11.
- Determinism preserved: fixed attestation order in T8, sorted reasons retained in T6, canonical Evidence marshalling in T2.
- Fixture caveat surfaced: T11 Step 1 documents the VEX-absent fallback rather than silently omitting VEX.
