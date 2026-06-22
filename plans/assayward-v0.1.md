# assayward v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run **one milestone per execution cycle**; do not start phase N+1 until phase N's verification gate is green.

**Goal:** Build a runtime trust gate that evaluates supply-chain attestations (forgeseal) and workload identities (svidmint) against a declarative policy and emits an explainable `allow`/`deny`/`audit` decision, shipped as a single deterministic Go core compiled to a CLI, a Wasm artifact, an npm package, a K8s admission webhook, a GitHub Action, and signed OCI policy bundles.

**Architecture:** One pure, deterministic, zero-I/O policy core (`pkg/core`) compiled to multiple surfaces (model on OPA: embeddable engine + Wasm artifact + thin per-surface adapters). No business logic in any adapter. All cryptographic verification reuses established libraries; assayward never generates attestations or mints identities — it is a consumer/verifier only.

**Tech Stack:** Go 1.25 (stdlib `GOOS=wasip1`/`js` wasm, no TinyGo), `sigstore-go`, `go-spiffe/v2`, `cyclonedx-go`, `openvex/go-vex`, `go-securesystemslib/dsse`, `in-toto/attestation`; goreleaser, Helm, ORAS, wazero (Wasm host for parity tests).

---

## Resolved Decisions (§12) — read before executing any phase

These five decisions gate the architecture and are **frozen** for v0.1. Each was resolved with the Wasm spike (below) as direct input.

### Decision 1 — Native typed evaluator vs. embedded Rego → **Native typed evaluator; Rego scaffolded only**
v0.1 ships a purpose-built typed evaluator for the built-in checks (signature, slsa, sbom, vex, identity). Rationale: the OPA `rego` runtime is a large dependency tree, is awkward to compile small under `GOOS=wasip1`, and its non-determinism surface (builtins, iteration order) fights the byte-identical golden-snapshot guarantee in §3. A typed evaluator over already-verified `Evidence` is tiny, trivially deterministic, and Wasm-clean. The Rego escape hatch is **scaffolded, not built**: a `policy.CustomEvaluator` interface plus a native-only stub (`//go:build !wasm`) and documentation, so org-custom Rego can be added later without reopening the core contract. We do **not** leave both half-built — Rego is interface + stub + docs only.

### Decision 2 — CLI attestation discovery → **Both; explicit bundle paths are the testable primitive, OCI referrers is the CI ergonomic default**
The CLI supports `--bundle <path>` (explicit, offline, deterministic) **and** cosign-style OCI referrers-API discovery (`--from-oci`, default when an image ref is given). Rationale: explicit paths are built first because they are the unit-testable primitive that backs committed fixtures with zero CI-time network (§8); referrers discovery is the ergonomic path most CI users hit. **Both live entirely in the CLI adapter (I/O); neither touches `pkg/core`.**

### Decision 3 — Wasm target → **`wasip1` primary, `js/wasm` secondary; both from stdlib Go (no TinyGo)**
`GOOS=wasip1 GOARCH=wasm` is the primary target (npm/Workers/Deno/Node/Lambda edge); `GOOS=js GOARCH=wasm` is a secondary build for browser/console. Rationale: the spike confirmed the full core dependency set compiles under stdlib `wasip1` — **TinyGo is not required** (and is not installed), removing a major toolchain cost. Both targets are the same source, different `GOOS`, built from one Makefile. The parity harness (§8) hosts the `.wasm` with **wazero** (pure-Go WASI runtime, no external binary) so CI parity tests are hermetic.

### Decision 4 — K8s identity-binding → **Attestation-only is a valid reduced mode; svidmint SVID is NOT a hard admission requirement**
The webhook gates on image attestations alone (signature + SLSA + SBOM + VEX) when `policy.identity.required: false`, and additionally performs the SPIFFE identity-binding check when `identity.required: true` and an SVID is presented. Rationale: making svidmint a hard dependency would block adoption for teams that have attestations but not yet a SPIFFE control plane; the WIMSE identity-binding check is the differentiator when enabled, not a precondition to deploy. **Consequence: svidmint is an *optional* dependency of the webhook.** Policy controls the mode; default built-ins that require identity say so explicitly.

### Decision 5 — `pkg/core` dependency Wasm-compatibility → **confirmed by spike; signature/Rekor crypto is the one native-only stage**

Spike method: per-dependency isolated module, `GOOS=wasip1 GOARCH=wasm go build ./...`. Results:

| Dependency | Version | Purpose | `wasip1` | Placement |
|---|---|---|---|---|
| `spiffe/go-spiffe/v2` (jwtsvid, x509svid, jwtbundle, spiffeid) | v2.8.1 | SVID verification | ✅ OK | **core** |
| `CycloneDX/cyclonedx-go` | v0.11.0 | SBOM parse | ✅ OK | **core** |
| `openvex/go-vex/pkg/vex` | v0.2.8 | VEX parse | ✅ OK | **core** |
| `secure-systems-lab/go-securesystemslib/dsse` | v0.11.0 | DSSE envelope decode | ✅ OK | **core** |
| `in-toto/attestation/go/v1` | v1.2.0 | in-toto Statement types | ✅ OK | **core** |
| `in-toto/in-toto-golang/.../slsa_provenance/v1` (subpackage only) | v0.11.0 | SLSA predicate types | ✅ OK | **core** |
| `in-toto/in-toto-golang/in_toto` (parent package) | v0.11.0 | DSSE + file recording | ❌ FAIL | **forbidden in core** |
| `sigstore/sigstore-go` | v1.2.1 | Sigstore bundle + Rekor verify | ❌ FAIL | **adapter, native-only** |

Root cause of both failures: `in_toto/util_unix.go` references `unix.Access`/`unix.W_OK`, undefined under `wasip1`. `sigstore-go` pulls the parent `in_toto` package transitively via `rekor/pkg/types/dsse/v0.0.1`. The SLSA predicate **types** live in a separate subpackage that is clean, and DSSE plumbing is replaced by `go-securesystemslib/dsse` — so we never import the failing parent package from core.

**Architectural consequence (frozen):** every verify stage is Wasm-clean **except Sigstore-bundle + Rekor verification**, which is native-only.
- `pkg/core/verify` defines a `SignatureVerifier` **interface**. The sigstore-go implementation lives in `pkg/core/verify/sigstore_native.go` behind `//go:build !wasm` and is compiled into native surfaces (CLI, webhook, Lambda-Go), where it sets `Attestation.Verified` in-process — full §4 compliance.
- The Wasm build links `sigstore_wasm.go` (`//go:build wasm`): a stub that **fails closed** (`Deny`, code `SIGNATURE_VERIFICATION_UNAVAILABLE`) when policy requires signature and no externally-supplied, pre-verified signature assertion is present in the evidence. The Wasm core still runs every other stage itself (SLSA, SBOM, VEX, identity/SVID crypto via go-spiffe), setting their own `Verified` flags in-sandbox.
- This preserves all four invariants: fail-closed default, `Verified` set only by stages, determinism of the decision *given verified evidence*, and "all network/Rekor I/O lives in adapters." Parity tests use fixtures with fixed signature status, so native and Wasm yield byte-identical decisions.

---

## Global Constraints

Every task's requirements implicitly include this section. Values are verbatim from the spec.

- **Module path:** `github.com/sns45/assayward`. Go **1.25**.
- **`pkg/core` is pure & deterministic:** no network, no filesystem, no clock reads except via an injected `Clock`/time-in-evidence interface. All inputs passed in.
- **Wasm-compatibility gate:** anything pulling cgo, raw sockets, or `os` calls is isolated behind an adapter interface and **never imported by `core`**. Re-run `GOOS=wasip1 GOARCH=wasm go build ./pkg/core/...` whenever a `core` dependency is added; it must pass.
- **No business logic in adapters.** Adapters do I/O and call `pkg/core`. A verification or policy decision in an adapter is a bug — route it to core.
- **Reuse, never hand-roll** signature or JWT verification. Use `sigstore-go`, `go-spiffe/v2`, `cyclonedx-go`, `go-vex`, `go-securesystemslib/dsse`, `in-toto/attestation`.
- **Consumer/verifier only.** assayward never generates attestations or mints identities.
- **`Verified` flags are set only inside verify stages.** The policy layer must never read a raw envelope. A lint/test enforces this (Task 1.9).
- **Fail-closed by default;** mode is policy-controlled: `enforce` | `audit` | `warn`.
- **Determinism is testable:** identical `Evidence` + policy + injected time → byte-identical decision across native and Wasm. Golden snapshots depend on this.
- **Strict policy parsing:** unknown YAML fields error. Policy is versioned; the version appears in **every** `Decision`.
- **Zero-dependency discipline:** no new `go.mod` dependency without strong justification and a confirmed `wasip1` build.
- **Prefer single comprehensive files** over fragmentation where context allows.
- **Runtime:** prefer `go`/`gofmt`; for any TS surface use `bun`/`bunx`, not npm/node.

---

## File Structure

```
assayward/
├── go.mod                              # module github.com/sns45/assayward, go 1.25
├── Makefile                            # build native + wasip1 + js/wasm; test; golden -update
├── pkg/core/
│   ├── model.go                        # FROZEN CONTRACT: Evidence, Attestation, WorkloadIdentity,
│   │                                   #   Decision, Reason, EvidenceSummary, ImageRef + enums
│   ├── clock.go                        # injected time interface (no clock reads in core)
│   ├── evaluate.go                     # Evaluate(Evidence, Policy, TrustRoots) Decision — top-level orchestration
│   ├── verify/
│   │   ├── dsse.go                     # DSSE decode via go-securesystemslib (Wasm-clean)
│   │   ├── signature.go               # SignatureVerifier interface + result type
│   │   ├── sigstore_native.go         # //go:build !wasm — sigstore-go impl
│   │   ├── sigstore_wasm.go           # //go:build wasm — fail-closed stub
│   │   ├── slsa.go                     # SLSA predicate parse + subject-digest match
│   │   ├── sbom.go                     # CycloneDX parse → component set
│   │   ├── vex.go                      # OpenVEX parse → CVE→status map
│   │   └── identity.go                # go-spiffe SVID verify + SPIFFE-ID/trust-domain/binding
│   └── policy/
│       ├── policy.go                   # TrustPolicy types, strict YAML parse, versioning
│       ├── evaluate.go                 # native typed evaluator → []Reason + Result
│       ├── custom.go                   # //go:build !wasm — CustomEvaluator (Rego) interface + stub
│       └── builtin/                    # baseline.yaml, slsa-l3.yaml, serverless-edge.yaml (go:embed)
├── core/wasm/
│   ├── main.go                         # //go:build wasm — ABI: evaluate(evidenceJSON,policyJSON,trustRootsJSON)->decisionJSON
│   └── abi.md                          # documented stable JSON ABI
├── cmd/assayward/
│   ├── main.go                         # cobra root
│   ├── verify.go, explain.go, policy.go
│   └── discover/                       # OCI referrers + explicit-bundle discovery (adapter I/O)
├── surfaces/
│   ├── k8s-webhook/                    # validating admission webhook (audit-mode first)
│   ├── lambda/                         # Lambda extension (Go)
│   └── npm/                            # TS wrapper around the wasm core (bun build) + Workers template src
├── deploy/helm/  deploy/kustomize/
├── policies/                           # signed OCI bundles (ORAS)
├── templates/cloudflare/               # wrangler template
├── action/                             # sns45/assayward-action
├── .goreleaser.yaml
└── testdata/                           # real committed forgeseal bundles + svidmint SVIDs + *.decision.json goldens
```

---

# M1 — Core (main thread + verifier-agent + policy-agent + test-agent)

**Milestone deliverable:** `pkg/core` model + DSSE/signature/SLSA/identity verifiers (+ SBOM/VEX) + native typed policy evaluator + golden tests, building clean for native **and** `GOOS=wasip1`.

**Verification gate (all must be green before M2):**
1. `go build ./...` — native — succeeds.
2. `GOOS=wasip1 GOARCH=wasm go build ./pkg/core/... ./core/wasm/...` — succeeds.
3. `go test ./pkg/core/...` — all table-driven verifier cases + golden tests pass.
4. Determinism test passes (same inputs → byte-identical decision).
5. The `Verified`-flag lint test (Task 1.9) passes.
6. Golden `*.decision.json` files committed under `testdata/`.

**Sub-agent dispatch (after the model is frozen in Task 1.1–1.2):**
- **verifier-agent** — owns `pkg/core/verify/*` (Tasks 1.3–1.7). Inherits: reuse libraries, never hand-roll; set `Verified` only here.
- **policy-agent** — owns `pkg/core/policy/*` (Tasks 1.10–1.13). **Must not start until verify interfaces are stubbed (Task 1.3 merged)** so it codes against signatures, not implementations.
- **test-agent** — owns the §8 harness + fixtures (Tasks 1.8, 1.14, 1.15). Sources real committed fixtures from forgeseal/svidmint; no CI-time network.
- Re-state in every dispatch: **no business logic in adapters; route verification/policy decisions to core.**

---

### Task 1.1 — Module bootstrap + frozen domain model

**Files:**
- Create: `go.mod`, `pkg/core/model.go`, `pkg/core/clock.go`
- Test: `pkg/core/model_test.go`

**Interfaces — Produces (every later task and sub-agent depends on these exact names/types):**

```go
// pkg/core/model.go
package core

import "time"

type Result string
const (
	ResultAllow Result = "allow"
	ResultDeny  Result = "deny"
	ResultAudit Result = "audit"
)

type Severity string
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type SVIDType string
const (
	SVIDTypeJWT  SVIDType = "jwt"
	SVIDTypeX509 SVIDType = "x509"
)

type ImageRef struct {
	Name   string `json:"name"`   // registry/repo:tag
	Digest string `json:"digest"` // sha256:...
}

type Evidence struct {
	Image        ImageRef          `json:"image"`
	Attestations []Attestation     `json:"attestations"`
	Identity     *WorkloadIdentity `json:"identity,omitempty"`
	FetchedAt    time.Time         `json:"fetchedAt"` // injected, not read from a clock
}

type Attestation struct {
	PredicateType string `json:"predicateType"`
	Envelope      []byte `json:"envelope"`           // DSSE
	Verified      bool   `json:"verified"`           // set ONLY by a verify stage
	SignatureNote string `json:"signatureNote,omitempty"`
}

type WorkloadIdentity struct {
	SPIFFEID string         `json:"spiffeID"`
	SVIDType SVIDType       `json:"svidType"`
	Claims   map[string]any `json:"claims"`
	Verified bool           `json:"verified"`
}

type Reason struct {
	Code     string   `json:"code"`     // stable machine-readable, e.g. SLSA_LEVEL_BELOW_THRESHOLD
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
	Met      bool     `json:"met"`
}

type EvidenceSummary struct {
	Image            ImageRef `json:"image"`
	AttestationTypes []string `json:"attestationTypes"`
	IdentityPresent  bool     `json:"identityPresent"`
	SPIFFEID         string   `json:"spiffeID,omitempty"`
}

type Decision struct {
	Result    Result          `json:"result"`
	Policy    string          `json:"policy"`    // name@version that decided
	Reasons   []Reason        `json:"reasons"`   // sorted by Code for determinism
	Evidence  EvidenceSummary `json:"evidence"`
	DecidedAt time.Time       `json:"decidedAt"` // from injected Clock
}
```

```go
// pkg/core/clock.go
package core

import "time"

type Clock interface{ Now() time.Time }

// FixedClock makes decisions deterministic and testable.
type FixedClock struct{ T time.Time }
func (c FixedClock) Now() time.Time { return c.T }
```

- [ ] **Step 1: Write the failing test** — `pkg/core/model_test.go`

```go
package core

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDecisionJSONRoundTrip(t *testing.T) {
	d := Decision{
		Result:    ResultDeny,
		Policy:    "slsa-l3@v1alpha1",
		Reasons:   []Reason{{Code: "SLSA_LEVEL_BELOW_THRESHOLD", Severity: SeverityHigh, Detail: "got 2 want 3", Met: false}},
		Evidence:  EvidenceSummary{Image: ImageRef{Name: "r/x:1", Digest: "sha256:abc"}, AttestationTypes: []string{"slsa"}},
		DecidedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(d)
	if err != nil { t.Fatal(err) }
	var got Decision
	if err := json.Unmarshal(b, &got); err != nil { t.Fatal(err) }
	if got.Result != ResultDeny || got.Policy != "slsa-l3@v1alpha1" || len(got.Reasons) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFixedClock(t *testing.T) {
	want := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	if (FixedClock{T: want}).Now() != want { t.Fatal("clock not fixed") }
}
```

- [ ] **Step 2: Run test to verify it fails** — Run: `go test ./pkg/core/ -run TestDecision` — Expected: FAIL (package/types undefined).
- [ ] **Step 3: Write `go.mod`, `model.go`, `clock.go`** with the exact contents above. `go mod init github.com/sns45/assayward && go mod edit -go=1.25`.
- [ ] **Step 4: Run tests** — Run: `go test ./pkg/core/ -run 'TestDecision|TestFixedClock' -v` — Expected: PASS.
- [ ] **Step 5: Verify Wasm cleanliness early** — Run: `GOOS=wasip1 GOARCH=wasm go build ./pkg/core/` — Expected: success.
- [ ] **Step 6: Commit** — `git add go.mod pkg/core/model.go pkg/core/clock.go pkg/core/model_test.go && git commit -m "M1: freeze pkg/core domain model (§3)"`

> **FREEZE POINT.** `model.go` is the contract every adapter depends on. Do not change it after this commit without re-circulating to all sub-agents.

---

### Task 1.2 — Top-level `Evaluate` orchestration skeleton

**Files:** Create `pkg/core/evaluate.go`; Test `pkg/core/evaluate_test.go`

**Interfaces — Produces:**
```go
// pkg/core/evaluate.go
package core
// TrustRoots carries injected trust material (Fulcio/Rekor roots, SPIFFE bundles) — opaque to policy.
type TrustRoots struct {
	SigstoreTUF []byte            `json:"sigstoreTUF,omitempty"`
	SPIFFEBundles map[string][]byte `json:"spiffeBundles,omitempty"` // trustDomain -> JWKS/PEM
}
// Evaluate is the single entry point. Pure: no I/O, time via clk.
func Evaluate(ev Evidence, pol Policy, roots TrustRoots, clk Clock) Decision
```
- Consumes: `Policy` (Task 1.10), verify stages (Tasks 1.3–1.7).
- [ ] Step 1: Failing test asserting `Evaluate` with an empty enforce policy returns `ResultAllow` and `DecidedAt == clk.Now()`.
- [ ] Step 2: `go test ./pkg/core/ -run TestEvaluateEmpty` → FAIL.
- [ ] Step 3: Minimal `Evaluate`: build `EvidenceSummary`, run no checks, return allow with `Policy = pol.Name+"@"+pol.Version`, `Reasons` sorted. (Wire stages in later tasks.)
- [ ] Step 4: `go test ./pkg/core/ -run TestEvaluateEmpty -v` → PASS.
- [ ] Step 5: Commit — `git commit -m "M1: Evaluate orchestration skeleton"`

---

### Task 1.3 — DSSE decode + `SignatureVerifier` interface (verifier-agent)

**Files:** Create `pkg/core/verify/dsse.go`, `pkg/core/verify/signature.go`; Test `pkg/core/verify/dsse_test.go`

**Interfaces — Produces:**
```go
// pkg/core/verify/signature.go
package verify
import core "github.com/sns45/assayward/pkg/core"
type SignatureResult struct { Verified bool; Issuer, SubjectIdentity string; RekorLogged bool; Err string }
type SignatureVerifier interface {
	// Verify checks a Sigstore bundle for one attestation against injected roots.
	Verify(att core.Attestation, img core.ImageRef, roots core.TrustRoots) SignatureResult
}
// DecodedEnvelope is the only way policy/stages read attestation contents.
type DecodedEnvelope struct { PayloadType string; Payload []byte }
func DecodeDSSE(envelope []byte) (DecodedEnvelope, error) // go-securesystemslib/dsse
```
- [ ] Step 1: Failing test: `DecodeDSSE` on a fixture DSSE envelope returns `PayloadType == "application/vnd.in-toto+json"`.
- [ ] Step 2: run → FAIL.
- [ ] Step 3: Implement `DecodeDSSE` using `github.com/secure-systems-lab/go-securesystemslib/dsse`. Define the `SignatureVerifier` interface (no impl yet).
- [ ] Step 4: `GOOS=wasip1 GOARCH=wasm go build ./pkg/core/verify/` → PASS (proves dsse is Wasm-clean). `go test ./pkg/core/verify/ -run TestDecodeDSSE` → PASS.
- [ ] Step 5: Commit — `git commit -m "M1: DSSE decode + SignatureVerifier interface"`

> After this commit, **policy-agent may start** (codes against interfaces).

---

### Task 1.4 — Sigstore signature verifier: native impl + Wasm fail-closed stub (verifier-agent)

**Files:** Create `pkg/core/verify/sigstore_native.go` (`//go:build !wasm`), `pkg/core/verify/sigstore_wasm.go` (`//go:build wasm`); Test `pkg/core/verify/sigstore_native_test.go` (`//go:build !wasm`)

**Interfaces — Produces:** `func NewSignatureVerifier() SignatureVerifier` (build-tag-dispatched).
- Native: implement with `github.com/sigstore/sigstore-go/pkg/verify` + `pkg/bundle`; support keyless (Fulcio cert + OIDC identity match) and keyed; verify Rekor inclusion proof. Trust roots injected via `core.TrustRoots`, never fetched here.
- Wasm: stub returns `SignatureResult{Verified:false, Err:"signature verification unavailable in wasm runtime"}` → caller fails closed with code `SIGNATURE_VERIFICATION_UNAVAILABLE` when policy requires signature.
- [ ] Step 1: Failing native test: valid committed bundle → `Verified==true, RekorLogged==true`; tampered bundle → `Verified==false`. (Uses fixtures from Task 1.8.)
- [ ] Step 2: run native → FAIL.
- [ ] Step 3: Implement native verifier; implement wasm stub.
- [ ] Step 4: `go test ./pkg/core/verify/ -run TestSigstore` → PASS. `GOOS=wasip1 GOARCH=wasm go build ./pkg/core/verify/` → PASS (proves sigstore-go is NOT linked into the wasm build).
- [ ] Step 5: Commit — `git commit -m "M1: sigstore-go signature verifier (native) + wasm fail-closed stub"`

---

### Task 1.5 — SLSA provenance verifier (verifier-agent)

**Files:** Create `pkg/core/verify/slsa.go`; Test `pkg/core/verify/slsa_test.go`

**Interfaces — Produces:**
```go
type SLSAResult struct { Verified bool; BuilderID string; BuildLevel int; SubjectDigestMatch bool; Err string }
func VerifySLSA(env DecodedEnvelope, img core.ImageRef) SLSAResult
```
- Parse the in-toto Statement (`in-toto/attestation/go/v1`) + SLSA predicate (`in_toto/.../slsa_provenance/v1` subpackage — Wasm-clean per spike). Extract builder ID; derive build level; **verify subject digest matches `img.Digest`**.
- [ ] Step 1: Table-driven failing tests: valid provenance (level 3, digest match) → `BuildLevel==3, SubjectDigestMatch==true`; subject-digest mismatch → `SubjectDigestMatch==false`.
- [ ] Step 2: run → FAIL. Step 3: Implement. Step 4: `go test ./pkg/core/verify/ -run TestSLSA` → PASS; `GOOS=wasip1 ... go build ./pkg/core/verify/` → PASS. Step 5: Commit `git commit -m "M1: SLSA provenance verifier + subject-digest match"`.

---

### Task 1.6 — SBOM (CycloneDX) + VEX (OpenVEX) verifiers (verifier-agent)

**Files:** Create `pkg/core/verify/sbom.go`, `pkg/core/verify/vex.go`; Tests alongside.

**Interfaces — Produces:**
```go
type SBOMResult struct { Present bool; Components []Component; Err string }
type Component struct { Name, Version, PURL, License string }
func VerifySBOM(env DecodedEnvelope) SBOMResult              // cyclonedx-go

type VEXResult struct { Present bool; Statuses map[string]string; Err string } // CVE -> status
func VerifyVEX(env DecodedEnvelope) VEXResult                // openvex/go-vex
```
- [ ] Step 1: Failing tests: CycloneDX fixture → component set non-empty; OpenVEX fixture with one `affected` critical → `Statuses["CVE-..."]=="affected"`.
- [ ] Step 2–4: implement; `go test ./pkg/core/verify/ -run 'TestSBOM|TestVEX'` PASS; wasip1 build PASS.
- [ ] Step 5: Commit — `git commit -m "M1: CycloneDX SBOM + OpenVEX verifiers"`

---

### Task 1.7 — Identity verifier (go-spiffe) + binding check (verifier-agent)

**Files:** Create `pkg/core/verify/identity.go`; Test `pkg/core/verify/identity_test.go`

**Interfaces — Produces:**
```go
type IdentityResult struct { Verified bool; SPIFFEID, TrustDomain string; BindingMatch bool; Err string }
// VerifyIdentity validates the SVID crypto via go-spiffe against injected bundles,
// checks trust domain + ID pattern, and confirms the identity binding matches the attested workload.
func VerifyIdentity(id core.WorkloadIdentity, img core.ImageRef, roots core.TrustRoots) IdentityResult
```
- Use `go-spiffe/v2` jwtsvid/x509svid (both Wasm-clean per spike). The binding check (WIMSE-aligned) confirms the SVID's bound workload matches `img.Digest`/claims.
- [ ] Step 1: Failing table tests: valid JWT-SVID right trust domain → `Verified&&BindingMatch`; expired SVID → `Verified==false`; wrong trust domain → `Verified==false`.
- [ ] Step 2–4: implement; tests PASS; `GOOS=wasip1 ... go build ./pkg/core/verify/` PASS.
- [ ] Step 5: Commit — `git commit -m "M1: go-spiffe identity verifier + binding check"`

---

### Task 1.8 — Real committed fixtures (test-agent)

**Files:** Create `testdata/bundles/*` (forgeseal Sigstore bundles, CycloneDX, SLSA, OpenVEX DSSE), `testdata/svid/*` (svidmint JWT-SVID + X509-SVID), `testdata/README.md` documenting provenance of each fixture.
- Copy **real** forgeseal-produced attestation bundles and svidmint-issued SVIDs. Include tampered/expired variants for negative cases. **No CI-time network fetches.**
- [ ] Step 1: Add fixtures. Step 2: Add a fixtures-loadable smoke test (`testdata` files parse). Step 3: `go test ./pkg/core/verify/ -run TestFixtures` → PASS. Step 4: Commit — `git commit -m "M1: real committed forgeseal/svidmint fixtures (§8)"`.

---

### Task 1.9 — `Verified`-flag enforcement lint/test (test-agent)

**Files:** Create `pkg/core/policy/raw_access_test.go`
- A test that statically asserts the `policy` package does **not** import `verify.DecodeDSSE` raw envelopes or read `Attestation.Envelope`. Implement by scanning policy package source with `go/parser` for `.Envelope` selector usage and failing if found; policy must consume only `*Result` structs.
- [ ] Step 1: Write the scan test (fails if any policy file references `.Envelope`). Step 2: Run → PASS (policy clean). Step 3: Commit — `git commit -m "M1: lint — policy may not read raw envelopes (§4 critical rule)"`.

---

### Task 1.10 — Policy types + strict YAML parse + versioning (policy-agent)

**Files:** Create `pkg/core/policy/policy.go`; Test `pkg/core/policy/policy_test.go`

**Interfaces — Produces:**
```go
package policy
type Mode string
const ( ModeEnforce Mode = "enforce"; ModeAudit Mode = "audit"; ModeWarn Mode = "warn" )
type Policy struct {
	APIVersion string; Kind string; Name string; Version string // version surfaced in every Decision
	Mode Mode
	Signature SignatureRule; SLSA SLSARule; VEX VEXRule; SBOM SBOMRule; Identity IdentityRule
}
type SignatureRule struct { Required bool; Keyless *KeylessRule; Rekor RekorRule }
type KeylessRule struct { Issuer, IdentityPattern string }
type RekorRule struct { Required bool }
type SLSARule struct { MinLevel int; AllowedBuilders []string }
type VEXRule struct { MaxUnmitigatedSeverity string }
type SBOMRule struct { Required bool; DisallowedLicenses []string }
type IdentityRule struct { Required bool; TrustDomain, IDPattern string }
// Parse does STRICT yaml (unknown fields error). Maps to core.Policy used by Evaluate.
func Parse(b []byte) (Policy, error)
```
- Use `yaml.UnmarshalStrict` (sigs.k8s.io/yaml or gopkg.in/yaml.v3 with KnownFields(true)) — confirm wasip1 build.
- [ ] Step 1: Failing tests: the §5 example YAML parses; an unknown field errors; `Version` populated. Step 2–4: implement; tests PASS; wasip1 build PASS. Step 5: Commit `git commit -m "M1: strict versioned TrustPolicy parse (§5)"`.

> Note: `pkg/core/evaluate.go`'s `Policy` (Task 1.2) is this `policy.Policy` re-exported or aliased; keep one type. If aliasing, `core.Policy = policy.Policy`.

---

### Task 1.11 — Native typed evaluator (policy-agent)

**Files:** Create `pkg/core/policy/evaluate.go`; Test `pkg/core/policy/evaluate_test.go`

**Interfaces — Produces:**
```go
// EvaluatePolicy turns verified stage results into Reasons + a Result, honoring Mode.
func EvaluatePolicy(pol Policy, sig SignatureResultView, slsa SLSAView, sbom SBOMView, vex VEXView, id IdentityView) (core.Result, []core.Reason)
```
(`*View` types are the policy-visible projections of the verify results — booleans + scalars only, never envelopes — satisfying Task 1.9.)
- Encodes the built-in checks with **stable codes**: `SIGNATURE_REQUIRED_MISSING`, `SIGNATURE_IDENTITY_MISMATCH`, `REKOR_REQUIRED_MISSING`, `SLSA_LEVEL_BELOW_THRESHOLD`, `SLSA_BUILDER_NOT_ALLOWED`, `SUBJECT_DIGEST_MISMATCH`, `VEX_UNMITIGATED_CRITICAL`, `SBOM_DISALLOWED_LICENSE`, `IDENTITY_REQUIRED_MISSING`, `IDENTITY_TRUST_DOMAIN_MISMATCH`, `IDENTITY_BINDING_MISMATCH`, `SIGNATURE_VERIFICATION_UNAVAILABLE`.
- Mode handling: `enforce` → deny on any unmet required check; `audit` → always allow, reasons recorded; `warn` → allow, unmet checks marked. Reasons sorted by `Code`.
- [ ] Step 1: Table-driven failing tests covering each code (valid; tampered sig; expired SVID; wrong trust domain; SLSA below threshold; VEX unmitigated critical; subject-digest mismatch; audit-mode-allows-on-failure). Step 2–4: implement; tests PASS; wasip1 build PASS. Step 5: Commit `git commit -m "M1: native typed policy evaluator + stable reason codes"`.

---

### Task 1.12 — Built-in policies (policy-agent)

**Files:** Create `pkg/core/policy/builtin/{baseline,slsa-l3,serverless-edge}.yaml`, `pkg/core/policy/builtin/embed.go` (`//go:embed`); Test `builtin_test.go`.
- `baseline` (signature required, no SLSA floor), `slsa-l3` (signature + SLSA≥3 + identity required — the dogfood policy), `serverless-edge` (identity-first, signature assertion optional — aligns with Decision 4 reduced mode).
- [ ] Step 1: Failing test: each built-in parses and round-trips; `slsa-l3` has `MinLevel==3` and `Identity.Required==true`. Step 2–4: implement. Step 5: Commit `git commit -m "M1: baseline/slsa-l3/serverless-edge built-in policies"`.

---

### Task 1.13 — Rego escape-hatch scaffold (policy-agent) — **scaffold only**

**Files:** Create `pkg/core/policy/custom.go` (`//go:build !wasm`); doc `pkg/core/policy/custom.md`.
```go
//go:build !wasm
package policy
// CustomEvaluator is the documented extension point for org Rego policy (native-only).
// v0.1 ships the interface + a stub that returns ErrCustomPolicyNotEnabled. NOT implemented.
type CustomEvaluator interface { Evaluate(input []byte) (core.Result, []core.Reason, error) }
var ErrCustomPolicyNotEnabled = errors.New("custom Rego policy is scaffolded but not enabled in v0.1")
```
- [ ] Step 1: Test asserts stub returns `ErrCustomPolicyNotEnabled`. Step 2–3: implement + doc. Step 4: Commit `git commit -m "M1: scaffold Rego custom-policy extension point (Decision 1; not built)"`.

---

### Task 1.14 — Wire `Evaluate` end-to-end + golden snapshots (test-agent + main thread)

**Files:** Modify `pkg/core/evaluate.go`; Create `pkg/core/golden_test.go`, `pkg/core/testdata/golden/*.decision.json`
- Wire `Evaluate` to run verify stages → project to `*View` → `EvaluatePolicy`. Add `-update` flag to regenerate goldens.
- [ ] Step 1: Failing golden test: a matrix of (fixture, built-in policy) cases compared byte-for-byte to committed `*.decision.json`. Step 2: run with `-update` to generate; review; commit goldens. Step 3: `go test ./pkg/core/... ` → PASS. Step 4: Commit `git commit -m "M1: wire Evaluate end-to-end + committed golden decisions (§8)"`.

---

### Task 1.15 — Determinism test (test-agent)

**Files:** Create `pkg/core/determinism_test.go`
- Run the same (evidence, policy, FixedClock) 100× and through a JSON re-marshal; assert byte-identical `Decision`. (Wasm parity is M3.)
- [ ] Step 1: Failing test. Step 2–3: ensure reasons sorted, maps iterated deterministically. Step 4: PASS. Step 5: Commit `git commit -m "M1: determinism test — byte-identical decisions"`.

**→ M1 gate check, then commit boundary: `git commit -m "M1 complete: core verifiers + native policy evaluator green (refs §9 M1)"`**

---

# M2 — CLI (cli-agent)

**Deliverable:** `cmd/assayward` with `verify`, `explain`, `policy validate`, `policy test`; goreleaser (binaries, Homebrew tap, Scoop, nfpm deb/rpm, Docker); exit-code contract. Attestation discovery: explicit `--bundle` **and** OCI referrers (Decision 2).

**Files:** `cmd/assayward/{main,verify,explain,policy}.go`, `cmd/assayward/discover/{oci.go,bundle.go}`, `.goreleaser.yaml`.

**Interfaces — Consumes:** `core.Evaluate`, `policy.Parse`, `policy/builtin`. **Produces:** exit codes — `0` allow/audit, `1` deny, `2` usage/error.

**Sub-agent brief (cli-agent):** Build the CLI as a pure adapter — all OCI/Rekor/file I/O here, all decisions delegated to `core.Evaluate`. Discovery: implement `--bundle` (explicit, offline, testable) first, then cosign-style OCI referrers (`--from-oci`, default for an image ref). Wire trust roots from flags/files into `core.TrustRoots`. `explain` renders the `[]Reason` human-readably. goreleaser: cross-platform binaries → GitHub Releases, Homebrew tap, Scoop, nfpm deb/rpm, Docker, pkg.go.dev. **No business logic in the CLI.**

**Naming sweep (do before first public commit / before goreleaser publish):** check GitHub org/repo, pkg.go.dev, npm, Homebrew core + tap, USPTO for `assayward`. If it does not clear, swap the identifier globally (no logic depends on it): `temperward` → `runeward` → `vouchgate`.

**Verification gate:**
1. `go build ./cmd/...` succeeds.
2. `go test ./cmd/...` — exit-code contract test (deny→1, allow→0, error→2) passes.
3. `assayward verify --bundle testdata/... --policy slsa-l3` against a known-deny fixture exits `1`; against a known-allow fixture exits `0`.
4. `goreleaser release --snapshot --clean` builds all artifacts locally.
5. `assayward policy validate` rejects an unknown-field policy (exit 2).

**Commit boundary:** `git commit -m "M2 complete: CLI verify/explain/policy + goreleaser (refs §9 M2)"`

---

# M3 — Wasm core + npm + Workers template (wasm-agent + npm-agent)

**Deliverable:** Wasm ABI shim, parity tests, npm package wrapping the wasm core, Cloudflare Workers template. Targets `wasip1` (primary) + `js/wasm` (secondary) per Decision 3.

**Files:** `core/wasm/main.go` (`//go:build wasm`), `core/wasm/abi.md`, `surfaces/npm/` (TS + `bun` build), `templates/cloudflare/`.

**Interfaces — Produces (stable ABI, version-pinned to the Go release):**
```
evaluate(evidenceJSON, policyJSON, trustRootsJSON) -> decisionJSON
```
TS: `await assay(evidence, policy, trustRoots?) -> Decision`.

**Sub-agent brief (wasm-agent):** Implement the ABI shim calling `core.Evaluate`. Build `GOOS=wasip1 GOARCH=wasm` (primary) and `GOOS=js GOARCH=wasm` (secondary) from one Makefile target; version-pin the artifact to the Go release tag. The signature stage is the fail-closed stub (Decision 5) — document in `abi.md` that signature verification requires a native pre-pass or a supplied verified assertion, else `SIGNATURE_VERIFICATION_UNAVAILABLE`. **npm-agent:** thin TS wrapper, no logic; load `.wasm`, marshal JSON, return typed `Decision`; build with `bun`. Workers template `wrangler init`-able to a working gate.

**Verification gate:**
1. `make wasm` produces `assayward.wasm` (wasip1) and `assayward_js.wasm` (js) — both build clean.
2. **Wasm-parity test** (`go test` hosting the wasm via **wazero**): the full fixture suite yields **byte-identical** decisions through native and wasm evaluators. **This is a definition-of-done item.**
3. `bun test` in `surfaces/npm/` — TS wrapper returns the same `Decision` JSON for a fixture.
4. `templates/cloudflare/` deploys via `wrangler dev` and gates a sample request.

**Commit boundary:** `git commit -m "M3 complete: wasm ABI + parity + npm + Workers (refs §9 M3)"`

---

# M4 — Kubernetes (k8s-agent)

**Deliverable:** Validating admission webhook (**audit mode first**), Helm chart → GHCR, Kustomize fallback.

**Files:** `surfaces/k8s-webhook/`, `deploy/helm/`, `deploy/kustomize/`.

**Sub-agent brief (k8s-agent):** Admission webhook is a pure adapter: parse `AdmissionReview`, fetch evidence (reuse `cmd/assayward/discover`), call `core.Evaluate`, return allow/deny. **Deploy audit-mode-first** (decision recorded, always admit) per §3 migration story. Per Decision 4: identity-binding is policy-controlled — the webhook runs without svidmint (attestation-only) and adds the SPIFFE check only when `identity.required` and an SVID is present (projected SVID volume / TokenReview). Helm chart is the primary install → image on GHCR; Kustomize as fallback. **No verification/policy logic in the webhook.**

**Verification gate:**
1. `go build ./surfaces/k8s-webhook/...` succeeds.
2. Adapter integration test: an `AdmissionReview` request → expected decision; audit-mode admits even on policy-deny while recording the reason.
3. `helm template deploy/helm` renders; `helm lint` passes.
4. Webhook runs against a kind cluster (or envtest) and admits/denies a test pod per policy.

**Commit boundary:** `git commit -m "M4 complete: K8s webhook (audit-mode) + Helm/GHCR (refs §9 M4)"`

---

# M5 — Action + signed policy bundles (action-agent + bundles-agent)

**Deliverable:** `sns45/assayward-action` GitHub Marketplace action wrapping `assayward verify`; OCI policy-bundle distribution (ORAS), signed with Sigstore, verified by forgeseal.

**Files:** `action/`, `policies/` (bundle build/sign/push scripts).

**Sub-agent brief (action-agent):** Marketplace action invoking the released `assayward verify` binary; inputs = image ref + policy ref; surfaces the exit-code contract; this is how most teams first meet the tool (§6.5). **bundles-agent:** package built-in + custom policies as OCI artifacts via ORAS; sign with Sigstore; verification path uses forgeseal — **the loop closes here** (§6.6).

**Verification gate:**
1. Action runs in a workflow and gates a sample build (allow passes, deny fails the job).
2. `oras push` a signed policy bundle; `oras pull` + Sigstore signature verifies.
3. forgeseal verifies the bundle signature end-to-end.

**Commit boundary:** `git commit -m "M5 complete: Marketplace action + signed OCI policy bundles (refs §9 M5)"`

---

# M6 — Dogfood / Self-Demonstrating Loop (main thread)

**Deliverable:** assayward gates forgeseal + svidmint CI per §10.

**Verification gate (Definition of Done, §10 + plan §4):**
1. forgeseal CI: `assayward verify` evaluates forgeseal's own SBOM/SLSA/VEX/Sigstore outputs **+ a svidmint publisher SVID** against the published `slsa-l3` policy; release proceeds **only on `allow`**.
2. Reverse: svidmint's release is gated identically.
3. Policy bundles signed with Sigstore and verified by forgeseal (loop closed).
4. Wasm-parity suite still green; M1–M5 gates still green.

**Commit boundary:** `git commit -m "M6 complete: trilogy gates itself end-to-end (refs §9 M6)"`

---

## Self-Review (against the spec)

- **§3 model** → Task 1.1 (all types + enums verbatim). **§3 explainable/fail-closed/deterministic** → Tasks 1.11 (codes, modes), 1.15 (determinism), M3 (parity).
- **§4 five verify stages** → Tasks 1.4 (signature), 1.5 (SLSA + digest match), 1.6 (SBOM, VEX), 1.7 (identity + binding). **§4 critical rule (Verified only in stages; no raw-envelope policy reads)** → Task 1.9 lint.
- **§5 policy** (strict parse, versioned, native typed, 3 built-ins, scaffolded Rego) → Tasks 1.10–1.13.
- **§6 surfaces** → M2 (CLI), M3 (Wasm/npm/Workers), M4 (K8s), M5 (Action/bundles). **§6 "no forked logic"** → adapter briefs forbid business logic.
- **§7 layout** → File Structure section. **§8 testing** (golden -update, table-driven, real fixtures, determinism, parity, adapter integration) → Tasks 1.8/1.11/1.14/1.15 + M2/M3/M4 gates.
- **§9 milestones** → M1–M6 with gates. **§10 dogfood** → M6. **§12 decisions** → Resolved Decisions section.
- **Naming sweep** → M2 pre-publish checklist.

**Placeholder scan:** no TBD/TODO/"handle edge cases"; verify-stage and policy code shown as concrete interfaces. M2–M6 are dispatched as bounded sub-agent briefs (per the user's phased-plan format) rather than per-line TDD, since each is an adapter over the frozen core; their gates are concrete and green/red.

**Type consistency:** `Policy` is one type (`policy.Policy`, aliased as `core.Policy`); `Decision`/`Reason`/`Result`/`Severity`/`SVIDType` defined once in Task 1.1 and consumed unchanged everywhere; verify `*Result` → policy `*View` projection is the single boundary that satisfies the §4 lint.
