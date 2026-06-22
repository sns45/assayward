# assayward — Requirements & Architecture Specification

> **Working name:** `assayward` (assay = test purity before acceptance; ward = guardian)
> **Module path:** `github.com/sns45/assayward`
> **One-line:** A runtime trust gate that evaluates supply-chain attestations and workload identities to decide *whether to let a workload run*.

> **Naming caveat:** Run the standard availability sweep (GitHub org/repo, pkg.go.dev, npm, Homebrew core + tap collisions, USPTO) before the first public commit. This spec uses `assayward` throughout; if it does not clear, swap the identifier globally — no logic depends on the name. Fallbacks in priority order: `temperward`, `runeward`, `vouchgate`.

---

## 1. Purpose & Position in the Trilogy

assayward is the third tool in a zero-trust supply-chain trilogy:

| Tool | Question | Output consumed by assayward |
|------|----------|------------------------------|
| **forgeseal** | *What* is running? | CycloneDX SBOM, Sigstore signature, SLSA provenance, VEX |
| **svidmint** | *Who* is running it? | SPIFFE-compatible JWT-SVID / X.509-SVID |
| **assayward** | *Whether to let it run* | — (terminal decision point) |

assayward is a **policy decision + enforcement layer**. It ingests the attestations forgeseal produces and the identities svidmint issues, evaluates them against a declarative policy, and emits an `allow` / `deny` / `audit` decision at the moment a workload is admitted or invoked.

**Non-goal:** assayward does not generate attestations or mint identities. It is a *consumer and verifier* only. Any temptation to re-implement SBOM parsing, signing, or identity issuance is out of scope — call into / verify the outputs of the other two tools.

### Strategic constraints (carried from forgeseal/svidmint)
- **Original contribution, not a port.** No existing tool unifies SBOM + SLSA + VEX + Sigstore signature verification *and* SPIFFE workload-identity verification into a single policy decision spanning both Kubernetes and the serverless/edge tier. That unified evaluator is the whole point — do not narrow it to "another admission controller."
- **Standards alignment:** SLSA (provenance levels), in-toto (attestation envelope), Sigstore/Rekor (signature + transparency), CycloneDX (SBOM), OpenVEX (vulnerability exploitability), SPIFFE/SPIRE + IETF WIMSE (workload identity).
- **Self-demonstrating launch:** forgeseal and svidmint must be gated by assayward in *their own* CI pipelines (see §10).

---

## 2. Architecture Overview

**Single Go policy core, compiled to multiple surfaces.** Model the split on OPA: an embeddable engine + a Wasm artifact + thin per-surface adapters. No business logic lives in an adapter.

```
                      ┌─────────────────────────────────┐
                      │   POLICY CORE  (pkg/core)        │
                      │   pure Go, zero I/O, deterministic│
                      │   - attestation verifiers         │
                      │   - identity verifiers            │
                      │   - policy evaluator              │
                      │   - decision model                │
                      └─────────────────────────────────┘
                       │            │              │
        ┌──────────────┘     ┌──────┘        ┌─────┘
        ▼                    ▼               ▼
  Wasm artifact         Go library     CLI (cmd/assayward)
  (core/wasm)           (direct import)  goreleaser
        │                    │
   ┌────┴─────┐         ┌─────┴──────┐
   ▼          ▼         ▼            ▼
 npm pkg   Workers   K8s admission  Lambda
 (JS/TS)   template  webhook        extension
```

### 2.1 Layering rules
- `pkg/core` is **pure and deterministic**: no network calls, no clock reads except through an injected interface, no filesystem access. All inputs (attestation bundles, identity tokens, trust roots, current time) are passed in. This is what makes the same code correct in a Wasm sandbox and in a webhook.
- **All I/O lives in adapters** (`cmd/`, `surfaces/`): fetching attestations from an OCI registry, reading a JWT off an HTTP header, calling Rekor, loading trust bundles.
- The Wasm build (`GOOS=wasip1 GOARCH=wasm` and/or `js/wasm`) exposes the evaluator over a stable, documented ABI (JSON in → JSON decision out). Adapters that cannot link Go directly (Cloudflare Workers, Deno) call the Wasm module.

### 2.2 Hard dependency constraints
- **Reuse, do not re-implement.** Verification primitives come from established libraries: `sigstore/sigstore-go` (bundle + Rekor verification), `in-toto/in-toto-golang` (DSSE envelopes / attestation predicates), `spiffe/go-spiffe/v2` (SVID validation), CycloneDX + OpenVEX Go libraries for parsing. Do **not** hand-roll signature or JWT verification.
- Keep the `pkg/core` dependency tree minimal and **Wasm-compatible**. Before adding any dependency, confirm it compiles under `GOOS=wasip1`. Anything pulling in cgo, raw sockets, or `os` calls must be isolated behind an adapter interface, never imported by `core`.
- Policy evaluation engine: evaluate **embedding OPA/Rego via `github.com/open-policy-agent/opa/rego`** vs. a purpose-built typed evaluator. Default recommendation below (§5) is a native typed evaluator for the v0.1 built-in checks, with a documented extension path to Rego for custom org policy. Decide explicitly in the plan; do not leave both half-built.

---

## 3. Core Domain Model (`pkg/core`)

Define these types first; everything else is built around them.

```go
// Evidence is everything assayward knows about a candidate workload.
type Evidence struct {
    Image        ImageRef            // OCI ref + digest
    Attestations []Attestation       // forgeseal outputs, DSSE-wrapped
    Identity     *WorkloadIdentity   // svidmint SVID, optional per policy
    FetchedAt    time.Time           // injected, not read from clock
}

type Attestation struct {
    PredicateType string          // SLSA provenance, CycloneDX, OpenVEX, ...
    Envelope      []byte          // DSSE
    Verified      bool            // set by verifier stage, never trust raw
}

type WorkloadIdentity struct {
    SPIFFEID   string
    SVIDType   SVIDType            // JWT or X509
    Claims     map[string]any
    Verified   bool
}

type Decision struct {
    Result    Result               // Allow | Deny | Audit
    Policy    string               // which policy/version decided
    Reasons   []Reason             // structured, machine-readable
    Evidence  EvidenceSummary      // what was checked, redacted
    DecidedAt time.Time
}

type Reason struct {
    Code     string                // e.g. "SLSA_LEVEL_BELOW_THRESHOLD"
    Severity Severity
    Detail   string
    Met      bool
}
```

**Decision model requirements:**
- Decisions are **explainable**: every deny must list the specific failed checks with stable machine-readable codes (for dashboards, alerting, and the audit-mode → enforce-mode migration story).
- **Fail-closed by default**, but the mode is policy-controlled: `enforce` (deny on failure), `audit` (log decision, always allow), `warn` (annotate, allow). Operators must be able to run `audit` first — a blocking gate nobody has watched is a blocking gate nobody trusts.
- Decisions must be **deterministic** given identical `Evidence` + policy + injected time. This is testable and is the property that makes golden-file snapshots viable.

---

## 4. Verification Stages (`pkg/core/verify`)

Each verifier takes raw evidence and returns a verified result or a typed error. Stages are independent and composable; policy decides which are required.

1. **Signature verification** — verify Sigstore bundles via `sigstore-go`. Support keyless (Fulcio cert + OIDC identity match) and keyed. Verify Rekor inclusion proof. Trust roots injected, not fetched in `core`.
2. **SLSA provenance** — parse the in-toto SLSA predicate, extract builder ID and build level, verify the subject digest matches the image under evaluation.
3. **SBOM presence/shape** — parse CycloneDX, expose component set + metadata to policy (e.g. "no components from disallowed licenses/sources").
4. **VEX evaluation** — parse OpenVEX, map known CVEs to exploitability status; policy can require "no `affected` criticals without a justification."
5. **Identity verification** — validate the SVID via `go-spiffe`, check the SPIFFE ID against an allowed trust-domain / ID pattern, and (key WIMSE-aligned check) confirm the identity binding matches the attested workload.

**Critical rule:** `Verified` flags are set *only* by these stages. The policy evaluator must never read an unverified field as if trusted. Add a lint/test that fails if policy reads a raw envelope.

---

## 5. Policy Model (`pkg/core/policy`)

A policy is a declarative, versioned document evaluated against `Evidence`.

**v0.1 — native typed policy (built-in checks):**
```yaml
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: production-default
spec:
  mode: enforce              # enforce | audit | warn
  signature:
    required: true
    keyless:
      issuer: "https://token.actions.githubusercontent.com"
      identityPattern: "https://github.com/sns45/*"
    rekor: { required: true }
  slsa:
    minLevel: 3
    allowedBuilders: ["https://github.com/sns45/*"]
  vex:
    maxUnmitigatedSeverity: high   # deny affected criticals w/o justification
  identity:
    required: true
    trustDomain: "spiffe://sns45.dev"
    idPattern: "spiffe://sns45.dev/ci/*"
```

**Extension path (document, scaffold, do not fully build in v0.1):** custom org logic via embedded Rego, where the verified `Evidence` is passed as `input`. This keeps the common case simple and typed while leaving an escape hatch — the explicit decision called for in §2.2.

Requirements:
- Policies are **versioned** and the version appears in every `Decision`.
- Policy parsing is strict (unknown fields error) to avoid silent misconfiguration.
- Ship a small set of **named built-in policies** (`baseline`, `slsa-l3`, `serverless-edge`) so adopters get value before authoring their own.

---

## 6. Distribution Surfaces

> Build the core + CLI + Wasm first (§ milestones). Surfaces are additive and must not fork logic.

### 6.1 CLI (`cmd/assayward`)
- Commands: `verify` (evaluate evidence against policy, exit non-zero on deny), `explain` (human-readable decision breakdown), `policy validate`, `policy test`.
- `assayward verify` is the **CI primitive** — it fetches attestations for an image ref (via OCI/cosign-style discovery), loads policy, prints a decision, exits 0/1.
- Build/release via **goreleaser**: cross-platform binaries on GitHub Releases, Homebrew tap, Scoop, deb/rpm via nfpm, Docker image, pkg.go.dev for library consumers.

### 6.2 Wasm core (`core/wasm`)
- Stable JSON ABI: `evaluate(evidenceJSON, policyJSON, trustRootsJSON) -> decisionJSON`.
- Built and version-pinned alongside the Go release; published as an artifact and embedded by the JS package.

### 6.3 Serverless / edge
- **npm package** wrapping the Wasm core for JS/TS runtimes (Cloudflare Workers, Deno via `npm:`, Node Lambda). Thin TS API: `await assay(evidence, policy) -> Decision`.
- **Cloudflare Workers template repo** — `wrangler init`-able to a working gate, dovetails with svidmint's Workers support.
- **AWS Lambda**: publish a Lambda Layer ARN (Go extension) for drop-in pre-invoke verification.

### 6.4 Kubernetes
- **Validating admission webhook** (primary), deployable **audit-only first**.
- Helm chart as primary install path; container image on **GHCR**; Kustomize manifests as fallback. List on artifacthub.io once stable.
- Optional init-container / sidecar verifier for the per-pod identity-binding check.

### 6.5 GitHub Marketplace Action
- `sns45/assayward-action` — runs `assayward verify` in CI. **Non-negotiable**: this is how most teams first meet the tool.

### 6.6 Policy bundles
- Distribute signed policy bundles via **OCI registries** (ORAS pattern, as OPA/Kyverno/Sigstore do).
- **Sign bundles with Sigstore; verify them with forgeseal.** The loop closes here.

---

## 7. Repository Layout

```
assayward/
├── cmd/assayward/            # CLI (goreleaser entrypoint)
├── pkg/core/                 # pure, deterministic, Wasm-safe
│   ├── verify/               # signature, slsa, sbom, vex, identity
│   ├── policy/               # parse, evaluate, built-in policies
│   └── model.go              # Evidence, Decision, Reason, ...
├── core/wasm/                # Wasm ABI shim + build
├── surfaces/
│   ├── k8s-webhook/          # admission controller adapter
│   ├── lambda/               # Lambda extension adapter
│   └── npm/                  # TS wrapper around Wasm (published to npm)
├── deploy/
│   ├── helm/                 # chart -> GHCR
│   └── kustomize/
├── policies/                 # baseline, slsa-l3, serverless-edge (signed bundles)
├── templates/cloudflare/     # wrangler template repo source
├── action/                   # GitHub Marketplace action
└── testdata/                 # see §8
```

Prefer single comprehensive files over fragmentation where context allows (consistent with forgeseal/svidmint conventions).

---

## 8. Testing Strategy

- **Golden-file snapshots** for decisions (mirrors forgeseal's `.sbom.json` pattern): committed `*.decision.json` artifacts regenerated with a `-update` flag. Given the determinism guarantee in §3, these are strong PR-review proof of correctness.
- **Real fixtures, committed, not fetched.** Copy real forgeseal-produced attestation bundles and svidmint-issued SVIDs into `testdata/` (consistent with the "copy lockfiles into testdata, no CI-time network fetches" principle). Avoids flaky network-dependent tests.
- **Table-driven verifier tests**: valid bundle, tampered signature, expired SVID, wrong trust domain, SLSA level below threshold, VEX unmitigated critical, subject-digest mismatch.
- **Determinism test**: same evidence + policy + injected time → byte-identical decision across native and Wasm builds.
- **Wasm parity test**: run a fixture suite through both the native evaluator and the Wasm ABI; assert identical decisions.
- **Adapter integration tests**: webhook admission review request → decision; CLI exit-code contract.

---

## 9. Milestones

| Phase | Deliverable | Est. |
|-------|-------------|------|
| **M1 — Core** | `pkg/core` model + signature/SLSA/identity verifiers + native policy evaluator + golden tests | 4–6 days |
| **M2 — CLI** | `cmd/assayward verify/explain/policy`, goreleaser, Homebrew tap, pkg.go.dev | 2–3 days |
| **M3 — Wasm** | Wasm ABI + parity tests + npm package + Workers template | 3–4 days |
| **M4 — K8s** | Validating admission webhook (audit mode), Helm chart, GHCR image | 4–5 days |
| **M5 — Action + bundles** | GitHub Marketplace action; OCI policy bundles signed w/ forgeseal | 2–3 days |
| **M6 — Dogfood** | assayward gates forgeseal + svidmint CI (see §10) | 2 days |

Add SBOM + VEX verifiers in M1 if time allows, otherwise M1.5 — they share the in-toto envelope plumbing with SLSA so the marginal cost is low.

---

## 10. Self-Demonstrating Launch (the credibility move)

At launch, **forgeseal and svidmint releases must not ship unless assayward verifies them**:

1. forgeseal CI produces SBOM/SLSA/VEX/Sigstore outputs for its own release (it already does this).
2. svidmint issues a publisher identity (GitHub Actions OIDC → SVID) for the release job.
3. `assayward verify` evaluates forgeseal's own attestations + the publisher SVID against the published `slsa-l3` policy. Release proceeds only on `allow`.
4. The reverse: svidmint's release is gated the same way.

This is the artifact to point KubeCon CFP reviewers and the spiffe.io ecosystem listing at — the trilogy verifying itself, end to end.

---

## 11. Standards & Adoption Targets (for positioning)

- Align identity-binding semantics with **IETF WIMSE** work (the differentiator vs. plain admission controllers).
- Pursue **spiffe.io ecosystem listing** alongside svidmint.
- Build toward **CNCF Sandbox** once external adopters exist (~18-month horizon; not a launch concern) — the unified trilogy story is what TAG-Security responds to.

---

## 12. Open Questions to Resolve in the Plan

1. Native typed evaluator vs. embedded Rego for v0.1 (§2.2, §5) — pick one, scaffold the other.
2. Attestation discovery mechanism for the CLI: cosign-style OCI referrers API vs. explicit bundle paths vs. both.
3. Wasm target: `wasip1` (server/edge) vs. `js/wasm` (browser console) — likely both, confirm toolchain cost.
4. Does the K8s identity-binding check require a svidmint-issued SVID at admission time, or is image-attestation-only a valid reduced mode? (Affects whether svidmint is a hard dependency of the webhook.)
5. Confirm every `pkg/core` dependency compiles under `GOOS=wasip1` before locking the dependency set.
