// Package engine is the composition root for the assayward policy-decision core.
// It imports core (model) and policy. Nothing imports engine back — this avoids
// import cycles (policy/verify import core; only engine and adapters import policy).
package engine

import (
	"encoding/json"
	"sort"
	"strings"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/verify"
)

// Evaluate is the single entry point used by every surface (CLI, wasm shim, webhook).
// Pure: no I/O; time via clk.
//
// Wiring order:
//  1. Signature: runs the SignatureVerifier over every attestation; aggregates.
//  2. Predicates: DecodeDSSE each attestation; routes by predicateType to SLSA/SBOM/VEX.
//     For each predicate type the LAST successfully parsed result wins (deterministic
//     when a single attestation of each type is present, which is the normal case).
//     Attestations that do not decode as DSSE (e.g. bare Sigstore bundles) are
//     skipped in this loop without affecting signature aggregation.
//  3. Identity: if ev.Identity != nil, runs VerifyIdentity.
//  4. Projects each result to a policy View and calls EvaluatePolicy.
func Evaluate(ev core.Evidence, pol policy.Policy, roots core.TrustRoots, clk core.Clock) core.Decision {
	summary := buildSummary(ev)

	// -------------------------------------------------------------------------
	// Step 1: Signature aggregation
	// -------------------------------------------------------------------------
	sigVerifier := verify.NewSignatureVerifier()

	// sigView accumulates across all attestations.
	// Available is true when the native verifier ran (any result had Available==true).
	// Verified is true when any attestation verified successfully.
	// Identity fields are carried from the first successfully verified attestation.
	var sigView policy.SignatureResultView

	for _, att := range ev.Attestations {
		r := sigVerifier.Verify(att, ev.Artifact, roots)
		if r.Available {
			sigView.Available = true
		}
		if r.Verified && !sigView.Verified {
			// Carry identity fields from the first verified attestation.
			sigView.Verified = true
			sigView.Issuer = r.Issuer
			sigView.SubjectIdentity = r.SubjectIdentity
			sigView.RekorLogged = r.RekorLogged
		}
	}

	// -------------------------------------------------------------------------
	// Step 2: Predicate routing via DSSE decoding.
	// Route by predicateType: contains "slsa.dev/provenance" -> SLSA;
	// contains "cyclonedx" -> SBOM; contains "openvex" -> VEX.
	// Same-type duplicate attestations: the LAST one in ev.Attestations order wins.
	// This is intentional and deterministic given an ordered attestation slice
	// (deterministic for the normal case of one attestation per predicate type).
	// Attestations that fail DecodeDSSE (e.g. bare Sigstore bundles) are
	// skipped here — they are handled by the signature verifier above.
	// -------------------------------------------------------------------------
	var slsaResult verify.SLSAResult
	var sbomResult verify.SBOMResult
	var vexResult verify.VEXResult

	for _, att := range ev.Attestations {
		env, err := verify.DecodeDSSE(att.Envelope)
		if err != nil {
			// Not a bare DSSE envelope (e.g. a Sigstore bundle JSON) — skip.
			continue
		}

		// Determine the predicate type from the decoded payload.
		predType := extractPredicateType(env.Payload)

		switch {
		case strings.Contains(predType, "slsa.dev/provenance"):
			slsaResult = verify.VerifySLSA(env, ev.Artifact)
		case strings.Contains(predType, "cyclonedx"):
			sbomResult = verify.VerifySBOM(env)
		case strings.Contains(predType, "openvex"):
			vexResult = verify.VerifyVEX(env)
		}
	}

	// -------------------------------------------------------------------------
	// Step 3: Identity
	// -------------------------------------------------------------------------
	var idResult verify.IdentityResult
	if ev.Identity != nil {
		idResult = verify.VerifyIdentity(*ev.Identity, ev.Artifact, roots)
	}

	// -------------------------------------------------------------------------
	// Step 4: Project to Views
	// -------------------------------------------------------------------------

	// SLSA view — zero value (BuildLevel=0, Verified=false, etc.) when no SLSA
	// attestation was present or parseable.
	slsaView := policy.SLSAView{
		Verified:           slsaResult.Verified,
		BuilderID:          slsaResult.BuilderID,
		BuildLevel:         slsaResult.BuildLevel,
		SubjectDigestMatch: slsaResult.SubjectDigestMatch,
	}

	// SBOM view — Licenses contains the non-empty License of each Component.
	var licenses []string
	for _, c := range sbomResult.Components {
		if c.License != "" {
			licenses = append(licenses, c.License)
		}
	}
	sort.Strings(licenses) // defensive: order-stable regardless of component iteration order
	sbomView := policy.SBOMView{
		Present:  sbomResult.Present,
		Licenses: licenses,
	}

	// VEX view — AffectedCVEs contains CVE IDs whose Statuses value == "affected".
	// sort.Strings ensures byte-identical output regardless of map iteration order.
	var affectedCVEs []string
	for cve, status := range vexResult.Statuses {
		if status == "affected" {
			affectedCVEs = append(affectedCVEs, cve)
		}
	}
	sort.Strings(affectedCVEs)
	vexView := policy.VEXView{
		Present:      vexResult.Present,
		AffectedCVEs: affectedCVEs,
	}

	// Identity view.
	idView := policy.IdentityView{
		Present:      ev.Identity != nil,
		Verified:     idResult.Verified,
		SPIFFEID:     idResult.SPIFFEID,
		TrustDomain:  idResult.TrustDomain,
		BindingMatch: idResult.BindingMatch,
	}

	// -------------------------------------------------------------------------
	// Step 5: Evaluate policy and build Decision.
	// -------------------------------------------------------------------------
	result, reasons := policy.EvaluatePolicy(pol, sigView, slsaView, sbomView, vexView, idView, ev.Findings)

	// Guarantee non-nil slice so JSON marshals to [] not null.
	if reasons == nil {
		reasons = []core.Reason{}
	}

	return core.Decision{
		Result:    result,
		Policy:    pol.Name + "@" + pol.Version,
		Reasons:   reasons,
		Evidence:  summary,
		DecidedAt: clk.Now(),
	}
}

// buildSummary constructs an EvidenceSummary from ev.
func buildSummary(ev core.Evidence) core.EvidenceSummary {
	types := make([]string, len(ev.Attestations))
	for i, a := range ev.Attestations {
		types[i] = a.PredicateType
	}

	var spiffeID string
	identityPresent := ev.Identity != nil
	if identityPresent {
		spiffeID = ev.Identity.SPIFFEID
	}

	return core.EvidenceSummary{
		Artifact:         ev.Artifact,
		AttestationTypes: types,
		IdentityPresent:  identityPresent,
		SPIFFEID:         spiffeID,
	}
}

// minStmt is a minimal in-toto Statement used to extract predicateType.
type minStmt struct {
	PredicateType string `json:"predicateType"`
}

// extractPredicateType extracts the predicateType field from a raw in-toto
// Statement JSON payload. Returns empty string on any parse error.
func extractPredicateType(payload []byte) string {
	var s minStmt
	if err := json.Unmarshal(payload, &s); err != nil {
		return ""
	}
	return s.PredicateType
}
