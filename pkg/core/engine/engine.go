// Package engine is the composition root for the assayward policy-decision core.
// It imports core (model) and policy. Nothing imports engine back — this avoids
// import cycles (policy/verify import core; only engine and adapters import policy).
package engine

import (
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/policy"
)

// Evaluate is the single entry point used by every surface (CLI, wasm shim, webhook).
// Pure: no I/O; time via clk.
//
// This is a skeleton: verify stages are wired in Task 1.14.
// For now it always returns ResultAllow with the evidence summary populated from ev.
func Evaluate(ev core.Evidence, pol policy.Policy, roots core.TrustRoots, clk core.Clock) core.Decision {
	summary := buildSummary(ev)

	// Reasons is initialized as non-nil empty so JSON marshals to [] not null.
	// Later tasks append Reason values and sort by Code.
	reasons := []core.Reason{}

	return core.Decision{
		Result:    core.ResultAllow,
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
		Image:            ev.Image,
		AttestationTypes: types,
		IdentityPresent:  identityPresent,
		SPIFFEID:         spiffeID,
	}
}
