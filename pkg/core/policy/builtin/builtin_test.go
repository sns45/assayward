package builtin_test

import (
	"testing"

	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// TestAllPoliciesParse verifies every built-in policy parses without error.
func TestAllPoliciesParse(t *testing.T) {
	all := builtin.All()
	if len(all) != 3 {
		t.Fatalf("expected 3 built-in policies, got %d", len(all))
	}
	for name, raw := range all {
		t.Run(name, func(t *testing.T) {
			p, err := policy.Parse(raw)
			if err != nil {
				t.Fatalf("policy.Parse(%q) error: %v", name, err)
			}
			if p.Name != name {
				t.Errorf("Name: got %q, want %q", p.Name, name)
			}
			if p.Version != "v1alpha1" {
				t.Errorf("Version: got %q, want %q", p.Version, "v1alpha1")
			}
		})
	}
}

// TestBaselinePolicy asserts the low-bar "signed and transparency-logged" policy.
func TestBaselinePolicy(t *testing.T) {
	p, err := policy.Parse(builtin.Baseline)
	if err != nil {
		t.Fatalf("Parse(Baseline) error: %v", err)
	}

	if !p.Signature.Required {
		t.Error("baseline: Signature.Required must be true")
	}
	if !p.Signature.Rekor.Required {
		t.Error("baseline: Signature.Rekor.Required must be true")
	}
	if p.SLSA.MinLevel != 0 {
		t.Errorf("baseline: SLSA.MinLevel must be 0 (no floor), got %d", p.SLSA.MinLevel)
	}
	if p.Identity.Required {
		t.Error("baseline: Identity.Required must be false")
	}
}

// TestSLSAL3Policy asserts the dogfood policy requiring SLSA level 3 + identity.
func TestSLSAL3Policy(t *testing.T) {
	p, err := policy.Parse(builtin.SLSAL3)
	if err != nil {
		t.Fatalf("Parse(SLSAL3) error: %v", err)
	}

	if !p.Signature.Required {
		t.Error("slsa-l3: Signature.Required must be true")
	}
	if p.Signature.Keyless == nil {
		t.Fatal("slsa-l3: Signature.Keyless must not be nil")
	}
	if p.Signature.Keyless.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("slsa-l3: Keyless.Issuer: got %q, want %q",
			p.Signature.Keyless.Issuer, "https://token.actions.githubusercontent.com")
	}
	if p.Signature.Keyless.IdentityPattern != "https://github.com/sns45/*" {
		t.Errorf("slsa-l3: Keyless.IdentityPattern: got %q, want %q",
			p.Signature.Keyless.IdentityPattern, "https://github.com/sns45/*")
	}
	if !p.Signature.Rekor.Required {
		t.Error("slsa-l3: Signature.Rekor.Required must be true")
	}
	if p.SLSA.MinLevel != 3 {
		t.Errorf("slsa-l3: SLSA.MinLevel must be 3, got %d", p.SLSA.MinLevel)
	}
	if len(p.SLSA.AllowedBuilders) == 0 {
		t.Error("slsa-l3: SLSA.AllowedBuilders must not be empty")
	}
	if p.VEX.MaxUnmitigatedSeverity != "high" {
		t.Errorf("slsa-l3: VEX.MaxUnmitigatedSeverity: got %q, want %q",
			p.VEX.MaxUnmitigatedSeverity, "high")
	}
	if !p.Identity.Required {
		t.Error("slsa-l3: Identity.Required must be true")
	}
	if p.Identity.TrustDomain != "spiffe://sns45.dev" {
		t.Errorf("slsa-l3: Identity.TrustDomain: got %q, want %q",
			p.Identity.TrustDomain, "spiffe://sns45.dev")
	}
	if p.Identity.IDPattern != "spiffe://sns45.dev/ci/*" {
		t.Errorf("slsa-l3: Identity.IDPattern: got %q, want %q",
			p.Identity.IDPattern, "spiffe://sns45.dev/ci/*")
	}
}

// TestServerlessEdgePolicy asserts the identity-first reduced mode policy.
func TestServerlessEdgePolicy(t *testing.T) {
	p, err := policy.Parse(builtin.ServerlessEdge)
	if err != nil {
		t.Fatalf("Parse(ServerlessEdge) error: %v", err)
	}

	if p.Signature.Required {
		t.Error("serverless-edge: Signature.Required must be false (wasm runtime cannot verify Sigstore bundles)")
	}
	if !p.Identity.Required {
		t.Error("serverless-edge: Identity.Required must be true")
	}
	if p.Identity.TrustDomain != "spiffe://sns45.dev" {
		t.Errorf("serverless-edge: Identity.TrustDomain: got %q, want %q",
			p.Identity.TrustDomain, "spiffe://sns45.dev")
	}
	if p.Identity.IDPattern != "spiffe://sns45.dev/*" {
		t.Errorf("serverless-edge: Identity.IDPattern: got %q, want %q",
			p.Identity.IDPattern, "spiffe://sns45.dev/*")
	}
	if p.Mode != policy.ModeEnforce {
		t.Errorf("serverless-edge: Mode: got %q, want %q", p.Mode, policy.ModeEnforce)
	}
}
