package policy_test

import (
	"testing"

	"github.com/sns45/assayward/pkg/core/policy"
)

// section5YAML is the verbatim example from §5 of the spec.
const section5YAML = `
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: production-default
spec:
  mode: enforce
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
    maxUnmitigatedSeverity: high
  identity:
    required: true
    trustDomain: "spiffe://sns45.dev"
    idPattern: "spiffe://sns45.dev/ci/*"
`

// TestParseSection5 verifies the §5 example YAML parses into the correct Policy fields.
func TestParseSection5(t *testing.T) {
	p, err := policy.Parse([]byte(section5YAML))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// top-level metadata
	if p.Name != "production-default" {
		t.Errorf("Name: got %q, want %q", p.Name, "production-default")
	}

	// Version should be the version token of apiVersion ("v1alpha1") when
	// metadata.version is absent.
	if p.Version != "v1alpha1" {
		t.Errorf("Version: got %q, want %q", p.Version, "v1alpha1")
	}

	if p.APIVersion != "assayward.dev/v1alpha1" {
		t.Errorf("APIVersion: got %q, want %q", p.APIVersion, "assayward.dev/v1alpha1")
	}

	if p.Kind != "TrustPolicy" {
		t.Errorf("Kind: got %q, want %q", p.Kind, "TrustPolicy")
	}

	if p.Mode != policy.ModeEnforce {
		t.Errorf("Mode: got %q, want %q", p.Mode, policy.ModeEnforce)
	}

	// Signature
	if !p.Signature.Required {
		t.Error("Signature.Required: got false, want true")
	}
	if p.Signature.Keyless == nil {
		t.Fatal("Signature.Keyless: got nil, want non-nil")
	}
	if p.Signature.Keyless.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Signature.Keyless.Issuer: got %q", p.Signature.Keyless.Issuer)
	}
	if p.Signature.Keyless.IdentityPattern != "https://github.com/sns45/*" {
		t.Errorf("Signature.Keyless.IdentityPattern: got %q", p.Signature.Keyless.IdentityPattern)
	}
	if !p.Signature.Rekor.Required {
		t.Error("Signature.Rekor.Required: got false, want true")
	}

	// SLSA
	if p.SLSA.MinLevel != 3 {
		t.Errorf("SLSA.MinLevel: got %d, want 3", p.SLSA.MinLevel)
	}
	if len(p.SLSA.AllowedBuilders) != 1 || p.SLSA.AllowedBuilders[0] != "https://github.com/sns45/*" {
		t.Errorf("SLSA.AllowedBuilders: got %v", p.SLSA.AllowedBuilders)
	}

	// VEX
	if p.VEX.MaxUnmitigatedSeverity != "high" {
		t.Errorf("VEX.MaxUnmitigatedSeverity: got %q, want %q", p.VEX.MaxUnmitigatedSeverity, "high")
	}

	// Identity
	if !p.Identity.Required {
		t.Error("Identity.Required: got false, want true")
	}
	if p.Identity.TrustDomain != "spiffe://sns45.dev" {
		t.Errorf("Identity.TrustDomain: got %q", p.Identity.TrustDomain)
	}
	if p.Identity.IDPattern != "spiffe://sns45.dev/ci/*" {
		t.Errorf("Identity.IDPattern: got %q", p.Identity.IDPattern)
	}
}

// TestParseVersionFromMetadata verifies that an explicit metadata.version wins
// over the version token extracted from apiVersion.
func TestParseVersionFromMetadata(t *testing.T) {
	const yamlWithExplicitVersion = `
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: explicit-version-policy
  version: "2"
spec:
  mode: audit
`
	p, err := policy.Parse([]byte(yamlWithExplicitVersion))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if p.Version != "2" {
		t.Errorf("Version: got %q, want %q", p.Version, "2")
	}
	if p.Name != "explicit-version-policy" {
		t.Errorf("Name: got %q, want %q", p.Name, "explicit-version-policy")
	}
}

// TestParseUnknownFieldErrors verifies that an unknown field at any nesting
// level causes Parse to return an error (strict mode prevents silent misconfiguration).
func TestParseUnknownFieldErrors(t *testing.T) {
	const unknownFieldYAML = `
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: bad-policy
spec:
  mode: enforce
  signature:
    bogus: 1
`
	_, err := policy.Parse([]byte(unknownFieldYAML))
	if err == nil {
		t.Fatal("Parse: expected error for unknown field, got nil")
	}
}

// TestParseValidModes verifies all three valid mode values are accepted.
func TestParseValidModes(t *testing.T) {
	modes := []struct {
		yaml string
		want policy.Mode
	}{
		{`
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: p
spec:
  mode: enforce
`, policy.ModeEnforce},
		{`
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: p
spec:
  mode: audit
`, policy.ModeAudit},
		{`
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: p
spec:
  mode: warn
`, policy.ModeWarn},
	}

	for _, tc := range modes {
		p, err := policy.Parse([]byte(tc.yaml))
		if err != nil {
			t.Errorf("mode %q: unexpected error: %v", tc.want, err)
			continue
		}
		if p.Mode != tc.want {
			t.Errorf("mode: got %q, want %q", p.Mode, tc.want)
		}
	}
}
