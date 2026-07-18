package policy_test

import (
	"sort"
	"testing"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/policy"
)

// helpers to build minimal Policy values

func minPol(mode policy.Mode) policy.Policy {
	return policy.Policy{
		Name:    "test",
		Version: "v1",
		Mode:    mode,
	}
}

// findReason returns the first Reason with the given Code, or the zero Reason (Met=false, Code="").
func findReason(reasons []core.Reason, code string) (core.Reason, bool) {
	for _, r := range reasons {
		if r.Code == code {
			return r, true
		}
	}
	return core.Reason{}, false
}

// hasCode reports whether any Reason has the given code.
func hasCode(reasons []core.Reason, code string) bool {
	_, ok := findReason(reasons, code)
	return ok
}

// TestSignatureVerificationUnavailable checks the fail-closed path when signature
// is required but the verifier could not run (e.g. wasm stub).
func TestSignatureVerificationUnavailable(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true

	sig := policy.SignatureResultView{Available: false, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SIGNATURE_VERIFICATION_UNAVAILABLE")
	if !ok {
		t.Fatal("expected reason SIGNATURE_VERIFICATION_UNAVAILABLE")
	}
	if r.Met {
		t.Error("expected Met=false for SIGNATURE_VERIFICATION_UNAVAILABLE")
	}
	if r.Severity != core.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", r.Severity)
	}
}

// TestSignatureRequiredMissing covers sig required, verifier available but sig not verified.
func TestSignatureRequiredMissing(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true

	sig := policy.SignatureResultView{Available: true, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SIGNATURE_REQUIRED_MISSING")
	if !ok {
		t.Fatal("expected reason SIGNATURE_REQUIRED_MISSING")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
	if r.Severity != core.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %q", r.Severity)
	}
	// SIGNATURE_VERIFICATION_UNAVAILABLE should NOT fire when verifier is available
	if hasCode(reasons, "SIGNATURE_VERIFICATION_UNAVAILABLE") {
		t.Error("SIGNATURE_VERIFICATION_UNAVAILABLE should not fire when Available=true")
	}
}

// TestSignatureIdentityMismatch: keyless rule set, sig verified but issuer or identity wrong.
func TestSignatureIdentityMismatch(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true
	pol.Signature.Keyless = &policy.KeylessRule{
		Issuer:          "https://token.actions.githubusercontent.com",
		IdentityPattern: "https://github.com/sns45/*",
	}

	sig := policy.SignatureResultView{
		Available:       true,
		Verified:        true,
		Issuer:          "https://WRONG.issuer.com",
		SubjectIdentity: "https://github.com/sns45/repo/.github/workflows/x.yml@refs/heads/main",
		RekorLogged:     true,
	}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SIGNATURE_IDENTITY_MISMATCH")
	if !ok {
		t.Fatal("expected SIGNATURE_IDENTITY_MISMATCH")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
}

// TestSignatureIdentityPatternMatch: glob should match across slashes.
func TestSignatureIdentityPatternMatch(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true
	pol.Signature.Keyless = &policy.KeylessRule{
		Issuer:          "https://token.actions.githubusercontent.com",
		IdentityPattern: "https://github.com/sns45/*",
	}

	sig := policy.SignatureResultView{
		Available:       true,
		Verified:        true,
		Issuer:          "https://token.actions.githubusercontent.com",
		SubjectIdentity: "https://github.com/sns45/repo/.github/workflows/x.yml@refs/heads/main",
		RekorLogged:     false,
	}
	_, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	r, ok := findReason(reasons, "SIGNATURE_IDENTITY_MISMATCH")
	if ok && !r.Met {
		t.Error("glob should match across slashes; SIGNATURE_IDENTITY_MISMATCH should not fail")
	}
}

// TestRekorRequiredMissing: Rekor required but not logged.
func TestRekorRequiredMissing(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Rekor.Required = true

	sig := policy.SignatureResultView{Available: true, Verified: true, RekorLogged: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "REKOR_REQUIRED_MISSING")
	if !ok {
		t.Fatal("expected REKOR_REQUIRED_MISSING")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
}

// TestSLSALevelBelowThreshold: build level below minimum.
func TestSLSALevelBelowThreshold(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.SLSA.MinLevel = 3

	slsa := policy.SLSAView{Verified: true, BuildLevel: 2, SubjectDigestMatch: true}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, slsa, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SLSA_LEVEL_BELOW_THRESHOLD")
	if !ok {
		t.Fatal("expected SLSA_LEVEL_BELOW_THRESHOLD")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
	if r.Severity != core.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %q", r.Severity)
	}
}

// TestSLSABuilderNotAllowed: builder not in allowed list.
func TestSLSABuilderNotAllowed(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.SLSA.AllowedBuilders = []string{"https://github.com/slsa-framework/slsa-github-generator/*"}

	slsa := policy.SLSAView{Verified: true, BuilderID: "https://evil.builder.io/bad", BuildLevel: 3, SubjectDigestMatch: true}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, slsa, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SLSA_BUILDER_NOT_ALLOWED")
	if !ok {
		t.Fatal("expected SLSA_BUILDER_NOT_ALLOWED")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
}

// TestSubjectDigestMismatch: SLSA in scope but digest doesn't match.
func TestSubjectDigestMismatch(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.SLSA.MinLevel = 2

	slsa := policy.SLSAView{Verified: true, BuildLevel: 3, SubjectDigestMatch: false}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, slsa, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SUBJECT_DIGEST_MISMATCH")
	if !ok {
		t.Fatal("expected SUBJECT_DIGEST_MISMATCH")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
	if r.Severity != core.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", r.Severity)
	}
}

// TestSubjectDigestMismatchNotFiredWhenSLSANotInScope: no SLSA policy means no digest check.
func TestSubjectDigestMismatchNotFiredWhenSLSANotInScope(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	// SLSA not configured

	slsa := policy.SLSAView{Verified: false, BuildLevel: 0, SubjectDigestMatch: false}
	_, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, slsa, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if hasCode(reasons, "SUBJECT_DIGEST_MISMATCH") {
		t.Error("SUBJECT_DIGEST_MISMATCH should not fire when SLSA not in scope")
	}
}

// TestVEXUnmitigatedCritical: affected CVEs present with max severity gate set.
func TestVEXUnmitigatedCritical(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.VEX.MaxUnmitigatedSeverity = "critical"

	vex := policy.VEXView{Present: true, AffectedCVEs: []string{"CVE-2024-1234"}}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, policy.SBOMView{}, vex, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "VEX_UNMITIGATED_CRITICAL")
	if !ok {
		t.Fatal("expected VEX_UNMITIGATED_CRITICAL")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
	if r.Severity != core.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", r.Severity)
	}
}

// TestVEXUnmitigatedNotFiredWhenNoAffected: no affected CVEs means no violation.
func TestVEXUnmitigatedNotFiredWhenNoAffected(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.VEX.MaxUnmitigatedSeverity = "critical"

	vex := policy.VEXView{Present: true, AffectedCVEs: nil}
	result, _ := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, policy.SBOMView{}, vex, policy.IdentityView{}, nil)

	if result != core.ResultAllow {
		t.Errorf("expected ResultAllow, got %q", result)
	}
}

// TestSBOMRequiredMissing: SBOM required but not present.
func TestSBOMRequiredMissing(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.SBOM.Required = true

	sbom := policy.SBOMView{Present: false}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, sbom, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SBOM_REQUIRED_MISSING")
	if !ok {
		t.Fatal("expected SBOM_REQUIRED_MISSING")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
	if r.Severity != core.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %q", r.Severity)
	}
}

// TestSBOMDisallowedLicense: license in disallowed list present in SBOM.
func TestSBOMDisallowedLicense(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.SBOM.DisallowedLicenses = []string{"GPL-3.0", "AGPL-3.0"}

	sbom := policy.SBOMView{Present: true, Licenses: []string{"MIT", "GPL-3.0"}}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, sbom, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "SBOM_DISALLOWED_LICENSE")
	if !ok {
		t.Fatal("expected SBOM_DISALLOWED_LICENSE")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
	if r.Severity != core.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %q", r.Severity)
	}
}

// TestSBOMAllLicensesAllowed: no intersection means no violation.
func TestSBOMAllLicensesAllowed(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.SBOM.DisallowedLicenses = []string{"GPL-3.0"}

	sbom := policy.SBOMView{Present: true, Licenses: []string{"MIT", "Apache-2.0"}}
	result, _ := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, sbom, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultAllow {
		t.Errorf("expected ResultAllow, got %q", result)
	}
}

// TestIdentityRequiredMissing: identity required but not present/verified.
func TestIdentityRequiredMissing(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Identity.Required = true

	id := policy.IdentityView{Present: false, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, id, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "IDENTITY_REQUIRED_MISSING")
	if !ok {
		t.Fatal("expected IDENTITY_REQUIRED_MISSING")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
}

// TestIdentityTrustDomainMismatch: verified identity but wrong trust domain.
func TestIdentityTrustDomainMismatch(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Identity.Required = true
	pol.Identity.TrustDomain = "example.com"

	id := policy.IdentityView{
		Present:      true,
		Verified:     true,
		TrustDomain:  "evil.com",
		SPIFFEID:     "spiffe://evil.com/service",
		BindingMatch: true,
	}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, id, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "IDENTITY_TRUST_DOMAIN_MISMATCH")
	if !ok {
		t.Fatal("expected IDENTITY_TRUST_DOMAIN_MISMATCH")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
}

// TestIdentityIDPatternMismatch: verified identity but SPIFFE ID doesn't match pattern.
func TestIdentityIDPatternMismatch(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Identity.Required = true
	pol.Identity.TrustDomain = "example.com"
	pol.Identity.IDPattern = "spiffe://example.com/allowed/*"

	id := policy.IdentityView{
		Present:      true,
		Verified:     true,
		TrustDomain:  "example.com",
		SPIFFEID:     "spiffe://example.com/disallowed/service",
		BindingMatch: true,
	}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, id, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "IDENTITY_TRUST_DOMAIN_MISMATCH")
	if !ok {
		t.Fatal("expected IDENTITY_TRUST_DOMAIN_MISMATCH for ID pattern mismatch")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
}

// TestIdentityBindingMismatch: verified identity but binding doesn't match.
func TestIdentityBindingMismatch(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Identity.Required = true

	id := policy.IdentityView{
		Present:      true,
		Verified:     true,
		TrustDomain:  "example.com",
		SPIFFEID:     "spiffe://example.com/service",
		BindingMatch: false,
	}
	result, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, id, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	r, ok := findReason(reasons, "IDENTITY_BINDING_MISMATCH")
	if !ok {
		t.Fatal("expected IDENTITY_BINDING_MISMATCH")
	}
	if r.Met {
		t.Error("expected Met=false")
	}
}

// TestAllPassAllow: a policy with all checks configured but all passing -> ResultAllow.
func TestAllPassAllow(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true
	pol.Signature.Keyless = &policy.KeylessRule{
		Issuer:          "https://token.actions.githubusercontent.com",
		IdentityPattern: "https://github.com/sns45/*",
	}
	pol.Signature.Rekor.Required = true
	pol.SLSA.MinLevel = 2
	pol.SLSA.AllowedBuilders = []string{"https://github.com/slsa-framework/*"}
	pol.VEX.MaxUnmitigatedSeverity = "critical"
	pol.SBOM.Required = true
	pol.SBOM.DisallowedLicenses = []string{"GPL-3.0"}
	pol.Identity.Required = true
	pol.Identity.TrustDomain = "example.com"
	pol.Identity.IDPattern = "spiffe://example.com/*"

	sig := policy.SignatureResultView{
		Available:       true,
		Verified:        true,
		Issuer:          "https://token.actions.githubusercontent.com",
		SubjectIdentity: "https://github.com/sns45/repo/.github/workflows/release.yml@refs/heads/main",
		RekorLogged:     true,
	}
	slsa := policy.SLSAView{
		Verified:           true,
		BuilderID:          "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator.yml@v1",
		BuildLevel:         3,
		SubjectDigestMatch: true,
	}
	sbom := policy.SBOMView{Present: true, Licenses: []string{"MIT", "Apache-2.0"}}
	vex := policy.VEXView{Present: true, AffectedCVEs: nil}
	id := policy.IdentityView{
		Present:      true,
		Verified:     true,
		TrustDomain:  "example.com",
		SPIFFEID:     "spiffe://example.com/svc",
		BindingMatch: true,
	}

	result, reasons := policy.EvaluatePolicy(pol, sig, slsa, sbom, vex, id, nil)

	if result != core.ResultAllow {
		t.Errorf("expected ResultAllow, got %q", result)
	}
	// Every check configured should emit a Met=true Reason
	for _, r := range reasons {
		if !r.Met {
			t.Errorf("all checks should pass but got Met=false for %q", r.Code)
		}
	}
}

// TestAuditModeAllowsOnFailure: policy with failing checks under ModeAudit -> ResultAudit.
func TestAuditModeAllowsOnFailure(t *testing.T) {
	pol := minPol(policy.ModeAudit)
	pol.Signature.Required = true

	sig := policy.SignatureResultView{Available: true, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultAudit {
		t.Errorf("audit mode: expected ResultAudit, got %q", result)
	}
	// Reasons must still be present and include the failure
	r, ok := findReason(reasons, "SIGNATURE_REQUIRED_MISSING")
	if !ok {
		t.Fatal("audit mode: expected SIGNATURE_REQUIRED_MISSING reason")
	}
	if r.Met {
		t.Error("audit mode: reason should still show Met=false")
	}
}

// TestWarnModeAllowsOnFailure: policy with failing checks under ModeWarn -> ResultAllow.
func TestWarnModeAllowsOnFailure(t *testing.T) {
	pol := minPol(policy.ModeWarn)
	pol.Signature.Required = true

	sig := policy.SignatureResultView{Available: true, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	// Finding 6: assert ResultAllow explicitly so a future result-enum change is caught.
	if result != core.ResultAllow {
		t.Errorf("warn mode: expected ResultAllow, got %q", result)
	}
	r, ok := findReason(reasons, "SIGNATURE_REQUIRED_MISSING")
	if !ok {
		t.Fatal("warn mode: expected SIGNATURE_REQUIRED_MISSING reason")
	}
	if r.Met {
		t.Error("warn mode: reason should still show Met=false (warning)")
	}
}

// TestRekorOnlyUnavailableIsFailClosed: Signature.Required=false but Rekor.Required=true and
// Available=false. Without the consolidated gating this would fail-open (Rekor check silently
// skipped). With the fix it must Deny with SIGNATURE_VERIFICATION_UNAVAILABLE only.
func TestRekorOnlyUnavailableIsFailClosed(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = false      // signature itself is not required
	pol.Signature.Rekor.Required = true // but Rekor log is required

	sig := policy.SignatureResultView{Available: false, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	// Must deny (fail-closed); the verifier could not run so Rekor cannot be checked.
	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny (fail-closed), got %q", result)
	}
	// SIGNATURE_VERIFICATION_UNAVAILABLE must be present.
	r, ok := findReason(reasons, "SIGNATURE_VERIFICATION_UNAVAILABLE")
	if !ok {
		t.Fatal("expected SIGNATURE_VERIFICATION_UNAVAILABLE to be emitted")
	}
	if r.Met {
		t.Error("SIGNATURE_VERIFICATION_UNAVAILABLE must have Met=false")
	}
	if r.Severity != core.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %q", r.Severity)
	}
	// REKOR_REQUIRED_MISSING must NOT fire (it cannot be evaluated; emitting it would be misleading).
	if hasCode(reasons, "REKOR_REQUIRED_MISSING") {
		t.Error("REKOR_REQUIRED_MISSING must not fire when verifier is unavailable (misleading dual-code)")
	}
}

// TestSigAndRekorBothUnavailable: Signature.Required=true, Rekor.Required=true, Available=false.
// Only SIGNATURE_VERIFICATION_UNAVAILABLE should fire; neither SIGNATURE_REQUIRED_MISSING nor
// REKOR_REQUIRED_MISSING should appear.
func TestSigAndRekorBothUnavailable(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true
	pol.Signature.Rekor.Required = true

	sig := policy.SignatureResultView{Available: false, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	if !hasCode(reasons, "SIGNATURE_VERIFICATION_UNAVAILABLE") {
		t.Error("expected SIGNATURE_VERIFICATION_UNAVAILABLE")
	}
	if hasCode(reasons, "SIGNATURE_REQUIRED_MISSING") {
		t.Error("SIGNATURE_REQUIRED_MISSING must not fire when verifier is unavailable")
	}
	if hasCode(reasons, "REKOR_REQUIRED_MISSING") {
		t.Error("REKOR_REQUIRED_MISSING must not fire when verifier is unavailable")
	}
}

// TestKeylessUnavailableNoIdentityMismatch: Available=false AND Keyless != nil AND
// Signature.Required=true. SIGNATURE_IDENTITY_MISMATCH must NOT be emitted; only
// SIGNATURE_VERIFICATION_UNAVAILABLE fires (Finding 5).
func TestKeylessUnavailableNoIdentityMismatch(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true
	pol.Signature.Keyless = &policy.KeylessRule{
		Issuer:          "https://token.actions.githubusercontent.com",
		IdentityPattern: "https://github.com/sns45/*",
	}

	sig := policy.SignatureResultView{Available: false, Verified: false}
	result, reasons := policy.EvaluatePolicy(pol, sig, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	if !hasCode(reasons, "SIGNATURE_VERIFICATION_UNAVAILABLE") {
		t.Error("expected SIGNATURE_VERIFICATION_UNAVAILABLE")
	}
	// SIGNATURE_IDENTITY_MISMATCH must not be emitted when the verifier could not run.
	if hasCode(reasons, "SIGNATURE_IDENTITY_MISMATCH") {
		t.Error("SIGNATURE_IDENTITY_MISMATCH must not fire when verifier is unavailable (Finding 5)")
	}
}

// TestReasonsAreSortedByCode: reasons must be stable-sorted by Code.
func TestReasonsAreSortedByCode(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.Signature.Required = true
	pol.SLSA.MinLevel = 3
	pol.Identity.Required = true

	// All checks fail: sig not verified, SLSA level 1, identity missing
	sig := policy.SignatureResultView{Available: true, Verified: false}
	slsa := policy.SLSAView{Verified: true, BuildLevel: 1, SubjectDigestMatch: true}
	id := policy.IdentityView{Present: false}

	_, reasons := policy.EvaluatePolicy(pol, sig, slsa, policy.SBOMView{}, policy.VEXView{}, id, nil)

	if !sort.SliceIsSorted(reasons, func(i, j int) bool {
		return reasons[i].Code < reasons[j].Code
	}) {
		codes := make([]string, len(reasons))
		for i, r := range reasons {
			codes[i] = r.Code
		}
		t.Errorf("reasons not sorted by Code: %v", codes)
	}
}

// TestNoChecksEmittedForUnconfiguredPolicy: if no checks are configured, no reasons emitted.
func TestNoChecksEmittedForUnconfiguredPolicy(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	// Nothing configured

	_, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, policy.SLSAView{}, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	if len(reasons) != 0 {
		t.Errorf("expected no reasons for unconfigured policy, got %d: %v", len(reasons), reasons)
	}
}

// TestSLSABuilderAllowedByGlob: valid builder matching glob should pass.
func TestSLSABuilderAllowedByGlob(t *testing.T) {
	pol := minPol(policy.ModeEnforce)
	pol.SLSA.AllowedBuilders = []string{"https://github.com/slsa-framework/*"}

	slsa := policy.SLSAView{
		Verified:           true,
		BuilderID:          "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator.yml@v1",
		BuildLevel:         3,
		SubjectDigestMatch: true,
	}
	_, reasons := policy.EvaluatePolicy(pol, policy.SignatureResultView{}, slsa, policy.SBOMView{}, policy.VEXView{}, policy.IdentityView{}, nil)

	r, ok := findReason(reasons, "SLSA_BUILDER_NOT_ALLOWED")
	if ok && !r.Met {
		t.Error("builder matching glob should pass; SLSA_BUILDER_NOT_ALLOWED should not fail")
	}
}
