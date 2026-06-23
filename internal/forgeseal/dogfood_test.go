package forgeseal_test

// TestDogfoodEvaluate is the §10 self-demonstrating loop: it builds Evidence
// from forgeseal's REAL output artifacts, attaches a svidmint REAL publisher
// JWT-SVID, evaluates them with assayward, and asserts the result is ALLOW.
//
// The §6.6 keyed-CA closure: the bundle's leaf cert (SAN https://forgeseal.dev/cli)
// chains to the forgeseal-signing-ca.crt injected into TrustRoots.SignatureCAs.
// The DSSE ECDSA signature is verified offline via stdlib crypto (no sigstore-go,
// no Rekor). SignatureResultView.Verified is true, closing the signature gap.
//
// If the result is NOT allow this test prints the full decision (all reasons)
// and fails — it does NOT fake the pass. A genuine DENY here means the wiring
// or the artifacts need investigation.
//
// A NEGATIVE assertion also verifies that flipping allowedBuilders to a wrong
// value causes a DENY with SLSA_BUILDER_NOT_ALLOWED — proving the gate
// discriminates and is not trivially open.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sns45/assayward/internal/forgeseal"
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"
)

// dogfoodDir returns the absolute path to testdata/dogfood.
func dogfoodDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("forgeseal: runtime.Caller(0) failed")
	}
	// This file is at internal/forgeseal/dogfood_test.go.
	// testdata/dogfood is at ../../testdata/dogfood.
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "dogfood")
}

// artifactDigestFromFile reads the artifact digest from the committed
// testdata/dogfood/artifact-digest.txt file (trimming trailing whitespace).
func artifactDigestFromFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(dogfoodDir(), "artifact-digest.txt")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read artifact-digest.txt: %v", err)
	}
	// Trim trailing newline/whitespace.
	digest := string(b)
	for len(digest) > 0 && (digest[len(digest)-1] == '\n' || digest[len(digest)-1] == '\r' || digest[len(digest)-1] == ' ') {
		digest = digest[:len(digest)-1]
	}
	return digest
}

// buildDogfoodRoots constructs TrustRoots with both the svidmint JWKS bundle
// and the forgeseal signing CA (for keyed signature verification).
func buildDogfoodRoots(t *testing.T) core.TrustRoots {
	t.Helper()
	dd := dogfoodDir()

	jwksBytes, err := os.ReadFile(filepath.Join(dd, "svidmint", "trust-bundle-jwks.json"))
	if err != nil {
		t.Fatalf("read trust-bundle-jwks.json: %v", err)
	}

	caBytes, err := os.ReadFile(filepath.Join(dd, "forgeseal", "forgeseal-signing-ca.crt"))
	if err != nil {
		t.Fatalf("read forgeseal-signing-ca.crt: %v", err)
	}

	return core.TrustRoots{
		SPIFFEBundles: map[string][]byte{
			"ci.svidmint.dev": jwksBytes,
		},
		SignatureCAs: caBytes,
	}
}

// TestDogfoodEvaluate_Allow verifies that forgeseal's real attestations
// combined with svidmint's real publisher JWT-SVID evaluate to ALLOW under
// the dogfood policy. Signature is now REAL — keyed CA verification.
func TestDogfoodEvaluate_Allow(t *testing.T) {
	dd := dogfoodDir()
	artifactDigest := artifactDigestFromFile(t)

	// -------------------------------------------------------------------------
	// 1. Build Evidence from forgeseal output.
	// -------------------------------------------------------------------------
	ev, err := forgeseal.EvidenceFromOutput(filepath.Join(dd, "forgeseal"), artifactDigest)
	if err != nil {
		t.Fatalf("EvidenceFromOutput: %v", err)
	}

	// -------------------------------------------------------------------------
	// 2. Attach svidmint publisher JWT-SVID.
	// -------------------------------------------------------------------------
	svidBytes, err := os.ReadFile(filepath.Join(dd, "svidmint", "publisher-jwt-svid.jwt"))
	if err != nil {
		t.Fatalf("read publisher-jwt-svid.jwt: %v", err)
	}
	ev.Identity = &core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      svidBytes,
	}

	// -------------------------------------------------------------------------
	// 3. Build TrustRoots with svidmint JWKS bundle AND forgeseal signing CA.
	// -------------------------------------------------------------------------
	roots := buildDogfoodRoots(t)

	// -------------------------------------------------------------------------
	// 4. Parse dogfood policy.
	// -------------------------------------------------------------------------
	polBytes, err := os.ReadFile(filepath.Join(dd, "policy-dogfood.yaml"))
	if err != nil {
		t.Fatalf("read policy-dogfood.yaml: %v", err)
	}
	pol, err := policy.Parse(polBytes)
	if err != nil {
		t.Fatalf("parse policy-dogfood.yaml: %v", err)
	}

	// -------------------------------------------------------------------------
	// 5. Evaluate with a fixed clock (2026-06-23T16:00:00Z).
	// -------------------------------------------------------------------------
	fixedNow := time.Date(2026, 6, 23, 16, 0, 0, 0, time.UTC)
	dec := engine.Evaluate(ev, pol, roots, core.FixedClock{T: fixedNow})

	// Print the full decision for diagnostic purposes regardless of result.
	decJSON, _ := json.MarshalIndent(dec, "", "  ")
	t.Logf("decision:\n%s", decJSON)

	// -------------------------------------------------------------------------
	// 6. Assert ALLOW — the self-demonstrating loop.
	// -------------------------------------------------------------------------
	if dec.Result != core.ResultAllow {
		t.Errorf("dogfood ALLOW assertion FAILED: result=%q", dec.Result)
		t.Errorf("per-stage reasons:")
		for _, r := range dec.Reasons {
			t.Errorf("  [met=%v] %s: %s", r.Met, r.Code, r.Detail)
		}
		t.FailNow()
	}

	// Verify per-stage reasons are all Met=true.
	for _, r := range dec.Reasons {
		if !r.Met {
			t.Errorf("reason %s unexpectedly failed: %s", r.Code, r.Detail)
		}
	}

	// Spot-check specific reasons for explainability — including signature reasons
	// which now must be present and Met=true (proving real signature verification).
	assertReasonMet(t, dec.Reasons, "SIGNATURE_REQUIRED_MISSING")
	assertReasonMet(t, dec.Reasons, "SIGNATURE_IDENTITY_MISMATCH")
	assertReasonMet(t, dec.Reasons, "SLSA_LEVEL_BELOW_THRESHOLD")
	assertReasonMet(t, dec.Reasons, "SLSA_BUILDER_NOT_ALLOWED")
	assertReasonMet(t, dec.Reasons, "SUBJECT_DIGEST_MISMATCH")
	assertReasonMet(t, dec.Reasons, "SBOM_REQUIRED_MISSING")
	assertReasonMet(t, dec.Reasons, "VEX_UNMITIGATED_CRITICAL")
	assertReasonMet(t, dec.Reasons, "IDENTITY_REQUIRED_MISSING")
	assertReasonMet(t, dec.Reasons, "IDENTITY_TRUST_DOMAIN_MISMATCH")
	assertReasonMet(t, dec.Reasons, "IDENTITY_BINDING_MISMATCH")
}

// TestDogfoodEvaluate_DenyWrongBuilder is the negative gate test: when
// allowedBuilders is set to something that does NOT match forgeseal's builder ID,
// the result must be DENY with SLSA_BUILDER_NOT_ALLOWED = false.
func TestDogfoodEvaluate_DenyWrongBuilder(t *testing.T) {
	dd := dogfoodDir()
	artifactDigest := artifactDigestFromFile(t)

	ev, err := forgeseal.EvidenceFromOutput(filepath.Join(dd, "forgeseal"), artifactDigest)
	if err != nil {
		t.Fatalf("EvidenceFromOutput: %v", err)
	}

	svidBytes, err := os.ReadFile(filepath.Join(dd, "svidmint", "publisher-jwt-svid.jwt"))
	if err != nil {
		t.Fatalf("read publisher-jwt-svid.jwt: %v", err)
	}
	ev.Identity = &core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      svidBytes,
	}

	roots := buildDogfoodRoots(t)

	polBytes, err := os.ReadFile(filepath.Join(dd, "policy-dogfood.yaml"))
	if err != nil {
		t.Fatalf("read policy-dogfood.yaml: %v", err)
	}
	pol, err := policy.Parse(polBytes)
	if err != nil {
		t.Fatalf("parse policy-dogfood.yaml: %v", err)
	}

	// Override: require a DIFFERENT builder — one that forgeseal does NOT use.
	pol.SLSA.AllowedBuilders = []string{"https://totally-different-builder.example.com/*"}

	fixedNow := time.Date(2026, 6, 23, 16, 0, 0, 0, time.UTC)
	dec := engine.Evaluate(ev, pol, roots, core.FixedClock{T: fixedNow})

	decJSON, _ := json.MarshalIndent(dec, "", "  ")
	t.Logf("negative decision (should be deny):\n%s", decJSON)

	if dec.Result != core.ResultDeny {
		t.Fatalf("NEGATIVE gate FAILED: expected DENY, got %q", dec.Result)
	}

	// The SLSA_BUILDER_NOT_ALLOWED reason must be present and unmet.
	found := false
	for _, r := range dec.Reasons {
		if r.Code == "SLSA_BUILDER_NOT_ALLOWED" && !r.Met {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SLSA_BUILDER_NOT_ALLOWED reason with Met=false in negative test")
	}
}

// TestDogfoodEvaluate_DenyWrongDigest verifies that supplying a tampered
// artifact digest causes SUBJECT_DIGEST_MISMATCH and DENY.
func TestDogfoodEvaluate_DenyWrongDigest(t *testing.T) {
	dd := dogfoodDir()

	tamperedDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev, err := forgeseal.EvidenceFromOutput(filepath.Join(dd, "forgeseal"), tamperedDigest)
	if err != nil {
		t.Fatalf("EvidenceFromOutput: %v", err)
	}

	svidBytes, err := os.ReadFile(filepath.Join(dd, "svidmint", "publisher-jwt-svid.jwt"))
	if err != nil {
		t.Fatalf("read publisher-jwt-svid.jwt: %v", err)
	}
	ev.Identity = &core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      svidBytes,
	}

	roots := buildDogfoodRoots(t)

	polBytes, err := os.ReadFile(filepath.Join(dd, "policy-dogfood.yaml"))
	if err != nil {
		t.Fatalf("read policy-dogfood.yaml: %v", err)
	}
	pol, err := policy.Parse(polBytes)
	if err != nil {
		t.Fatalf("parse policy-dogfood.yaml: %v", err)
	}

	fixedNow := time.Date(2026, 6, 23, 16, 0, 0, 0, time.UTC)
	dec := engine.Evaluate(ev, pol, roots, core.FixedClock{T: fixedNow})

	decJSON, _ := json.MarshalIndent(dec, "", "  ")
	t.Logf("tampered-digest decision (should be deny):\n%s", decJSON)

	if dec.Result != core.ResultDeny {
		t.Fatalf("NEGATIVE gate (tampered digest) FAILED: expected DENY, got %q", dec.Result)
	}
}

// assertReasonMet checks that a reason with the given code is present and Met.
func assertReasonMet(t *testing.T, reasons []core.Reason, code string) {
	t.Helper()
	for _, r := range reasons {
		if r.Code == code {
			if !r.Met {
				t.Errorf("reason %s: expected Met=true, got false: %s", code, r.Detail)
			}
			return
		}
	}
	t.Errorf("reason %s: not found in decision", code)
}
