package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// forgesealRealFixtureDir returns the absolute path to the REAL forgeseal
// pipeline-output fixtures committed under internal/forgeseal/testdata.
func forgesealRealFixtureDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// This file is at cmd/assayward/forgeseal_compose_test.go.
	// internal/forgeseal/testdata is at ../../internal/forgeseal/testdata.
	return filepath.Join(filepath.Dir(filename), "..", "..", "internal", "forgeseal", "testdata")
}

// sbomDigest derives the SLSA subject digest from the real fixture: forgeseal's
// SLSA subject is the SBOM file, so the artifact digest is sha256(sbom.cdx.json).
func sbomDigest(t *testing.T, pipelineDir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pipelineDir, "sbom.cdx.json"))
	if err != nil {
		t.Fatalf("read sbom.cdx.json: %v", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// composePolicyYAML is a minimal enforce policy requiring a verified signature
// and SLSA L3 from the forgeseal builder, but NOT workload identity (the
// pipeline fixture carries no SVID). Written to a temp file per test.
const composePolicyYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: forgeseal-compose
  version: v0.1.0
spec:
  mode: enforce
  signature:
    required: true
    keyless:
      issuer: ""
      identityPattern: "https://forgeseal.dev/*"
    rekor:
      required: false
  slsa:
    minLevel: 3
    allowedBuilders:
      - "https://forgeseal.dev/*"
  sbom:
    required: true
  identity:
    required: false
`

func writeComposePolicy(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy-compose.yaml")
	if err := os.WriteFile(p, []byte(composePolicyYAML), 0o600); err != nil {
		t.Fatalf("write compose policy: %v", err)
	}
	return p
}

// findReason returns the reason with the given code from a decoded decision, and
// whether it was found.
func findReason(dec map[string]any, code string) (met bool, detail string, found bool) {
	reasons, ok := dec["reasons"].([]any)
	if !ok {
		return false, "", false
	}
	for _, r := range reasons {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if rm["code"] == code {
			m, _ := rm["met"].(bool)
			d, _ := rm["detail"].(string)
			return m, d, true
		}
	}
	return false, "", false
}

// TestVerifyForgesealPipelineAutoDetectedCAAllows proves that the keyed SLSA
// signature in the REAL forgeseal pipeline output verifies via the
// AUTO-DETECTED signing CA — no explicit --signature-ca is passed, and no file
// is copied. A signature.required policy that reaches ALLOW can only do so if
// the keyed DSSE signature verified against the CA that inputs.build()
// auto-detected from the --forgeseal-output directory.
//
// This is deliberately distinct from the dogfood CLI test (which supplies
// --signature-ca explicitly and exercises workload identity): here the value
// added is the auto-detection path against real pipeline output.
func TestVerifyForgesealPipelineAutoDetectedCAAllows(t *testing.T) {
	pipeline := filepath.Join(forgesealRealFixtureDir(t), "pipeline-output")
	digest := sbomDigest(t, pipeline)
	polFile := writeComposePolicy(t)

	args := []string{
		"verify",
		"--forgeseal-output", pipeline,
		"--image", "forgeseal-artifact@" + digest,
		// NOTE: no --signature-ca. The CA must be auto-detected from the output dir.
		"--policy-file", polFile,
		"--output", "json",
	}

	code, stdout := runVerify(t, args)
	t.Logf("compose (auto-CA) stdout:\n%s", stdout)

	if code != ExitAllow {
		t.Fatalf("auto-detected-CA compose: exit code = %d, want %d (allow)", code, ExitAllow)
	}

	var dec map[string]any
	if err := json.Unmarshal([]byte(stdout), &dec); err != nil {
		t.Fatalf("decision is not valid JSON: %v\n%s", err, stdout)
	}
	// The signature stage must be MET (verified) — the whole point of auto-CA.
	met, detail, found := findReason(dec, "SIGNATURE_REQUIRED_MISSING")
	if !found {
		t.Fatalf("SIGNATURE_REQUIRED_MISSING reason not present in decision:\n%s", stdout)
	}
	if !met {
		t.Errorf("keyed SLSA signature did NOT verify via auto-detected CA: %s", detail)
	}
}

// TestVerifyForgesealBlobDigestMismatchNotVerified is the honesty test: a real
// forgeseal keyed blob bundle whose messageDigest does NOT match the supplied
// artifact digest must be reported NOT verified, and the run must DENY under a
// signature-required policy. The bundle and CA are genuine; only the --image
// digest is wrong, so the fail-closed messageDigest check must reject it.
func TestVerifyForgesealBlobDigestMismatchNotVerified(t *testing.T) {
	td := forgesealRealFixtureDir(t)
	blobBundle := filepath.Join(td, "blob", "artifact.bin.sigstore.json")
	caFile := filepath.Join(td, "pipeline-output", "forgeseal-signing-ca.crt")
	polFile := writeComposePolicy(t)

	// A wrong digest: NOT the digest the blob was signed over.
	wrongDigest := "sha256:" + strings.Repeat("00", 32)

	args := []string{
		"verify",
		"--signed-blob", blobBundle,
		"--image", "forgeseal-artifact@" + wrongDigest,
		"--signature-ca", caFile,
		"--policy-file", polFile,
		"--output", "json",
	}

	code, stdout := runVerify(t, args)
	t.Logf("blob mismatch stdout:\n%s", stdout)

	if code != ExitDeny {
		t.Fatalf("blob digest mismatch: exit code = %d, want %d (deny)", code, ExitDeny)
	}

	var dec map[string]any
	if err := json.Unmarshal([]byte(stdout), &dec); err != nil {
		t.Fatalf("decision is not valid JSON: %v\n%s", err, stdout)
	}
	// The signature stage must be UNMET: the blob over a different digest is not
	// a verified signature for this artifact.
	met, detail, found := findReason(dec, "SIGNATURE_REQUIRED_MISSING")
	if !found {
		t.Fatalf("SIGNATURE_REQUIRED_MISSING reason not present:\n%s", stdout)
	}
	if met {
		t.Errorf("a blob over a mismatched digest was reported VERIFIED (fail-open!): %s", detail)
	}
}
