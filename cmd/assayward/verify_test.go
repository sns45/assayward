package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sns45/assayward/internal/testfix"
)

// testdataRoot returns the absolute path to repo-root testdata/.
func testdataRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("verify_test: runtime.Caller(0) failed")
	}
	// verify_test.go is at cmd/assayward/verify_test.go
	// repo root is ../../
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

// baseVerifyArgs returns the base set of args for a verify invocation
// against the golden M1 fixtures.
func baseVerifyArgs(root string) []string {
	return []string{
		"verify",
		"--image", "ghcr.io/sns45/example:1.0.0@" + testfix.TestImageDigest,
		"--bundle", filepath.Join(root, "signature", "bundle-provenance.json"),
		"--bundle", filepath.Join(root, "slsa", "valid-l3.dsse.json"),
		"--bundle", filepath.Join(root, "sbom", "cyclonedx.dsse.json"),
		"--bundle", filepath.Join(root, "vex", "affected-critical.dsse.json"),
		"--sigstore-trust-root", filepath.Join(root, "signature", "trusted-root-public-good.json"),
		"--spiffe-bundle", "sns45.dev=" + filepath.Join(root, "svid", "jwt-bundle.json"),
		"--svid", filepath.Join(root, "svid", "jwt-valid.jwt"),
	}
}

// runVerify runs the verify subcommand in-process and returns the exit code
// and captured stdout.
func runVerify(t *testing.T, args []string) (code int, stdout string) {
	t.Helper()

	var buf bytes.Buffer

	// Replace the global rootCmd with a fresh one so tests don't interfere.
	oldRoot := rootCmd
	rootCmd = newRootCmd()
	defer func() { rootCmd = oldRoot }()

	// Register the verify command on the fresh root.
	registerVerifyCmd(rootCmd, &buf)

	rootCmd.SetArgs(args)
	code = Execute()
	return code, buf.String()
}

// TestVerifyBaselineAllows verifies that the golden fixtures pass the baseline policy.
func TestVerifyBaselineAllows(t *testing.T) {
	root := testdataRoot()
	args := append(baseVerifyArgs(root), "--policy", "baseline")

	code, stdout := runVerify(t, args)
	if code != ExitAllow {
		t.Errorf("baseline: exit code = %d, want %d (allow)", code, ExitAllow)
	}

	// Output must contain a JSON decision with "allow".
	if !strings.Contains(stdout, `"allow"`) {
		t.Errorf("baseline: stdout does not contain \"allow\":\n%s", stdout)
	}

	// Validate it is valid JSON.
	var dec map[string]any
	if err := json.Unmarshal([]byte(stdout), &dec); err != nil {
		t.Errorf("baseline: stdout is not valid JSON: %v\n%s", err, stdout)
	}
}

// TestVerifySLSAL3Denies verifies that the golden fixtures are denied by slsa-l3.
func TestVerifySLSAL3Denies(t *testing.T) {
	root := testdataRoot()
	args := append(baseVerifyArgs(root), "--policy", "slsa-l3")

	code, stdout := runVerify(t, args)
	if code != ExitDeny {
		t.Errorf("slsa-l3: exit code = %d, want %d (deny)", code, ExitDeny)
	}

	// Output must still be valid JSON with "deny".
	if !strings.Contains(stdout, `"deny"`) {
		t.Errorf("slsa-l3: stdout does not contain \"deny\":\n%s", stdout)
	}

	var dec map[string]any
	if err := json.Unmarshal([]byte(stdout), &dec); err != nil {
		t.Errorf("slsa-l3: stdout is not valid JSON: %v\n%s", err, stdout)
	}
}

// TestVerifyUnknownPolicyExits2 verifies that an unknown built-in name exits with code 2
// and that no decision JSON is written to stdout (errors go to stderr only).
func TestVerifyUnknownPolicyExits2(t *testing.T) {
	root := testdataRoot()
	args := append(baseVerifyArgs(root), "--policy", "bogus")

	code, stdout := runVerify(t, args)
	if code != ExitError {
		t.Errorf("unknown policy: exit code = %d, want %d (error)", code, ExitError)
	}
	if stdout != "" {
		t.Errorf("unknown policy: expected empty stdout on error path, got: %s", stdout)
	}
}

// TestVerifyMissingImageExits2 verifies that omitting --image exits with code 2
// and that no decision JSON is written to stdout (errors go to stderr only).
func TestVerifyMissingImageExits2(t *testing.T) {
	root := testdataRoot()
	// Build args without --image.
	args := []string{
		"verify",
		"--bundle", filepath.Join(root, "signature", "bundle-provenance.json"),
		"--policy", "baseline",
	}

	code, stdout := runVerify(t, args)
	if code != ExitError {
		t.Errorf("missing --image: exit code = %d, want %d (error)", code, ExitError)
	}
	if stdout != "" {
		t.Errorf("missing --image: expected empty stdout on error path, got: %s", stdout)
	}
}

// TestVerifyBogusOutputExits2 verifies that --output=bogus exits with code 2 without
// performing any verification work (validation must happen before policy resolution).
func TestVerifyBogusOutputExits2(t *testing.T) {
	root := testdataRoot()
	args := append(baseVerifyArgs(root), "--policy", "baseline", "--output", "bogus")

	code, stdout := runVerify(t, args)
	if code != ExitError {
		t.Errorf("bogus --output: exit code = %d, want %d (error)", code, ExitError)
	}
	if stdout != "" {
		t.Errorf("bogus --output: expected empty stdout on error path, got: %s", stdout)
	}
}

// TestVerifyNoAttestationSourceExits2 verifies that when neither --bundle nor
// --from-oci is supplied, verify exits with code 2 and emits no JSON to stdout.
func TestVerifyNoAttestationSourceExits2(t *testing.T) {
	// Intentionally omit --bundle and --from-oci.
	args := []string{
		"verify",
		"--image", "ghcr.io/sns45/example:1.0.0@" + testfix.TestImageDigest,
		"--policy", "baseline",
	}

	code, stdout := runVerify(t, args)
	if code != ExitError {
		t.Errorf("no attestation source: exit code = %d, want %d (error)", code, ExitError)
	}
	if stdout != "" {
		t.Errorf("no attestation source: expected empty stdout on error path, got: %s", stdout)
	}
}
