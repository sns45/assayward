package main

import (
	"bytes"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sns45/assayward/internal/testfix"
)

// testdataRootExplain returns the absolute path to repo-root testdata/.
// Defined here separately to avoid any dependency on verify_test helpers
// (though the logic is identical).
func testdataRootExplain() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("explain_test: runtime.Caller(0) failed")
	}
	// explain_test.go is at cmd/assayward/explain_test.go
	// repo root is ../../
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

// baseExplainArgs returns the base set of CLI args for an explain invocation
// against the golden M1 fixtures (same scenario as verify).
func baseExplainArgs(root string) []string {
	return []string{
		"explain",
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

// runExplain runs the explain subcommand in-process and returns the exit code
// and captured stdout.
func runExplain(t *testing.T, args []string) (code int, stdout string) {
	t.Helper()

	var buf bytes.Buffer

	// Replace the global rootCmd with a fresh one so tests do not interfere.
	oldRoot := rootCmd
	rootCmd = newRootCmd()
	defer func() { rootCmd = oldRoot }()

	// Register the explain command on the fresh root.
	registerExplainCmd(rootCmd, &buf)

	rootCmd.SetArgs(args)
	code = Execute()
	return code, buf.String()
}

// TestExplainSLSAL3Denies checks that slsa-l3 produces exit 1, prints the
// DENY decision header, and shows [x] markers for all failed checks including
// SIGNATURE_IDENTITY_MISMATCH and VEX_UNMITIGATED_CRITICAL.
func TestExplainSLSAL3Denies(t *testing.T) {
	root := testdataRootExplain()
	args := append(baseExplainArgs(root), "--policy", "slsa-l3")

	code, stdout := runExplain(t, args)
	if code != ExitDeny {
		t.Errorf("slsa-l3: exit code = %d, want %d (deny)", code, ExitDeny)
	}

	if !strings.Contains(stdout, "Decision: DENY") {
		t.Errorf("slsa-l3: stdout does not contain 'Decision: DENY':\n%s", stdout)
	}

	if !strings.Contains(stdout, "SIGNATURE_IDENTITY_MISMATCH") {
		t.Errorf("slsa-l3: stdout does not mention SIGNATURE_IDENTITY_MISMATCH:\n%s", stdout)
	}

	if !strings.Contains(stdout, "VEX_UNMITIGATED_CRITICAL") {
		t.Errorf("slsa-l3: stdout does not mention VEX_UNMITIGATED_CRITICAL:\n%s", stdout)
	}

	if !strings.Contains(stdout, "[x]") {
		t.Errorf("slsa-l3: stdout does not contain '[x]' failure markers:\n%s", stdout)
	}
}

// TestExplainBaselineAllows checks that the baseline policy produces exit 0 and
// a ALLOW decision header in the human-readable output.
func TestExplainBaselineAllows(t *testing.T) {
	root := testdataRootExplain()
	args := append(baseExplainArgs(root), "--policy", "baseline")

	code, stdout := runExplain(t, args)
	if code != ExitAllow {
		t.Errorf("baseline: exit code = %d, want %d (allow)", code, ExitAllow)
	}

	if !strings.Contains(stdout, "Decision: ALLOW") {
		t.Errorf("baseline: stdout does not contain 'Decision: ALLOW':\n%s", stdout)
	}
}

// TestExplainUnknownPolicyExits2 checks that an unknown built-in name exits 2
// and produces no output to stdout.
func TestExplainUnknownPolicyExits2(t *testing.T) {
	root := testdataRootExplain()
	args := append(baseExplainArgs(root), "--policy", "bogus")

	code, stdout := runExplain(t, args)
	if code != ExitError {
		t.Errorf("unknown policy: exit code = %d, want %d (error)", code, ExitError)
	}
	if stdout != "" {
		t.Errorf("unknown policy: expected empty stdout on error path, got: %s", stdout)
	}
}

// TestExplainMissingImageExits2 checks that omitting --image exits 2 with no
// stdout output.
func TestExplainMissingImageExits2(t *testing.T) {
	root := testdataRootExplain()
	args := []string{
		"explain",
		"--bundle", filepath.Join(root, "signature", "bundle-provenance.json"),
		"--policy", "baseline",
	}

	code, stdout := runExplain(t, args)
	if code != ExitError {
		t.Errorf("missing --image: exit code = %d, want %d (error)", code, ExitError)
	}
	if stdout != "" {
		t.Errorf("missing --image: expected empty stdout on error path, got: %s", stdout)
	}
}
