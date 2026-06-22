package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// runPolicy runs the policy subcommand (with the given sub-args, e.g.
// []string{"validate", "<file>"}) in-process and returns exit code and stdout.
func runPolicy(t *testing.T, args []string) (code int, stdout string) {
	t.Helper()

	var buf bytes.Buffer

	oldRoot := rootCmd
	rootCmd = newRootCmd()
	defer func() { rootCmd = oldRoot }()

	registerPolicyCmd(rootCmd, &buf)

	fullArgs := append([]string{"policy"}, args...)
	rootCmd.SetArgs(fullArgs)
	code = Execute()
	return code, buf.String()
}

// -------------------------------------------------------------------------
// policy validate tests
// -------------------------------------------------------------------------

// TestPolicyValidateValidFile verifies that a well-formed TrustPolicy YAML
// written to a temp file exits 0 and prints "ok:" to stdout.
func TestPolicyValidateValidFile(t *testing.T) {
	const validYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: mytest
  version: "v1"
spec:
  mode: enforce
  signature:
    required: false
  slsa: {}
  vex: {}
  sbom: {}
  identity:
    required: false
`
	f := writeTempFile(t, "policy-*.yaml", []byte(validYAML))

	code, stdout := runPolicy(t, []string{"validate", f})
	if code != ExitAllow {
		t.Errorf("valid file: exit code = %d, want %d (allow/ok)", code, ExitAllow)
	}
	if !strings.Contains(stdout, "ok:") {
		t.Errorf("valid file: stdout does not contain \"ok:\"; got:\n%s", stdout)
	}
}

// TestPolicyValidateUnknownFieldExits2 verifies that a YAML with an unknown
// field (spec.signature.bogus) exits 2 (ExitError).
func TestPolicyValidateUnknownFieldExits2(t *testing.T) {
	const badYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: mytest
  version: "v1"
spec:
  mode: enforce
  signature:
    required: false
    bogus: 1
  slsa: {}
  vex: {}
  sbom: {}
  identity:
    required: false
`
	f := writeTempFile(t, "policy-bad-*.yaml", []byte(badYAML))

	code, _ := runPolicy(t, []string{"validate", f})
	if code != ExitError {
		t.Errorf("unknown field: exit code = %d, want %d (error)", code, ExitError)
	}
}

// TestPolicyValidateBuiltinBaseline verifies that the built-in baseline YAML
// written to a temp file parses successfully (exit 0, stdout contains "ok:").
func TestPolicyValidateBuiltinBaseline(t *testing.T) {
	f := writeTempFile(t, "baseline-*.yaml", builtin.Baseline)

	code, stdout := runPolicy(t, []string{"validate", f})
	if code != ExitAllow {
		t.Errorf("builtin baseline: exit code = %d, want %d", code, ExitAllow)
	}
	if !strings.Contains(stdout, "ok:") {
		t.Errorf("builtin baseline: stdout does not contain \"ok:\"; got:\n%s", stdout)
	}
}

// TestPolicyValidateMissingArgExits2 verifies that omitting the file path
// argument exits 2.
func TestPolicyValidateMissingArgExits2(t *testing.T) {
	code, _ := runPolicy(t, []string{"validate"})
	if code != ExitError {
		t.Errorf("missing arg: exit code = %d, want %d (error)", code, ExitError)
	}
}

// -------------------------------------------------------------------------
// policy test tests
// -------------------------------------------------------------------------

// basePolicyTestArgs returns the shared evidence flags for the golden M1 fixtures.
func basePolicyTestArgs(root string) []string {
	return []string{
		"test",
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

// TestPolicyTestSLSAL3ExpectDenyPasses verifies that slsa-l3 denies the
// fixture scenario and --expect deny therefore exits 0 (PASS).
func TestPolicyTestSLSAL3ExpectDenyPasses(t *testing.T) {
	root := testdataRoot()
	args := append(basePolicyTestArgs(root), "--policy", "slsa-l3", "--expect", "deny")

	code, stdout := runPolicy(t, args)
	if code != ExitAllow {
		t.Errorf("slsa-l3 expect=deny: exit code = %d, want %d (PASS)", code, ExitAllow)
	}
	if !strings.Contains(stdout, "PASS") {
		t.Errorf("slsa-l3 expect=deny: stdout does not contain \"PASS\"; got:\n%s", stdout)
	}
}

// TestPolicyTestSLSAL3ExpectAllowFails verifies that slsa-l3 denies the
// fixture scenario and --expect allow therefore exits 1 (FAIL mismatch).
func TestPolicyTestSLSAL3ExpectAllowFails(t *testing.T) {
	root := testdataRoot()
	args := append(basePolicyTestArgs(root), "--policy", "slsa-l3", "--expect", "allow")

	code, stdout := runPolicy(t, args)
	if code != ExitDeny {
		t.Errorf("slsa-l3 expect=allow: exit code = %d, want %d (FAIL)", code, ExitDeny)
	}
	if !strings.Contains(stdout, "FAIL") {
		t.Errorf("slsa-l3 expect=allow: stdout does not contain \"FAIL\"; got:\n%s", stdout)
	}
}

// TestPolicyTestBaselineExpectAllowPasses verifies that baseline allows the
// fixture scenario and --expect allow therefore exits 0 (PASS).
func TestPolicyTestBaselineExpectAllowPasses(t *testing.T) {
	root := testdataRoot()
	args := append(basePolicyTestArgs(root), "--policy", "baseline", "--expect", "allow")

	code, stdout := runPolicy(t, args)
	if code != ExitAllow {
		t.Errorf("baseline expect=allow: exit code = %d, want %d (PASS)", code, ExitAllow)
	}
	if !strings.Contains(stdout, "PASS") {
		t.Errorf("baseline expect=allow: stdout does not contain \"PASS\"; got:\n%s", stdout)
	}
}

// TestPolicyTestBogusExpectExits2 verifies that an invalid --expect value
// exits 2 (usage error).
func TestPolicyTestBogusExpectExits2(t *testing.T) {
	root := testdataRoot()
	args := append(basePolicyTestArgs(root), "--policy", "baseline", "--expect", "bogus")

	code, _ := runPolicy(t, args)
	if code != ExitError {
		t.Errorf("bogus --expect: exit code = %d, want %d (error)", code, ExitError)
	}
}

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

// writeTempFile creates a temp file with the given name pattern and content.
// It is removed when the test ends.
func writeTempFile(t *testing.T, pattern string, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("writeTempFile: create: %v", err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatalf("writeTempFile: write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("writeTempFile: close: %v", err)
	}
	return f.Name()
}
