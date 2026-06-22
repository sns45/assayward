package main

import (
	"testing"

	core "github.com/sns45/assayward/pkg/core"
)

// TestExitCodeForResult verifies the exit-code contract:
// allow -> 0, audit -> 0, deny -> 1.
func TestExitCodeForResult(t *testing.T) {
	tests := []struct {
		result   core.Result
		wantCode int
	}{
		{core.ResultAllow, ExitAllow},
		{core.ResultAudit, ExitAllow}, // audit is non-blocking: exit 0
		{core.ResultDeny, ExitDeny},
	}
	for _, tc := range tests {
		got := ExitCodeForResult(tc.result)
		if got != tc.wantCode {
			t.Errorf("ExitCodeForResult(%q) = %d, want %d", tc.result, got, tc.wantCode)
		}
	}
}

// TestExecuteVersionFlag verifies that invoking the root command with --version
// returns exit code 0.
func TestExecuteVersionFlag(t *testing.T) {
	rootCmd.SetArgs([]string{"--version"})
	defer rootCmd.SetArgs(nil) // restore default args after test

	code := Execute()
	if code != 0 {
		t.Errorf("Execute() with --version returned %d, want 0", code)
	}
}
