package main

import (
	"errors"
	"fmt"
	"os"

	core "github.com/sns45/assayward/pkg/core"
)

// Process exit codes for assayward.
const (
	ExitAllow = 0 // decision: allow or audit (non-blocking)
	ExitDeny  = 1 // decision: deny
	ExitError = 2 // non-usage operational failure
	ExitUsage = 2 // usage / flag error (same code as ExitError per spec)
)

// CLIError is a non-usage failure that carries a specific exit code.
// Returning a *CLIError from a cobra RunE causes Execute to print Msg to
// stderr and return Code; cobra will NOT print its own usage line.
type CLIError struct {
	Code int
	Msg  string
}

func (e *CLIError) Error() string { return e.Msg }

// ExitCodeForResult maps a core.Result to a process exit code.
// Both ResultAllow and ResultAudit map to ExitAllow (0) because audit is
// advisory only and must not block a pipeline.
// ResultDeny maps to ExitDeny (1).
func ExitCodeForResult(r core.Result) int {
	switch r {
	case core.ResultDeny:
		return ExitDeny
	default:
		return ExitAllow
	}
}

// Execute runs the root cobra command and maps the outcome to a process exit
// code suitable for os.Exit:
//
//   - nil error          -> 0
//   - errVersion         -> 0 (version was printed; clean exit)
//   - *CLIError          -> print Msg to stderr, return Code
//   - any other error    -> cobra already printed it, return ExitError (2)
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, errVersion) {
			return 0
		}
		var cliErr *CLIError
		if errors.As(err, &cliErr) {
			fmt.Fprintln(os.Stderr, cliErr.Msg)
			return cliErr.Code
		}
		// Cobra already printed the usage/parse error.
		return ExitError
	}
	return 0
}
