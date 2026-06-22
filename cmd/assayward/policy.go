package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"
)

// registerPolicyCmd creates the policy parent command and registers the
// validate and test subcommands onto it, then adds policy to parent.
// stdout is where non-error output is written; nil falls back to os.Stdout.
func registerPolicyCmd(parent *cobra.Command, stdout io.Writer) {
	if stdout == nil {
		stdout = os.Stdout
	}

	policyCmd := &cobra.Command{
		Use:          "policy",
		Short:        "Policy management and assertion utilities",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	registerPolicyValidateCmd(policyCmd, stdout)
	registerPolicyTestCmd(policyCmd, stdout)

	parent.AddCommand(policyCmd)
}

// registerPolicyValidateCmd creates the "policy validate <file>" subcommand.
// It reads the file, calls policy.Parse in strict mode, and on success prints
// "ok: <name>@<version> (mode <mode>)" to stdout (exit 0). On any parse or
// read error it returns a *CLIError with Code: ExitError (exit 2).
func registerPolicyValidateCmd(parent *cobra.Command, stdout io.Writer) {
	cmd := &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a TrustPolicy YAML file (strict parse gate)",
		Long: `validate reads the specified TrustPolicy YAML file and parses it with
strict field checking. Any unknown field, invalid mode, or missing version
causes an error (exit 2). On success it prints a one-line summary (exit 0).`,
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]

			raw, err := os.ReadFile(filePath)
			if err != nil {
				return &CLIError{
					Code: ExitError,
					Msg:  fmt.Sprintf("policy validate: read file: %v", err),
				}
			}

			pol, err := policy.Parse(raw)
			if err != nil {
				return &CLIError{
					Code: ExitError,
					Msg:  fmt.Sprintf("policy validate: %v", err),
				}
			}

			fmt.Fprintf(stdout, "ok: %s@%s (mode %s)\n", pol.Name, pol.Version, pol.Mode)
			return nil
		},
	}

	// Override the default cobra ExactArgs error to return ExitError (2).
	// We wrap RunE with an arg check so that a missing arg produces a *CLIError.
	cmd.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return &CLIError{
				Code: ExitError,
				Msg:  "policy validate: requires exactly one argument: <file>",
			}
		}
		return nil
	}

	parent.AddCommand(cmd)
}

// registerPolicyTestCmd creates the "policy test" subcommand.
// It reuses evalInputs for evidence and policy selection flags, adds
// --expect <allow|deny|audit>, evaluates the policy, and compares the
// result to the expectation.
//
// Exit codes:
//
//	0 (ExitAllow) = assertion matched (PASS)
//	1 (ExitDeny)  = assertion mismatch (FAIL)
//	2 (ExitError) = usage/input error (bad --expect, bad flags, etc.)
func registerPolicyTestCmd(parent *cobra.Command, stdout io.Writer) {
	var (
		inputs evalInputs
		expect string
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Evaluate a policy against evidence and assert the expected result",
		Long: `test assembles attestations, workload identity, and trust roots from local
files, evaluates them against the named policy, and asserts that the decision
matches --expect. Exit codes: 0=PASS, 1=FAIL (mismatch), 2=error.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate --expect before doing any evaluation work.
			switch core.Result(expect) {
			case core.ResultAllow, core.ResultDeny, core.ResultAudit:
				// valid
			default:
				return &CLIError{
					Code: ExitError,
					Msg:  fmt.Sprintf("policy test: invalid --expect %q: must be allow|deny|audit", expect),
				}
			}

			// Assemble inputs (policy, evidence, trust roots).
			ev, pol, roots, err := inputs.build("policy test")
			if err != nil {
				return err
			}

			// Evaluate.
			dec := engine.Evaluate(ev, pol, roots, systemClock{})

			expectedResult := core.Result(expect)
			if dec.Result == expectedResult {
				fmt.Fprintf(stdout, "PASS: got %s as expected\n", dec.Result)
				return nil
			}

			// Mismatch: collect failed reason codes for a one-line summary.
			var failedCodes []string
			for _, r := range dec.Reasons {
				if !r.Met {
					failedCodes = append(failedCodes, r.Code)
				}
			}

			summary := ""
			if len(failedCodes) > 0 {
				summary = " [failed: " + strings.Join(failedCodes, ", ") + "]"
			}

			fmt.Fprintf(stdout, "FAIL: expected %s, got %s%s\n", expectedResult, dec.Result, summary)
			return &CLIError{
				Code: ExitDeny,
				Msg:  fmt.Sprintf("policy test: assertion failed: expected %s, got %s", expectedResult, dec.Result),
			}
		},
	}

	registerEvalFlags(cmd, &inputs)
	cmd.Flags().StringVar(&expect, "expect", "", "expected result: allow|deny|audit (required)")
	_ = cmd.MarkFlagRequired("expect")

	parent.AddCommand(cmd)
}

// init registers the policy command on the package-level rootCmd.
func init() {
	registerPolicyCmd(rootCmd, nil)
}
