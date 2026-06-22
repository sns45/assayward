package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// builtinPolicies maps canonical built-in policy names to their raw YAML bytes.
var builtinPolicies = map[string][]byte{
	"baseline":        builtin.Baseline,
	"slsa-l3":         builtin.SLSAL3,
	"serverless-edge": builtin.ServerlessEdge,
}

// registerVerifyCmd creates the verify subcommand and registers it on parent.
// stdout is where the JSON decision is written; passing a non-nil writer
// allows tests to capture output without hijacking os.Stdout.
func registerVerifyCmd(parent *cobra.Command, stdout io.Writer) {
	if stdout == nil {
		stdout = os.Stdout
	}

	var (
		inputs     evalInputs
		flagOutput string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Evaluate supply-chain evidence against a trust policy",
		Long: `verify assembles attestations, workload identity, and trust roots from
local files and evaluates them against the named policy. The decision is
printed as indented JSON. Exit codes: 0=allow/audit, 1=deny, 2=error.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// ----------------------------------------------------------
			// 0. Validate --output early so an invalid format fails fast
			//    at exit 2 without doing any verification work.
			// ----------------------------------------------------------
			if flagOutput != "json" {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: unsupported --output %q: only json is supported", flagOutput)}
			}

			// ----------------------------------------------------------
			// 1-4. Assemble inputs (policy, evidence, trust roots)
			// ----------------------------------------------------------
			ev, pol, roots, err := inputs.build("verify")
			if err != nil {
				return err
			}

			// ----------------------------------------------------------
			// 5. Evaluate
			// ----------------------------------------------------------
			dec := engine.Evaluate(ev, pol, roots, systemClock{})

			// ----------------------------------------------------------
			// 6. Output
			// ----------------------------------------------------------
			out, err := json.MarshalIndent(dec, "", "  ")
			if err != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: marshal decision: %v", err)}
			}
			fmt.Fprintln(stdout, string(out))

			// Print first, then return the deny error so Execute can set exit 1.
			if dec.Result == core.ResultDeny {
				return &CLIError{Code: ExitDeny, Msg: "policy denied"}
			}
			return nil
		},
	}

	registerEvalFlags(cmd, &inputs)
	cmd.Flags().StringVar(&flagOutput, "output", "json", "output format: json")

	parent.AddCommand(cmd)
}

// init registers the verify subcommand on the package-level rootCmd.
func init() {
	registerVerifyCmd(rootCmd, nil)
}
