package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
)

// registerExplainCmd creates the explain subcommand and registers it on parent.
// stdout is where the human-readable breakdown is written; passing a non-nil
// writer allows tests to capture output without hijacking os.Stdout.
func registerExplainCmd(parent *cobra.Command, stdout io.Writer) {
	if stdout == nil {
		stdout = os.Stdout
	}

	var inputs evalInputs

	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Evaluate supply-chain evidence and show a human-readable decision breakdown",
		Long: `explain assembles attestations, workload identity, and trust roots from
local files, evaluates them against the named policy, and renders the decision
as a human-readable breakdown. Exit codes: 0=allow/audit, 1=deny, 2=error.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// ----------------------------------------------------------
			// 1-4. Assemble inputs (policy, evidence, trust roots)
			// ----------------------------------------------------------
			ev, pol, roots, err := inputs.build("explain")
			if err != nil {
				return err
			}

			// ----------------------------------------------------------
			// 5. Evaluate
			// ----------------------------------------------------------
			dec := engine.Evaluate(ev, pol, roots, systemClock{})

			// ----------------------------------------------------------
			// 6. Render human-readable breakdown
			// ----------------------------------------------------------
			renderExplain(stdout, dec)

			// Return deny error AFTER rendering so the breakdown is always visible.
			if dec.Result == core.ResultDeny {
				return &CLIError{Code: ExitDeny, Msg: "policy denied"}
			}
			return nil
		},
	}

	registerEvalFlags(cmd, &inputs)

	parent.AddCommand(cmd)
}

// renderExplain writes the human-readable decision breakdown to w.
//
// Format:
//
//	Decision: <ALLOW|DENY|AUDIT> (policy <name@version>)
//	  [x] CODE  (severity)  detail    <- failed check
//	  [ok] CODE  detail                <- passing check
//	N checks, M failed
func renderExplain(w io.Writer, dec core.Decision) {
	// Header.
	fmt.Fprintf(w, "Decision: %s (policy %s)\n", strings.ToUpper(string(dec.Result)), dec.Policy)

	failed := 0
	for _, r := range dec.Reasons {
		if r.Met {
			fmt.Fprintf(w, "  [ok] %-40s  %s\n", r.Code, r.Detail)
		} else {
			fmt.Fprintf(w, "  [x]  %-40s  (%s)  %s\n", r.Code, r.Severity, r.Detail)
			failed++
		}
	}

	// Summary line.
	total := len(dec.Reasons)
	fmt.Fprintf(w, "%d checks, %d failed\n", total, failed)
}

// init registers the explain subcommand on the package-level rootCmd.
func init() {
	registerExplainCmd(rootCmd, nil)
}
