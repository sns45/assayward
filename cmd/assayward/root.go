package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// version is the build-time version string.
// Override at link time: -ldflags "-X main.version=v1.2.3"
var version = "dev"

// errVersion is the internal sentinel returned from RunE when the --version
// flag is set. Execute treats this as a successful (exit 0) run.
var errVersion = errors.New("version requested")

// rootCmd is the top-level cobra command for assayward.
// Subcommands from later tasks register themselves via rootCmd.AddCommand.
var rootCmd = newRootCmd()

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assayward",
		Short: "Evaluate supply-chain evidence against a policy",
		Long: `assayward evaluates cryptographic supply-chain evidence (SLSA provenance,
SBOMs, VEX statements, workload identity) against a declarative policy and
produces an allow / audit / deny decision with structured reasons.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// RunE handles --version; for any other invocation without a subcommand
		// it prints help. Subcommands added later will shadow this RunE for their
		// own invocation paths.
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _ := cmd.Flags().GetBool("version")
			if v {
				fmt.Printf("assayward %s\n", version)
				return errVersion
			}
			return cmd.Help()
		},
	}

	cmd.Flags().Bool("version", false, "Print version and exit")

	return cmd
}
