package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sns45/assayward/cmd/assayward/discover"
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"
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
		flagBundles       []string
		flagPolicy        string
		flagPolicyFile    string
		flagImage         string
		flagSigstoreRoot  string
		flagSPIFFEBundles []string
		flagSVID          string
		flagSVIDType      string
		flagOutput        string
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
			// 1. Resolve policy
			// ----------------------------------------------------------
			var pol policy.Policy

			switch {
			case flagPolicyFile != "":
				raw, err := os.ReadFile(flagPolicyFile)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: read policy file: %v", err)}
				}
				pol, err = policy.Parse(raw)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: parse policy file: %v", err)}
				}

			case flagPolicy != "":
				raw, ok := builtinPolicies[flagPolicy]
				if !ok {
					return &CLIError{
						Code: ExitError,
						Msg:  fmt.Sprintf("verify: unknown built-in policy %q: choose baseline|slsa-l3|serverless-edge", flagPolicy),
					}
				}
				var err error
				pol, err = policy.Parse(raw)
				if err != nil {
					// Should never happen with embedded built-ins, but guard defensively.
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: parse built-in policy %q: %v", flagPolicy, err)}
				}

			default:
				return &CLIError{Code: ExitError, Msg: "verify: exactly one of --policy or --policy-file is required"}
			}

			// ----------------------------------------------------------
			// 2. Parse --image
			// ----------------------------------------------------------
			if flagImage == "" {
				return &CLIError{Code: ExitError, Msg: "verify: --image is required"}
			}
			imageRef, err := parseImageRef(flagImage)
			if err != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: --image: %v", err)}
			}

			// ----------------------------------------------------------
			// 3. Assemble Evidence
			// ----------------------------------------------------------
			atts, err := discover.FromBundles(flagBundles)
			if err != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: %v", err)}
			}

			ev := core.Evidence{
				Image:        imageRef,
				Attestations: atts,
				FetchedAt:    systemClock{}.Now(),
			}

			if flagSVID != "" {
				raw, err := os.ReadFile(flagSVID)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: read --svid: %v", err)}
				}
				svidType := resolveSVIDType(flagSVIDType, raw)
				ev.Identity = &core.WorkloadIdentity{
					SVIDType: svidType,
					Raw:      raw,
				}
			}

			// ----------------------------------------------------------
			// 4. Build TrustRoots
			// ----------------------------------------------------------
			roots := core.TrustRoots{}

			if flagSigstoreRoot != "" {
				raw, err := os.ReadFile(flagSigstoreRoot)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: read --sigstore-trust-root: %v", err)}
				}
				roots.SigstoreTUF = raw
			}

			if len(flagSPIFFEBundles) > 0 {
				roots.SPIFFEBundles = make(map[string][]byte, len(flagSPIFFEBundles))
				for _, entry := range flagSPIFFEBundles {
					domain, path, ok := strings.Cut(entry, "=")
					if !ok {
						return &CLIError{
							Code: ExitError,
							Msg:  fmt.Sprintf("verify: --spiffe-bundle %q: must be trustDomain=path", entry),
						}
					}
					raw, err := os.ReadFile(path)
					if err != nil {
						return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: read --spiffe-bundle %q: %v", path, err)}
					}
					roots.SPIFFEBundles[domain] = raw
				}
			}

			// ----------------------------------------------------------
			// 5. Evaluate
			// ----------------------------------------------------------
			dec := engine.Evaluate(ev, pol, roots, systemClock{})

			// ----------------------------------------------------------
			// 6. Output
			// ----------------------------------------------------------
			// Only "json" is supported in this task; text rendering belongs to the
			// explain command (a later task).
			if flagOutput != "json" {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("verify: unsupported --output %q: only json is supported", flagOutput)}
			}

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

	cmd.Flags().StringArrayVar(&flagBundles, "bundle", nil, "local attestation file path (repeatable)")
	cmd.Flags().StringVar(&flagPolicy, "policy", "", "built-in policy name: baseline|slsa-l3|serverless-edge")
	cmd.Flags().StringVar(&flagPolicyFile, "policy-file", "", "path to a TrustPolicy YAML file")
	cmd.Flags().StringVar(&flagImage, "image", "", "image ref as name@sha256:<hex> (required)")
	cmd.Flags().StringVar(&flagSigstoreRoot, "sigstore-trust-root", "", "path to a Sigstore trusted-root JSON")
	cmd.Flags().StringArrayVar(&flagSPIFFEBundles, "spiffe-bundle", nil, "trustDomain=path entries (repeatable)")
	cmd.Flags().StringVar(&flagSVID, "svid", "", "path to SVID credential (JWT token or PEM X.509)")
	cmd.Flags().StringVar(&flagSVIDType, "svid-type", "auto", "jwt|x509|auto")
	cmd.Flags().StringVar(&flagOutput, "output", "json", "output format: json")

	parent.AddCommand(cmd)
}

// parseImageRef splits "name@sha256:<hex>" on the LAST '@' and validates
// that the digest portion starts with "sha256:".
func parseImageRef(s string) (core.ImageRef, error) {
	idx := strings.LastIndex(s, "@")
	if idx < 0 {
		return core.ImageRef{}, fmt.Errorf("must be name@sha256:<hex>, got %q", s)
	}
	name := s[:idx]
	digest := s[idx+1:]
	if !strings.HasPrefix(digest, "sha256:") {
		return core.ImageRef{}, fmt.Errorf("digest must start with sha256:, got %q", digest)
	}
	if name == "" {
		return core.ImageRef{}, fmt.Errorf("image name must not be empty")
	}
	return core.ImageRef{Name: name, Digest: digest}, nil
}

// resolveSVIDType determines the SVIDType based on the --svid-type flag and
// the raw credential bytes. "auto" detects x509 when the content starts with
// "-----BEGIN", otherwise assumes JWT.
func resolveSVIDType(flagValue string, raw []byte) core.SVIDType {
	switch flagValue {
	case "jwt":
		return core.SVIDTypeJWT
	case "x509":
		return core.SVIDTypeX509
	default: // "auto"
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "-----BEGIN") {
			return core.SVIDTypeX509
		}
		return core.SVIDTypeJWT
	}
}

// init registers the verify subcommand on the package-level rootCmd.
func init() {
	registerVerifyCmd(rootCmd, nil)
}
