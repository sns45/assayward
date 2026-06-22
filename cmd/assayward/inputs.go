package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sns45/assayward/cmd/assayward/discover"
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/policy"
)

// evalInputs holds the raw flag values shared between the verify and explain
// subcommands. It is populated by registerEvalFlags and consumed by build().
type evalInputs struct {
	Bundles       []string
	Policy        string
	PolicyFile    string
	Image         string
	SigstoreRoot  string
	SPIFFEBundles []string
	SVID          string
	SVIDType      string
}

// registerEvalFlags binds the shared flag set onto cmd and wires the flags into
// the evalInputs receiver. Call this once per subcommand that needs input assembly.
func registerEvalFlags(cmd *cobra.Command, o *evalInputs) {
	cmd.Flags().StringArrayVar(&o.Bundles, "bundle", nil, "local attestation file path (repeatable)")
	cmd.Flags().StringVar(&o.Policy, "policy", "", "built-in policy name: baseline|slsa-l3|serverless-edge")
	cmd.Flags().StringVar(&o.PolicyFile, "policy-file", "", "path to a TrustPolicy YAML file")
	cmd.Flags().StringVar(&o.Image, "image", "", "image ref as name@sha256:<hex> (required)")
	cmd.Flags().StringVar(&o.SigstoreRoot, "sigstore-trust-root", "", "path to a Sigstore trusted-root JSON")
	cmd.Flags().StringArrayVar(&o.SPIFFEBundles, "spiffe-bundle", nil, "trustDomain=path entries (repeatable)")
	cmd.Flags().StringVar(&o.SVID, "svid", "", "path to SVID credential (JWT token or PEM X.509)")
	cmd.Flags().StringVar(&o.SVIDType, "svid-type", "auto", "jwt|x509|auto")
}

// build assembles core.Evidence, policy.Policy, and core.TrustRoots from the
// flag values stored in o. All validation errors wrap ExitError so callers can
// return them directly as *CLIError values.
//
// The cmdName parameter is used in error messages to identify the calling
// subcommand (e.g. "verify" or "explain").
func (o *evalInputs) build(cmdName string) (core.Evidence, policy.Policy, core.TrustRoots, error) {
	// ----------------------------------------------------------
	// 1. Resolve policy
	// ----------------------------------------------------------
	var pol policy.Policy

	switch {
	case o.PolicyFile != "":
		raw, err := os.ReadFile(o.PolicyFile)
		if err != nil {
			return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
				Code: ExitError,
				Msg:  fmt.Sprintf("%s: read policy file: %v", cmdName, err),
			}
		}
		pol, err = policy.Parse(raw)
		if err != nil {
			return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
				Code: ExitError,
				Msg:  fmt.Sprintf("%s: parse policy file: %v", cmdName, err),
			}
		}

	case o.Policy != "":
		raw, ok := builtinPolicies[o.Policy]
		if !ok {
			return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
				Code: ExitError,
				Msg:  fmt.Sprintf("%s: unknown built-in policy %q: choose baseline|slsa-l3|serverless-edge", cmdName, o.Policy),
			}
		}
		var err error
		pol, err = policy.Parse(raw)
		if err != nil {
			return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
				Code: ExitError,
				Msg:  fmt.Sprintf("%s: parse built-in policy %q: %v", cmdName, o.Policy, err),
			}
		}

	default:
		return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
			Code: ExitError,
			Msg:  fmt.Sprintf("%s: exactly one of --policy or --policy-file is required", cmdName),
		}
	}

	// ----------------------------------------------------------
	// 2. Parse --image
	// ----------------------------------------------------------
	if o.Image == "" {
		return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
			Code: ExitError,
			Msg:  fmt.Sprintf("%s: --image is required", cmdName),
		}
	}
	imageRef, err := parseImageRef(o.Image)
	if err != nil {
		return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
			Code: ExitError,
			Msg:  fmt.Sprintf("%s: --image: %v", cmdName, err),
		}
	}

	// ----------------------------------------------------------
	// 3. Assemble Evidence
	// ----------------------------------------------------------
	atts, err := discover.FromBundles(o.Bundles)
	if err != nil {
		return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
			Code: ExitError,
			Msg:  fmt.Sprintf("%s: %v", cmdName, err),
		}
	}

	ev := core.Evidence{
		Image:        imageRef,
		Attestations: atts,
		FetchedAt:    systemClock{}.Now(),
	}

	if o.SVID != "" {
		raw, err := os.ReadFile(o.SVID)
		if err != nil {
			return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
				Code: ExitError,
				Msg:  fmt.Sprintf("%s: read --svid: %v", cmdName, err),
			}
		}
		svidType := resolveSVIDType(o.SVIDType, raw)
		ev.Identity = &core.WorkloadIdentity{
			SVIDType: svidType,
			Raw:      raw,
		}
	}

	// ----------------------------------------------------------
	// 4. Build TrustRoots
	// ----------------------------------------------------------
	roots := core.TrustRoots{}

	if o.SigstoreRoot != "" {
		raw, err := os.ReadFile(o.SigstoreRoot)
		if err != nil {
			return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
				Code: ExitError,
				Msg:  fmt.Sprintf("%s: read --sigstore-trust-root: %v", cmdName, err),
			}
		}
		roots.SigstoreTUF = raw
	}

	if len(o.SPIFFEBundles) > 0 {
		roots.SPIFFEBundles = make(map[string][]byte, len(o.SPIFFEBundles))
		for _, entry := range o.SPIFFEBundles {
			domain, path, ok := strings.Cut(entry, "=")
			if !ok {
				return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
					Code: ExitError,
					Msg:  fmt.Sprintf("%s: --spiffe-bundle %q: must be trustDomain=path", cmdName, entry),
				}
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return core.Evidence{}, policy.Policy{}, core.TrustRoots{}, &CLIError{
					Code: ExitError,
					Msg:  fmt.Sprintf("%s: read --spiffe-bundle %q: %v", cmdName, path, err),
				}
			}
			roots.SPIFFEBundles[domain] = raw
		}
	}

	return ev, pol, roots, nil
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
