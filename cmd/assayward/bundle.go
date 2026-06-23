package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sns45/assayward/internal/bundle"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// registerBundleCmd creates the "bundle" parent command and registers
// push/pull/sign/verify subcommands. stdout is where non-error output is
// written; nil falls back to os.Stdout. transport is the http.RoundTripper
// to inject (nil uses the oras default; tests inject an httptest transport).
func registerBundleCmd(parent *cobra.Command, stdout io.Writer, transport http.RoundTripper) {
	if stdout == nil {
		stdout = os.Stdout
	}

	bundleCmd := &cobra.Command{
		Use:          "bundle",
		Short:        "OCI policy bundle push, pull, sign, and verify",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	registerBundlePushCmd(bundleCmd, stdout, transport)
	registerBundlePullCmd(bundleCmd, stdout, transport)
	registerBundleSignCmd(bundleCmd, stdout, transport)
	registerBundleVerifyCmd(bundleCmd, stdout, transport)

	parent.AddCommand(bundleCmd)
}

// registerBundlePushCmd registers "bundle push <ref> --policy <file>... [--from-builtins]".
func registerBundlePushCmd(parent *cobra.Command, stdout io.Writer, transport http.RoundTripper) {
	var (
		policyFiles  []string
		fromBuiltins bool
		bundleName   string
		bundleVer    string
		plainHTTP    bool
	)

	cmd := &cobra.Command{
		Use:          "push <ref>",
		Short:        "Pack policy files as an OCI artifact and push to <ref>",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			ctx := context.Background()

			policies := make(map[string][]byte)

			if fromBuiltins {
				for name, raw := range builtin.All() {
					policies[name] = raw
				}
			}

			for _, f := range policyFiles {
				raw, err := os.ReadFile(f)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle push: read policy file %q: %v", f, err)}
				}
				// Use the filename without extension as the policy name.
				name := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
				policies[name] = raw
			}

			if len(policies) == 0 {
				return &CLIError{Code: ExitError, Msg: "bundle push: no policies specified: use --policy <file> or --from-builtins"}
			}

			if bundleName == "" {
				bundleName = tagFromRef(ref)
			}

			meta := bundle.Meta{BundleName: bundleName, Version: bundleVer}

			store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
			if err != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle push: pack: %v", err)}
			}

			digest, err := bundle.Push(ctx, store, manifestDesc, ref, bundle.PushOptions{
				PlainHTTP: plainHTTP,
				Transport: transport,
			})
			if err != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle push: %v", err)}
			}

			fmt.Fprintf(stdout, "pushed %s\ndigest: %s\n", ref, digest)
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&policyFiles, "policy", nil, "policy YAML file to include (repeatable)")
	cmd.Flags().BoolVar(&fromBuiltins, "from-builtins", false, "include all 3 built-in policies")
	cmd.Flags().StringVar(&bundleName, "bundle-name", "", "bundle name (default: tag portion of ref)")
	cmd.Flags().StringVar(&bundleVer, "bundle-version", "v0.1.0", "bundle version")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "use HTTP instead of HTTPS")

	parent.AddCommand(cmd)
}

// registerBundlePullCmd registers "bundle pull <ref> [--out <dir>]".
func registerBundlePullCmd(parent *cobra.Command, stdout io.Writer, transport http.RoundTripper) {
	var (
		outDir    string
		plainHTTP bool
	)

	cmd := &cobra.Command{
		Use:          "pull <ref>",
		Short:        "Pull and validate a policy bundle from <ref>",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			ctx := context.Background()

			policies, meta, err := bundle.Pull(ctx, ref, bundle.PullOptions{
				PlainHTTP: plainHTTP,
				Transport: transport,
			})
			if err != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle pull: %v", err)}
			}

			if outDir != "" {
				if err := os.MkdirAll(outDir, 0755); err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle pull: mkdir %q: %v", outDir, err)}
				}
				for name, raw := range policies {
					path := filepath.Join(outDir, name+".yaml")
					if err := os.WriteFile(path, raw, 0644); err != nil {
						return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle pull: write %q: %v", path, err)}
					}
					fmt.Fprintf(stdout, "wrote %s\n", path)
				}
			} else {
				fmt.Fprintf(stdout, "bundle: %s@%s\n", meta.BundleName, meta.Version)
				for _, name := range meta.PolicyFiles {
					fmt.Fprintf(stdout, "  %s\n", name)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&outDir, "out", "", "directory to write pulled policy files")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "use HTTP instead of HTTPS")

	parent.AddCommand(cmd)
}

// registerBundleSignCmd registers "bundle sign <ref>".
//
// Signing modes (pick one):
//
//   - Keyed-CA (default, offline-verifiable): --ca-key <k> --ca-cert <c>
//     Signs with a leaf cert issued by the provided CA. The leaf cert (DER)
//     is carried in the signature referrer so verifiers can check the chain.
//
//   - Keyless CI: --keyless
//     Uses Sigstore Fulcio + Rekor (OIDC token required from CI). Returns a
//     clear "OIDC required" error when invoked offline.
//
//   - Legacy bare-key (back-compat): --key <ecdsa-private-key.pem>
//     Original M5 keyed-proxy path. Still functional; keyed-CA is preferred.
func registerBundleSignCmd(parent *cobra.Command, stdout io.Writer, transport http.RoundTripper) {
	var (
		keyFile    string
		caKeyFile  string
		caCertFile string
		keyless    bool
		plainHTTP  bool
	)

	cmd := &cobra.Command{
		Use:   "sign <ref>",
		Short: "Sign a policy bundle at <ref> and push the signature as a referrer",
		Long: `sign computes an ECDSA signature of the bundle manifest digest and pushes
it as an OCI referrer artifact (subject = the bundle manifest).

Signing modes (mutually exclusive):

  --ca-key <key.pem> --ca-cert <ca.pem>  (keyed-CA, default)
      Self-signed or external CA issues a leaf cert (URI SAN = signer identity,
      ExtKeyUsage CodeSigning). The leaf cert is stored in the referrer so
      verifiers can check the chain without trusting just a bare public key.
      Offline-verifiable: no network access required beyond the registry.

  --keyless
      Sigstore keyless path: Fulcio issues a short-lived cert backed by OIDC,
      and the signature is logged to Rekor. Requires CI (OIDC token). Returns a
      clear "OIDC required" error when invoked offline.

  --key <key.pem>
      Legacy bare-key ECDSA path (M5 back-compat). Still functional; keyed-CA
      is the recommended path going forward.`,
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			ctx := context.Background()

			// Count how many signing modes are active.
			modeCount := 0
			if keyless {
				modeCount++
			}
			if caKeyFile != "" || caCertFile != "" {
				modeCount++
			}
			if keyFile != "" {
				modeCount++
			}
			if modeCount > 1 {
				return &CLIError{Code: ExitUsage, Msg: "bundle sign: --keyless, --ca-key/--ca-cert, and --key are mutually exclusive"}
			}

			// Resolve the manifest descriptor directly from the registry.
			subjectDesc, resolveErr := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{
				PlainHTTP: plainHTTP,
				Transport: transport,
			})
			if resolveErr != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle sign: resolve manifest at %q: %v", ref, resolveErr)}
			}

			switch {
			case keyless:
				if err := bundle.SignKeyless(subjectDesc.Digest.String()); err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle sign --keyless: %v", err)}
				}

			case caKeyFile != "" || caCertFile != "":
				if caKeyFile == "" || caCertFile == "" {
					return &CLIError{Code: ExitUsage, Msg: "bundle sign: --ca-key and --ca-cert must both be provided"}
				}
				caKey, err := loadECPrivateKey(caKeyFile)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle sign: load CA key %q: %v", caKeyFile, err)}
				}
				caCert, err := loadCACert(caCertFile)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle sign: load CA cert %q: %v", caCertFile, err)}
				}
				if err := bundle.SignWithCAAndPushReferrer(ctx, subjectDesc, ref, caKey, caCert, bundle.PushOptions{
					PlainHTTP: plainHTTP,
					Transport: transport,
				}); err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle sign: %v", err)}
				}

			default:
				// Legacy bare-key path.
				if keyFile == "" {
					return &CLIError{Code: ExitUsage, Msg: "bundle sign: one of --ca-key/--ca-cert, --keyless, or --key is required"}
				}
				priv, err := loadECPrivateKey(keyFile)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle sign: load key %q: %v", keyFile, err)}
				}
				if err := bundle.SignAndPushReferrer(ctx, subjectDesc, ref, priv, bundle.PushOptions{
					PlainHTTP: plainHTTP,
					Transport: transport,
				}); err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle sign: %v", err)}
				}
			}

			fmt.Fprintf(stdout, "signed %s\ndigest: %s\n", ref, subjectDesc.Digest.String())
			return nil
		},
	}

	cmd.Flags().StringVar(&caKeyFile, "ca-key", "", "path to CA ECDSA private key PEM file (keyed-CA mode)")
	cmd.Flags().StringVar(&caCertFile, "ca-cert", "", "path to CA certificate PEM file (keyed-CA mode)")
	cmd.Flags().BoolVar(&keyless, "keyless", false, "use Sigstore keyless signing via Fulcio + Rekor (requires CI/OIDC)")
	cmd.Flags().StringVar(&keyFile, "key", "", "path to ECDSA private key PEM file (legacy bare-key mode)")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "use HTTP instead of HTTPS")

	parent.AddCommand(cmd)
}

// registerBundleVerifyCmd registers "bundle verify <ref>".
//
// Exit codes: 0 valid, 1 invalid/missing, 2 usage error.
//
// Verification modes (mutually exclusive):
//   - --ca-cert <ca.pem>  keyed-CA verification (default, offline-verifiable)
//   - --key <pub.pem>     legacy bare-key verification (back-compat)
func registerBundleVerifyCmd(parent *cobra.Command, stdout io.Writer, transport http.RoundTripper) {
	var (
		pubKeyFile string
		caCertFile string
		plainHTTP  bool
	)

	cmd := &cobra.Command{
		Use:   "verify <ref>",
		Short: "Verify a policy bundle signature at <ref>",
		Long: `verify pulls the signature referrer for the bundle at <ref> and checks
the signature chain.

Exit codes: 0 = valid, 1 = invalid or no signature, 2 = usage/input error.

Verification modes (mutually exclusive):

  --ca-cert <ca.pem>  (keyed-CA, recommended)
      Verifies the keyed-CA referrer: leaf cert must chain to the CA, and the
      ECDSA-ASN1 signature over the manifest digest must be valid under the leaf.
      Offline-verifiable: no network access beyond the registry.

  --key <pub.pem>  (legacy back-compat)
      Verifies the legacy bare-key referrer pushed by "bundle sign --key".`,
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			ctx := context.Background()

			if caCertFile != "" && pubKeyFile != "" {
				return &CLIError{Code: ExitUsage, Msg: "bundle verify: --ca-cert and --key are mutually exclusive"}
			}
			if caCertFile == "" && pubKeyFile == "" {
				return &CLIError{Code: ExitUsage, Msg: "bundle verify: one of --ca-cert or --key is required"}
			}

			// Resolve the manifest descriptor directly from the registry so the
			// digest being verified is the actual stored manifest digest.
			subjectDesc, resolveErr := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{
				PlainHTTP: plainHTTP,
				Transport: transport,
			})
			if resolveErr != nil {
				return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle verify: resolve manifest at %q: %v", ref, resolveErr)}
			}

			manifestDigest := subjectDesc.Digest.String()

			if caCertFile != "" {
				pool, err := loadCACertPool(caCertFile)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle verify: load CA cert %q: %v", caCertFile, err)}
				}
				if err := bundle.PullAndVerifyWithCAReferrer(ctx, manifestDigest, ref, pool, bundle.PullOptions{
					PlainHTTP: plainHTTP,
					Transport: transport,
				}); err != nil {
					fmt.Fprintf(stdout, "INVALID: %v\n", err)
					return &CLIError{Code: ExitDeny, Msg: fmt.Sprintf("bundle verify: %v", err)}
				}
			} else {
				pub, err := loadECPublicKey(pubKeyFile)
				if err != nil {
					return &CLIError{Code: ExitError, Msg: fmt.Sprintf("bundle verify: load key %q: %v", pubKeyFile, err)}
				}
				if err := bundle.PullAndVerifyReferrer(ctx, manifestDigest, ref, pub, bundle.PullOptions{
					PlainHTTP: plainHTTP,
					Transport: transport,
				}); err != nil {
					fmt.Fprintf(stdout, "INVALID: %v\n", err)
					return &CLIError{Code: ExitDeny, Msg: fmt.Sprintf("bundle verify: %v", err)}
				}
			}

			fmt.Fprintf(stdout, "OK: signature valid\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&caCertFile, "ca-cert", "", "path to CA certificate PEM file for keyed-CA verification (recommended)")
	cmd.Flags().StringVar(&pubKeyFile, "key", "", "path to ECDSA public key PEM file (legacy bare-key mode)")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "use HTTP instead of HTTPS")

	parent.AddCommand(cmd)
}

// ---------------------------------------------------------------------------
// Key file helpers (shared between sign and verify CLI tests)
// ---------------------------------------------------------------------------

// loadECPrivateKey reads an ECDSA private key from a PEM file.
func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return key, nil
}

// loadECPublicKey reads an ECDSA public key from a PEM file (PKIX DER encoding).
func loadECPublicKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PublicKey, got %T", pub)
	}
	return ec, nil
}

// loadCACert reads a CA certificate from a PEM file and returns the parsed
// *x509.Certificate. Used by the keyed-CA sign path.
func loadCACert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// loadCACertPool reads a PEM certificate file and returns an *x509.CertPool
// containing all CA certificates in the file. Used by the keyed-CA verify path.
func loadCACertPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	pool := x509.NewCertPool()
	rest := raw
	added := 0
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse certificate in %q: %w", path, parseErr)
		}
		pool.AddCert(cert)
		added++
	}
	if added == 0 {
		return nil, fmt.Errorf("no CERTIFICATE PEM blocks found in %q", path)
	}
	return pool, nil
}

// tagFromRef is re-exported for the CLI package. Delegates to the bundle
// package helper via the same logic (avoids a cyclic dependency on bundle's
// unexported helper).
func tagFromRef(ref string) string {
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == ':' {
			hasSlash := false
			for j := 0; j < i; j++ {
				if ref[j] == '/' {
					hasSlash = true
					break
				}
			}
			if hasSlash {
				return ref[i+1:]
			}
		}
	}
	return "latest"
}

// init registers the bundle command on the package-level rootCmd.
func init() {
	registerBundleCmd(rootCmd, nil, nil)
}
