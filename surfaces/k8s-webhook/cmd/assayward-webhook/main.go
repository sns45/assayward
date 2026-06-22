// Command assayward-webhook is the Kubernetes validating-admission-webhook
// server for assayward. It evaluates container image trust using the real
// engine.Evaluate and discover.FromOCI paths, behind a TLS HTTP server.
//
// Admission webhook AUDIT-FIRST: the default mode is "audit" so operators can
// roll out the webhook observing deny-signals as Kubernetes Warnings before
// switching to "enforce". This is the recommended deployment path per §3.
//
// Usage:
//
//	assayward-webhook \
//	  --mode audit \
//	  --policy serverless-edge \
//	  --tls-cert /tls/tls.crt \
//	  --tls-key  /tls/tls.key
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
	webhook "github.com/sns45/assayward/surfaces/k8s-webhook"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("assayward-webhook: %v", err)
	}
}

func run() error {
	fs := flag.NewFlagSet("assayward-webhook", flag.ContinueOnError)

	// Core flags.
	mode := fs.String("mode", "audit", "webhook mode: audit|enforce|warn (default: audit for safe rollout)")
	policyName := fs.String("policy", "baseline", "builtin policy name: baseline|slsa-l3|serverless-edge")
	policyFile := fs.String("policy-file", "", "path to a custom TrustPolicy YAML file (overrides --policy)")
	addr := fs.String("addr", ":8443", "TCP address to listen on")
	certFile := fs.String("tls-cert", "", "path to TLS certificate PEM file (required)")
	keyFile := fs.String("tls-key", "", "path to TLS private key PEM file (required)")

	// Trust root flags.
	sigstoreTrustRoot := fs.String("sigstore-trust-root", "", "path to Sigstore TUF trusted-root JSON (optional)")
	var spiffeBundles stringSlice
	fs.Var(&spiffeBundles, "spiffe-bundle", "SPIFFE bundle in trustDomain=path format; repeatable")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	// Validate mode.
	wMode := webhook.Mode(*mode)
	switch wMode {
	case webhook.ModeAudit, webhook.ModeEnforce, webhook.ModeWarn:
		// valid
	default:
		return fmt.Errorf("invalid --mode %q: must be audit|enforce|warn", *mode)
	}

	// Prominent audit-mode notice so operators see it in logs.
	log.Printf("assayward-webhook: effective admission mode = %s", strings.ToUpper(*mode))
	if wMode == webhook.ModeAudit {
		log.Printf("assayward-webhook: AUDIT mode — deny-signals appear as Kubernetes Warnings; no admission is blocked")
	}

	// Load policy.
	var rawPolicy []byte
	if *policyFile != "" {
		b, err := os.ReadFile(*policyFile)
		if err != nil {
			return fmt.Errorf("read --policy-file %q: %w", *policyFile, err)
		}
		rawPolicy = b
	} else {
		all := builtin.All()
		b, ok := all[*policyName]
		if !ok {
			names := make([]string, 0, len(all))
			for k := range all {
				names = append(names, k)
			}
			return fmt.Errorf("unknown --policy %q: available builtin policies: %s", *policyName, strings.Join(names, ", "))
		}
		rawPolicy = b
	}

	pol, err := policy.Parse(rawPolicy)
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	log.Printf("assayward-webhook: loaded policy %q version %q", pol.Name, pol.Version)

	// Build trust roots.
	roots := core.TrustRoots{}
	if *sigstoreTrustRoot != "" {
		b, err := os.ReadFile(*sigstoreTrustRoot)
		if err != nil {
			return fmt.Errorf("read --sigstore-trust-root %q: %w", *sigstoreTrustRoot, err)
		}
		roots.SigstoreTUF = b
		log.Printf("assayward-webhook: loaded Sigstore trust root from %s", *sigstoreTrustRoot)
	}

	if len(spiffeBundles) > 0 {
		roots.SPIFFEBundles = make(map[string][]byte, len(spiffeBundles))
		for _, kv := range spiffeBundles {
			td, path, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("--spiffe-bundle %q: expected trustDomain=path format", kv)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read SPIFFE bundle for %q from %q: %w", td, path, err)
			}
			roots.SPIFFEBundles[td] = b
			log.Printf("assayward-webhook: loaded SPIFFE bundle for trust domain %q from %s", td, path)
		}
	}

	eval := webhook.NewEvaluator(pol, roots)

	// TLS files are required for production; warn clearly.
	if *certFile == "" || *keyFile == "" {
		return fmt.Errorf("--tls-cert and --tls-key are required: admission webhooks must be HTTPS")
	}

	cfg := webhook.Config{
		Mode:     wMode,
		Addr:     *addr,
		CertFile: *certFile,
		KeyFile:  *keyFile,
		Eval:     eval,
	}

	log.Printf("assayward-webhook: listening on %s (TLS)", *addr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return cfg.ListenAndServeTLS(ctx)
}

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }

func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}
