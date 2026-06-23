package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/spf13/cobra"

	"github.com/sns45/assayward/internal/bundle"
	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// writeCACertPEM writes a DER-encoded certificate to a PEM file. Used by CA CLI tests.
func writeCACertPEM(t *testing.T, dir string, name string, derBytes []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(path, certPEM, 0644); err != nil {
		t.Fatalf("writeCACertPEM: %v", err)
	}
	return path
}

// writeCAKeyPEM writes an ECDSA private key to a PEM file. Used by CA CLI tests.
func writeCAKeyPEM(t *testing.T, dir string, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	path := filepath.Join(dir, name)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatalf("writeCAKeyPEM: %v", err)
	}
	return path
}

// newBundleTestRegistry spins up an in-memory OCI registry with referrers
// support. Returns the server and a plain-http transport that routes to it.
func newBundleTestRegistry(t *testing.T) (*httptest.Server, http.RoundTripper) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	// Use the default transport; httptest.Server listens on 127.0.0.1 and oras
	// will connect via plain HTTP when PlainHTTP=true.
	return srv, http.DefaultTransport
}

// TestBundleCmd_PushAndPull_BuiltinsRoundTrip tests end-to-end:
// pack all 3 built-ins, push to in-memory registry, pull back,
// check all 3 are present and parseable.
func TestBundleCmd_PushAndPull_BuiltinsRoundTrip(t *testing.T) {
	srv, transport := newBundleTestRegistry(t)
	host := srv.Listener.Addr().String()
	ref := fmt.Sprintf("%s/testbundle:latest", host)

	ctx := context.Background()

	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	policies := builtin.All()
	meta := bundle.Meta{BundleName: "builtins", Version: "v0.1.0"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}
	_, err = bundle.Push(ctx, store, manifestDesc, ref, pushOpts)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	pulled, pulledMeta, err := bundle.Pull(ctx, ref, pullOpts)
	if err != nil {
		t.Fatalf("Pull() error: %v", err)
	}

	if pulledMeta.BundleName != "builtins" {
		t.Errorf("BundleName: got %q, want %q", pulledMeta.BundleName, "builtins")
	}
	if len(pulled) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(pulled))
	}
	for name, raw := range pulled {
		if _, err := policy.Parse(raw); err != nil {
			t.Errorf("policy.Parse(%q): %v", name, err)
		}
	}
}

// TestBundleCmd_SignAndVerify_CorrectKey signs a pushed bundle with a valid
// key and verifies it succeeds.
func TestBundleCmd_SignAndVerify_CorrectKey(t *testing.T) {
	srv, transport := newBundleTestRegistry(t)
	host := srv.Listener.Addr().String()
	ref := fmt.Sprintf("%s/signtest:v1", host)

	ctx := context.Background()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "sign-test", Version: "v1.0.0"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}
	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	_, err = bundle.Push(ctx, store, manifestDesc, ref, pushOpts)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	resolvedDesc, err := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{PlainHTTP: true, Transport: transport})
	if err != nil {
		t.Fatalf("ResolveDigest() error: %v", err)
	}

	if err := bundle.SignAndPushReferrer(ctx, resolvedDesc, ref, priv, pushOpts); err != nil {
		t.Fatalf("SignAndPushReferrer() error: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyReferrer(ctx, resolvedDesc.Digest.String(), ref, &priv.PublicKey, pullOpts); err != nil {
		t.Errorf("PullAndVerifyReferrer() error: %v", err)
	}
}

// TestBundleCmd_SignAndVerify_WrongKey verifies that using the wrong public
// key for verification fails.
func TestBundleCmd_SignAndVerify_WrongKey(t *testing.T) {
	srv, transport := newBundleTestRegistry(t)
	host := srv.Listener.Addr().String()
	ref := fmt.Sprintf("%s/wrongkeytest:v1", host)

	ctx := context.Background()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "wrong-key-test", Version: "v1.0.0"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}
	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	_, err = bundle.Push(ctx, store, manifestDesc, ref, pushOpts)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	resolvedDesc, err := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{PlainHTTP: true, Transport: transport})
	if err != nil {
		t.Fatalf("ResolveDigest() error: %v", err)
	}

	if err := bundle.SignAndPushReferrer(ctx, resolvedDesc, ref, priv, pushOpts); err != nil {
		t.Fatalf("SignAndPushReferrer() error: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyReferrer(ctx, resolvedDesc.Digest.String(), ref, &wrongPriv.PublicKey, pullOpts); err == nil {
		t.Error("PullAndVerifyReferrer() with wrong key returned nil, want error")
	}
}

// TestBundleCmd_CLIRegisterCommand verifies the bundle command and its
// subcommands are registered on the root cobra command.
func TestBundleCmd_CLIRegisterCommand(t *testing.T) {
	var buf bytes.Buffer
	cmd := newRootCmd()
	registerBundleCmd(cmd, &buf, nil)

	bundleCmd, _, err := cmd.Find([]string{"bundle"})
	if err != nil || bundleCmd == nil {
		t.Fatalf("bundle command not found: %v", err)
	}

	for _, sub := range []string{"push", "pull", "sign", "verify"} {
		found := false
		for _, c := range bundleCmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bundle subcommand %q not registered", sub)
		}
	}
}

// TestBundleCmd_CLIOutputsDigest exercises the CLI push operation and verifies
// the returned digest has the expected sha256: prefix.
func TestBundleCmd_CLIOutputsDigest(t *testing.T) {
	srv, transport := newBundleTestRegistry(t)
	host := srv.Listener.Addr().String()
	ref := fmt.Sprintf("%s/clitest:v1", host)

	ctx := context.Background()
	policies := builtin.All()
	meta := bundle.Meta{BundleName: "cli-test", Version: "v1.0.0"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}
	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	digest, err := bundle.Push(ctx, store, manifestDesc, ref, pushOpts)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest does not start with sha256:, got %q", digest)
	}
}

// TestBundleCmd_WriteKeyFile verifies PEM key loading used by the bundle
// sign/verify CLI commands (loadECPrivateKey / loadECPublicKey).
func TestBundleCmd_WriteKeyFile(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "key.pem")
	pubPath := filepath.Join(dir, "pub.pem")

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	loadedPriv, err := loadECPrivateKey(privPath)
	if err != nil {
		t.Fatalf("loadECPrivateKey: %v", err)
	}
	loadedPub, err := loadECPublicKey(pubPath)
	if err != nil {
		t.Fatalf("loadECPublicKey: %v", err)
	}

	digest := "sha256:deadbeef00000000000000000000000000000000000000000000000000000000"
	sig, err := bundle.Sign(digest, loadedPriv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if err := bundle.Verify(digest, sig, loadedPub); err != nil {
		t.Errorf("Verify() with loaded keys: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RED: keyed-CA CLI tests — test the new --ca-key / --ca-cert flags and the
// --keyless offline-guard on the CLI layer. These fail until CLI is wired.
// ---------------------------------------------------------------------------

// TestBundleCmd_CASignAndVerify_CLI pushes a bundle, signs it with --ca-key /
// --ca-cert, and verifies it with --ca-cert, all via the library API (the CLI
// subcommand wiring is tested by TestBundleCmd_CLIRegisterCommand checking for
// the sign/verify subcommands, and by the flag presence test below).
func TestBundleCmd_CASignAndVerify_CLI(t *testing.T) {
	ctx := context.Background()
	srv, transport := newBundleTestRegistry(t)
	host := srv.Listener.Addr().String()
	ref := fmt.Sprintf("%s/casigntest:v1", host)

	caKey, caDER, err := bundle.GenerateSelfSignedCA()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "ca-cli-test", Version: "v1.0.0"}
	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	if _, err := bundle.Push(ctx, store, manifestDesc, ref, pushOpts); err != nil {
		t.Fatalf("Push: %v", err)
	}

	resolvedDesc, err := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{PlainHTTP: true, Transport: transport})
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}

	if err := bundle.SignWithCAAndPushReferrer(ctx, resolvedDesc, ref, caKey, caCert, pushOpts); err != nil {
		t.Fatalf("SignWithCAAndPushReferrer: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyWithCAReferrer(ctx, resolvedDesc.Digest.String(), ref, pool, pullOpts); err != nil {
		t.Errorf("PullAndVerifyWithCAReferrer: %v", err)
	}
}

// TestBundleCmd_CLIHasCACertFlag verifies that the bundle sign subcommand
// accepts --ca-key and --ca-cert flags and the verify subcommand accepts --ca-cert.
func TestBundleCmd_CLIHasCACertFlag(t *testing.T) {
	var buf bytes.Buffer
	cmd := newRootCmd()
	registerBundleCmd(cmd, &buf, nil)

	bundleCmd, _, err := cmd.Find([]string{"bundle"})
	if err != nil || bundleCmd == nil {
		t.Fatalf("bundle command not found: %v", err)
	}

	// sign must have --ca-key and --ca-cert
	var signCmd, verifyCmd *cobra.Command
	for _, c := range bundleCmd.Commands() {
		switch c.Name() {
		case "sign":
			signCmd = c
		case "verify":
			verifyCmd = c
		}
	}
	if signCmd == nil {
		t.Fatal("bundle sign subcommand not found")
	}
	if verifyCmd == nil {
		t.Fatal("bundle verify subcommand not found")
	}

	for _, flagName := range []string{"ca-key", "ca-cert"} {
		if signCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("bundle sign missing --%s flag", flagName)
		}
	}
	if verifyCmd.Flags().Lookup("ca-cert") == nil {
		t.Error("bundle verify missing --ca-cert flag")
	}

	// sign must still have --keyless flag
	if signCmd.Flags().Lookup("keyless") == nil {
		t.Error("bundle sign missing --keyless flag")
	}
}

// TestBundleCmd_KeylessFlag_OfflineError verifies that invoking the library
// keyless path returns a clear OIDC-required error offline.
func TestBundleCmd_KeylessFlag_OfflineError(t *testing.T) {
	err := bundle.SignKeyless("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("SignKeyless offline returned nil, want error")
	}
	if !strings.Contains(err.Error(), "OIDC") && !strings.Contains(err.Error(), "keyless") {
		t.Errorf("SignKeyless offline error %q does not mention OIDC or keyless", err.Error())
	}
}

// TestBundleCmd_LoadCACertFile exercises loadCACertPool for PEM cert loading.
func TestBundleCmd_LoadCACertFile(t *testing.T) {
	caKey, caDER, err := bundle.GenerateSelfSignedCA()
	_ = caKey
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}

	dir := t.TempDir()
	certPath := writeCACertPEM(t, dir, "ca.pem", caDER)

	pool, err := loadCACertPool(certPath)
	if err != nil {
		t.Fatalf("loadCACertPool: %v", err)
	}
	if pool == nil {
		t.Error("loadCACertPool returned nil pool")
	}
}
