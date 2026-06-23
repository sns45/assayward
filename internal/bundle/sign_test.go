package bundle_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/sns45/assayward/internal/bundle"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// generateTestKey generates a fresh ECDSA P-256 key pair for testing.
func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateTestKey: %v", err)
	}
	return priv, &priv.PublicKey
}

// newSignTestRegistry spins up an in-memory registry for sign tests.
func newSignTestRegistry(t *testing.T) (*httptest.Server, http.RoundTripper) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	return srv, http.DefaultTransport
}

// TestSignAndVerify_Roundtrip generates a key, signs a manifest digest, and
// verifies the signature succeeds.
func TestSignAndVerify_Roundtrip(t *testing.T) {
	priv, pub := generateTestKey(t)
	digest := "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"

	sig, err := bundle.Sign(digest, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign() returned empty signature")
	}

	if err := bundle.Verify(digest, sig, pub); err != nil {
		t.Errorf("Verify() error for valid sig: %v", err)
	}
}

// TestVerify_TamperedDigest verifies that a different digest fails verification.
func TestVerify_TamperedDigest(t *testing.T) {
	priv, pub := generateTestKey(t)
	original := "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	tampered := "sha256:000000def456abc123def456abc123def456abc123def456abc123def456abc1"

	sig, err := bundle.Sign(original, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if err := bundle.Verify(tampered, sig, pub); err == nil {
		t.Error("Verify() with tampered digest returned nil, want error")
	}
}

// TestVerify_WrongKey verifies that a signature created with one key fails
// verification with a different key.
func TestVerify_WrongKey(t *testing.T) {
	priv, _ := generateTestKey(t)
	_, wrongPub := generateTestKey(t)
	digest := "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"

	sig, err := bundle.Sign(digest, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if err := bundle.Verify(digest, sig, wrongPub); err == nil {
		t.Error("Verify() with wrong public key returned nil, want error")
	}
}

// TestSignAndVerify_ReferrerRoundtrip performs a full end-to-end test:
//  1. Pack + push a bundle to an in-memory registry.
//  2. Sign the manifest digest and push the signature referrer.
//  3. Pull the signature referrer back and verify.
func TestSignAndVerify_ReferrerRoundtrip(t *testing.T) {
	ctx := context.Background()
	priv, pub := generateTestKey(t)

	srv, transport := newSignTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := map[string][]byte{
		"baseline": builtin.Baseline,
	}
	meta := bundle.Meta{BundleName: "sig-test", Version: "v0.0.1"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}

	ref := fmt.Sprintf("%s/sigtest:v0.0.1", host)
	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	_, err = bundle.Push(ctx, store, manifestDesc, ref, pushOpts)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	// Resolve the stored manifest descriptor to get the authoritative digest + size.
	resolvedDesc, err := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{PlainHTTP: true, Transport: transport})
	if err != nil {
		t.Fatalf("ResolveDigest() error: %v", err)
	}

	if err := bundle.SignAndPushReferrer(ctx, resolvedDesc, ref, priv, pushOpts); err != nil {
		t.Fatalf("SignAndPushReferrer() error: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyReferrer(ctx, resolvedDesc.Digest.String(), ref, pub, pullOpts); err != nil {
		t.Fatalf("PullAndVerifyReferrer() error: %v", err)
	}
}

// TestPullAndVerifyReferrer_WrongKey verifies that pulling a valid signature
// referrer but verifying with the wrong key returns an error.
func TestPullAndVerifyReferrer_WrongKey(t *testing.T) {
	ctx := context.Background()
	priv, _ := generateTestKey(t)
	_, wrongPub := generateTestKey(t)

	srv, transport := newSignTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "wrongkey-test", Version: "v0.0.1"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}

	ref := fmt.Sprintf("%s/wrongkey:v0.0.1", host)
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
	if err := bundle.PullAndVerifyReferrer(ctx, resolvedDesc.Digest.String(), ref, wrongPub, pullOpts); err == nil {
		t.Error("PullAndVerifyReferrer() with wrong key returned nil, want error")
	}
}

// TestResolveDigest_SignVerify_EndToEnd proves that signing with a resolved
// descriptor and verifying against that resolved digest succeeds, and that
// a wrong key still fails (verifying crypto is not weakened).
func TestResolveDigest_SignVerify_EndToEnd(t *testing.T) {
	ctx := context.Background()
	priv, pub := generateTestKey(t)
	_, wrongPub := generateTestKey(t)

	srv, transport := newSignTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := builtin.All()
	meta := bundle.Meta{BundleName: "resolve-test", Version: "v1.0.0"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}

	ref := fmt.Sprintf("%s/resolvetest:v1.0.0", host)
	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	if _, err := bundle.Push(ctx, store, manifestDesc, ref, pushOpts); err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	// Resolve the real registry descriptor (binds signature to stored manifest).
	resolvedDesc, err := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{PlainHTTP: true, Transport: transport})
	if err != nil {
		t.Fatalf("ResolveDigest() error: %v", err)
	}

	// The resolved digest must start with sha256:.
	if d := resolvedDesc.Digest.String(); len(d) < 7 || d[:7] != "sha256:" {
		t.Errorf("resolved digest %q does not start with sha256:", d)
	}

	// The resolved size must be non-zero (OCI spec requires it for subject).
	if resolvedDesc.Size <= 0 {
		t.Errorf("resolved descriptor Size = %d, want > 0", resolvedDesc.Size)
	}

	// Sign with the resolved descriptor and push the referrer.
	if err := bundle.SignAndPushReferrer(ctx, resolvedDesc, ref, priv, pushOpts); err != nil {
		t.Fatalf("SignAndPushReferrer() error: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}

	// Happy path: correct key verifies OK.
	if err := bundle.PullAndVerifyReferrer(ctx, resolvedDesc.Digest.String(), ref, pub, pullOpts); err != nil {
		t.Errorf("PullAndVerifyReferrer() correct key error: %v", err)
	}

	// Negative: wrong key must fail.
	if err := bundle.PullAndVerifyReferrer(ctx, resolvedDesc.Digest.String(), ref, wrongPub, pullOpts); err == nil {
		t.Error("PullAndVerifyReferrer() wrong key returned nil, want error")
	}

	// Negative: tampered digest must fail (no referrer found for a different digest).
	tamperedDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := bundle.PullAndVerifyReferrer(ctx, tamperedDigest, ref, pub, pullOpts); err == nil {
		t.Error("PullAndVerifyReferrer() tampered digest returned nil, want error")
	}
}

// ---------------------------------------------------------------------------
// RED: keyed-CA (SignWithCA / VerifyWithCA) tests — these test the new
// Sigstore-style bundle signing path. They fail until the implementation
// is added to sign.go.
// ---------------------------------------------------------------------------

// generateTestCA creates a self-signed CA key pair for test use.
// Returns (caKey, caCert DER bytes).
func generateTestCA(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	ca, caDER, err := bundle.GenerateSelfSignedCA()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	return ca, caDER
}

// TestSignWithCA_RoundTrip generates a self-signed CA, signs a manifest digest,
// and verifies the CA-keyed signature succeeds.
func TestSignWithCA_RoundTrip(t *testing.T) {
	caKey, caDER := generateTestCA(t)

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	manifestDigest := "sha256:aabbccdd00000000000000000000000000000000000000000000000000000000"

	sigBytes, leafDER, err := bundle.SignWithCA(manifestDigest, caKey, caCert)
	if err != nil {
		t.Fatalf("SignWithCA: %v", err)
	}
	if len(sigBytes) == 0 {
		t.Fatal("SignWithCA returned empty sig")
	}
	if len(leafDER) == 0 {
		t.Fatal("SignWithCA returned empty leaf cert DER")
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	if err := bundle.VerifyWithCA(manifestDigest, sigBytes, leafDER, pool); err != nil {
		t.Errorf("VerifyWithCA valid: %v", err)
	}
}

// TestSignWithCA_TamperedDigest verifies that a tampered manifest digest fails CA verification.
func TestSignWithCA_TamperedDigest(t *testing.T) {
	caKey, caDER := generateTestCA(t)
	caCert, _ := x509.ParseCertificate(caDER)

	original := "sha256:aabbccdd00000000000000000000000000000000000000000000000000000000"
	tampered := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	sigBytes, leafDER, err := bundle.SignWithCA(original, caKey, caCert)
	if err != nil {
		t.Fatalf("SignWithCA: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	if err := bundle.VerifyWithCA(tampered, sigBytes, leafDER, pool); err == nil {
		t.Error("VerifyWithCA with tampered digest returned nil, want error")
	}
}

// TestSignWithCA_WrongCA verifies that a leaf cert from a different CA fails chain verification.
func TestSignWithCA_WrongCA(t *testing.T) {
	caKey, caDER := generateTestCA(t)
	caCert, _ := x509.ParseCertificate(caDER)

	_, wrongCaDER := generateTestCA(t)
	wrongCaCert, _ := x509.ParseCertificate(wrongCaDER)

	manifestDigest := "sha256:aabbccdd00000000000000000000000000000000000000000000000000000000"

	sigBytes, leafDER, err := bundle.SignWithCA(manifestDigest, caKey, caCert)
	if err != nil {
		t.Fatalf("SignWithCA: %v", err)
	}

	wrongPool := x509.NewCertPool()
	wrongPool.AddCert(wrongCaCert)

	if err := bundle.VerifyWithCA(manifestDigest, sigBytes, leafDER, wrongPool); err == nil {
		t.Error("VerifyWithCA with wrong CA returned nil, want error")
	}
}

// TestSignWithCA_MissingSignature verifies that VerifyWithCA with empty sig bytes fails.
func TestSignWithCA_MissingSignature(t *testing.T) {
	_, caDER := generateTestCA(t)
	caCert, _ := x509.ParseCertificate(caDER)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	manifestDigest := "sha256:aabbccdd00000000000000000000000000000000000000000000000000000000"

	// A valid leaf cert but empty sig bytes.
	caKey2, caDER2 := generateTestCA(t)
	caCert2, _ := x509.ParseCertificate(caDER2)
	_, leafDER, _ := bundle.SignWithCA(manifestDigest, caKey2, caCert2)

	if err := bundle.VerifyWithCA(manifestDigest, []byte{}, leafDER, pool); err == nil {
		t.Error("VerifyWithCA with empty sig returned nil, want error")
	}
}

// TestCASignAndPushReferrer_RoundTrip performs a full registry end-to-end test
// with keyed-CA signing:
//  1. Pack + push a bundle.
//  2. SignWithCAAndPushReferrer with a self-signed CA.
//  3. PullAndVerifyWithCAReferrer against the same CA pool.
func TestCASignAndPushReferrer_RoundTrip(t *testing.T) {
	ctx := context.Background()

	caKey, caDER := generateTestCA(t)
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srv, transport := newSignTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "ca-sig-test", Version: "v0.0.1"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	ref := fmt.Sprintf("%s/casigtest:v0.0.1", host)
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

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyWithCAReferrer(ctx, resolvedDesc.Digest.String(), ref, pool, pullOpts); err != nil {
		t.Fatalf("PullAndVerifyWithCAReferrer valid CA: %v", err)
	}
}

// TestCASignAndPushReferrer_WrongCA verifies that verification against the wrong CA fails.
func TestCASignAndPushReferrer_WrongCA(t *testing.T) {
	ctx := context.Background()

	caKey, caDER := generateTestCA(t)
	caCert, _ := x509.ParseCertificate(caDER)

	_, wrongCaDER := generateTestCA(t)
	wrongCaCert, _ := x509.ParseCertificate(wrongCaDER)
	wrongPool := x509.NewCertPool()
	wrongPool.AddCert(wrongCaCert)

	srv, transport := newSignTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "ca-wrongca-test", Version: "v0.0.1"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	ref := fmt.Sprintf("%s/cawrongca:v0.0.1", host)
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

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyWithCAReferrer(ctx, resolvedDesc.Digest.String(), ref, wrongPool, pullOpts); err == nil {
		t.Error("PullAndVerifyWithCAReferrer with wrong CA returned nil, want error")
	}
}

// TestCASignAndPushReferrer_MissingSignature verifies that pulling when no
// CA-keyed signature referrer exists returns an error.
func TestCASignAndPushReferrer_MissingSignature(t *testing.T) {
	ctx := context.Background()

	_, caDER := generateTestCA(t)
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srv, transport := newSignTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "ca-nosig-test", Version: "v0.0.1"}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	ref := fmt.Sprintf("%s/canosig:v0.0.1", host)
	pushOpts := bundle.PushOptions{PlainHTTP: true, Transport: transport}
	if _, err := bundle.Push(ctx, store, manifestDesc, ref, pushOpts); err != nil {
		t.Fatalf("Push: %v", err)
	}

	resolvedDesc, err := bundle.ResolveDigest(ctx, ref, bundle.PullOptions{PlainHTTP: true, Transport: transport})
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	// No signature pushed: should fail with "no signature referrer found".
	if err := bundle.PullAndVerifyWithCAReferrer(ctx, resolvedDesc.Digest.String(), ref, pool, pullOpts); err == nil {
		t.Error("PullAndVerifyWithCAReferrer without a signature returned nil, want error")
	}
}

// TestKeylessSigning_RequiresOIDC verifies that the keyless signing path
// returns a clear "OIDC required" error when called outside CI (offline).
// This test is safe to run anywhere: it must NOT attempt network I/O.
func TestKeylessSigning_RequiresOIDC(t *testing.T) {
	err := bundle.SignKeyless("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("SignKeyless() returned nil offline, want OIDC-required error")
	}
	if !strings.Contains(err.Error(), "OIDC") && !strings.Contains(err.Error(), "keyless") {
		t.Errorf("SignKeyless() offline error %q does not mention OIDC or keyless", err.Error())
	}
}
