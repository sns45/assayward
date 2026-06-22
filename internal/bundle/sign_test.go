package bundle_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	manifestDigest, err := bundle.Push(ctx, store, manifestDesc, ref, pushOpts)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	if err := bundle.SignAndPushReferrer(ctx, manifestDigest, ref, priv, pushOpts); err != nil {
		t.Fatalf("SignAndPushReferrer() error: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyReferrer(ctx, manifestDigest, ref, pub, pullOpts); err != nil {
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
	manifestDigest, err := bundle.Push(ctx, store, manifestDesc, ref, pushOpts)
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}

	if err := bundle.SignAndPushReferrer(ctx, manifestDigest, ref, priv, pushOpts); err != nil {
		t.Fatalf("SignAndPushReferrer() error: %v", err)
	}

	pullOpts := bundle.PullOptions{PlainHTTP: true, Transport: transport}
	if err := bundle.PullAndVerifyReferrer(ctx, manifestDigest, ref, wrongPub, pullOpts); err == nil {
		t.Error("PullAndVerifyReferrer() with wrong key returned nil, want error")
	}
}
