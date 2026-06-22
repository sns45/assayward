//go:build !wasm

package verify_test

import (
	"bytes"
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/verify"
)

func TestSigstoreVerifier_ValidBundle(t *testing.T) {
	bundleBytes := testfix.Load(t, "signature/bundle-provenance.json")
	rootBytes := testfix.Load(t, "signature/trusted-root-public-good.json")

	v := verify.NewSignatureVerifier()
	att := core.Attestation{Envelope: bundleBytes}
	img := core.ImageRef{Name: "test", Digest: "sha256:0000"}
	roots := core.TrustRoots{SigstoreTUF: rootBytes}

	result := v.Verify(att, img, roots)

	if !result.Verified {
		t.Fatalf("expected Verified=true, got false; Err=%q", result.Err)
	}
	if !result.RekorLogged {
		t.Error("expected RekorLogged=true")
	}
	if result.Issuer == "" {
		t.Error("expected non-empty Issuer")
	}
	if result.SubjectIdentity == "" {
		t.Error("expected non-empty SubjectIdentity")
	}
	t.Logf("Issuer=%q SubjectIdentity=%q", result.Issuer, result.SubjectIdentity)
}

func TestSigstoreVerifier_TamperedBundle(t *testing.T) {
	bundleBytes := testfix.Load(t, "signature/bundle-provenance.json")
	rootBytes := testfix.Load(t, "signature/trusted-root-public-good.json")

	// Corrupt the bundle by flipping a byte in the middle of the JSON.
	tampered := bytes.Clone(bundleBytes)
	mid := len(tampered) / 2
	tampered[mid] ^= 0xFF

	v := verify.NewSignatureVerifier()
	att := core.Attestation{Envelope: tampered}
	img := core.ImageRef{Name: "test", Digest: "sha256:0000"}
	roots := core.TrustRoots{SigstoreTUF: rootBytes}

	result := v.Verify(att, img, roots)

	if result.Verified {
		t.Fatal("expected Verified=false for tampered bundle, got true")
	}
	if result.Err == "" {
		t.Error("expected non-empty Err for tampered bundle")
	}
	t.Logf("tampered error: %q", result.Err)
}

func TestSigstoreVerifier_NoTrustMaterial(t *testing.T) {
	bundleBytes := testfix.Load(t, "signature/bundle-provenance.json")

	v := verify.NewSignatureVerifier()
	att := core.Attestation{Envelope: bundleBytes}
	img := core.ImageRef{Name: "test", Digest: "sha256:0000"}
	roots := core.TrustRoots{} // empty SigstoreTUF

	result := v.Verify(att, img, roots)

	if result.Verified {
		t.Fatal("expected Verified=false for empty trust material, got true")
	}
	if result.Err != "no trust material" {
		t.Errorf("expected Err=%q, got %q", "no trust material", result.Err)
	}
}
