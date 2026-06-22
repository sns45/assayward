//go:build !wasm

package verify_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// TestSigstore_TamperedSignature_CryptoReject verifies that the crypto path
// (not the JSON parser) rejects a structurally valid bundle whose DSSE
// signature bytes have been bit-flipped. Unlike TestSigstoreVerifier_TamperedBundle,
// which corrupts the JSON itself and is rejected at parse time, this test
// keeps valid JSON but alters the base64-encoded signature value so that
// sigstore-go's verifier path catches the forgery.
func TestSigstore_TamperedSignature_CryptoReject(t *testing.T) {
	bundleBytes := testfix.Load(t, "signature/bundle-provenance.json")
	rootBytes := testfix.Load(t, "signature/trusted-root-public-good.json")

	// Parse the bundle as generic JSON so we can surgically alter the sig field.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bundleBytes, &raw); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}

	var dsseEnv map[string]json.RawMessage
	if err := json.Unmarshal(raw["dsseEnvelope"], &dsseEnv); err != nil {
		t.Fatalf("unmarshal dsseEnvelope: %v", err)
	}

	var sigs []map[string]json.RawMessage
	if err := json.Unmarshal(dsseEnv["signatures"], &sigs); err != nil {
		t.Fatalf("unmarshal signatures: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("no signatures in bundle")
	}

	// Extract the original base64-encoded sig value (JSON string with quotes).
	var originalSigB64 string
	if err := json.Unmarshal(sigs[0]["sig"], &originalSigB64); err != nil {
		t.Fatalf("unmarshal sig: %v", err)
	}

	// Decode, flip one bit, re-encode to the same base64 length.
	sigBytes, err := base64.StdEncoding.DecodeString(originalSigB64)
	if err != nil {
		// Try RawStdEncoding in case there is no padding.
		sigBytes, err = base64.RawStdEncoding.DecodeString(originalSigB64)
		if err != nil {
			t.Fatalf("base64 decode sig: %v", err)
		}
	}
	corrupted := bytes.Clone(sigBytes)
	corrupted[0] ^= 0x01
	if bytes.Equal(corrupted, sigBytes) {
		t.Fatal("corruption did not change bytes — logic error")
	}
	newSigB64 := base64.StdEncoding.EncodeToString(corrupted)

	// Verify the re-encoded length matches the original (same byte length, same encoding).
	if len(newSigB64) != len(originalSigB64) {
		t.Fatalf("re-encoded sig length changed: %d -> %d", len(originalSigB64), len(newSigB64))
	}
	if newSigB64 == originalSigB64 {
		t.Fatal("re-encoded sig is identical to original — corruption had no effect")
	}

	// Write the corrupted sig back and rebuild the JSON.
	newSigJSON, _ := json.Marshal(newSigB64)
	sigs[0]["sig"] = newSigJSON
	sigsJSON, _ := json.Marshal(sigs)
	dsseEnv["signatures"] = sigsJSON
	dsseEnvJSON, _ := json.Marshal(dsseEnv)
	raw["dsseEnvelope"] = dsseEnvJSON
	tamperedBundle, _ := json.Marshal(raw)

	// Sanity check: the tampered bytes are valid JSON (parser won't reject it).
	var checkParse map[string]json.RawMessage
	if parseErr := json.Unmarshal(tamperedBundle, &checkParse); parseErr != nil {
		t.Fatalf("tampered bundle is not valid JSON — test setup error: %v", parseErr)
	}

	v := verify.NewSignatureVerifier()
	att := core.Attestation{Envelope: tamperedBundle}
	img := core.ImageRef{Name: "test", Digest: "sha256:0000"}
	roots := core.TrustRoots{SigstoreTUF: rootBytes}

	result := v.Verify(att, img, roots)

	if result.Verified {
		t.Fatal("expected Verified=false for crypto-tampered bundle, got true — CRITICAL: verifier accepted forged signature")
	}
	if result.Err == "" {
		t.Error("expected non-empty Err for crypto-tampered bundle")
	}
	t.Logf("crypto-tamper rejection error: %q", result.Err)
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
