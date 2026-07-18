//go:build !wasm

package verify_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
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
	art := core.ImageRef{Name: "test", Digest: "sha256:0000"}.AsArtifact()
	roots := core.TrustRoots{SigstoreTUF: rootBytes}

	result := v.Verify(att, art, roots)

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
	art := core.ImageRef{Name: "test", Digest: "sha256:0000"}.AsArtifact()
	roots := core.TrustRoots{SigstoreTUF: rootBytes}

	result := v.Verify(att, art, roots)

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
	art := core.ImageRef{Name: "test", Digest: "sha256:0000"}.AsArtifact()
	roots := core.TrustRoots{SigstoreTUF: rootBytes}

	result := v.Verify(att, art, roots)

	if result.Verified {
		t.Fatal("expected Verified=false for crypto-tampered bundle, got true — CRITICAL: verifier accepted forged signature")
	}
	if result.Err == "" {
		t.Error("expected non-empty Err for crypto-tampered bundle")
	}
	t.Logf("crypto-tamper rejection error: %q", result.Err)
}

// TestSigstoreVerifier_TUFFallback_AttemptsMade verifies that when SigstoreTUF
// is empty, the verifier attempts TUF-based trust root resolution rather than
// immediately returning "no trust material". In environments with network access
// the verification may succeed; in offline environments it will fail with a TUF
// or verification error. In either case the result must NOT report the static
// "no trust material" error.
func TestSigstoreVerifier_TUFFallback_AttemptsMade(t *testing.T) {
	bundleBytes := testfix.Load(t, "signature/bundle-provenance.json")

	v := verify.NewSignatureVerifier()
	att := core.Attestation{Envelope: bundleBytes}
	art := core.ImageRef{Name: "test", Digest: "sha256:0000"}.AsArtifact()
	roots := core.TrustRoots{} // empty SigstoreTUF — triggers TUF fallback

	result := v.Verify(att, art, roots)

	// The verifier must NOT return the old "no trust material" fast-fail error.
	// It must attempt TUF resolution first (and either succeed or fail with a
	// TUF/network/verification error).
	if result.Err == "no trust material" {
		t.Fatal("verifier returned immediate 'no trust material' error; expected TUF fallback to be attempted")
	}
	// Sanity: Available must be true (native verifier ran).
	if !result.Available {
		t.Error("expected Available=true from native verifier")
	}
	t.Logf("TUF fallback result: Verified=%v Err=%q", result.Verified, result.Err)
}

// TestSigstoreVerifier_TUFFallback_PublicGood verifies end-to-end keyless
// verification against the Sigstore public-good instance by fetching the trusted
// root via TUF at runtime (no pre-committed SigstoreTUF bytes).
//
// This test hits the public TUF repository and Rekor log. It is gated behind
// ASSAYWARD_TEST_NETWORK=1 to avoid flakiness in offline CI environments.
func TestSigstoreVerifier_TUFFallback_PublicGood(t *testing.T) {
	if os.Getenv("ASSAYWARD_TEST_NETWORK") != "1" {
		t.Skip("skipping network test: set ASSAYWARD_TEST_NETWORK=1 to run")
	}

	bundleBytes := testfix.Load(t, "signature/bundle-provenance.json")

	v := verify.NewSignatureVerifier()
	att := core.Attestation{Envelope: bundleBytes}
	art := core.ImageRef{Name: "test", Digest: "sha256:0000"}.AsArtifact()
	// Empty SigstoreTUF: the verifier must fetch the trusted root from TUF.
	roots := core.TrustRoots{}

	result := v.Verify(att, art, roots)

	if !result.Verified {
		t.Fatalf("expected Verified=true with public-good TUF fallback, got false; Err=%q", result.Err)
	}
	if !result.RekorLogged {
		t.Error("expected RekorLogged=true for public-good keyless bundle")
	}
	if result.Issuer == "" {
		t.Error("expected non-empty Issuer")
	}
	if result.SubjectIdentity == "" {
		t.Error("expected non-empty SubjectIdentity")
	}
	t.Logf("TUF fallback: Issuer=%q SubjectIdentity=%q", result.Issuer, result.SubjectIdentity)
}
