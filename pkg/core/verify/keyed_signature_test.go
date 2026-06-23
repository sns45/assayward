package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/verify"
)

// dogfoodForgesealDir returns the absolute path to testdata/dogfood/forgeseal.
func dogfoodForgesealDir(t testing.TB) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// This file is at pkg/core/verify/keyed_signature_test.go.
	// testdata/dogfood/forgeseal is at ../../../testdata/dogfood/forgeseal.
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "testdata", "dogfood", "forgeseal")
}

// loadKeyedTestFixtures loads the real forgeseal bundle and CA cert for keyed verification tests.
func loadKeyedTestFixtures(t testing.TB) (att core.Attestation, caBytes []byte) {
	t.Helper()
	dir := dogfoodForgesealDir(t)

	bundleBytes, err := os.ReadFile(filepath.Join(dir, "slsa.sigstore-bundle.json"))
	if err != nil {
		t.Fatalf("read slsa.sigstore-bundle.json: %v", err)
	}
	caBytes, err = os.ReadFile(filepath.Join(dir, "forgeseal-signing-ca.crt"))
	if err != nil {
		t.Fatalf("read forgeseal-signing-ca.crt: %v", err)
	}

	// adapter.go extracts the dsseEnvelope from the bundle; reproduce that here
	// so att.Envelope is the bare DSSE envelope, same as in production.
	var bundle struct {
		Content struct {
			DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
		} `json:"content"`
	}
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}

	att = core.Attestation{
		PredicateType: "https://slsa.dev/provenance/v1",
		// Pass the full bundle bytes so verifyKeyedBundle can read rawBytes from
		// verificationMaterial.certificate; the DSSE envelope is inside content.dsseEnvelope.
		Envelope: bundleBytes,
	}
	return att, caBytes
}

// TestKeyedBundle_HappyPath verifies that a real forgeseal keyed Sigstore bundle
// passes verification when the correct CA is supplied.
func TestKeyedBundle_HappyPath(t *testing.T) {
	att, caBytes := loadKeyedTestFixtures(t)
	img := core.ImageRef{Name: "forgeseal-artifact", Digest: "sha256:9380231e5a304d44828280dac94dd10e511171879d4b9086722065e251f7ed74"}
	roots := core.TrustRoots{SignatureCAs: caBytes}

	result, handled := verify.VerifyKeyedBundle(att, img, roots)

	if !handled {
		t.Fatal("expected handled=true for keyed bundle with SignatureCAs set")
	}
	if !result.Available {
		t.Errorf("expected Available=true, got false")
	}
	if !result.Verified {
		t.Errorf("expected Verified=true, got false; Err=%q", result.Err)
	}
	if result.SubjectIdentity != "https://forgeseal.dev/cli" {
		t.Errorf("expected SubjectIdentity=%q, got %q", "https://forgeseal.dev/cli", result.SubjectIdentity)
	}
	if result.RekorLogged {
		t.Errorf("expected RekorLogged=false for keyed bundle")
	}
	t.Logf("SubjectIdentity=%q Verified=%v", result.SubjectIdentity, result.Verified)
}

// TestKeyedBundle_TamperedPayload verifies that flipping a byte in the payload
// (while keeping valid JSON by altering a non-structural byte inside a string field)
// causes Verified=false.
func TestKeyedBundle_TamperedPayload(t *testing.T) {
	dir := dogfoodForgesealDir(t)
	bundleBytes, err := os.ReadFile(filepath.Join(dir, "slsa.sigstore-bundle.json"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	caBytes, err := os.ReadFile(filepath.Join(dir, "forgeseal-signing-ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}

	// Parse bundle JSON and tamper with the payload base64 string.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bundleBytes, &raw); err != nil {
		t.Fatalf("unmarshal bundle outer: %v", err)
	}
	var content map[string]json.RawMessage
	if err := json.Unmarshal(raw["content"], &content); err != nil {
		t.Fatalf("unmarshal content: %v", err)
	}
	var dsseEnv map[string]json.RawMessage
	if err := json.Unmarshal(content["dsseEnvelope"], &dsseEnv); err != nil {
		t.Fatalf("unmarshal dsseEnvelope: %v", err)
	}

	// Extract the payload string and flip a byte inside the base64 data.
	var payloadB64 string
	if err := json.Unmarshal(dsseEnv["payload"], &payloadB64); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	// Flip a byte in the middle of the base64 string (changing a character
	// that is still valid base64: A<->B).
	pb := []byte(payloadB64)
	mid := len(pb) / 2
	if pb[mid] == 'A' {
		pb[mid] = 'B'
	} else {
		pb[mid] = 'A'
	}
	newPayloadJSON, _ := json.Marshal(string(pb))
	dsseEnv["payload"] = newPayloadJSON
	newDSSEJSON, _ := json.Marshal(dsseEnv)
	content["dsseEnvelope"] = newDSSEJSON
	raw["content"] = func() json.RawMessage { b, _ := json.Marshal(content); return b }()
	tamperedBundle, _ := json.Marshal(raw)

	// Sanity: still valid JSON.
	var check map[string]json.RawMessage
	if err := json.Unmarshal(tamperedBundle, &check); err != nil {
		t.Fatalf("tampered bundle not valid JSON (test setup error): %v", err)
	}

	att := core.Attestation{Envelope: tamperedBundle}
	img := core.ImageRef{Name: "forgeseal-artifact", Digest: "sha256:9380231e5a304d44828280dac94dd10e511171879d4b9086722065e251f7ed74"}
	roots := core.TrustRoots{SignatureCAs: caBytes}

	result, handled := verify.VerifyKeyedBundle(att, img, roots)

	if !handled {
		t.Fatal("expected handled=true")
	}
	if result.Verified {
		t.Fatal("expected Verified=false for tampered payload, got true — CRITICAL")
	}
	t.Logf("tampered-payload Err=%q", result.Err)
}

// TestKeyedBundle_WrongCA verifies that supplying a different (unrelated) CA
// causes Verified=false because the leaf cert cannot chain to it.
func TestKeyedBundle_WrongCA(t *testing.T) {
	att, _ := loadKeyedTestFixtures(t)
	img := core.ImageRef{Name: "forgeseal-artifact", Digest: "sha256:9380231e5a304d44828280dac94dd10e511171879d4b9086722065e251f7ed74"}

	// Use a truncated/malformed PEM that will not parse as a valid CA cert.
	// x509.CertPool.AppendCertsFromPEM silently ignores malformed PEM blocks,
	// so the pool will be empty, and the chain verification will fail.
	fakeCAPEM := []byte("-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----\n")

	roots := core.TrustRoots{SignatureCAs: fakeCAPEM}

	result, handled := verify.VerifyKeyedBundle(att, img, roots)

	if !handled {
		t.Fatal("expected handled=true (certificate material present, SignatureCAs set)")
	}
	if result.Verified {
		t.Fatal("expected Verified=false for wrong CA, got true")
	}
	t.Logf("wrong-CA Err=%q", result.Err)
}

// TestKeyedBundle_NoSignatureCAs verifies that when roots.SignatureCAs is empty,
// verifyKeyedBundle returns handled=false so the caller falls through to keyless/stub.
func TestKeyedBundle_NoSignatureCAs(t *testing.T) {
	att, _ := loadKeyedTestFixtures(t)
	img := core.ImageRef{Name: "forgeseal-artifact", Digest: "sha256:9380231e5a304d44828280dac94dd10e511171879d4b9086722065e251f7ed74"}
	roots := core.TrustRoots{} // no SignatureCAs

	_, handled := verify.VerifyKeyedBundle(att, img, roots)

	if handled {
		t.Fatal("expected handled=false when SignatureCAs is empty")
	}
}

// TestKeyedBundle_SkipsKeylessBundle_WithTlogEntries verifies that a bundle
// containing tlogEntries (a keyless/Fulcio+Rekor bundle) causes VerifyKeyedBundle
// to return handled=false so the caller falls through to the sigstore-go keyless path.
// A keyed forgeseal bundle has verificationMaterial.certificate and NO tlogEntries.
func TestKeyedBundle_SkipsKeylessBundle_WithTlogEntries(t *testing.T) {
	// Construct a minimal keyless-shaped bundle: it has verificationMaterial.certificate
	// (a Fulcio leaf) AND tlogEntries (a Rekor inclusion). The keyed verifier must
	// recognise the tlogEntries and return handled=false rather than claiming the bundle.
	keylessBundleJSON := []byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
		"verificationMaterial": {
			"certificate": {
				"rawBytes": "MIIB2zCCAYCgAwIBAgIQCj6UAl3ZTUGyF7nQ34laPDAKBggqhkjOPQQDAjAzMRIwEAYDVQQKEwlGb3JnZXNlYWwxHTAbBgNVBAMTFEZvcmdlc2VhbCBTaWduaW5nIENBMAoGCCqGSM49BAMCAwoG"
			},
			"tlogEntries": [
				{
					"logIndex": "12345",
					"logId": {"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="},
					"kindVersion": {"kind": "intoto", "version": "0.0.2"},
					"integratedTime": "1681839912",
					"inclusionPromise": {"signedEntryTimestamp": "MEYCIQCQxXRPzxtA3rie/Gg8vErjJNfGRBwWtfyJZWekPepLIwIhAKCP6p9llDiaqkuOzjlGNfqWqHESGEiAGvS7RSNc6mLr"},
					"canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjIifQ=="
				}
			]
		},
		"content": {
			"dsseEnvelope": {
				"payloadType": "application/vnd.in-toto+json",
				"payload": "e30=",
				"signatures": [{"sig": "MEQCIBxxx"}]
			}
		}
	}`)

	att := core.Attestation{
		PredicateType: "https://slsa.dev/provenance/v1",
		Envelope:      keylessBundleJSON,
	}
	img := core.ImageRef{Name: "test-image", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}

	// With SignatureCAs set: the old code would claim this bundle (certificate present +
	// SignatureCAs set = handled=true). The new code must detect tlogEntries and return
	// handled=false so the keyless path can handle it instead.
	_, caBytes := loadKeyedTestFixtures(t)
	roots := core.TrustRoots{SignatureCAs: caBytes}

	_, handled := verify.VerifyKeyedBundle(att, img, roots)

	if handled {
		t.Fatal("VerifyKeyedBundle must return handled=false for a bundle with tlogEntries (keyless bundle); keyed verifier must not claim keyless bundles")
	}
}

// TestKeyedBundle_SkipsKeylessBundle_WithX509CertChain verifies that a bundle
// containing x509CertificateChain (multi-cert Fulcio chain) causes VerifyKeyedBundle
// to return handled=false. Keyed forgeseal bundles carry a single
// verificationMaterial.certificate, not an x509CertificateChain.
func TestKeyedBundle_SkipsKeylessBundle_WithX509CertChain(t *testing.T) {
	keylessBundleJSON := []byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": {
			"x509CertificateChain": {
				"certificates": [
					{"rawBytes": "MIIB2zCCAYCgAwIBAgIQCj6UAl3ZTUGyF7nQ34laPDAKBggqhkjOPQQDAg=="}
				]
			},
			"tlogEntries": [
				{
					"logIndex": "18300934",
					"logId": {"keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="},
					"kindVersion": {"kind": "intoto", "version": "0.0.2"},
					"integratedTime": "1681839912",
					"inclusionPromise": {"signedEntryTimestamp": "MEYCIQCQxXRPzxtA3rie/Gg8vErjJNfGRBwWtfyJZWekPepLIwIhAKCP6p9llDiaqkuOzjlGNfqWqHESGEiAGvS7RSNc6mLr"},
					"canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjIifQ=="
				}
			]
		},
		"dsseEnvelope": {
			"payloadType": "application/vnd.in-toto+json",
			"payload": "e30=",
			"signatures": [{"sig": "MEQ="}]
		}
	}`)

	att := core.Attestation{
		PredicateType: "https://slsa.dev/provenance/v1",
		Envelope:      keylessBundleJSON,
	}
	img := core.ImageRef{Name: "test-image", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}

	_, caBytes := loadKeyedTestFixtures(t)
	roots := core.TrustRoots{SignatureCAs: caBytes}

	_, handled := verify.VerifyKeyedBundle(att, img, roots)

	if handled {
		t.Fatal("VerifyKeyedBundle must return handled=false for a bundle with x509CertificateChain+tlogEntries (keyless bundle)")
	}
}
