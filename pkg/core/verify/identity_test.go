package verify_test

// Identity verifier tests (task 1.7).
//
// Fixtures are generated synthetically by testdata/gen/main.go and loaded via
// internal/testfix. They are SYNTHETIC PLACEHOLDERS; real SVID credentials
// will be supplied by the svidmint pipeline before v0.1 ships.

import (
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/verify"
)

// testImg returns an ImageRef using the canonical test image name and digest.
func testImg() core.ImageRef {
	return core.ImageRef{
		Name:   testfix.TestImageName,
		Digest: testfix.TestImageDigest,
	}
}

// testRoots builds a TrustRoots with the given bundle bytes at key "sns45.dev".
func testRoots(bundle []byte) core.TrustRoots {
	return core.TrustRoots{
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": bundle,
		},
	}
}

// ---- JWT-SVID tests ----

func TestVerifyIdentity_JWT_Valid(t *testing.T) {
	token := testfix.Load(t, "svid/jwt-valid.jwt")
	bundle := testfix.Load(t, "svid/jwt-bundle.json")

	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      token,
	}
	result := verify.VerifyIdentity(id, testImg(), testRoots(bundle))

	if !result.Verified {
		t.Fatalf("expected Verified=true, got false; err=%q", result.Err)
	}
	if !result.BindingMatch {
		t.Errorf("expected BindingMatch=true (audience matches image digest)")
	}
	if result.TrustDomain != "spiffe://sns45.dev" {
		t.Errorf("expected TrustDomain=spiffe://sns45.dev, got %q", result.TrustDomain)
	}
	if result.SPIFFEID == "" {
		t.Errorf("expected non-empty SPIFFEID")
	}
}

func TestVerifyIdentity_JWT_Expired(t *testing.T) {
	token := testfix.Load(t, "svid/jwt-expired.jwt")
	bundle := testfix.Load(t, "svid/jwt-bundle.json")

	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      token,
	}
	result := verify.VerifyIdentity(id, testImg(), testRoots(bundle))

	if result.Verified {
		t.Fatalf("expected Verified=false for expired token, got true")
	}
	if result.Err == "" {
		t.Errorf("expected non-empty Err for expired token")
	}
}

func TestVerifyIdentity_JWT_WrongDomain(t *testing.T) {
	token := testfix.Load(t, "svid/jwt-wrong-domain.jwt")
	bundle := testfix.Load(t, "svid/jwt-bundle.json")

	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      token,
	}
	result := verify.VerifyIdentity(id, testImg(), testRoots(bundle))

	if result.Verified {
		t.Fatalf("expected Verified=false for wrong-domain token, got true")
	}
}

func TestVerifyIdentity_JWT_WrongAudience(t *testing.T) {
	// Valid JWT but validated against a DIFFERENT image digest => binding fails.
	token := testfix.Load(t, "svid/jwt-valid.jwt")
	bundle := testfix.Load(t, "svid/jwt-bundle.json")

	differentImg := core.ImageRef{
		Name:   testfix.TestImageName,
		Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      token,
	}
	result := verify.VerifyIdentity(id, differentImg, testRoots(bundle))

	if result.Verified {
		t.Fatalf("expected Verified=false when audience does not match image digest, got true")
	}
}

// ---- X509-SVID tests ----

// TestVerifyIdentity_JWT_WrongKey verifies that a JWT-SVID signed by a key NOT
// in the trust bundle is rejected with a signature failure. The trust domain
// sns45.dev IS found in the bundle (so this is a cryptographic rejection, not a
// missing-bundle rejection).
func TestVerifyIdentity_JWT_WrongKey(t *testing.T) {
	token := testfix.Load(t, "svid/jwt-wrong-key.jwt")
	bundle := testfix.Load(t, "svid/jwt-bundle.json")

	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      token,
	}
	result := verify.VerifyIdentity(id, testImg(), testRoots(bundle))

	if result.Verified {
		t.Fatalf("expected Verified=false for wrong-key token, got true")
	}
	if result.Err == "" {
		t.Errorf("expected non-empty Err for wrong-key token")
	}
}

// ---- X509-SVID tests ----

func TestVerifyIdentity_X509_Valid(t *testing.T) {
	certPEM := testfix.Load(t, "svid/x509-valid.pem")
	bundlePEM := testfix.Load(t, "svid/x509-bundle.pem")

	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeX509,
		Raw:      certPEM,
	}
	roots := core.TrustRoots{
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": bundlePEM,
		},
	}
	result := verify.VerifyIdentity(id, testImg(), roots)

	if !result.Verified {
		t.Fatalf("expected Verified=true for valid X509-SVID, got false; err=%q", result.Err)
	}
	if result.TrustDomain != "spiffe://sns45.dev" {
		t.Errorf("expected TrustDomain=spiffe://sns45.dev, got %q", result.TrustDomain)
	}
	if result.SPIFFEID == "" {
		t.Errorf("expected non-empty SPIFFEID")
	}
	// v0.1 binding: BindingMatch is true when SPIFFE ID is in the expected trust domain.
	if !result.BindingMatch {
		t.Errorf("expected BindingMatch=true (SPIFFE ID in trust domain sns45.dev)")
	}
}

// TestVerifyIdentity_X509_Expired verifies that a cert whose NotAfter is in the
// past is rejected. The cert is signed by the trusted CA (chain is valid) but
// the validity window has elapsed.
func TestVerifyIdentity_X509_Expired(t *testing.T) {
	certPEM := testfix.Load(t, "svid/x509-expired.pem")
	bundlePEM := testfix.Load(t, "svid/x509-bundle.pem")

	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeX509,
		Raw:      certPEM,
	}
	roots := core.TrustRoots{
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": bundlePEM,
		},
	}
	result := verify.VerifyIdentity(id, testImg(), roots)

	if result.Verified {
		t.Fatalf("expected Verified=false for expired X509-SVID, got true")
	}
	if result.Err == "" {
		t.Errorf("expected non-empty Err for expired X509-SVID")
	}
}

// TestVerifyIdentity_X509_WrongCA verifies that a cert signed by an untrusted CA
// (not present in x509-bundle.pem) is rejected. The SPIFFE ID is valid but the
// signing authority is not in the trust bundle.
func TestVerifyIdentity_X509_WrongCA(t *testing.T) {
	certPEM := testfix.Load(t, "svid/x509-wrong-ca.pem")
	bundlePEM := testfix.Load(t, "svid/x509-bundle.pem")

	id := core.WorkloadIdentity{
		SVIDType: core.SVIDTypeX509,
		Raw:      certPEM,
	}
	roots := core.TrustRoots{
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": bundlePEM,
		},
	}
	result := verify.VerifyIdentity(id, testImg(), roots)

	if result.Verified {
		t.Fatalf("expected Verified=false for wrong-CA X509-SVID, got true")
	}
	if result.Err == "" {
		t.Errorf("expected non-empty Err for wrong-CA X509-SVID")
	}
}
