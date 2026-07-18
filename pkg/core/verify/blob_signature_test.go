package verify

import (
	"encoding/base64"
	"strings"
	"testing"

	core "github.com/sns45/assayward/pkg/core"
)

// A DSSE bundle carries a dsseEnvelope and no messageSignature; it must not be
// accepted by the blob (messageSignature) verify path.
func TestVerifyBlobBundleRejectsNonMessageSignature(t *testing.T) {
	dsse := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{"payload":"e30=","payloadType":"application/vnd.in-toto+json","signatures":[]}}`)
	got := VerifyBlobBundle(dsse, "sha256:"+strings.Repeat("ab", 32), core.TrustRoots{})
	if got.Verified {
		t.Fatal("a DSSE bundle must not verify as a blob signature")
	}
	if !got.Available {
		t.Fatal("verifier ran, so Available must be true")
	}
	if got.Err == "" {
		t.Fatal("a rejected DSSE bundle must carry an error")
	}
}

// A non-JSON payload must fail closed with an error.
func TestVerifyBlobBundleRejectsMalformed(t *testing.T) {
	got := VerifyBlobBundle([]byte("not json"), "sha256:"+strings.Repeat("ab", 32), core.TrustRoots{})
	if got.Verified || got.Err == "" {
		t.Fatalf("malformed bundle must fail closed with an error: %+v", got)
	}
}

// A malformed artifact digest (wrong algorithm) must fail closed before any
// bundle inspection.
func TestVerifyBlobBundleRejectsBadDigest(t *testing.T) {
	got := VerifyBlobBundle([]byte(`{}`), "sha512:deadbeef", core.TrustRoots{})
	if got.Verified || got.Err == "" {
		t.Fatalf("a non-sha256 digest must fail closed: %+v", got)
	}
}

// A keyed messageSignature bundle whose messageDigest does not equal the
// artifact digest must fail closed. SignatureCAs + certificate + no tlog routes
// it to the keyed path where the digest is checked without any network access.
func TestVerifyBlobBundleDigestMismatchFailsClosed(t *testing.T) {
	// messageDigest is base64 of 32 zero bytes; the artifact digest is all 0xab.
	wrongDigest := base64.StdEncoding.EncodeToString(make([]byte, 32))
	bundle := []byte(`{"verificationMaterial":{"certificate":{"rawBytes":"AAAA"}},` +
		`"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"` + wrongDigest + `"},"signature":"AAAA"}}`)
	roots := core.TrustRoots{SignatureCAs: []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")}
	got := VerifyBlobBundle(bundle, "sha256:"+strings.Repeat("ab", 32), roots)
	if got.Verified {
		t.Fatal("a digest mismatch must never verify (fail-open bug)")
	}
	if !got.Available {
		t.Fatal("the keyed verifier ran, so Available must be true")
	}
	if got.Err == "" {
		t.Fatal("a digest mismatch must carry an error")
	}
}
