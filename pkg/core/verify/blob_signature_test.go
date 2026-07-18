package verify

import (
	"bytes"
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

// A keyed messageSignature bundle whose messageDigest DOES equal the artifact
// digest must still fail closed if the certificate cannot be parsed/chained.
// This drives the keyed path PAST blobDigestMatches (the earliest gate) into
// the cert-chain + ECDSA gate, pinning that gate as load-bearing: a regression
// that returned Verified:true right after the digest check (skipping chain
// and signature verification) would slip past every other test in this file
// but must be caught here.
func TestVerifyBlobBundleKeyedRejectsJunkCertOnDigestMatch(t *testing.T) {
	// messageDigest is base64 of 32 bytes of 0xab, exactly matching the
	// artifact digest passed below, so blobDigestMatches succeeds.
	matchingDigest := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	// rawBytes "AAAA" is valid base64 but decodes to 3 zero bytes, which is
	// not a parseable X.509 certificate: the leaf cert parse must fail.
	bundle := []byte(`{"verificationMaterial":{"certificate":{"rawBytes":"AAAA"}},` +
		`"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"` + matchingDigest + `"},"signature":"AAAA"}}`)
	roots := core.TrustRoots{SignatureCAs: []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")}
	got := VerifyBlobBundle(bundle, "sha256:"+strings.Repeat("ab", 32), roots)
	if got.Verified {
		t.Fatal("a bundle with an unparseable leaf certificate must never verify, even on digest match (fail-open regression)")
	}
	if !got.Available {
		t.Fatal("the keyed verifier ran, so Available must be true")
	}
	if got.Err == "" {
		t.Fatal("a rejected bundle must carry an error")
	}
	if strings.Contains(got.Err, "messageDigest") {
		t.Fatalf("failure must come from the cert/chain gate, not the digest check: %+v", got)
	}
}
