//go:build !wasm

// Package verify — blob_signature.go provides VerifyBlobBundle, the release-blob
// (Sigstore messageSignature) verify path. It is SECURITY-CRITICAL: every path
// fails CLOSED (Verified:false with an Err) on any doubt so an invalid signature
// is never treated as verified.
//
// This file mirrors the keyed-first-then-keyless dispatch of sigstore_native.go:
//   - KEYED: a forgeseal self-signed-CA bundle carries verificationMaterial.
//     certificate and NO tlogEntries. The leaf is chained to roots.SignatureCAs
//     with stdlib crypto/x509, the bundle messageDigest is checked to equal the
//     artifact digest, and the messageSignature is verified as an ECDSA signature
//     over the artifact's sha256 digest under the leaf public key.
//   - KEYLESS: a Fulcio/Rekor bundle is verified with sigstore-go, binding the
//     messageSignature to the artifact digest via sgverify.WithArtifactDigest.
//
// Because the keyless path imports sigstore-go (not WASM-safe), this file is
// gated to non-WASM builds; blob_signature_wasm.go supplies a fail-closed stub.
package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	core "github.com/sns45/assayward/pkg/core"
)

// messageSignature is the minimal JSON of a Sigstore messageSignature: a digest
// of the signed artifact plus the raw signature over it.
type messageSignature struct {
	MessageDigest struct {
		Algorithm string `json:"algorithm"`
		Digest    string `json:"digest"`
	} `json:"messageDigest"`
	Signature string `json:"signature"`
}

// blobBundle is the minimal JSON of a Sigstore blob bundle. A messageSignature
// may live at content.messageSignature (canonical protobuf JSON) or top-level;
// a dsseEnvelope (content or top-level) marks a NON-blob bundle we must reject.
type blobBundle struct {
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		// TlogEntries is present on KEYLESS (Fulcio+Rekor) bundles. A keyed
		// forgeseal bundle has none; if present we must fall through to keyless.
		TlogEntries []json.RawMessage `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	MessageSignature *messageSignature `json:"messageSignature"`
	DSSEEnvelope     json.RawMessage   `json:"dsseEnvelope"`
	Content          struct {
		MessageSignature *messageSignature `json:"messageSignature"`
		DSSEEnvelope     json.RawMessage   `json:"dsseEnvelope"`
	} `json:"content"`
}

// VerifyBlobBundle verifies a Sigstore messageSignature (blob) bundle binds to
// artifactDigest (form "sha256:<hex>"). It returns the shared SignatureResult.
//
// Fail-closed contract: any parse error, digest mismatch, chain failure, or
// signature failure yields Verified:false with a non-empty Err. Available is
// true on every path where the verifier ran (including error paths); it is
// never false here because the native verifier is always able to run.
func VerifyBlobBundle(bundle []byte, artifactDigest string, roots core.TrustRoots) SignatureResult {
	// 1. Parse and validate the artifact digest: require "sha256:<hex>".
	alg, hexStr, ok := strings.Cut(artifactDigest, ":")
	if !ok || alg != "sha256" || hexStr == "" {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob: artifact digest must be sha256:<hex>, got %q", artifactDigest)}
	}
	digestBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob: decode artifact digest hex: %v", err)}
	}

	// 2. Parse the bundle and locate the messageSignature. A bundle with a
	//    dsseEnvelope and no messageSignature is not a blob bundle.
	var b blobBundle
	if err := json.Unmarshal(bundle, &b); err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob: parse bundle: %v", err)}
	}
	msgSig := b.MessageSignature
	if msgSig == nil {
		msgSig = b.Content.MessageSignature
	}
	if msgSig == nil {
		// No messageSignature: either a DSSE bundle or a malformed one. Reject.
		return SignatureResult{Available: true, Verified: false, Err: "blob: not a messageSignature bundle"}
	}

	hasCert := b.VerificationMaterial.Certificate != nil && b.VerificationMaterial.Certificate.RawBytes != ""
	hasTlog := len(b.VerificationMaterial.TlogEntries) > 0

	// 3. KEYED first: certificate present, no Rekor entries, SignatureCAs set.
	if hasCert && !hasTlog && len(roots.SignatureCAs) > 0 {
		return verifyKeyedBlob(b, msgSig, digestBytes, hexStr, roots)
	}

	// 4. KEYLESS: bind the messageSignature to the artifact digest via sigstore-go.
	return verifyKeylessBlob(bundle, digestBytes, roots)
}

// verifyKeyedBlob verifies a keyed (self-signed-CA) messageSignature bundle
// using stdlib crypto only. All checks are necessary conditions; any failure
// fails closed.
func verifyKeyedBlob(b blobBundle, msgSig *messageSignature, digestBytes []byte, artifactHex string, roots core.TrustRoots) SignatureResult {
	// 3a. The bundle messageDigest MUST equal the artifact digest. Checked first
	//     so a mismatch is rejected without touching the certificate or signature.
	if !blobDigestMatches(msgSig.MessageDigest.Digest, digestBytes, artifactHex) {
		return SignatureResult{Available: true, Verified: false, Err: "blob keyed: messageDigest does not match artifact digest"}
	}

	// 3b. Chain the leaf certificate to roots.SignatureCAs.
	certDER, err := base64.StdEncoding.DecodeString(b.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyed: base64-decode leaf cert: %v", err)}
	}
	leaf, err := chainLeafToCAs(certDER, roots)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyed: %v", err)}
	}

	// 3c. Verify the messageSignature as an ECDSA signature over the artifact's
	//     sha256 digest bytes under the leaf public key. For a Sigstore
	//     messageSignature the signature is ECDSA_Sign(sha256(artifact)); the
	//     32-byte digest IS the pre-hashed input to ecdsa.VerifyASN1.
	//     (Task 11's real fixture confirms this exact form for forgeseal.)
	sigBytes, err := base64.StdEncoding.DecodeString(msgSig.Signature)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyed: base64-decode signature: %v", err)}
	}
	ecPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return SignatureResult{Available: true, Verified: false, Err: "blob keyed: leaf cert public key is not ECDSA"}
	}
	if !ecdsa.VerifyASN1(ecPub, digestBytes, sigBytes) {
		return SignatureResult{Available: true, Verified: false, Err: "blob keyed: ECDSA signature verification failed"}
	}

	var subjectIdentity string
	if len(leaf.URIs) > 0 {
		subjectIdentity = leaf.URIs[0].String()
	}
	return SignatureResult{
		Available:       true,
		Verified:        true,
		Issuer:          "", // keyed bundles carry no OIDC issuer
		SubjectIdentity: subjectIdentity,
		RekorLogged:     false, // keyed offline verification: no Rekor
	}
}

// verifyKeylessBlob verifies a Fulcio/Rekor messageSignature bundle with
// sigstore-go, binding the signature to the artifact digest.
func verifyKeylessBlob(rawBundle []byte, digestBytes []byte, roots core.TrustRoots) SignatureResult {
	// Resolve trusted root: injected SigstoreTUF JSON, else public-good live root.
	var trustedMaterial root.TrustedMaterial
	if len(roots.SigstoreTUF) > 0 {
		tr, err := root.NewTrustedRootFromJSON(roots.SigstoreTUF)
		if err != nil {
			return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyless: parse trusted root: %v", err)}
		}
		trustedMaterial = tr
	} else {
		ltr, err := fetchPublicGoodLiveRoot()
		if err != nil {
			return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyless: fetch public-good TUF root: %v", err)}
		}
		trustedMaterial = ltr
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(rawBundle); err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyless: parse bundle: %v", err)}
	}

	sev, err := sgverify.NewVerifier(
		root.TrustedMaterialCollection{trustedMaterial},
		sgverify.WithTransparencyLog(1),
		sgverify.WithObserverTimestamps(1),
	)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyless: create verifier: %v", err)}
	}

	// Bind the messageSignature to the artifact digest: WithArtifactDigest makes
	// the signature cryptographically checked against digestBytes. Identity match
	// is deferred to the policy layer via WithoutIdentitiesUnsafe.
	policy := sgverify.NewPolicy(
		sgverify.WithArtifactDigest("sha256", digestBytes),
		sgverify.WithoutIdentitiesUnsafe(),
	)

	res, err := sev.Verify(&b, policy)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("blob keyless: verify: %v", err)}
	}

	// Fail closed: a "verified" result with no certificate identity is malformed.
	if res.Signature == nil || res.Signature.Certificate == nil {
		return SignatureResult{Available: true, Verified: false, Err: "blob keyless: verified bundle missing certificate identity"}
	}
	cert := res.Signature.Certificate
	return SignatureResult{
		Available:       true,
		Verified:        true,
		Issuer:          cert.Extensions.Issuer,
		SubjectIdentity: cert.SubjectAlternativeName,
		RekorLogged:     len(res.VerifiedTimestamps) > 0,
	}
}

// blobDigestMatches reports whether a bundle messageDigest.digest field equals
// the artifact's raw digest bytes. Sigstore protobuf JSON base64-encodes the
// digest; forgeseal may emit hex. Both encodings are tried and compared to the
// raw bytes, so the check succeeds only on a genuine match and otherwise fails
// closed. (Task 11's real fixture confirms which encoding forgeseal uses.)
func blobDigestMatches(field string, wantBytes []byte, wantHex string) bool {
	if field == "" {
		return false
	}
	if raw, err := base64.StdEncoding.DecodeString(field); err == nil && bytes.Equal(raw, wantBytes) {
		return true
	}
	if raw, err := hex.DecodeString(field); err == nil && bytes.Equal(raw, wantBytes) {
		return true
	}
	// Direct case-insensitive hex string compare, in case of odd padding.
	return strings.EqualFold(field, wantHex)
}

// chainLeafToCAs parses a DER leaf certificate and verifies it chains to a CA in
// roots.SignatureCAs (a PEM bundle). It mirrors the chain logic in
// keyed_signature.go's VerifyKeyedBundle (kept local to preserve file scope).
// The leaf's NotBefore is used as the reference time so short-lived leaves
// verify without a live clock.
func chainLeafToCAs(leafDER []byte, roots core.TrustRoots) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	pool := x509.NewCertPool()
	rest := roots.SignatureCAs
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		ca, caErr := x509.ParseCertificate(block.Bytes)
		if caErr != nil {
			continue
		}
		pool.AddCert(ca)
	}
	opts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: leaf.NotBefore.Add(1),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, fmt.Errorf("leaf cert chain verification failed: %w", err)
	}
	return leaf, nil
}
