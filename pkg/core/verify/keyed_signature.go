// Package verify — keyed_signature.go provides KEYED (self-signed-CA) Sigstore
// bundle verification using stdlib crypto only. No sigstore-go is imported here,
// making this file safe for WASM builds (no build tag required).
package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"

	core "github.com/sns45/assayward/pkg/core"
)

// keyedBundle is the minimal JSON representation of a keyed Sigstore bundle.
// Only fields needed for keyed (self-signed-CA) verification are decoded.
type keyedBundle struct {
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		// TlogEntries is non-nil and non-empty on KEYLESS (Fulcio+Rekor) bundles.
		// A keyed forgeseal bundle has no tlogEntries; if present we must not claim
		// the bundle and should fall through to the sigstore-go keyless path.
		TlogEntries []json.RawMessage `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	Content struct {
		DSSEEnvelope *struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				Sig string `json:"sig"`
			} `json:"signatures"`
		} `json:"dsseEnvelope"`
	} `json:"content"`
}

// VerifyKeyedBundle verifies a keyed (self-signed-CA) Sigstore bundle.
//
// It checks that the leaf certificate chains to a CA in roots.SignatureCAs,
// and that the DSSE signature in the bundle verifies under the leaf key.
//
// Returns (result, handled):
//   - handled=false means this is not a keyed bundle we can verify (no
//     certificate material in the bundle, or roots.SignatureCAs is empty).
//     The caller should fall through to the keyless/stub verifier.
//   - handled=true means we attempted verification; inspect result.Verified.
//
// This function uses only stdlib crypto (crypto/x509, crypto/ecdsa, crypto/sha256)
// and never imports sigstore-go, keeping it safe for WASM builds.
func VerifyKeyedBundle(att core.Attestation, _ core.ArtifactRef, roots core.TrustRoots) (SignatureResult, bool) {
	// Parse the bundle JSON.
	var b keyedBundle
	if err := json.Unmarshal(att.Envelope, &b); err != nil {
		// Not a parseable bundle at all — not handled.
		return SignatureResult{}, false
	}

	// No certificate material present: not a keyed bundle.
	if b.VerificationMaterial.Certificate == nil || b.VerificationMaterial.Certificate.RawBytes == "" {
		return SignatureResult{}, false
	}

	// tlogEntries present: this is a KEYLESS (Fulcio+Rekor) bundle. A keyed forgeseal
	// bundle has verificationMaterial.certificate and NO tlogEntries. The Fulcio leaf
	// cert does not chain to a self-signed SignatureCAs entry, so we must not claim
	// this bundle. Fall through to the sigstore-go keyless path.
	if len(b.VerificationMaterial.TlogEntries) > 0 {
		return SignatureResult{}, false
	}

	// No SignatureCAs: caller has not configured keyed verification.
	if len(roots.SignatureCAs) == 0 {
		return SignatureResult{}, false
	}

	// From here we are "handled" — errors return a failed result, not fall-through.

	// 1. Decode and parse the leaf certificate.
	certDER, err := base64.StdEncoding.DecodeString(b.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       fmt.Sprintf("keyed: base64-decode leaf cert: %v", err),
		}, true
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       fmt.Sprintf("keyed: parse leaf cert: %v", err),
		}, true
	}

	// 2. Build an x509 cert pool from roots.SignatureCAs (PEM bundle).
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

	// 3. Verify the leaf cert chains to the CA pool.
	// We use the leaf's NotBefore as the reference time so that the short-lived
	// leaf (1-year validity in the dogfood setup) verifies without a live clock.
	opts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: leaf.NotBefore.Add(1),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       fmt.Sprintf("keyed: leaf cert chain verification failed: %v", err),
		}, true
	}

	// 4. Verify the DSSE signature.
	if b.Content.DSSEEnvelope == nil {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       "keyed: bundle has no content.dsseEnvelope",
		}, true
	}
	env := b.Content.DSSEEnvelope
	if len(env.Signatures) == 0 {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       "keyed: no signatures in dsseEnvelope",
		}, true
	}

	// Decode the payload (base64-standard per DSSE spec).
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		// Fall back to URL-safe base64.
		payloadBytes, err = base64.URLEncoding.DecodeString(env.Payload)
		if err != nil {
			return SignatureResult{
				Available: true,
				Verified:  false,
				Err:       fmt.Sprintf("keyed: base64-decode DSSE payload: %v", err),
			}, true
		}
	}

	// Reconstruct the DSSEv1 Pre-Authentication Encoding (PAE).
	// PAE = "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
	// Byte lengths are ASCII decimal of the UTF-8 byte count.
	pae := dssePAE(env.PayloadType, payloadBytes)
	digest := sha256.Sum256(pae)

	// Decode the signature bytes.
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       fmt.Sprintf("keyed: base64-decode signature: %v", err),
		}, true
	}

	// Verify with the leaf public key. Only ECDSA is supported (P-256 per forgeseal).
	ecPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       "keyed: leaf cert public key is not ECDSA",
		}, true
	}
	if !ecdsa.VerifyASN1(ecPub, digest[:], sigBytes) {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       "keyed: ECDSA signature verification failed",
		}, true
	}

	// 5. Extract the subject identity from the leaf cert's URI SAN.
	var subjectIdentity string
	if len(leaf.URIs) > 0 {
		subjectIdentity = leaf.URIs[0].String()
	}

	return SignatureResult{
		Available:       true,
		Verified:        true,
		Issuer:          "", // keyed bundles do not carry an OIDC issuer
		SubjectIdentity: subjectIdentity,
		RekorLogged:     false, // keyed offline verification: no Rekor
	}, true
}

// dssePAE constructs the DSSEv1 Pre-Authentication Encoding.
// PAE(type, body) = "DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
// where len() is the ASCII decimal representation of the UTF-8 byte count.
func dssePAE(payloadType string, payload []byte) []byte {
	// Pre-allocate a reasonable buffer.
	typeLen := strconv.Itoa(len(payloadType))
	bodyLen := strconv.Itoa(len(payload))

	// "DSSEv1 " + typeLen + " " + payloadType + " " + bodyLen + " " + payload
	prefix := "DSSEv1 " + typeLen + " " + payloadType + " " + bodyLen + " "
	result := make([]byte, 0, len(prefix)+len(payload))
	result = append(result, []byte(prefix)...)
	result = append(result, payload...)
	return result
}
