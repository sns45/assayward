//go:build !wasm

package verify

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	core "github.com/sns45/assayward/pkg/core"
)

// nativeVerifier is the production Sigstore verifier. It requires tlog
// inclusion (Rekor) and certificate chain to Fulcio but is policy-agnostic
// about which identity is allowed; identity extraction is left to the policy
// layer.
type nativeVerifier struct{}

// NewSignatureVerifier returns the native Sigstore-backed verifier. This
// constructor is only compiled into non-WASM builds.
func NewSignatureVerifier() SignatureVerifier {
	return &nativeVerifier{}
}

// Verify checks a Sigstore bundle for the given attestation. The
// implementation:
//  1. Parses the trusted root from roots.SigstoreTUF.
//  2. Parses the Sigstore bundle from att.Envelope.
//  3. Verifies the bundle: tlog inclusion + cert chain (Fulcio).
//  4. Extracts OIDC issuer and SAN from the verified leaf certificate.
//
// It is deliberately policy-agnostic: it does NOT enforce which identity
// signed; that enforcement belongs to the policy layer.
func (v *nativeVerifier) Verify(att core.Attestation, _ core.ImageRef, roots core.TrustRoots) SignatureResult {
	if len(roots.SigstoreTUF) == 0 {
		return SignatureResult{Verified: false, Err: "no trust material"}
	}

	// Parse trusted root from injected JSON bytes.
	trustedRoot, err := root.NewTrustedRootFromJSON(roots.SigstoreTUF)
	if err != nil {
		return SignatureResult{Verified: false, Err: fmt.Sprintf("parse trusted root: %v", err)}
	}

	// Parse the Sigstore bundle from att.Envelope bytes.
	var b bundle.Bundle
	if unmarshalErr := b.UnmarshalJSON(att.Envelope); unmarshalErr != nil {
		return SignatureResult{Verified: false, Err: fmt.Sprintf("parse bundle: %v", unmarshalErr)}
	}

	// Build a verifier: require tlog inclusion (Rekor) + an observer
	// timestamp so that the short-lived Fulcio cert can be validated.
	// We do NOT require CTlog entries here because older bundles (v0.1)
	// may lack embedded SCTs.
	sev, err := sgverify.NewVerifier(
		root.TrustedMaterialCollection{trustedRoot},
		sgverify.WithTransparencyLog(1),
		sgverify.WithObserverTimestamps(1),
	)
	if err != nil {
		return SignatureResult{Verified: false, Err: fmt.Sprintf("create verifier: %v", err)}
	}

	// Use WithoutIdentitiesUnsafe so the verifier only checks the
	// cryptographic chain + tlog inclusion without enforcing a specific SAN.
	// The policy layer (a later task) does the identity match.
	policy := sgverify.NewPolicy(
		sgverify.WithoutArtifactUnsafe(),
		sgverify.WithoutIdentitiesUnsafe(),
	)

	res, err := sev.Verify(&b, policy)
	if err != nil {
		return SignatureResult{Verified: false, Err: fmt.Sprintf("verify: %v", err)}
	}

	// Extract issuer and SAN from the verified certificate summary.
	var issuer, san string
	if res.Signature != nil && res.Signature.Certificate != nil {
		cert := res.Signature.Certificate
		issuer = cert.Extensions.Issuer
		san = cert.SubjectAlternativeName
	}

	// RekorLogged is true when the verifier successfully verified a tlog entry.
	rekorLogged := len(res.VerifiedTimestamps) > 0

	return SignatureResult{
		Verified:        true,
		Issuer:          issuer,
		SubjectIdentity: san,
		RekorLogged:     rekorLogged,
	}
}
