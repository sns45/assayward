package verify

// IdentityVerifier validates SPIFFE Verifiable Identity Documents (SVIDs) — both
// JWT-SVIDs and X509-SVIDs — using the go-spiffe library.
//
// # Binding semantics (v0.1 placeholder, documented)
//
// JWT-SVID binding: the workload's expected audience is set to img.Digest (the
// OCI image digest). ParseAndValidate is called with that audience so the
// SPIFFE JWT-SVID must have been issued specifically for this image. This is a
// v0.1 WIMSE placeholder: real workload-image binding will use a richer
// mechanism in a future release.
//
// X509-SVID binding (v0.1 placeholder): BindingMatch is true when the leaf
// SPIFFE ID belongs to trust domain spiffe://sns45.dev. X509-SVIDs carry no
// audience field, so proper image-binding is deferred to a future release.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	core "github.com/sns45/assayward/pkg/core"
)

const snsDevTrustDomain = "sns45.dev"

// IdentityResult is the outcome of verifying a SPIFFE workload identity.
type IdentityResult struct {
	// Verified is true when the SVID parsed and validated successfully against
	// the provided trust bundle and the trust domain is spiffe://sns45.dev.
	Verified bool

	// SPIFFEID is the SPIFFE ID string extracted from the verified SVID.
	// Empty when Verified is false.
	SPIFFEID string

	// TrustDomain is the SPIFFE trust domain URI (e.g. "spiffe://sns45.dev")
	// extracted from the SVID. Empty when Verified is false.
	TrustDomain string

	// BindingMatch reflects whether the SVID is bound to the specific workload
	// identified by img. See package-level doc for v0.1 semantics.
	BindingMatch bool

	// Err is a non-empty human-readable error string when verification failed.
	// Empty on success.
	Err string
}

// VerifyIdentity validates id.Raw as a SPIFFE SVID (JWT or X509) against the
// trust material in roots. The img argument is used for workload binding (see
// package-level doc).
//
// On any parse or validation error IdentityResult.Verified is false and
// IdentityResult.Err is non-empty. This function never panics.
func VerifyIdentity(id core.WorkloadIdentity, img core.ImageRef, roots core.TrustRoots) IdentityResult {
	switch id.SVIDType {
	case core.SVIDTypeJWT:
		return verifyJWT(id.Raw, img, roots)
	case core.SVIDTypeX509:
		return verifyX509(id.Raw, img, roots)
	default:
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity: unknown SVIDType %q", id.SVIDType),
		}
	}
}

// verifyJWT validates id.Raw as a compact JWT-SVID token.
func verifyJWT(raw []byte, img core.ImageRef, roots core.TrustRoots) IdentityResult {
	bundleBytes, ok := roots.SPIFFEBundles[snsDevTrustDomain]
	if !ok {
		return IdentityResult{
			Verified: false,
			Err:      "identity/jwt: no SPIFFE bundle for trust domain " + snsDevTrustDomain,
		}
	}

	td, err := spiffeid.TrustDomainFromString(snsDevTrustDomain)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/jwt: invalid trust domain: %v", err),
		}
	}

	bundle, err := jwtbundle.Parse(td, bundleBytes)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/jwt: parse JWKS bundle: %v", err),
		}
	}

	// Audience-as-binding (v0.1 WIMSE placeholder): the JWT-SVID must have been
	// issued with the image digest as its audience. This binds the credential to
	// the specific image being admitted.
	audience := []string{img.Digest}
	token := string(raw)

	svid, err := jwtsvid.ParseAndValidate(token, bundle, audience)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/jwt: validation failed: %v", err),
		}
	}

	// Verify that the SPIFFE ID belongs to the expected trust domain.
	if !svid.ID.MemberOf(td) {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/jwt: SPIFFE ID %q is not in trust domain %q", svid.ID, td),
		}
	}

	return IdentityResult{
		Verified:     true,
		SPIFFEID:     svid.ID.String(),
		TrustDomain:  "spiffe://" + td.String(),
		BindingMatch: true, // audience matched img.Digest
	}
}

// verifyX509 validates raw as a PEM-encoded X509-SVID cert chain.
func verifyX509(raw []byte, _ core.ImageRef, roots core.TrustRoots) IdentityResult {
	bundleBytes, ok := roots.SPIFFEBundles[snsDevTrustDomain]
	if !ok {
		return IdentityResult{
			Verified: false,
			Err:      "identity/x509: no SPIFFE bundle for trust domain " + snsDevTrustDomain,
		}
	}

	td, err := spiffeid.TrustDomainFromString(snsDevTrustDomain)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: invalid trust domain: %v", err),
		}
	}

	bundle, err := x509bundle.Parse(td, bundleBytes)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: parse X509 bundle: %v", err),
		}
	}

	// Parse the PEM-encoded cert chain from id.Raw.
	certs, err := parsePEMCerts(raw)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: parse cert PEM: %v", err),
		}
	}
	if len(certs) == 0 {
		return IdentityResult{
			Verified: false,
			Err:      "identity/x509: no certificates found in Raw",
		}
	}

	// Verify the chain using go-spiffe. This performs full X.509 path
	// validation and extracts the SPIFFE ID from the leaf's URI SAN.
	spiffeID, _, err := x509svid.Verify(certs, bundle)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: verification failed: %v", err),
		}
	}

	// Check trust domain membership.
	if !spiffeID.MemberOf(td) {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: SPIFFE ID %q is not in trust domain %q", spiffeID, td),
		}
	}

	// v0.1 binding placeholder: BindingMatch is true when the leaf is in the
	// expected trust domain. X509-SVIDs carry no audience; proper image-binding
	// is deferred to a future release.
	return IdentityResult{
		Verified:     true,
		SPIFFEID:     spiffeID.String(),
		TrustDomain:  "spiffe://" + td.String(),
		BindingMatch: true,
	}
}

// parsePEMCerts decodes all PEM CERTIFICATE blocks from b and parses them as
// x509.Certificate objects. It is a helper to avoid importing internal go-spiffe
// packages.
func parsePEMCerts(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
