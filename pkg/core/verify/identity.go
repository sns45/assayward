package verify

// IdentityVerifier validates SPIFFE Verifiable Identity Documents (SVIDs) — both
// JWT-SVIDs and X509-SVIDs — using the go-spiffe library.
//
// # Binding semantics (v0.1 placeholder, documented)
//
// JWT-SVID binding: the workload's expected audience is set to
// "sha256:"+art.Digest["sha256"] (the OCI image digest, in the pre-ArtifactRef
// "sha256:<hex>" form). ParseAndValidate is called with that audience so the
// SPIFFE JWT-SVID must have been issued specifically for this image. This is a
// v0.1 WIMSE placeholder: real workload-image binding will use a richer
// mechanism in a future release.
//
// X509-SVID binding (v0.1 placeholder): BindingMatch is true when the leaf
// SPIFFE ID's trust domain is found in roots.SPIFFEBundles. X509-SVIDs carry
// no audience field, so proper image-binding is deferred to a future release.
//
// # Trust domain resolution
//
// verifyJWT calls ParseInsecure to extract the SPIFFE ID from the sub claim
// before cryptographic validation; the trust domain is used to select the
// correct JWKS bundle from roots.SPIFFEBundles. This supports any trust domain
// without compile-time coupling. The sns45.dev constant is retained only for
// legacy test fixtures that supply a hard-coded key name; it is not used in
// verification logic for JWT-SVIDs.
//
// verifyX509 parses the leaf certificate to extract the URI SAN, derives the
// trust domain, and selects the matching X.509 bundle from roots.SPIFFEBundles.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	core "github.com/sns45/assayward/pkg/core"
)

// IdentityResult is the outcome of verifying a SPIFFE workload identity.
type IdentityResult struct {
	// Verified is true when the SVID parsed and validated successfully against
	// the provided trust bundle.
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
func VerifyIdentity(id core.WorkloadIdentity, art core.ArtifactRef, roots core.TrustRoots) IdentityResult {
	switch id.SVIDType {
	case core.SVIDTypeJWT:
		return verifyJWT(id.Raw, art, roots)
	case core.SVIDTypeX509:
		return verifyX509(id.Raw, art, roots)
	default:
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity: unknown SVIDType %q", id.SVIDType),
		}
	}
}

// verifyJWT validates id.Raw as a compact JWT-SVID token.
//
// Trust domain resolution: the JWT sub claim contains the SPIFFE ID
// (e.g. "spiffe://ci.svidmint.dev/..."). The trust domain is extracted from
// that SPIFFE ID and used to select the correct JWKS from roots.SPIFFEBundles.
// This removes the compile-time coupling to any specific trust domain.
func verifyJWT(raw []byte, art core.ArtifactRef, roots core.TrustRoots) IdentityResult {
	token := string(raw)

	// Step 1: ParseInsecure to extract SPIFFE ID (sub) without bundle lookup.
	// Audience validation here uses "sha256:"+art.Digest["sha256"] — same
	// audience we will require in the secure pass below. This reconstructs the
	// pre-ArtifactRef "sha256:<hex>" form (DigestSet stores bare hex) so the
	// v0.1 audience-binding placeholder's format is unchanged. If audience does
	// not match we fail early before any bundle lookup.
	audience := []string{"sha256:" + art.Digest["sha256"]}
	insecure, err := jwtsvid.ParseInsecure(token, audience)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/jwt: parse insecure (audience/format check): %v", err),
		}
	}

	// Step 2: extract trust domain from the SPIFFE ID obtained above.
	td := insecure.ID.TrustDomain()
	tdName := td.String() // e.g. "sns45.dev" or "ci.svidmint.dev"

	// Step 3: look up the bundle for this trust domain.
	bundleBytes, ok := roots.SPIFFEBundles[tdName]
	if !ok {
		return IdentityResult{
			Verified: false,
			Err:      "identity/jwt: no SPIFFE bundle for trust domain " + tdName,
		}
	}

	bundle, err := jwtbundle.Parse(td, bundleBytes)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/jwt: parse JWKS bundle: %v", err),
		}
	}

	// Step 4: full cryptographic validation with the bundle.
	svid, err := jwtsvid.ParseAndValidate(token, bundle, audience)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/jwt: validation failed: %v", err),
		}
	}

	// Verify that the SPIFFE ID still belongs to the trust domain we looked up
	// (defensive: ParseAndValidate should enforce this, but be explicit).
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
		BindingMatch: true, // audience matched art.Digest["sha256"]
	}
}

// verifyX509 validates raw as a PEM-encoded X509-SVID cert chain.
//
// Trust domain resolution: the leaf certificate's URI SAN is parsed to extract
// the SPIFFE ID and thus the trust domain; the matching bundle is selected from
// roots.SPIFFEBundles. This removes the compile-time coupling to sns45.dev.
func verifyX509(raw []byte, _ core.ArtifactRef, roots core.TrustRoots) IdentityResult {
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

	// Extract trust domain from the leaf certificate's URI SAN.
	tdName, err := trustDomainFromCert(certs[0])
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: extract trust domain: %v", err),
		}
	}

	td, err := spiffeid.TrustDomainFromString(tdName)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: invalid trust domain %q: %v", tdName, err),
		}
	}

	bundleBytes, ok := roots.SPIFFEBundles[tdName]
	if !ok {
		return IdentityResult{
			Verified: false,
			Err:      "identity/x509: no SPIFFE bundle for trust domain " + tdName,
		}
	}

	bundle, err := x509bundle.Parse(td, bundleBytes)
	if err != nil {
		return IdentityResult{
			Verified: false,
			Err:      fmt.Sprintf("identity/x509: parse X509 bundle: %v", err),
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

// trustDomainFromCert extracts the trust domain string from the first SPIFFE
// URI SAN of cert. The SPIFFE URI has the form "spiffe://<trustDomain>/..."
// so the trust domain is the URI host.
func trustDomainFromCert(cert *x509.Certificate) (string, error) {
	for _, uri := range cert.URIs {
		u, err := url.Parse(uri.String())
		if err != nil {
			continue
		}
		if strings.ToLower(u.Scheme) == "spiffe" && u.Host != "" {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("no SPIFFE URI SAN found in certificate")
}
